/*
  Copyright 2012, Stanford University. This file is licensed under GPL v2 plus
  a special exception, as described in included LICENSE_EXCEPTION.txt.

  Author: mchang@cs.stanford.com (Michael Chang)
          peyman.kazemian@gmail.com (Peyman Kazemian)
*/

#include "app.h"
#include "data.h"
#include "ntf.h"
#include "tf.h"
#include <pthread.h>

#define PROGRESS_CNT 1000

static const uint32_t *g_out;
static int g_nout;
static uint32_t g_hop_count;
static bool g_find_loop;

struct tdata {
  pthread_t tid;
  int sw;
  struct list_res res;
};

static struct list_res *queues;
static pthread_cond_t  *conds;

static unsigned int waiters;
static pthread_mutex_t wait_lock = PTHREAD_ADAPTIVE_MUTEX_INITIALIZER_NP;

static bool
is_loop (int port, const struct res *res)
{
  for (; res; res = res->parent)
    if (res->port == port) return true;
  return false;
}

static void
ref_add (struct res *child, struct res *parent)
{
  child->parent = parent;
  parent->refs++;
}


void
app_init (void)
{
  assert (data_file && !queues);
  int n = data_file->ntfs - 1;
  queues = xcalloc (n, sizeof *queues);
  conds = xmalloc (n * sizeof *conds);
  for (int i = 0; i < n; i++) pthread_cond_init (&conds[i], NULL);
}

void
app_fini (void)
{
  free (conds);
  free (queues);
}


void
app_add_in (const struct hs *hs, uint32_t port)
{
  struct res *in = res_create (data_file->stages + 1);
  hs_copy (&in->hs, hs);
  in->port = port;
  list_append (&queues[ntf_get_sw (in->port)], in);
}

static void *
reach_thread (void *vdata)
{
  struct tdata *data = vdata;
  int sw = data->sw;
  struct list_res *res = &data->res;

  const uint32_t *out = g_out;
  int nout = g_nout;
  int ntfs = data_file->ntfs - 1;

  //int count = 0, loops = 0;
  while (true) {
    struct list_res queue = {0};
    pthread_mutex_lock (&wait_lock);
    //fprintf (stderr, "%d %d\n", sw, queues[sw].n);
    while (!queues[sw].head) {
      waiters |= 1 << sw;
      if (waiters + 1 == 1 << ntfs) {
        for (int i = 0; i < ntfs; i++) {
          if (i == sw) continue;
          pthread_cond_broadcast (&conds[i]);
        }
        pthread_mutex_unlock (&wait_lock);
        return NULL;
      }

      pthread_cond_wait (&conds[sw], &wait_lock);

      if (waiters + 1 == 1 << ntfs) {
        pthread_mutex_unlock (&wait_lock);
        return NULL;
      }
      assert (waiters | (1 << sw));
    }
    queue = queues[sw];
    memset (&queues[sw], 0, sizeof queues[sw]);
    pthread_mutex_unlock (&wait_lock);

    struct res *cur;
    while ((cur = queue.head)) {
      list_pop (&queue);

      bool new_res = false;
      struct list_res nextqs[ntfs];
      memset (nextqs, 0, sizeof nextqs);

      struct list_res ntf_res = ntf_apply (cur, sw);
      struct res *ntf_cur = ntf_res.head;
      while (ntf_cur) {
        struct res *ntf_next = ntf_cur->next;
        if (!g_find_loop && (!out || int_find (ntf_cur->port, out, nout))) {
          int count = 0;
          if (g_hop_count > 0) {
          	for (const struct res *r = cur; r != NULL; r = r->parent, count++);
          }
          if (count == 0 || count == g_hop_count-1) {
		    list_append (res, ntf_cur);
			ref_add (ntf_cur, cur);
			if (out) {
		      ntf_cur = ntf_next;
			  continue;
			}
          }
        }

        struct list_res ttf_res = tf_apply (tf_get (0), ntf_cur, true);
        struct res *ttf_cur = ttf_res.head;
        while (ttf_cur) {
          struct res *ttf_next = ttf_cur->next;
          if (is_loop (ttf_cur->port, cur)) {
        	if (!g_find_loop) {
        	  res_free (ttf_cur);
        	  ttf_cur = ttf_next;
        	} else {
        	  list_append (res, ttf_cur);
        	  ref_add (ttf_cur, cur);
        	  ttf_cur = ttf_next;
        	}
            //loops++;
            continue;
          }

          ref_add (ttf_cur, cur);
          if (!g_find_loop && out && int_find (ttf_cur->port, out, nout)) list_append (res, ttf_cur);
          else {
            int new_sw = ntf_get_sw (ttf_cur->port);
            list_append (&nextqs[new_sw], ttf_cur);
            //count++;
            new_res = true;
          }
          ttf_cur = ttf_next;
        }
        if (out) res_free (ntf_cur);
        ntf_cur = ntf_next;
      }
      res_free_mt (cur, true);

      if (!new_res) continue;
      pthread_mutex_lock (&wait_lock);
      unsigned int wake = 0;
      for (int i = 0; i < ntfs; i++) {
        if (!nextqs[i].head) continue;
        list_concat (&queues[i], &nextqs[i]);
        pthread_cond_broadcast (&conds[i]);
        wake |= 1 << i;
      }
      waiters &= ~wake;
      pthread_mutex_unlock (&wait_lock);
    }
  }
}

struct list_res
reachability (const uint32_t *out, int nout, int hop_count, bool find_loop)
{
  struct list_res res = {0};
  int n = data_file->ntfs - 1;
  struct tdata data[n];
  memset (data, 0, sizeof data);

  g_out = out;
  g_nout = nout;
  g_hop_count = hop_count;
  g_find_loop = find_loop;

  for (int i = 0; i < n; i++) {
    struct tdata *p = &data[i];
    p->sw = i;
    pthread_create (&p->tid, NULL, reach_thread, p);
  }
  for (int i = 0; i < n; i++) {
    pthread_join (data[i].tid, NULL);
    list_concat (&res, &data[i].res);
  }

  return res;
}

