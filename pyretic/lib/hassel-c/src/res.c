/*
  Copyright 2012, Stanford University. This file is licensed under GPL v2 plus
  a special exception, as described in included LICENSE_EXCEPTION.txt.

  Author: mchang@cs.stanford.com (Michael Chang)
          peyman.kazemian@gmail.com (Peyman Kazemian)
*/

#include "res.h"
#include "data.h"
#include "tf.h"

struct res *
res_create (int nrules)
{
  struct res *res = xcalloc (1, sizeof *res + nrules * sizeof *res->rules.arr);
  res->rules.n = nrules;

  pthread_mutexattr_t attr;
  pthread_mutexattr_init (&attr);
  pthread_mutexattr_settype (&attr, PTHREAD_MUTEX_ADAPTIVE_NP);
  pthread_mutex_init (&res->lock, &attr);
  return res;
}

void
res_free (struct res *res)
{
  if (res->refs) { res->next = NULL; return; }

  hs_destroy (&res->hs);
  pthread_mutex_destroy (&res->lock);
  struct res *parent = res->parent;
  free (res);
  if (parent) { parent->refs--; res_free (parent); }
}

void
res_free_mt (struct res *res, bool lock)
{
  if (lock) pthread_mutex_lock (&res->lock);
  if (res->refs) {
    res->next = NULL;
    pthread_mutex_unlock (&res->lock);
    return;
  }

  pthread_mutex_unlock (&res->lock);
  hs_destroy (&res->hs);
  pthread_mutex_destroy (&res->lock);
  struct res *parent = res->parent;
  free (res);

  if (parent) {
    pthread_mutex_lock (&parent->lock);
    parent->refs--;
    res_free_mt (parent, false);
  }
}

void
res_print (const struct res *res)
{
  if (res->parent) res_print (res->parent);
  printf ("-> Port: %d", res->port);
  if (res->rules.cur) {
    printf (", Rules: ");
    for (int i = 0; i < res->rules.cur; i++) {
      if (i) printf (", ");
      const struct res_rule *r = &res->rules.arr[i];
      printf ("%s_%d", r->tf ? r->tf : "", r->rule);
    }
  }
  printf ("\n");
}


struct res *
res_extend (const struct res *src, const struct hs *hs, uint32_t port,
            bool append)
{
  struct res *res = res_create (src->rules.n);
  if (hs) hs_copy (&res->hs, hs);
  res->port = port;
  if (append) {
    res->rules.cur = src->rules.cur;
    memcpy (res->rules.arr, src->rules.arr, res->rules.cur * sizeof *res->rules.arr);
  }
  return res;
}

void
res_rule_add (struct res *res, const struct tf *tf, int rule)
{
  struct res_rule tmp = {tf->prefix ? DATA_STR (tf->prefix) : NULL, rule};
  assert (res->rules.cur < res->rules.n);
  res->rules.arr[res->rules.cur++] = tmp;
}


/* Won't free structs with refs, but next pointers will be NULLed. */
void
list_res_free (struct list_res *l)
{ list_destroy (l, res_free); }

void
list_res_print (const struct list_res *l)
{
  int count = 0;
  for (const struct res *res = l->head; res; res = res->next, count++) {
    res_print (res);
    printf ("   HS: ");
    hs_print (&res->hs);
    printf ("-----\n");
  }
  printf ("Count: %d\n", count);
}

