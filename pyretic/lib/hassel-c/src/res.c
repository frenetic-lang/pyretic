/*
  Copyright 2012, Stanford University. This file is licensed under GPL v2 plus
  a special exception, as described in included LICENSE_EXCEPTION.txt.

  Author: mchang@cs.stanford.com (Michael Chang)
          peyman.kazemian@gmail.com (Peyman Kazemian)
*/

#include "res.h"
#include "data.h"
#include "tf.h"

#define MAX_STR 65536

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
res_print (const struct res *res, bool backward)
{
  if (!backward && res->parent) res_print (res->parent, backward);
  printf ("-> Port: %d", res->port);
  printf ("\n");
  printf ("-> HS: \n");
  hs_print (&res->hs);
  if (res->rules.cur) {
    printf (", Rules: ");
    for (int i = 0; i < res->rules.cur; i++) {
      if (i) printf (", ");
      const struct res_rule *r = &res->rules.arr[i];
      printf ("%s_%d", r->tf ? r->tf : "", r->rule);
      printf ("\n");
      rule_print (r->tf_rule, r->tf_tf);
    }
  }
  printf ("\n");
  if (backward && res->parent) res_print (res->parent, backward);
}

struct list_res
res_walk_parents (const struct res *out, const struct hs *hs, int in_port,
		  array_t* out_arr)
{
  struct res *curr_res = (struct res*) out;
  struct list_res currq = {0};

  // set up initial result to start inversion
  struct hs int_hs;
  hs_isect_arr (&int_hs, &out->hs, out_arr);
  list_append (&currq, res_extend (out, &int_hs, out->port, true));

  struct res *cur;

  while (curr_res) {
    if (curr_res->rules.cur) {
      for (int i = curr_res->rules.cur - 1; i >= 0; i--) {
	struct list_res nextq = {0};
	struct res_rule r = curr_res->rules.arr[i];
	while ((cur = currq.head)) {
	  list_pop (&currq);
	  struct list_res tmp = rule_inv_apply (r.tf_tf, r.tf_rule, cur, false);
	  list_concat (&nextq, &tmp);
	  res_free (cur);
	} // for each current result from rule inversion
	currq = nextq;
      } // for each rule
    }
    else return currq;

    // set (hs,port) which the inverted (hs,port) results must intersect
    struct res *parent = curr_res->parent;
    struct hs *next_hs = hs_create (curr_res->hs.len);
    int next_port;
    if (parent) {
      hs_copy (next_hs, &parent->hs);
      next_port = parent->port;
    }
    else {
      hs_copy (next_hs, hs);
      next_port = in_port;
    }

    // Intersect the results in `currq` with the target (hs,port)
    struct list_res nextq = {0};
    while ((cur = currq.head)) {
      list_pop (&currq);
      struct hs *new_hs = hs_isect_a (&cur->hs, next_hs);
      if (cur->port == next_port && new_hs)
	list_append (&nextq, res_extend (cur, new_hs, next_port, false));
      else
	res_free (cur);
    }
    currq = nextq;
    curr_res = parent;
  }

  return currq;
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
res_rule_add (struct res *res, const struct tf *tf, int rule,
	      const struct rule *tf_rule)
{
  struct res_rule tmp = {tf->prefix ? DATA_STR (tf->prefix) : NULL, rule,
			 (struct rule*) tf_rule, (struct tf*) tf};
  assert (res->rules.cur < res->rules.n);
  res->rules.arr[res->rules.cur++] = tmp;
}


/* Won't free structs with refs, but next pointers will be NULLed. */
void
list_res_free (struct list_res *l)
{ list_destroy (l, res_free); }

void
list_res_fileprint_json (const struct list_res *l, FILE* ofp)
{
  char s[MAX_STR];
  for (const struct res *res = l->head; res; res = res->next) {
    hs_get_json (&res->hs, s);
    fprintf (ofp, "%s\n", s);
  }
}

void
list_res_print (const struct list_res *l, bool backward)
{
  int count = 0;
  for (const struct res *res = l->head; res; res = res->next, count++) {
    res_print (res, backward);
    printf ("   HS: ");
    hs_print (&res->hs);
    hs_print_json (&res->hs);
    printf ("-----\n");
  }
  printf ("Count: %d\n", count);
}

