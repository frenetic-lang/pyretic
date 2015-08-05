/*
  Copyright 2012, Stanford University. This file is licensed under GPL v2 plus
  a special exception, as described in included LICENSE_EXCEPTION.txt.

  Author: mchang@cs.stanford.com (Michael Chang)
          peyman.kazemian@gmail.com (Peyman Kazemian)
*/

#include "tf.h"
#include "data.h"

#define MAX_APP 10240

#define CAST(TF) ( (const uint8_t *) (TF) )

#define OFS_(TF, X) ( CAST (TF) + (TF)->X ## _ofs )
#define DEPS(TF, D) ( (const struct deps *) (OFS_ (TF, deps) + ((D) - VALID_OFS)) )
#define MAP(TF) ( (const struct port_map *) OFS_ (TF, map) )
#define PORTS(TF, P) ( (const struct ports *) (OFS_ (TF, ports) + (-(P) - VALID_OFS)) )

static void
app_add (uint32_t idx, uint32_t *app, int *napp)
{
  assert (*napp <= MAX_APP);
  app[(*napp)++] = idx;
}

static int
map_cmp (const void *a, const void *b)
{ return ((const struct port_map_elem *)a)->port -
         ((const struct port_map_elem *)b)->port; }

static bool
port_match (uint32_t port, int32_t ofs, const struct tf *tf)
{
  const struct ports *p = PORTS (tf, ofs);
  return int_find (port, p->arr, p->n);
}


static void
deps_diff (struct hs *hs, uint32_t port, const struct deps *deps,
           const struct tf *tf, const uint32_t *app, int napp)
{
  for (int i = 0; i < deps->n; i++) {
    const struct dep *dep = &deps->deps[i];
    if (app && !int_find (dep->rule, app, napp)) continue;
    if (dep->port > 0 && dep->port != port) continue;
    if (dep->port < 0 && !port_match (port, dep->port, tf)) continue;
    hs_diff (hs, DATA_ARR (dep->match));
  }
}

static void
print_ports (int32_t p, const struct tf *tf)
{
  if (p >= 0) {
    if (p > 0) printf ("%" PRId32, p);
    printf ("\n");
    return;
  }

  const struct ports *ports = PORTS (tf, p);
  for (int i = 0; i < ports->n; i++) {
    if (i) printf (", ");
    printf ("%" PRIu32, ports->arr[i]);
  }
  printf ("\n");
}

static bool
port_append_res (struct list_res *res, const struct rule *r,
		 const struct tf *tf, const struct res *in, int32_t ports,
		 bool append, const struct hs *hs)
{
  /* Create new result containing headerspace `hs` for each port in `ports`. */
  bool used_hs = false;
  uint32_t n, x;
  const uint32_t *a;
  if (ports > 0) { n = 1; x = ports; a = &x; }
  else {
    const struct ports *p = PORTS (tf, ports);
    n = p->n; a = p->arr;
  }

  for (int i = 0; i < n; i++) {
    if (a[i] == in->port) continue;
    struct res *tmp;
    if (used_hs) tmp = res_extend (in, hs, a[i], append);
    else {
      tmp = res_extend (in, NULL, a[i], append);
      tmp->hs = *hs;
      used_hs = true;
    }
    res_rule_add (tmp, tf, r->idx, r);
    list_append (res, tmp);
  }

  return used_hs;
}


static struct list_res
rule_apply (const struct rule *r, const struct tf *tf, const struct res *in,
            bool append, uint32_t *app, int *napp)
{
  struct list_res res = {0};

  if (!r->out) app_add (r->idx, app, napp);
  if (!r->out || r->out == in->port) return res;

  struct hs hs;
  if (!r->match) hs_copy (&hs, &in->hs);
  else {
    if (!hs_isect_arr (&hs, &in->hs, DATA_ARR (r->match))) return res;
    if (r->deps) deps_diff (&hs, in->port, DEPS (tf, r->deps), tf, app, *napp);
    if (!hs_compact_m (&hs, r->mask ? DATA_ARR (r->mask) : NULL)) { hs_destroy (&hs); return res; }
    if (r->mask) hs_rewrite (&hs, DATA_ARR (r->mask), DATA_ARR (r->rewrite));
  }

  bool used_hs = port_append_res (&res, r, tf, in, r->out, append, &hs);

  if (res.head) app_add (r->idx, app, napp);
  if (!used_hs) hs_destroy (&hs);
  return res;
}

static const struct port_map_elem *
rule_get (const struct tf *tf, uint32_t port)
{
  const struct port_map *m = MAP (tf);
  struct port_map_elem tmp = {port};
  return bsearch (&tmp, m->elems, m->n, sizeof tmp, map_cmp);
}

void
rule_print (const struct rule *r, const struct tf *tf)
{
  printf ("Rule %u\nIn: ", r->idx);
  print_ports (r->in, tf);
  printf ("Out: ");
  print_ports (r->out, tf);
  if (r->match) {
    char *match = array_to_str (DATA_ARR (r->match), data_arrs_len, true);
    printf ("Match: %s\n", match);
    free (match);
    if (r->mask) {
      char *mask = array_to_str (DATA_ARR (r->mask), data_arrs_len, false);
      char *rewrite = array_to_str (DATA_ARR (r->rewrite), data_arrs_len, false);
      printf ("Mask: %s\nRewrite: %s\n", mask, rewrite);
      free (mask);
      free (rewrite);
    }
    //printf ("Deps:\n");
    //deps_print (r->deps);
  }
  printf ("-----\n");
}

static void
deps_diff_inv (struct hs *hs, uint32_t port, const struct deps *deps,
	       const struct tf *tf)
{
  for (int i = 0; i < deps->n; i++) {
    const struct dep *dep = &deps->deps[i];
    if (dep->port > 0 && dep->port != port) continue;
    if (dep->port < 0 && !port_match (port, dep->port, tf)) continue;
    hs_diff (hs, DATA_ARR (dep->match));
  }
}

struct list_res
rule_inv_apply(const struct tf *tf, const struct rule *r, const struct res *in,
	       bool append)
{
  /* Given a rule `r` in a tf `tf`, apply the inverse of `r` on the input
     (headerspace,port) `in`. */
  uint32_t app[MAX_APP];
  int napp = 0;
  struct list_res res = {0};

  // prune cases where rule outport doesn't include the current port
  if (r->out > 0 && r->out != in->port) return res;
  if (r->out < 0 && !port_match(in->port, r->out, tf)) return res;
  if (!r->out) return res;

  // set up inverse match and rewrite arrays
  array_t *new_mat, *inv_mask, *new_rw, *inv_mat, *inv_rw, *masked_mat;
  array_t *isect_mat;
  int ln = in->hs->len;
  if (r->mask) { // rewrite rule
    assert (r->match); // rewrite rules MUST have a match
    inv_mask = array_not_a (DATA_ARR (r->mask), ln);
    new_rw   = array_and_a (inv_mask, DATA_ARR (r->rewrite));
    masked_mat = array_and_a (DATA_ARR (r->match), DATA_ARR (r->mask));
    inv_mat  = array_or_a  (new_rw, masked_mat);
    inv_rw = array_and_a (DATA_ARR (r->match), inv_mask);
    isect_mat = inv_mat;
  }
  else { // fwding and topology rules
    if (r->match) isect_mat = array_copy (DATA_ARR (r->match), ln);
  }

  struct hs hs;
  if (!r->match) hs_copy (&hs, &in->hs); // topology rule
  else { // fwding and rewrite rules
    if (!hs_isect_arr (&hs, &in->hs, isect_mat)) return res;
    if (r->mask) hs_rewrite (&hs, inv_mask, inv_rw);
    if (r->deps) deps_diff_inv (&hs, in->port, DEPS (tf, r->deps), tf);
    if (!hs_compact_m (&hs, r->mask ? DATA_ARR (r->mask) : NULL)) { hs_destroy(&hs); return res; }
  }

  // there is a new hs result corresponding to each rule inport
  bool used_hs = port_append_res (&res, r, tf, in, r->in, append, &hs);

  // free memory
  if (new_mat) array_free (new_mat);
  if (inv_mask) array_free (inv_mask);
  if (new_rw) array_free (new_rw);
  if (inv_mat) array_free (inv_mat);
  if (inv_rw) array_free (inv_rw);
  if (masked_mat) array_free (masked_mat);
  if (isect_mat) array_free (isect_mat);
  if (!used_hs) hs_destroy (&hs);

  return res;
}


struct list_res
tf_apply (const struct tf *tf, const struct res *in, bool append)
{
  assert (in->hs.len == data_arrs_len);
  uint32_t app[MAX_APP];
  int napp = 0;
  struct list_res res = {0};

  const struct port_map_elem *rules = rule_get (tf, in->port);
  if (!rules) return res;

  if (rules->start != UINT32_MAX) {
    for (uint32_t cur = rules->start; cur < tf->nrules; cur++) {
      const struct rule *r = &tf->rules[cur];
      assert (r->in > 0);
      if (r->in != in->port) break;

      struct list_res tmp;
      tmp = rule_apply (r, tf, in, append, app, &napp);
      list_concat (&res, &tmp);
    }
  }

  /* Check all rules with multiple ports. */
  for (int i = 0; i < tf->nrules; i++) {
    const struct rule *r = &tf->rules[i];
    if (r->in >= 0) break;
    if (!port_match (in->port, r->in, tf)) continue;

    struct list_res tmp;
    tmp = rule_apply (r, tf, in, append, app, &napp);
    list_concat (&res, &tmp);
  }

  return res;
}

struct tf *
tf_get (int idx)
{
  assert (idx >= 0 && idx < data_file->ntfs);
  uint32_t ofs = data_file->tf_ofs[idx];
  return (struct tf *) (data_raw + ofs);
}

void
tf_print (const struct tf *tf)
{
  if (tf->prefix) printf ("Prefix: %s\n", DATA_STR (tf->prefix));
  for (int i = 0; i < tf->nrules; i++)
    rule_print (&tf->rules[i], tf);
}

