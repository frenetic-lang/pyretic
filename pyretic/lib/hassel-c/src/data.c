/*
  Copyright 2012, Stanford University. This file is licensed under GPL v2 plus
  a special exception, as described in included LICENSE_EXCEPTION.txt.

  Author: mchang@cs.stanford.com (Michael Chang)
          peyman.kazemian@gmail.com (Peyman Kazemian)
*/

#include "data.h"
#include "parse.h"
#include "tf.h"
#include <fcntl.h>
#include <stddef.h>
#include <sys/mman.h>
#include <unistd.h>

struct file *data_file;
uint8_t     *data_raw;
size_t       data_size;

array_t *data_arrs;
uint32_t data_arrs_len, data_arrs_n;
char    *data_strs;

struct PACKED arrs {
  uint32_t len, n;
  array_t arrs[0];
};

void
data_load (const char *name)
{
  int fd = open (name, O_RDONLY);
  if (fd < 0) err (1, "open(%s) failed", name);
  data_size = lseek (fd, 0, SEEK_END);
  assert (data_size >= 0);

  data_raw = mmap (NULL, data_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (data_raw == MAP_FAILED) err (1, "mmap() failed");
  close (fd);
  data_file = (struct file *) data_raw;

  struct arrs *arrs = (struct arrs *) (data_raw + data_file->arrs_ofs);
  data_arrs_len = arrs->len;
  data_arrs_n = arrs->n;
  data_arrs = arrs->arrs;
  data_strs = (char *) (data_raw + data_file->strs_ofs);
}

void
data_unload (void)
{ munmap (data_raw, data_size); }


static uint32_t arr_len;

static int
arr_cmp (const void *a, const void *b)
{ return memcmp (a, b, ARRAY_BYTES (arr_len)); }

static uint32_t
arr_find (const array_t *a, const array_t *arrs, int n)
{
  if (!a) return 0;
  int len = ARRAY_BYTES (arr_len);
  array_t *b = bsearch (a, arrs, n, len, arr_cmp);
  assert (b);
  return VALID_OFS + ((uint8_t *)b - (uint8_t *)arrs);
}

static int
rule_cmp (const void *va, const void *vb)
{
  const struct rule *a = va, *b = vb;
  if ((a->in < 0 && b->in < 0) || a->in == b->in) return a->idx - b->idx;
  return a->in - b->in;
}


static array_t *
gen_arrs (const struct parse_ntf *ntf, uint32_t *n)
{
  char *buf, *buf2;
  size_t bufsz, buf2sz;
  FILE *f = open_memstream (&buf, &bufsz);

  uint32_t len = ARRAY_BYTES (arr_len);
  int count = 0;
  for (int i = 0; i < ntf->ntfs; i++) {
    const struct parse_tf *tf = ntf->tfs[i];
    for (struct parse_rule *r = tf->rules.head; r; r = r->next) {
      assert (r->match);
      fwrite (r->match, len, 1, f);
      count++;
      if (r->mask) {
        fwrite (r->mask, len, 1, f);
        fwrite (r->rewrite, len, 1, f);
        count += 2;
      }
      for (struct parse_dep *dep = r->deps.head; dep; dep = dep->next) {
        fwrite (dep->match, len, 1, f);
        count++;
      }
    }
  }
  fclose (f);

  printf ("Arrays: %d (%zu)", count, bufsz);
  fflush (stdout);
  assert (count * len == bufsz);

  qsort (buf, count, len, arr_cmp);
  array_t *arrs = (array_t *) buf;
  int count2 = 0, last = -1;

  f = open_memstream (&buf2, &buf2sz);
  for (int i = 0; i < count * (len / sizeof (array_t)); i += len / sizeof (array_t)) {
    if (last != -1 && array_is_eq (&arrs[i], &arrs[last], arr_len)) continue;
    fwrite (&arrs[i], len, 1, f);
    last = i;
    count2++;
  }
  fclose (f);
  free (buf);

  printf (" -> %d (%zu)\n", count2, buf2sz);
  assert (count2 * len == buf2sz);

  *n = count2;
  return (array_t *) buf2;
}

static void
gen_map (FILE *out, const struct map *m, const struct rule *rules, int nrules)
{
  uint32_t n = m->used;
  fwrite (&n, sizeof n, 1, out);
  for (int i = 0; i < m->used; i++) {
    struct map_elem *e = &m->elems[i];
    struct port_map_elem tmp = {e->key, UINT32_MAX};
    int min = -1;
    for (struct map_val *v = e->vals.head; v; v = v->next) {
      struct parse_rule *r = v->val;
      if (r->in.n != 1) continue;
      if (min == -1 || r->idx < min) min = r->idx;
    }
    if (min != -1) {
      struct rule key = {min, tmp.port};
      struct rule *f = bsearch (&key, rules, nrules, sizeof key, rule_cmp);
      assert (f);
      tmp.start = f - rules;
    }
    fwrite (&tmp, sizeof tmp, 1, out);
  }
}

static int32_t
gen_ports (const uint32_t *arr, uint32_t n, FILE *f_ports)
{
  if (!n) return 0;
  if (n == 1) return arr[0];

  int32_t ret = -(VALID_OFS + ftell (f_ports));
  fwrite (&n, sizeof n, 1, f_ports);
  fwrite (arr, sizeof *arr, n, f_ports);
  return ret;
}

static uint32_t
gen_deps (struct list_parse_dep *deps, FILE *f_deps, FILE *f_ports,
          const array_t *arrs, int narrs)
{
  uint32_t n = deps->n;
  uint32_t ret = VALID_OFS + ftell (f_deps);
  fwrite (&n, sizeof n, 1, f_deps);
  for (struct parse_dep *dep = deps->head; dep; dep = dep->next) {
    struct dep tmp = {dep->rule};
    tmp.match = arr_find (dep->match, arrs, narrs);
    tmp.port = gen_ports (dep->ports, dep->nports, f_ports);
    fwrite (&tmp, sizeof tmp, 1, f_deps);
  }
  return ret;
}

static void
gen_tf (const struct parse_tf *tf, FILE *out, FILE *f_strs, const array_t *arrs,
        int narrs)
{
  char *buf_deps, *buf_ports;
  size_t sz_deps, sz_ports;
  FILE *f_ports = open_memstream (&buf_ports, &sz_ports);
  FILE *f_deps = open_memstream (&buf_deps, &sz_deps);

  int start = ftell (out);
  struct tf hdr = {ftell (f_strs) + VALID_OFS, tf->nrules};

  if (tf->prefix) fwrite (tf->prefix, 1, strlen (tf->prefix) + 1, f_strs);
  else hdr.prefix = 0;
  fwrite (&hdr, sizeof hdr, 1, out);
  /* TODO: Alignment? */

  struct rule rules[hdr.nrules];
  memset (rules, 0, sizeof rules);

  int i = 0;
  for (struct parse_rule *r = tf->rules.head; r; r = r->next, i++) {
    struct rule *tmp = &rules[i];
    tmp->idx = r->idx;
    tmp->in = gen_ports (ARR (r->in), r->in.n, f_ports);
    tmp->out = gen_ports (ARR (r->out), r->out.n, f_ports);
    tmp->match = arr_find (r->match, arrs, narrs);
    tmp->mask = arr_find (r->mask, arrs, narrs);
    tmp->rewrite = arr_find (r->rewrite, arrs, narrs);
    if (r->deps.head) tmp->deps = gen_deps (&r->deps, f_deps, f_ports, arrs, narrs);
    //tmp->desc = barfoo;
  }
  fclose (f_ports);
  fclose (f_deps);

  qsort (rules, hdr.nrules, sizeof *rules, rule_cmp);
  fwrite (rules, hdr.nrules, sizeof *rules, out);

  hdr.map_ofs = ftell (out) - start;
  gen_map (out, &tf->in_map, rules, ARR_LEN (rules));

  hdr.ports_ofs = ftell (out) - start;
  fwrite (buf_ports, 1, sz_ports, out);
  free (buf_ports);

  hdr.deps_ofs = ftell (out) - start;
  fwrite (buf_deps, 1, sz_deps, out);
  free (buf_deps);

  int end = ftell (out);
  fseek (out, start, SEEK_SET);
  fwrite (&hdr, sizeof hdr, 1, out);
  fseek (out, end, SEEK_SET);
}

void
data_gen (const char *name, const struct parse_ntf *ntf, const struct parse_tf *ttf)
{
  FILE *out = fopen (name, "w");
  if (!out) err (1, "Can't open output file %s", name);

  int ntfs = ntf->ntfs + 1;
  char *buf_strs;
  size_t sz_strs;
  FILE *f_strs = open_memstream (&buf_strs, &sz_strs);

  uint32_t narrs;
  arr_len = ntf->tfs[0]->len;
  array_t *arrs = gen_arrs (ntf, &narrs);

  int hdr_size = offsetof (struct file, tf_ofs[ntfs]);
  struct file *hdr = xmalloc (hdr_size);
  memset (hdr, 0, hdr_size);
  hdr->ntfs = ntfs;
  hdr->stages = ntf->stages;
  fwrite (hdr, hdr_size, 1, out);

  for (int i = 0; i < ntfs; i++) {
    hdr->tf_ofs[i] = ftell (out);
    printf ("%" PRIu32 "\n", hdr->tf_ofs[i]);
    if (!i) gen_tf (ttf, out, f_strs, arrs, narrs);
    else gen_tf (ntf->tfs[i - 1], out, f_strs, arrs, narrs);
  }
  fclose (f_strs);

  int len = ARRAY_BYTES (arr_len);
  hdr->arrs_ofs = ftell (out);
  fwrite (&arr_len, sizeof arr_len, 1, out);
  fwrite (&narrs, sizeof narrs, 1, out);
  fwrite (arrs, len, narrs, out);
  free (arrs);

  hdr->strs_ofs = ftell (out);
  fwrite (buf_strs, 1, sz_strs, out);
  free (buf_strs);

  int end = ftell (out);
  rewind (out);
  fwrite (hdr, hdr_size, 1, out);
  free (hdr);

  printf ("Total: %d bytes\n", end);
  fclose (out);
}

