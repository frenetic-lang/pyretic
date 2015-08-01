/*
  Copyright 2012, Stanford University. This file is licensed under GPL v2 plus
  a special exception, as described in included LICENSE_EXCEPTION.txt.

  Author: mchang@cs.stanford.com (Michael Chang)
          peyman.kazemian@gmail.com (Peyman Kazemian)
*/

#include "parse.h"
#include "data.h"
#include <dirent.h>
#include <limits.h>

#define MAX_ARR_SIZE 1024
#define MAX_PREFIX 255

static void
add_rule (struct parse_tf *tf, struct parse_rule *r)
{
  r->idx = ++tf->nrules;
  list_append (&tf->rules, r);

  for (int i = 0; i < r->in.n; i++) {
    struct map_elem *e = map_find_create (&tf->in_map, ARR (r->in)[i]);
    struct map_val *tmp = xmalloc (sizeof *tmp);
    tmp->val = r;
    list_append (&e->vals, tmp);
  }
}

static int
filter_tfs (const struct dirent *ent)
{
  char *ext = strrchr (ent->d_name, '.');
  if (!ext || strcmp (ext, ".tf")) return false;
  return strcmp (ent->d_name, "topology.tf");
}

static struct arr_ptr_uint32_t
read_array (char *s, uint32_t *res)
{
  uint32_t buf[MAX_ARR_SIZE];
  if (!res) res = buf;

  int end, n = 0;
  if (*s == '[') { s++; s[strlen (s) - 1] = 0; }
  while (sscanf (s, " %" SCNu32 "%n", &res[n], &end) == 1) {
    n++; s += end;
    if (*s == ',') s++;
  }

  struct arr_ptr_uint32_t tmp = {0};
  if (!n) return tmp;

  qsort (res, n, sizeof *res, int_cmp);
  tmp.n = n;
  if (res == buf) {
    ARR_ALLOC (tmp, n);
    memcpy (ARR (tmp), buf, n * sizeof *buf);
  }
  return tmp;
}

static struct list_parse_dep
read_deps (char *s)
{
  char *save;
  struct list_parse_dep res = {0};
  for (char *depstr = strtok_r (s, "#", &save); depstr;
       depstr = strtok_r (NULL, "#", &save)) {
    char *save2;
    char *match, *portstr;
    int rule;

    rule = atoi (strtok_r (depstr, ";", &save2)) + 1;
    match = strtok_r (NULL, ";", &save2);
    portstr = strtok_r (NULL, ";", &save2);

    uint32_t ports[MAX_ARR_SIZE];
    struct arr_ptr_uint32_t nports = read_array (portstr, ports);

    struct parse_dep *tmp = xmalloc (sizeof *tmp + nports.n * sizeof *ports);
    tmp->rule = rule;
    tmp->match = array_from_str (match);
    tmp->nports = nports.n;
    memcpy (tmp->ports, ports, nports.n * sizeof *ports);

    list_append (&res, tmp);
  }
  return res;
}


static struct parse_tf *
parse_tf (const char *name)
{
  FILE *in = fopen (name, "r");
  char *line = NULL;
  int len;
  size_t n;

  if (!in || (len = getline (&line, &n, in)) == -1)
    err (1, "Can't read file \"%s\"", name);

  int tflen;
  char prefix[MAX_PREFIX + 1];

  int res = sscanf (line, "%d$%" QUOTE (MAX_PREFIX) "[^$]$", &tflen, prefix);
  if (res < 1) errx (1, "Can't read len from first line \"%s\".", line);
  tflen /= 2; /* Convert to L */

  struct parse_tf *tf = xcalloc (1, sizeof *tf);
  tf->len = tflen;
  if (res == 2) tf->prefix = xstrdup (prefix);

  /* Skip next line */
  getline (&line, &n, in);
  while ((len = getline (&line, &n, in)) != -1) {
    char *save;
    char *type, *instr, *match, *mask, *rewrite, *outstr, *affected;
    //char *file, *lines, *id;

    type = strtok_r (line, "$", &save);
    instr = strtok_r (NULL, "$", &save);
    match = strtok_r (NULL, "$", &save);
    mask = strtok_r (NULL, "$", &save);
    rewrite = strtok_r (NULL, "$", &save);
    /*inv_match =*/ strtok_r (NULL, "$", &save);
    /*inv_rewrite =*/ strtok_r (NULL, "$", &save);
    outstr = strtok_r (NULL, "$", &save);
    affected = strtok_r (NULL, "$", &save);
    /*influence = */strtok_r (NULL, "$", &save);
    /* TODO: desc
    file = strtok_r (NULL, "$", &save);
    lines = strtok_r (NULL, "$", &save);
    id = strtok_r (NULL, "$", &save);
    if (!id) { id = file; file = lines = NULL; }*/

    struct parse_rule *r = xcalloc (1, sizeof *r);
    r->in = read_array (instr, NULL);
    r->out = read_array (outstr, NULL);
    /*if (file) {
      r->file = xstrdup (file);
      lines[strlen (lines) - 1] = 0;
      r->lines = xstrdup (lines);
    }*/

    if (strcmp (type, "link")) {
      r->match = array_from_str (match);
      if (!strcmp (type, "rw")) {
        r->mask = array_from_str (mask);
        r->rewrite = array_from_str (rewrite);
      }
    }
    r->deps = read_deps (affected);
    add_rule (tf, r);
  }

  free (line);
  fclose (in);
  return tf;
}


static void
free_dep (struct parse_dep *dep)
{ array_free (dep->match); free (dep); }

static void
free_rule (struct parse_rule *r)
{
  ARR_FREE (r->in);
  ARR_FREE (r->out);
  array_t *arrs[] = {r->match, r->mask, r->rewrite};
  for (int i = 0; i < ARR_LEN (arrs); i++) array_free (arrs[i]);
  list_destroy (&r->deps, free_dep);
  free (r);
}

static void
free_tf (struct parse_tf *tf)
{
  free (tf->prefix);
  list_destroy (&tf->rules, free_rule);
  map_destroy (&tf->in_map);
  free (tf);
}


static void
free_ntf (struct parse_ntf *ntf)
{
  for (int i = 0; i < ntf->ntfs; i++) free_tf (ntf->tfs[i]);
  free (ntf);
}


void
parse_dir (const char *outdir, const char *tfdir, const char *name)
{
  printf ("Parsing: ");
  fflush (stdout);

  struct parse_ntf *ntf;
  struct parse_tf *ttf;
  int stages;

  char buf[PATH_MAX + 1];
  snprintf (buf, sizeof buf, "%s/%s", tfdir, name);
  char *base = buf + strlen (buf);

  strcpy (base, "/stages");
  FILE *f = fopen (buf, "r");
  if (!f) err (1, "Can't open %s", buf);
  if (!fscanf (f, "%d", &stages)) errx (1, "Can't read NTF stages from %s", buf);
  fclose (f);

  *base = 0;
  struct dirent **tfs;
  int n = scandir (buf, &tfs, filter_tfs, alphasort);
  if (n <= 0) err (1, "Couldn't find .tf files in %s", buf);

  ntf = xmalloc (sizeof *ntf + n * sizeof *ntf->tfs);
  ntf->ntfs = n;
  ntf->stages = stages;
  *base = '/';
  for (int i = 0; i < n; i++) {
    strcpy (base + 1, tfs[i]->d_name);
    free (tfs[i]);
    struct parse_tf *tf = parse_tf (buf);
    assert (tf);
    ntf->tfs[i] = tf;
  }
  free (tfs);

  strcpy (base, "/topology.tf");
  ttf = parse_tf (buf);
  assert (ttf);
  printf ("done\n");

  snprintf (buf, sizeof buf, "%s/%s.dat", outdir, name);
  data_gen (buf, ntf, ttf);

  free_ntf (ntf);
  free_tf (ttf);
}

