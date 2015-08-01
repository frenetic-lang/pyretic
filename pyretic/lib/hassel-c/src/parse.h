/*
  Copyright 2012, Stanford University. This file is licensed under GPL v2 plus
  a special exception, as described in included LICENSE_EXCEPTION.txt.

  Author: mchang@cs.stanford.com (Michael Chang)
          peyman.kazemian@gmail.com (Peyman Kazemian)
*/

#ifndef _PARSE_H_
#define _PARSE_H_

#include "array.h"
#include "map.h"

/* These structures are used by data_gen() to create the data file used by
   tf/ntf/app. A parser should create and NTF (a parse_ntf) and TTF (a parse_tf)
   and pass these to data_gen(). */
struct parse_dep {
  struct parse_dep *next;
  int rule;
  array_t *match;
  int nports;
  uint32_t ports[0];
};

struct parse_rule {
  struct parse_rule *next;
  int idx;
  ARR_PTR(uint32_t, uint32_t) in, out;
  array_t *match;
  array_t *mask, *rewrite;
  LIST (parse_dep) deps;
  //char *file, *lines;
};

struct parse_tf {
  int len, nrules;
  char *prefix;
  LIST (parse_rule) rules;

  struct map in_map;
};

struct parse_ntf {
  int ntfs;
  int stages;
  struct parse_tf *tfs[0];
};

/* Parse the .tf files in TFDIR/NETNAME, generating OUTDIR/NETNAME.dat, which is
   suitable for loading via data_load(). */
void parse_dir (const char *outdir, const char *tfdir, const char *netname);

#endif

