/*
  Copyright 2012, Stanford University. This file is licensed under GPL v2 plus
  a special exception, as described in included LICENSE_EXCEPTION.txt.

  Author: mchang@cs.stanford.com (Michael Chang)
          peyman.kazemian@gmail.com (Peyman Kazemian)
*/

#ifndef _RES_H_
#define _RES_H_

#include "hs.h"
#include <pthread.h>

struct tf;

struct res_rule {
  char *tf;
  int rule;
};

struct res {
  struct res *next, *parent;
  int refs;
  pthread_mutex_t lock;

  struct hs hs;
  uint32_t port;
  struct {
    int n, cur;
    struct res_rule arr[0];
  } rules;
};

struct res *res_create   (int nrules);
void        res_free     (struct res *res);
/* Thread-safe. If LOCK, acquire lock first; else lock must already be held. */
void        res_free_mt  (struct res *res, bool lock);
void        res_print    (const struct res *res);

/* Create res based on SRC, with HS and PORT. If APPEND, copy rules from SRC. */
struct res *res_extend   (const struct res *src, const struct hs *hs,
                          uint32_t port, bool append);
void        res_rule_add (struct res *res, const struct tf *tf, int rule);

LIST (res);
void list_res_free  (struct list_res *l);
void list_res_print (const struct list_res *l);

#endif

