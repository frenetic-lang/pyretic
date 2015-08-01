/*
  Copyright 2012, Stanford University. This file is licensed under GPL v2 plus
  a special exception, as described in included LICENSE_EXCEPTION.txt.

  Author: mchang@cs.stanford.com (Michael Chang)
          peyman.kazemian@gmail.com (Peyman Kazemian)
*/

#include "ntf.h"
#include "data.h"
#include "tf.h"

#define SWITCH_ID 100000
#define OUTPUT_ID 20000

int
ntf_get_sw (uint32_t port)
{
  int idx = port / SWITCH_ID - 1;
  assert (idx >= 0 && idx < data_file->ntfs - 1);
  return idx;
}

struct list_res
ntf_apply (const struct res *in, int sw)
{
  struct tf *tf = tf_get (sw + 1);

  struct list_res queue = tf_apply (tf, in, false);
  for (int i = 0; i < data_file->stages - 1; i++) {
    struct list_res nextq = {0};
    for (struct res *cur = queue.head; cur; cur = cur->next) {
      struct list_res tmp = tf_apply (tf, cur, true);
      list_concat (&nextq, &tmp);
    }
    list_res_free (&queue);
    queue = nextq;
  }

  struct res *cur = queue.head, *prev = NULL;
  while (cur) {
    int p = in->port + OUTPUT_ID;
    if (cur->port == p) list_remove (&queue, cur, prev, res_free);
    else { prev = cur; cur = cur->next; }
  }

  return queue;
}

struct list_res
ntf_search (const struct res *in, const uint32_t * search_ports, int num)
{
  int sw = ntf_get_sw(in->port);
  struct tf *tf = tf_get (sw + 1);

  struct list_res queue = tf_apply (tf, in, false);
  struct list_res found = {0};
  for (int i = 0; i < data_file->stages - 1; i++) {
    struct list_res nextq = {0};
    for (struct res *cur = queue.head; cur; cur = cur->next) {
    	list_pop (&queue);
    	if (search_ports && int_find (cur->port, search_ports, num)) {
    		list_append(&found,cur);
    	} else {
    		struct list_res tmp = tf_apply (tf, cur, true);
    		list_concat (&nextq, &tmp);
    	}
    }
    list_res_free (&queue);
    queue = nextq;
  }
  return found;
}
