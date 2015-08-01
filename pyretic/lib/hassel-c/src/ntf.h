/*
  Copyright 2012, Stanford University. This file is licensed under GPL v2 plus
  a special exception, as described in included LICENSE_EXCEPTION.txt.

  Author: mchang@cs.stanford.com (Michael Chang)
          peyman.kazemian@gmail.com (Peyman Kazemian)
*/

#ifndef _NTF_H_
#define _NTF_H_

#include "res.h"

int             ntf_get_sw (uint32_t port);
struct list_res ntf_apply  (const struct res *in, int sw);
struct list_res ntf_search (const struct res *in, const uint32_t * search_ports, int num);
#endif

