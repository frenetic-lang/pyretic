/*
  Copyright 2012, Stanford University. This file is licensed under GPL v2 plus
  a special exception, as described in included LICENSE_EXCEPTION.txt.

  Author: mchang@cs.stanford.com (Michael Chang)
          peyman.kazemian@gmail.com (Peyman Kazemian)
*/

#ifndef _APP_H_
#define _APP_H_

#include "res.h"

void app_init (void);
void app_fini (void);

void app_add_in (const struct hs *hs, uint32_t port);

/* Reachability of HS from IN to OUT. If OUT == NULL, computes reachability to
   all output ports. if hop_count > 0, limit the result to packets that go
   through at least hop_count transfer functions (including ttf)*/
struct list_res reachability (const uint32_t *out, int nout, int hop_count, bool find_loop);

#endif

