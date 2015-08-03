/*
  Copyright 2012, Stanford University. This file is licensed under GPL v2 plus
  a special exception, as described in included LICENSE_EXCEPTION.txt.

  Author: mchang@cs.stanford.com (Michael Chang)
          peyman.kazemian@gmail.com (Peyman Kazemian)
*/

#include "app.h"
#include "data.h"
#include <libgen.h>
#include <limits.h>
#include <sys/time.h>
#include <unistd.h>
#include "ntf.h"

#ifndef NTF_STAGES
#define NTF_STAGES 1
#endif

static inline int64_t
diff (struct timeval *a, struct timeval *b)
{
  int64_t x = (int64_t)a->tv_sec * 1000000 + a->tv_usec;
  int64_t y = (int64_t)b->tv_sec * 1000000 + b->tv_usec;
  return x - y;
}

static void
unload (void)
{ data_unload (); }


static void
load (char *net)
{
  char name[PATH_MAX + 1];
  snprintf (name, sizeof name, "data/%s.dat", net);
  data_load (name);
  if (atexit (unload)) errx (1, "Failed to set exit handler.");
}

bool
hs_inters_test ()
{
  struct hs hs1, hs2, hs3, hs4;
  memset (&hs1, 0, sizeof hs1);
  memset (&hs2, 0, sizeof hs2);
  memset (&hs3, 0, sizeof hs3);
  memset (&hs4, 0, sizeof hs4);
  hs1.len = hs2.len = hs3.len = hs4.len = data_arrs_len;
  hs_add (&hs1, array_create (hs1.len, BIT_X));
  hs_add (&hs2, array_create (hs2.len, BIT_0));
  hs_add (&hs3, array_create (hs3.len, BIT_1));
  hs_add (&hs4, array_create (hs4.len, BIT_Z));
  struct hs hs_res1, hs_res2, hs_res3, hs_res4;
  array_t * a = array_from_str("xxxxxxxx,xxxxxxxx,xxxxxxxx,xxxxxxxx,xxxxxxxx,xxxxxxxx,00000000,01001111,xxxxxxxx,xxxxxxxx,xxxxxxxx,00001010,00000000,00000000,00000001,xxxxxxxx,xxxxxxxx,xxxxxxxx,xxxxxxxx,xxxxxxxx,xxxxxxxx,xxxxxxxx,xxxxxxxx,xxxxxxxx,xxxxxxxx,00000000,00000000,00000000,00000000,00000000,00000001");
  bool matched;
  matched = hs_isect_arr (&hs_res1, &hs1, a);
  printf("Got you there. %d\n", matched);
  if (matched) hs_print (&hs_res1);
  matched = hs_isect_arr (&hs_res2, &hs2, a);
  printf("Got you there. %d\n", matched);
  if (matched) hs_print (&hs_res2);
  matched = hs_isect_arr (&hs_res3, &hs3, a);
  printf("Got you there. %d\n", matched);
  if (matched) hs_print (&hs_res3);
  matched = hs_isect_arr (&hs_res4, &hs4, a);
  printf("Got you there. %d\n", matched);
  if (matched) hs_print (&hs_res4);
  printf("All done, apparently.\n");
  return matched;
}

int
main (int argc, char **argv)
{
  if (argc < 2) {
    fprintf (stderr, "Usage: %s [-loop] [-h header] [-o] [-c hop_count] <in_port> [<out_ports>...]\n", argv[0]);
    exit (1);
  }

  bool one_step = false;
  char *net = basename (argv[0]);
  chdir (dirname (argv[0]));
  load (net);
  app_init ();

  struct hs hs;
  memset (&hs, 0, sizeof hs);
  hs.len = data_arrs_len;
  int hop_count = 0;
  int offset = 1;
  bool find_loop = false;

  // sample header space intersection test. TODO(ngsrinivas): remove later.
  hs_inters_test();

  if (strcmp(argv[offset],"-loop") == 0) {
	  find_loop = true;
	  offset++;
  }
  if (strcmp(argv[offset],"-h") == 0) {
	  array_t * a = array_from_str (argv[offset+1]);
	  hs_add (&hs, a);
	  offset += 2;
  } else {
	  hs_add (&hs, array_create (hs.len, BIT_X));
  }

  if (strcmp(argv[offset],"-o") == 0) {
	  one_step = true;
	  offset++;
  }

  if (strcmp(argv[offset],"-c") == 0) {
	  hop_count = atoi (argv[1 + offset]) + 1;
	  offset += 2;
  } else {
	  hop_count = 0;
  }

  uint32_t in_port = atoi(argv[offset]);
  offset++;
  int nout = argc - offset;
  uint32_t out[nout];
  for (int i = 0; i < nout; i++) out[i] = atoi (argv[i + offset]);

  struct timeval start, end;
  struct list_res res;
  gettimeofday (&start, NULL);
  if (one_step) {
	  struct res *in = res_create (data_file->stages + 1);
	  hs_copy (&in->hs, &hs);
	  in->port = in_port;
	  res = ntf_search(in, nout ? out : NULL, nout);
  } else {
	  app_add_in (&hs, in_port);
	  res = reachability (nout ? out : NULL, nout, hop_count, find_loop);
  }
  gettimeofday (&end, NULL);

  list_res_print (&res);
  printf ("Time: %" PRId64 " us\n", diff (&end, &start));

  list_res_free (&res);
  hs_destroy (&hs);
  app_fini ();
  return 0;
}

