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

