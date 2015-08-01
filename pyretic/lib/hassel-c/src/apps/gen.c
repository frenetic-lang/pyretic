/*
  Copyright 2012, Stanford University. This file is licensed under GPL v2 plus
  a special exception, as described in included LICENSE_EXCEPTION.txt.

  Author: mchang@cs.stanford.com (Michael Chang)
          peyman.kazemian@gmail.com (Peyman Kazemian)
*/

#include "parse.h"

int
main (int argc, char **argv)
{
  if (argc < 2) {
    fprintf (stderr, "Usage: %s <network>\n", argv[0]);
    exit (1);
  }
  parse_dir ("data", "tfs", argv[1]);
  return 0;
}

