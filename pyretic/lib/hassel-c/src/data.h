/*
  Copyright 2012, Stanford University. This file is licensed under GPL v2 plus
  a special exception, as described in included LICENSE_EXCEPTION.txt.

  Author: mchang@cs.stanford.com (Michael Chang)
          peyman.kazemian@gmail.com (Peyman Kazemian)
*/

#ifndef _DATA_H_
#define _DATA_H_

#include "array.h"
#include "parse.h"

struct PACKED file {
  uint32_t arrs_ofs, strs_ofs;
  uint32_t ntfs, stages;
  uint32_t tf_ofs[0];
};

#define VALID_OFS 1

extern struct file *data_file;
extern uint8_t     *data_raw;
extern size_t       data_size;

#define DATA_ARR(X) ( data_arrs + ((X) - VALID_OFS) / sizeof (array_t) )
#define DATA_STR(X) ( data_strs + ((X) - VALID_OFS) )

extern array_t *data_arrs;
extern uint32_t data_arrs_len, data_arrs_n;
extern char    *data_strs;

void data_load   (const char *file);
void data_unload (void);

void data_gen (const char *out, const struct parse_ntf *ntf, const struct parse_tf *ttf);

#endif

