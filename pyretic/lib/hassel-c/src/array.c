/*
  Copyright 2012, Stanford University. This file is licensed under GPL v2 plus
  a special exception, as described in included LICENSE_EXCEPTION.txt.

  Author: mchang@cs.stanford.com (Michael Chang)
          peyman.kazemian@gmail.com (Peyman Kazemian)
*/

#include "array.h"
#include <limits.h>

#define SIZE(L) ( DIV_ROUND_UP (2 * (L), sizeof (array_t)) )

/* If using anything larger than 64-bit, these need to be changed. */
#define EVEN_MASK ( (array_t) 0xaaaaaaaaaaaaaaaaull )
#define ODD_MASK  ( (array_t) 0x5555555555555555ull )

static inline bool
has_x (array_t x)
{ return x & (x >> 1) & ODD_MASK; }

static inline bool
has_z (array_t x)
{ return has_x (~x); }

/* Convert X from two-bit representation to integer and writes string to OUT.
   X must contain only 0s and 1s (no x or z) or be all x. OUT must have space
   for 5 chars. Returns number of chars written. */
static int
int_str (uint16_t x, char *out)
{
  if (x == UINT16_MAX) return sprintf (out, "DX,");
  x = (x >> 1) & 0x5555;
  x = (x | (x >> 1)) & 0x3333;
  x = (x | (x >> 2)) & 0x0f0f;
  x = (x | (x >> 4)) & 0x00ff;
  return sprintf (out, "D%d,", x);
}

static inline int
x_count (array_t a, array_t mask)
{
  array_t tmp = a & (a >> 1) & mask & ODD_MASK;
  return __builtin_popcountll (tmp);
}


array_t *
array_create (int len, enum bit_val val)
{
  int alen = SIZE (len);
  /* TODO: Alignment */
  array_t *res = xmalloc (alen * sizeof *res);
  if (val != BIT_UNDEF) memset (res, val * 0x55, 2 * len);
  memset ((uint8_t *) res + 2 * len, 0xff, alen * sizeof *res - 2 * len);
  return res;
}

void
array_free (array_t *a)
{ free (a); }


array_t *
array_copy (const array_t *a, int len)
{
  array_t *res = array_create (len, BIT_UNDEF);
  memcpy (res, a, 2 * len);
  return res;
}

array_t *
array_from_str (const char *s)
{
  bool commas = strchr (s, ',');
  int div = CHAR_BIT + commas;
  int len = strlen (s) + commas;
  assert (len % div == 0);
  len /= div;

  const char *cur = s;
  array_t *res = array_create (len, BIT_UNDEF);
  uint8_t *rcur = (uint8_t *) res;
  for (int i = 0; i < 2 * len; i++) {
    uint8_t tmp = 0;
    for (int j = 0; j < CHAR_BIT / 2; j++, cur++) {
      enum bit_val val;
      switch (*cur) {
        case 'z': case 'Z': val = BIT_Z; break;
        case '0': val = BIT_0; break;
        case '1': val = BIT_1; break;
        case 'x': case 'X': val = BIT_X; break;
        default: errx (1, "Invalid character '%c' in \"%s\".", *cur, s);
      }
      tmp <<= 2;
      tmp |= val;
    }
    *rcur++ = tmp;
    if (commas && (i % 2)) { assert (!*cur || *cur == ','); cur++; }
  }
  return res;
}

char *
array_to_str (const array_t *a, int len, bool decimal)
{
  if (!a) return NULL;

  int slen = len * (CHAR_BIT + 1);
  char buf[slen];
  char *cur = buf;
  const uint8_t *acur = (const uint8_t *) a;
  for (int i = 0; i < len; i++, acur += 2) {
    uint8_t tmp[] = {acur[0], acur[1]};
    uint16_t byte = tmp[0] << CHAR_BIT | tmp[1];
    if (decimal && (!has_x (byte) || byte == UINT16_MAX)) {
      cur += int_str (byte, cur);
      continue;
    }

    for (int j = 0; j < 2; j++) {
      char *next = cur + CHAR_BIT / 2 - 1;
      for (int k = 0; k < CHAR_BIT / 2; k++) {
        static char chars[] = "z01x";
        *next-- = chars[tmp[j] & BIT_X];
        tmp[j] >>= 2;
      }
      cur += CHAR_BIT / 2;
    }
    *cur++ = ',';
  }
  cur[-1] = 0;
  return xstrdup (buf);
}


bool
array_has_x (const array_t *a, int len)
{
  for (int i = 0; i < SIZE (len); i++) {
    array_t tmp = a[i];
    if (i == SIZE (len) - 1) tmp &= ~((1ull << (len % (sizeof *a / 2))) - 1);
    if (has_x (a[i])) return true;
  }
  return false;
}

bool
array_has_z (const array_t *a, int len)
{
  for (int i = 0; i < SIZE (len); i++)
    if (has_z (a[i])) return true;
  return false;
}

bool
array_is_eq (const array_t *a, const array_t *b, int len)
{ return !memcmp (a, b, SIZE (len) * sizeof *a); }

bool
array_is_sub (const array_t *a, const array_t *b, int len)
{
  for (int i = 0; i < SIZE (len); i++)
    if (b[i] & ~a[i]) return false;
  return true;
}

void
array_combine(array_t **_a, array_t **_b, array_t **extra,
              const array_t *mask, int len) {
  array_t *a = *_a;
  array_t *b = *_b;
  bool equal = true;
  bool aSubb = true;
  bool bSuba = true;
  int diff_count = 0;
  array_t tmp[SIZE (len)];
  for (int i = 0; i < SIZE (len); i++) {
    if (equal && a[i] != b[i]) equal = false;
    if (!equal && bSuba && (b[i] & ~a[i])) bSuba = false;
    if (!equal && aSubb && (a[i] & ~b[i])) aSubb = false;
    if (mask && diff_count <= 1) {
      if (bSuba) tmp[i] = b[i];
      else if (aSubb) tmp[i] = a[i];
      else {
        array_t isect = a[i] & b[i];
        array_t diffs = ((isect | (isect >> 1)) & ODD_MASK) |
            ((isect | (isect << 1)) & EVEN_MASK);
        diffs = ~diffs;
        if (diffs & mask[i] & EVEN_MASK) {*extra = NULL; return;}
        int count = __builtin_popcountll(diffs) / 2;
        if (count == 0) tmp[i] = isect;
        else {
          diff_count += count;
          if (diff_count == 1) tmp[i] = isect | diffs;
        }
      }
    // in case of no combine, if no subset detected, return.
    } else if (!mask && !bSuba && !aSubb) {*extra = NULL; return;}
    // more than one non-intersecting bits - no combine.
    if (diff_count > 1) {*extra = NULL; return;}
  }
  // keep a if equal or b is subset of a
  if (equal || bSuba) {free(b); *_b = NULL; *extra = NULL;}
  // keep b if a is subset of b
  else if (aSubb) {free(a); *_a = NULL; *extra = NULL; }
  // keep b and a untouched if there is no merge. e.g. 100x u 1xx0
  else if (diff_count == 0) {*extra = NULL;}
  // or we will have a combine:
  else {
    bool b1 = array_is_sub(tmp,a,len);
    bool b2 = array_is_sub(tmp,b,len);
    // e.g. 10x0 U 10x1 --> 10xx
    if (b1 && b2) { free(a); free(b); *_a = NULL; *_b = NULL;
      *extra = array_copy(tmp,len); }
    // e.g. 1001 U 1xx0 --> 100x U 1xx0
    else if (b1) { free(a); *_a = NULL; *extra = array_copy(tmp,len);}
    // e.g. 1xx0 U 1001 --> 1xx0 U 100x
    else if (b2) { free(b); *_b = NULL; *extra = array_copy(tmp,len);}
    // e.g. 10x1 U 1x00 --> 10x1 U 1x00 U 100X
    else {*extra = array_copy(tmp,len);}
  }
}


enum bit_val
array_get_bit (const array_t *a, int byte, int bit)
{
  const uint8_t *p = (const uint8_t *) a;
  uint8_t x = p[2 * byte + bit / (CHAR_BIT / 2)];
  int shift = 2 * (CHAR_BIT / 2 - (bit % (CHAR_BIT / 2)) - 1);
  return x >> shift;
}

uint16_t
array_get_byte (const array_t *a, int byte)
{
  const uint8_t *p = (const uint8_t *) a;
  return (p[2 * byte] << CHAR_BIT) | p[2 * byte + 1];
}

void
array_set_bit (array_t *a, enum bit_val val, int byte, int bit)
{
  uint8_t *p = (uint8_t *) a;
  int idx = 2 * byte + bit / (CHAR_BIT / 2);
  int shift = 2 * (CHAR_BIT / 2 - (bit % (CHAR_BIT / 2)) - 1);
  uint8_t mask = BIT_X >> shift;
  p[idx] = (p[idx] & ~mask) | (val << shift);
}

void
array_set_byte (array_t *a, uint16_t val, int byte)
{
  uint8_t *p = (uint8_t *) a;
  p[2 * byte] = val >> CHAR_BIT;
  a[2 * byte + 1] = val & 0xff;
}


void
array_and (const array_t *a, const array_t *b, int len, array_t *res)
{
  for (int i = 0; i < SIZE (len); i++)
    res[i] = ((a[i] | b[i]) & ODD_MASK) | (a[i] & b[i] & EVEN_MASK);
}

bool
array_cmpl (const array_t *a, int len, int *n, array_t **res)
{
  *n = 0;
  for (int i = 0; i < SIZE (len); i++) {
    array_t cur = ~a[i];
    while (cur) {
      array_t next = cur & (cur - 1);
      array_t bit = cur & ~next;

      bit = ((bit >> 1) & ODD_MASK) | ((bit << 1) & EVEN_MASK);
      res[*n] = array_create (len, BIT_X);
      res[*n][i] &= ~bit;
      ++*n;
      cur = next;
    }
  }
  return *n;
}

bool
array_diff (const array_t *a, const array_t *b, int len, int *n, array_t **res)
{
  int n_cmpl;
  if (!array_cmpl (b, len, &n_cmpl, res)) return false;

  *n = 0;
  for (int i = 0; i < n_cmpl; i++)
    if (array_isect (a, res[i], len, res[*n])) ++*n;
  for (int i = *n; i < n_cmpl; i++)
    array_free (res[i]);
  return *n;
}

bool
array_isect (const array_t *a, const array_t *b, int len, array_t *res)
{
  for (int i = 0; i < SIZE (len); i++) {
    res[i] = a[i] & b[i];
    if (has_z (res[i])) return false;
  }
  return true;
}

void
array_not (const array_t *a, int len, array_t *res)
{
  for (int i = 0; i < SIZE (len); i++)
    res[i] = ((a[i] >> 1) & ODD_MASK) | ((a[i] << 1) & EVEN_MASK);
}

void
array_or (const array_t *a, const array_t *b, int len, array_t *res)
{
  for (int i = 0; i < SIZE (len); i++)
    res[i] = (a[i] & b[i] & ODD_MASK) | ((a[i] | b[i]) & EVEN_MASK);
}

/* Rewrite A using MASK and REWRITE. Returns number of x's in result. */
int
array_rewrite (array_t *a, const array_t *mask, const array_t *rewrite, int len)
{
  int n = 0;
  for (int i = 0; i < SIZE (len); i++) {
    n += x_count (a[i], mask[i]);
    a[i] = (((a[i] | mask[i]) & rewrite[i]) & ODD_MASK) |
           (((a[i] & mask[i]) | rewrite[i]) & EVEN_MASK);
  }
  return n;
}

int
array_x_count (const array_t *a, const array_t *mask, int len)
{
  int n = 0;
  for (int i = 0; i < SIZE (len); i++)
    n += x_count (a[i], mask[i]);
  return n;
}


array_t *
array_and_a (const array_t *a, const array_t *b, int len)
{
  array_t *res = array_create (len, BIT_UNDEF);
  array_and (a, b, len, res);
  return res;
}

array_t **
array_cmpl_a (const array_t *a, int len, int *n)
{
  array_t *tmp[len * CHAR_BIT];
  if (!array_cmpl (a, len, n, tmp)) return NULL;
  array_t **res = xmemdup (tmp, *n * sizeof *res);
  return res;
}

array_t **
array_diff_a (const array_t *a, const array_t *b, int len, int *n)
{
  array_t *tmp[len * CHAR_BIT];
  if (!array_diff (a, b, len, n, tmp)) return NULL;
  array_t **res = xmemdup (tmp, *n * sizeof *res);
  return res;
}

//TODO: Move HS optimization here
array_t *
array_isect_a (const array_t *a, const array_t *b, int len)
{
  array_t *res = array_create (len, BIT_UNDEF);
  if (!array_isect (a, b, len, res)) {
    free (res);
    return NULL;
  }
  return res;
}

array_t *
array_not_a (const array_t *a, int len)
{
  array_t *res = array_create (len, BIT_UNDEF);
  array_not (a, len, res);
  return res;
}

array_t *
array_or_a (const array_t *a, const array_t *b, int len)
{
  array_t *res = array_create (len, BIT_UNDEF);
  array_or (a, b, len, res);
  return res;
}


void
array_shift_left (array_t *a, int len, int start, int shift, enum bit_val val)
{
  assert (start % 4 == 0 && shift % 4 == 0);
  assert (start / 4 + shift / 4 <= len * 2);
  uint8_t *p = (uint8_t *) a;
  int bytes = 2 * len - start / 4 - shift / 4;
  memmove (p + start / 4, p + start / 4 + shift / 4, bytes);
  memset (p + 2 * len - shift / 4, 0x55 * val, shift / 4);
}

void
array_shift_right (array_t *a, int len, int start, int shift, enum bit_val val)
{
  assert (start % 4 == 0 && shift % 4 == 0);
  assert (start / 4 + shift / 4 <= len * 2);
  uint8_t *p = (uint8_t *) a;
  int bytes = 2 * len - start / 4 - shift / 4;
  memmove (p + start / 4 + shift / 4, p + start / 4, bytes);
  memset (p + start / 4, 0x55 * val, shift / 4);
}

