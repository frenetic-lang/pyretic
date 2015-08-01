/*
  Copyright 2012, Stanford University. This file is licensed under GPL v2 plus
  a special exception, as described in included LICENSE_EXCEPTION.txt.

  Author: mchang@cs.stanford.com (Michael Chang)
          peyman.kazemian@gmail.com (Peyman Kazemian)
*/

#ifndef _LIST_H_
#define _LIST_H_

/* Singly-linked list with tail pointer.
   Usage:
   struct foo { struct foo *next; ... };
   struct bar { LIST(foo) list; ... } bar;
   list_append (&bar.list, ...); */

/* Define a list of type T. This should be used exactly once. It can appear
   anywhere a struct definition can appear.
     For example: struct bar { LIST (foo) list; };
     or: LIST (foo); (on its own line)
   The declared type is "struct list_<T>". Use this type for all future
   references. */
#define LIST(T) struct list_ ## T { struct T *head, *tail; int n; }

/* void list_append (struct list_<T> *l, struct <T> *e); */
#define list_append(L, E) \
  do { \
    (E)->next = NULL; \
    if (!(L)->tail) (L)->head = (E); else (L)->tail->next = (E); \
    (L)->tail = (E); \
    (L)->n++; \
  } while (0)

/* B remains in tact, but it will point to a sublist of A. */
/* void list_concat (struct list_<T> *a, struct list_<T> *b); */
#define list_concat(A, B) \
  do { \
    if (!(B)->head) break; \
    if ((A)->tail) (A)->tail->next = (B)->head; \
    else (A)->head = (B)->head; \
    (A)->tail = (B)->tail; \
    (A)->n += (B)->n; \
  } while (0)

/* void list_destroy (struct list_<T> *l, void (*f) (struct <T> *)); */
#define list_destroy(L, F) \
  do { \
    while ((L)->head) { \
      (L)->tail = (L)->head->next; \
      (F) ((L)->head); \
      (L)->head = (L)->tail; \
    } \
    (L)->n = 0; \
  } while (0)

/* void list_pop (struct list_<T> *l); */
#define list_pop(L) \
  do { \
    if ((L)->head->next) (L)->head = (L)->head->next; \
    else { (L)->head = (L)->tail = NULL; } \
    (L)->n--; \
  } while (0)

/* Remove CUR from L, given that PREV precedes CUR. CUR will point to the
   following element (or NULL). */
/* void list_remove (struct list_<T> *l, struct <T> *&cur, struct <T> *prev,
                     void (*f) (struct <T> *); */
#define list_remove(L, C, P, F) \
  do { \
    if ((P)) (P)->next = (C)->next; \
    else (L)->head = (C)->next; \
    if ((L)->tail == (C)) (L)->tail = (P); \
    (F) ((C)); \
    (C) = (P) ? (P)->next : (L)->head; \
    (L)->n--; \
  } while (0)

#endif

