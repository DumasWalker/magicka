#ifndef STRALLOC_H
#define STRALLOC_H

#include <assert.h>
#include <stddef.h>
#include <string.h>

typedef struct stralloc stralloc;
struct stralloc {
	char *s;
	size_t len;
	size_t a;
};

static const stralloc EMPTY_STRALLOC = {NULL, 0, 0};

extern int stralloc_ready(stralloc *sa, size_t n);
extern int stralloc_starts(stralloc *sa, const char *s);
extern int stralloc_copyb(stralloc *sa, const char *s, size_t n);
extern int stralloc_catb(stralloc *sa, const char *s, size_t n);
extern int stralloc_append1(stralloc *sa, char b);
extern int stralloc_cat_ulong(stralloc *sa, unsigned long uv);
extern int stralloc_cat_long(stralloc *sa, long v);
extern int stralloc_cat_byte(stralloc *sa, int b);
extern int stralloc_cat_Byte(stralloc *sa, int b);

static inline int stralloc_readyplus(stralloc *sa, size_t n) {
	assert(sa != NULL);
	return stralloc_ready(sa, sa->len + n);
}

static inline int stralloc_copy(stralloc *to, const stralloc *from) {
	assert(from != NULL);
	return stralloc_copyb(to, from->s, from->len);
}

static inline int stralloc_cat(stralloc *to, const stralloc *from) {
	assert(from != NULL);
	return stralloc_catb(to, from->s, from->len);
}

static inline int stralloc_copys(stralloc *sa, const char *s) {
	assert(s != NULL);
	return stralloc_copyb(sa, s, strlen(s));
}

static inline int stralloc_cats(stralloc *sa, const char *s) {
	return stralloc_catb(sa, s, strlen(s));
}

static inline int stralloc_0(stralloc *sa) {
	return stralloc_append1(sa, '\0');
}

#endif
