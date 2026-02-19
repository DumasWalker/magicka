#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "stralloc.h"

int stralloc_ready(stralloc *sa, size_t n) {
	size_t na;
	char *ns;

	assert(sa != NULL);
	if (sa->s == NULL) {
		sa->len = 0;
		sa->a = n;
		sa->s = malloc(n);
		return sa != NULL;
	}
	if (sa->a >= n)
		return 1;
	na = 30 + n + (n >> 3);
	ns = realloc(sa->s, na);
	if (ns == NULL)
		return 0;
	memset(ns + sa->len, 0, na - sa->len);
	sa->a = na;
	sa->s = ns;
	return 1;
}

int stralloc_starts(stralloc *sa, const char *s) {
	size_t len;
	assert(sa != NULL);
	assert(s != NULL);
	len = strlen(s);
	return (sa->len >= len) && memcmp(sa->s, s, len) == 0;
}

int stralloc_copyb(stralloc *sa, const char *s, size_t n) {
	assert(sa != NULL);
	assert(s != NULL);
	if (!stralloc_ready(sa, n + 1)) return 0;
	memmove(sa->s, s, n);
	sa->len = n;
	sa->s[n] = 'Z'; /* ``offensive programming'' */
	return 1;
}

int stralloc_catb(stralloc *sa, const char *s, size_t n) {
	assert(sa != NULL);
	assert(s != NULL);
	if (sa->s == NULL) return stralloc_copyb(sa, s, n);
	if (!stralloc_readyplus(sa, n + 1)) return 0;
	memmove(sa->s + sa->len, s, n);
	sa->len += n;
	sa->s[sa->len] = 'Z'; /* ``offensive programming'' */
	return 1;
}

int stralloc_append1(stralloc *sa, char b) {
	assert(sa != NULL);
	if (!stralloc_readyplus(sa, 1)) return 0;
	sa->s[sa->len++] = b;
	return 1;
}

static int stralloc_cat_ulong_rec(stralloc *sa, unsigned long uv) {
	if (uv == 0) return 1;
	if (!stralloc_cat_ulong_rec(sa, uv / 10)) return 0;
	return stralloc_append1(sa, (uv % 10) + '0');
}

int stralloc_cat_ulong(stralloc *sa, unsigned long uv) {
	if (uv == 0)
		return stralloc_append1(sa, '0');
	return stralloc_cat_ulong_rec(sa, uv);
}

int stralloc_cat_long(stralloc *sa, long v) {
	if (v < 0)
		if (!stralloc_append1(sa, '-')) return 0;
	return stralloc_cat_ulong(sa, labs(v));
}

int stralloc_cat_byte(stralloc *sa, int b) {
	static const char *hex = "0123456789abcdef";
	if (!stralloc_append1(sa, hex[(b >> 4) & 0xF])) return 0;
	return stralloc_append1(sa, hex[(b >> 0) & 0xF]);
}

int stralloc_cat_Byte(stralloc *sa, int b) {
	static const char *hex = "0123456789ABCDEF";
	if (!stralloc_append1(sa, hex[(b >> 4) & 0xF])) return 0;
	return stralloc_append1(sa, hex[(b >> 0) & 0xF]);
}
