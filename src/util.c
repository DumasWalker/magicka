#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

#include "bbs.h"

extern struct bbs_config conf;
extern int mynode;

void die(const char *msg) {
	dolog(msg);
	exit(-1);
}

void *malloz(size_t size) {
	void *p = malloc(size);
	if (p == NULL)
		die("Out of memory");
	memset(p, 0, size);
	return p;
}

char *file2str(const char *path) {
	struct stat s;
	int fd;

	memset(&s, 0, sizeof(s));
	if (stat(path, &s) < 0)
		return NULL;
	if (!S_ISREG(s.st_mode))
		return NULL;
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return NULL;
	char *contents = malloz(s.st_size + 1);
	if (read(fd, contents, s.st_size) != s.st_size) {
		free(contents);
		close(fd);
		return NULL;
	}
	close(fd);
	contents[s.st_size] = '\0';
	return contents;
}

stralloc file2stralloc(const char *path) {
	struct stat s;
	int fd;

	memset(&s, 0, sizeof(s));
	if (stat(path, &s) < 0)
		return EMPTY_STRALLOC;
	if (!S_ISREG(s.st_mode))
		return EMPTY_STRALLOC;
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return EMPTY_STRALLOC;
	size_t len = s.st_size;
	char *p = mmap(NULL, len, PROT_READ, MAP_SHARED, fd, 0);
	if (p == NULL) {
		close(fd);
		return EMPTY_STRALLOC;
	}
	stralloc sa = EMPTY_STRALLOC;
	stralloc_copyb(&sa, p, len);
	munmap(p, len);
	close(fd);

	return sa;
}

char *str5dup(const char *a, const char *b, const char *c, const char *d, const char *e) {
	char *p;
	size_t alen, blen, clen, dlen, elen;

	if (a == NULL)
		a = "";
	if (b == NULL)
		b = "";
	if (c == NULL)
		c = "";
	if (d == NULL)
		d = "";
	if (e == NULL)
		e = "";

	alen = strlen(a);
	blen = strlen(b);
	clen = strlen(c);
	dlen = strlen(d);
	elen = strlen(e);

	p = malloz(alen + blen + clen + dlen + elen + 1);
	memmove(p, a, alen);
	memmove(p + alen, b, blen);
	memmove(p + alen + blen, c, clen);
	memmove(p + alen + blen + clen, d, dlen);
	memmove(p + alen + blen + clen + dlen, e, elen);

	return p;
}

char *str4dup(const char *a, const char *b, const char *c, const char *d) {
	return str5dup(a, b, c, d, "");
}

char *str3dup(const char *a, const char *b, const char *c) {
	return str5dup(a, b, c, "", "");
}

char *str2dup(const char *a, const char *b) {
	return str5dup(a, b, "", "", "");
}

void init_ptr_vector(struct ptr_vector *vec) {
	assert(vec != NULL);
	memset(vec, 0, sizeof(*vec));
}

void ptr_vector_clear(struct ptr_vector *vec) {
	assert(vec != NULL);
	vec->len = 0;
	memset(vec->ptrs, 0, sizeof(void *) * vec->capacity);
}

void *ptr_vector_get(struct ptr_vector *vec, size_t i) {
	assert(vec != NULL);
	if (i >= vec->len)
		return NULL;
	assert(vec->ptrs != NULL);
	return vec->ptrs[i];
}

int ptr_vector_put(struct ptr_vector *vec, void *p, size_t i) {
	assert(vec != NULL);
	if (i >= vec->len)
		return 0;
	assert(vec->ptrs != NULL);
	vec->ptrs[i] = p;
	return 1;
}

int ptr_vector_ins(struct ptr_vector *vec, void *p, size_t i) {
	assert(vec != NULL);
	if (i > vec->len)
		return 0;
	// Note: If we're inserting at the end of the array
	// and we're not reallocating, the call to `memmove()`
	// below would take a dest argument pointing immediately
	// after the end of the array.  It is unclear whether
	// this is undefined behavior according to the ISO C
	// standard, even though the size in that case would be
	// zero, so sidestep the issue by explicitly testing
	// for and simply appending in this case.
	if (i == vec->len)
		return ptr_vector_append(vec, p);
	ptr_vector_append(vec, NULL); // Make space in the vector.
	memmove(vec->ptrs + i + 1, vec->ptrs + i,
	        (vec->len - (i + 1)) * sizeof(void *));
	vec->ptrs[i] = p;
	++vec->len;
	return 1;
}

void *ptr_vector_del(struct ptr_vector *vec, size_t i) {
	void *p;
	assert(vec != NULL);
	if (i >= vec->len)
		return NULL;
	assert(vec->ptrs != NULL);
	p = vec->ptrs[i];
	memmove(vec->ptrs + i, vec->ptrs + i + 1,
	        (vec->len - (i + 1)) * sizeof(void *));
	--vec->len;
	return p;
}

int ptr_vector_append(struct ptr_vector *vec, void *p) {
	assert(vec != NULL);
	if (vec->len == vec->capacity) {
		void **ps;
		size_t oldcap = vec->capacity;
		if (vec->capacity == 0)
			vec->capacity = 1;
		else
			vec->capacity *= 2;
		ps = realloc(vec->ptrs, vec->capacity * sizeof(void *));
		assert(ps != NULL);
		vec->ptrs = ps;
		memset(vec->ptrs + oldcap, 0, (vec->capacity - oldcap) * sizeof(void *));
	}
	vec->ptrs[vec->len] = p;
	++vec->len;
	return 1;
}

int ptr_vector_append_if_unique(struct ptr_vector *vec, void *p) {
	assert(vec != NULL);

	for (int i = 0; i < vec->len; i++) {
		if (vec->ptrs[i] == p) {
			return 0;
		}
	}

	return ptr_vector_append(vec, p);
}

size_t ptr_vector_len(struct ptr_vector *vec) {
	assert(vec != NULL);
	return vec->len;
}

void **ptr_vector_ptrs(struct ptr_vector *vec) {
	assert(vec != NULL);
	return vec->ptrs;
}

void ptr_vector_apply(struct ptr_vector *vec, void (*f)(void *arg)) {
	assert(vec != NULL);
	assert(f != NULL);
	for (size_t i = 0; i < vec->len; ++i)
		f(vec->ptrs[i]);
}

void **consume_ptr_vector(struct ptr_vector *vec) {
	if (vec->len == 0) {
		return NULL;
	}
	assert(vec != NULL);
	void **ps = realloc(vec->ptrs, vec->len * sizeof(void *));
	assert(ps != NULL);
	vec->ptrs = NULL;
	vec->len = 0;
	vec->capacity = 0;
	return ps;
}

void destroy_ptr_vector(struct ptr_vector *vec) {
	assert(vec != NULL);
	free(vec->ptrs);
	vec->ptrs = NULL;
	vec->capacity = 0;
	vec->len = 0;
}

FILE *fopen_bbs_path(const char *filename, const char *mode) {
	char buffer[PATH_MAX];

	snprintf(buffer, PATH_MAX, "%s/%s", conf.bbs_path, filename);

	return fopen(buffer, mode);
}

FILE *fopen_node_path(const char *filename, const char *mode) {
	char buffer[PATH_MAX];

	snprintf(buffer, PATH_MAX, "%s/node%d/%s", conf.bbs_path, mynode, filename);

	return fopen(buffer, mode);
}

int check_security(struct user_record *user, int level, struct ptr_vector *req_flags, struct ptr_vector *not_flags) {
	if (level != -1 && user->sec_level < level) {
		return 0;
	}

	for (int i; i < ptr_vector_len(req_flags);i++) {
		if (!user_check_flag(user, ptr_vector_get(req_flags, i))) {
			return 0;
		}
	}

	for (int i; i < ptr_vector_len(not_flags); i++) {
		if (user_check_flag(user, ptr_vector_get(not_flags, i))) {
			return 0;
		}
	}
	return 1;
}
