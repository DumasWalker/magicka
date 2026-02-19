#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bbs.h"

extern struct bbs_config conf;

char *undefined = "Undefined String";
static struct ptr_vector strings;
int string_count;

void chomp(char *str) {
	char *end;
	assert(str != NULL);
	size_t len = strlen(str);
	if (len == 0) {
		return;
	}
	end = str + len - 1;
	while (end != str && (*end == '\r' || *end == '\n')) {
		*end-- = '\0';
	}
}

char *parse_newlines(char *str) {
	char *nstring = strdup(str);
	char *s, *p;
	for (s = p = nstring; *s != '\0'; ++s) {
		if (*s != '\\') {
			*p++ = *s;
			continue;
		}
		switch (*++s) {
			case '\0': continue;
			case 'n': *p++ = '\n'; break;
			case 'r': *p++ = '\r'; break;
			case 'e': *p++ = '\e'; break;
			case '\\': *p++ = '\\'; break;
		}
	}
	*p = '\0';
	return nstring;
}

char *get_string(int offset) {
	char *str = ptr_vector_get(&strings, offset);
	if (str == NULL) {
		return undefined;
	}
	return str;
}

void load_strings() {
	FILE *fptr;
	char buffer[1024];

	if (conf.string_file == NULL) {
		fprintf(stderr, "Strings file can not be undefined!\n");
		exit(-1);
	}

	fptr = fopen(conf.string_file, "r");
	if (!fptr) {
		fprintf(stderr, "Unable to open strings file!\n");
		exit(-1);
	}

	init_ptr_vector(&strings);
	fgets(buffer, 1024, fptr);
	while (!feof(fptr)) {
		chomp(buffer);
		ptr_vector_append(&strings, parse_newlines(buffer));
		fgets(buffer, 1024, fptr);
	}
	fclose(fptr);
}

char **split_on_space(char *str, size_t *lenp) {
	struct ptr_vector tokens;
	char *token;

	init_ptr_vector(&tokens);

	token = strtok(str, " ");
	ptr_vector_append(&tokens, token);
	while (token != NULL) {
		token = strtok(NULL, " ");
		if (token != NULL) {
			ptr_vector_append(&tokens, token);
		}
	}
	if (lenp != NULL) {
		*lenp = ptr_vector_len(&tokens);
	}

	return (char **)consume_ptr_vector(&tokens);
}

void split_to_ptr_vector(const char *str, struct ptr_vector *pv) {
	char *token;
	char *ptr = strdup(str);
	token = strtok(ptr, " ");
	ptr_vector_append(pv, strdup(token));
	while (token != NULL) {
		token = strtok(NULL, " ");
		if (token != NULL) {
			ptr_vector_append(pv, strdup(token));
		}
	}
	free(ptr);
}

char **split_args(char *str, size_t *lenp) {
	struct ptr_vector tokens;
	char *token;

	init_ptr_vector(&tokens);
	token = strtok(str, " ");
	ptr_vector_append(&tokens, token);
	while (token != NULL) {
		token = strtok(NULL, " ");
		if (token != NULL) {
			ptr_vector_append(&tokens, token);
		}
	}

	ptr_vector_append(&tokens, NULL);

	if (lenp != NULL) {
		*lenp = ptr_vector_len(&tokens);
	}

	return (char **)consume_ptr_vector(&tokens);
}
