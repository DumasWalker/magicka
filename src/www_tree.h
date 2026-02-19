#if defined(ENABLE_WWW)
#ifndef __WWW_TREE_H__
#define __WWW_TREE_H__

#include "bbs.h"

struct www_tag {
	char *tag;
	char *data;
	struct ptr_vector attribs;
	struct ptr_vector values;

	struct ptr_vector children;
};

extern struct www_tag *www_tag_new(char *tag, char *data);
extern void www_tag_add_attrib(struct www_tag *tag, char *attrib, char *value);
extern struct www_tag *www_tag_duplicate(struct www_tag *oldtag);
extern void www_tag_add_child(struct www_tag *tag, struct www_tag *child);
extern char *www_tag_destroy(struct www_tag *tag);
extern char *www_tag_unwravel(struct www_tag *tag);
#endif
#endif
