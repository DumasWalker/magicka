#if defined(ENABLE_WWW)

#include <stdlib.h>
#include "www_tree.h"
#include "bbs.h"

static char *www_tag_sanatize(char *data, int isdata) {
	stralloc str = EMPTY_STRALLOC;
	for (char *p = data; *p != '\0'; ++p) {
		switch (*p) {
			case '\"':
				stralloc_cats(&str, "&quot;");
				break;
			case '&':
				stralloc_cats(&str, "&amp;");
				break;
			case '<':
				stralloc_cats(&str, "&lt;");
				break;
			case '>':
				stralloc_cats(&str, "&gt;");
				break;
			case '\x01':
				stralloc_cats(&str, "&#x263A;");
				break;
			case '\x02':
				stralloc_cats(&str, "&#x263B;");
				break;
			case '\x03':
				stralloc_cats(&str, "&#x2665;");
				break;
			case '\x04':
				stralloc_cats(&str, "&#x2666;");
				break;
			case '\x05':
				stralloc_cats(&str, "&#x2663;");
				break;
			case '\x06':
				stralloc_cats(&str, "&#x2660;");
				break;
			case '\x07':
				stralloc_cats(&str, "&#x2022;");
				break;
			case '\x08':
				stralloc_cats(&str, "&#x25D8;");
				break;
			case '\x09':
				stralloc_cats(&str, "&#x25CB;");
				break;
			case '\x0b':
				stralloc_cats(&str, "&#x2642;");
				break;
			case '\x0c':
				stralloc_cats(&str, "&#x2640;");
				break;
			case '\x0e':
				stralloc_cats(&str, "&#x266B;");
				break;
			case '\x0f':
				stralloc_cats(&str, "&#x263C;");
				break;
			case '\x10':
				stralloc_cats(&str, "&#x25B8;");
				break;
			case '\x11':
				stralloc_cats(&str, "&#x25C2;");
				break;
			case '\x12':
				stralloc_cats(&str, "&#x2195;");
				break;
			case '\x13':
				stralloc_cats(&str, "&#x203C;");
				break;
			case '\x14':
				stralloc_cats(&str, "&#x00B6;");
				break;
			case '\x15':
				stralloc_cats(&str, "&#x00A7;");
				break;
			case '\x16':
				stralloc_cats(&str, "&#x25AC;");
				break;
			case '\x17':
				stralloc_cats(&str, "&#x21A8;");
				break;
			case '\x18':
				stralloc_cats(&str, "&#x2191;");
				break;
			case '\x19':
				stralloc_cats(&str, "&#x2193;");
				break;
			case '\x1a':
				stralloc_cats(&str, "&#x2192;");
				break;
			case '\x1b':
				stralloc_cats(&str, "&#x2190;");
				break;
			case '\x1c':
				stralloc_cats(&str, "&#x221F;");
				break;
			case '\x1d':
				stralloc_cats(&str, "&#x2194;");
				break;
			case '\x1e':
				stralloc_cats(&str, "&#x25B4;");
				break;
			case '\x1f':
				stralloc_cats(&str, "&#x25BE;");
				break;
				/*
            case '\x21':
				stralloc_cats(&str, "&#x0021;");
				break;
            case '\x22':
				stralloc_cats(&str, "&#x0022;");
				break;
            case '\x24':
				stralloc_cats(&str, "&#x0024;");
				break;
            case '\x25':
				stralloc_cats(&str, "&#x0025;");
				break;
            case '\x27':
				stralloc_cats(&str, "&#x0027;");
				break;
            case '\x28':
				stralloc_cats(&str, "&#x0028;");
				break;
            case '\x29':
				stralloc_cats(&str, "&#x0029;");
				break;
            case '\x2a':
				stralloc_cats(&str, "&#x002A;");
				break;
            case '\x2b':
				stralloc_cats(&str, "&#x002B;");
				break;
            case '\x2c':
				stralloc_cats(&str, "&#x002C;");
				break;
*/
			case '\x7f':
				stralloc_cats(&str, "&#x2302;");
				break;
			case '\x80':
				stralloc_cats(&str, "&#x00C7;");
				break;
			case '\x81':
				stralloc_cats(&str, "&#x00FC;");
				break;
			case '\x82':
				stralloc_cats(&str, "&#x00E9;");
				break;
			case '\x83':
				stralloc_cats(&str, "&#x00E2;");
				break;
			case '\x84':
				stralloc_cats(&str, "&#x00E4;");
				break;
			case '\x85':
				stralloc_cats(&str, "&#x00E0;");
				break;
			case '\x86':
				stralloc_cats(&str, "&#x00E5;");
				break;
			case '\x87':
				stralloc_cats(&str, "&#x00E7;");
				break;
			case '\x88':
				stralloc_cats(&str, "&#x00EA;");
				break;
			case '\x89':
				stralloc_cats(&str, "&#x00EB;");
				break;
			case '\x8a':
				stralloc_cats(&str, "&#x00E8;");
				break;
			case '\x8b':
				stralloc_cats(&str, "&#x00EF;");
				break;
			case '\x8c':
				stralloc_cats(&str, "&#x00EE;");
				break;
			case '\x8d':
				stralloc_cats(&str, "&#x00EC;");
				break;
			case '\x8e':
				stralloc_cats(&str, "&#x00C4;");
				break;
			case '\x8f':
				stralloc_cats(&str, "&#x00C5;");
				break;
			case '\x90':
				stralloc_cats(&str, "&#x00C9;");
				break;
			case '\x91':
				stralloc_cats(&str, "&#x00E6;");
				break;
			case '\x92':
				stralloc_cats(&str, "&#x00C6;");
				break;
			case '\x93':
				stralloc_cats(&str, "&#x00F4;");
				break;
			case '\x94':
				stralloc_cats(&str, "&#x00F6;");
				break;
			case '\x95':
				stralloc_cats(&str, "&#x00F2;");
				break;
			case '\x96':
				stralloc_cats(&str, "&#x00FB;");
				break;
			case '\x97':
				stralloc_cats(&str, "&#x00F9;");
				break;
			case '\x98':
				stralloc_cats(&str, "&#x00FF;");
				break;
			case '\x99':
				stralloc_cats(&str, "&#x00D6;");
				break;
			case '\x9a':
				stralloc_cats(&str, "&#x00DC;");
				break;
			case '\x9b':
				stralloc_cats(&str, "&#x00A2;");
				break;
			case '\x9c':
				stralloc_cats(&str, "&#x00A3;");
				break;
			case '\x9d':
				stralloc_cats(&str, "&#x00A5;");
				break;
			case '\x9e':
				stralloc_cats(&str, "&#x20A7;");
				break;
			case '\x9f':
				stralloc_cats(&str, "&#x0192;");
				break;
			case '\xa0':
				stralloc_cats(&str, "&#x00E1;");
				break;
			case '\xa1':
				stralloc_cats(&str, "&#x00ED;");
				break;
			case '\xa2':
				stralloc_cats(&str, "&#x00F3;");
				break;
			case '\xa3':
				stralloc_cats(&str, "&#x00FA;");
				break;
			case '\xa4':
				stralloc_cats(&str, "&#x00F1;");
				break;
			case '\xa5':
				stralloc_cats(&str, "&#x00D1;");
				break;
			case '\xa6':
				stralloc_cats(&str, "&#x00AA;");
				break;
			case '\xa7':
				stralloc_cats(&str, "&#x00BA;");
				break;
			case '\xa8':
				stralloc_cats(&str, "&#x00BF;");
				break;
			case '\xa9':
				stralloc_cats(&str, "&#x2310;");
				break;
			case '\xaa':
				stralloc_cats(&str, "&#x00AC;");
				break;
			case '\xab':
				stralloc_cats(&str, "&#x00BD;");
				break;
			case '\xac':
				stralloc_cats(&str, "&#x00BC;");
				break;
			case '\xad':
				stralloc_cats(&str, "&#x00A1;");
				break;
			case '\xae':
				stralloc_cats(&str, "&#x00AB;");
				break;
			case '\xaf':
				stralloc_cats(&str, "&#x00BB;");
				break;
			case '\xb0':
				stralloc_cats(&str, "&#x2591;");
				break;
			case '\xb1':
				stralloc_cats(&str, "&#x2592;");
				break;
			case '\xb2':
				stralloc_cats(&str, "&#x2593;");
				break;
			case '\xb3':
				stralloc_cats(&str, "&#x2502;");
				break;
			case '\xb4':
				stralloc_cats(&str, "&#x2524;");
				break;
			case '\xb5':
				stralloc_cats(&str, "&#x2561;");
				break;
			case '\xb6':
				stralloc_cats(&str, "&#x2562;");
				break;
			case '\xb7':
				stralloc_cats(&str, "&#x2556;");
				break;
			case '\xb8':
				stralloc_cats(&str, "&#x2555;");
				break;
			case '\xb9':
				stralloc_cats(&str, "&#x2563;");
				break;
			case '\xba':
				stralloc_cats(&str, "&#x2551;");
				break;
			case '\xbb':
				stralloc_cats(&str, "&#x2557;");
				break;
			case '\xbc':
				stralloc_cats(&str, "&#x255D;");
				break;
			case '\xbd':
				stralloc_cats(&str, "&#x255C;");
				break;
			case '\xbe':
				stralloc_cats(&str, "&#x255B;");
				break;
			case '\xbf':
				stralloc_cats(&str, "&#x2510;");
				break;
			case '\xc0':
				stralloc_cats(&str, "&#x2514;");
				break;
			case '\xc1':
				stralloc_cats(&str, "&#x2534;");
				break;
			case '\xc2':
				stralloc_cats(&str, "&#x252C;");
				break;
			case '\xc3':
				stralloc_cats(&str, "&#x251C;");
				break;
			case '\xc4':
				stralloc_cats(&str, "&#x2500;");
				break;
			case '\xc5':
				stralloc_cats(&str, "&#x253C;");
				break;
			case '\xc6':
				stralloc_cats(&str, "&#x255E;");
				break;
			case '\xc7':
				stralloc_cats(&str, "&#x255F;");
				break;
			case '\xc8':
				stralloc_cats(&str, "&#x255A;");
				break;
			case '\xc9':
				stralloc_cats(&str, "&#x2554;");
				break;
			case '\xca':
				stralloc_cats(&str, "&#x2569;");
				break;
			case '\xcb':
				stralloc_cats(&str, "&#x2566;");
				break;
			case '\xcc':
				stralloc_cats(&str, "&#x2560;");
				break;
			case '\xcd':
				stralloc_cats(&str, "&#x2550;");
				break;
			case '\xce':
				stralloc_cats(&str, "&#x256C;");
				break;
			case '\xcf':
				stralloc_cats(&str, "&#x2567;");
				break;
			case '\xd0':
				stralloc_cats(&str, "&#x2568;");
				break;
			case '\xd1':
				stralloc_cats(&str, "&#x2564;");
				break;
			case '\xd2':
				stralloc_cats(&str, "&#x2565;");
				break;
			case '\xd3':
				stralloc_cats(&str, "&#x2559;");
				break;
			case '\xd4':
				stralloc_cats(&str, "&#x255B;");
				break;
			case '\xd5':
				stralloc_cats(&str, "&#x2552;");
				break;
			case '\xd6':
				stralloc_cats(&str, "&#x2553;");
				break;
			case '\xd7':
				stralloc_cats(&str, "&#x256B;");
				break;
			case '\xd8':
				stralloc_cats(&str, "&#x256A;");
				break;
			case '\xd9':
				stralloc_cats(&str, "&#x2518;");
				break;
			case '\xda':
				stralloc_cats(&str, "&#x250C;");
				break;
			case '\xdb':
				stralloc_cats(&str, "&#x2588;");
				break;
			case '\xdc':
				stralloc_cats(&str, "&#x2584;");
				break;
			case '\xdd':
				stralloc_cats(&str, "&#x258C;");
				break;
			case '\xde':
				stralloc_cats(&str, "&#x2590;");
				break;
			case '\xdf':
				stralloc_cats(&str, "&#x2580;");
				break;
			case '\xe0':
				stralloc_cats(&str, "&#x03B1;");
				break;
			case '\xe1':
				stralloc_cats(&str, "&#x03B2;");
				break;
			case '\xe2':
				stralloc_cats(&str, "&#x0393;");
				break;
			case '\xe3':
				stralloc_cats(&str, "&#x03C0;");
				break;
			case '\xe4':
				stralloc_cats(&str, "&#x03A3;");
				break;
			case '\xe5':
				stralloc_cats(&str, "&#x03C3;");
				break;
			case '\xe6':
				stralloc_cats(&str, "&#x00B5;");
				break;
			case '\xe7':
				stralloc_cats(&str, "&#x03C4;");
				break;
			case '\xe8':
				stralloc_cats(&str, "&#x03A6;");
				break;
			case '\xe9':
				stralloc_cats(&str, "&#x0398;");
				break;
			case '\xea':
				stralloc_cats(&str, "&#x03A9;");
				break;
			case '\xeb':
				stralloc_cats(&str, "&#x03B4;");
				break;
			case '\xec':
				stralloc_cats(&str, "&#x221E;");
				break;
			case '\xed':
				stralloc_cats(&str, "&#x2205;");
				break;
			case '\xee':
				stralloc_cats(&str, "&#x2208;");
				break;
			case '\xef':
				stralloc_cats(&str, "&#x2229;");
				break;
			case '\xf0':
				stralloc_cats(&str, "&#x2261;");
				break;
			case '\xf1':
				stralloc_cats(&str, "&#x00B1;");
				break;
			case '\xf2':
				stralloc_cats(&str, "&#x2265;");
				break;
			case '\xf3':
				stralloc_cats(&str, "&#x2264;");
				break;
			case '\xf4':
				stralloc_cats(&str, "&#x2320;");
				break;
			case '\xf5':
				stralloc_cats(&str, "&#x2321;");
				break;
			case '\xf6':
				stralloc_cats(&str, "&#x00F7;");
				break;
			case '\xf7':
				stralloc_cats(&str, "&#x2248;");
				break;
			case '\xf8':
				stralloc_cats(&str, "&#x00B0;");
				break;
			case '\xf9':
				stralloc_cats(&str, "&#x2219;");
				break;
			case '\xfa':
				stralloc_cats(&str, "&#x00B7;");
				break;
			case '\xfb':
				stralloc_cats(&str, "&#x221A;");
				break;
			case '\xfc':
				stralloc_cats(&str, "&#x207F;");
				break;
			case '\xfd':
				stralloc_cats(&str, "&#x00B2;");
				break;
			case '\xfe':
				stralloc_cats(&str, "&#x25AA;");
				break;
			case ' ':
				if (isdata) {
					if (*(p + 1) == ' ') {
						stralloc_cats(&str, "&nbsp;");
					} else {
						if (p > data && (*(p - 1) == ' ' || *(p - 1) == '\n')) {
							stralloc_cats(&str, "&nbsp;");
						} else if (data == p) {
							stralloc_cats(&str, "&nbsp;");
						} else {
							stralloc_append1(&str, ' ');
						}
					}
				} else {
					stralloc_append1(&str, ' ');
				}
				break;

			default:
				stralloc_append1(&str, *p);
				break;
		}
	}
	stralloc_0(&str);
	return str.s;
}

struct www_tag *www_tag_new(char *tag, char *data) {
	struct www_tag *new_tag = malloz(sizeof(struct www_tag));

	new_tag->attribs = EMPTY_PTR_VECTOR;
	new_tag->values = EMPTY_PTR_VECTOR;
	new_tag->children = EMPTY_PTR_VECTOR;

	if (tag == NULL) {
		new_tag->tag = NULL;

		/* SANATIZE DATA HERE */
		new_tag->data = www_tag_sanatize(data, 1);
	} else {
		new_tag->tag = strdup(tag);
		new_tag->data = NULL;

		init_ptr_vector(&new_tag->attribs);
		init_ptr_vector(&new_tag->values);
	}

	init_ptr_vector(&new_tag->children);

	return new_tag;
}

struct www_tag *www_tag_duplicate(struct www_tag *oldtag) {
	struct www_tag *newtag = www_tag_new(oldtag->tag, oldtag->data);
	for (int i = 0; i < oldtag->attribs.len; i++) {
		www_tag_add_attrib(newtag, strdup(ptr_vector_get(&oldtag->attribs, i)), strdup(ptr_vector_get(&oldtag->values, i)));
	}
	return newtag;
}

void www_tag_add_attrib(struct www_tag *tag, char *attrib, char *value) {
	ptr_vector_append(&tag->attribs, strdup(attrib));
	ptr_vector_append(&tag->values, www_tag_sanatize(value, 0));
}

void www_tag_add_child(struct www_tag *tag, struct www_tag *child) {
	ptr_vector_append(&tag->children, child);
}

/* char *www_tag_destroy(struct www_tag *tag) {
	while (tag->children.len > 0) {
		struct www_tag *child = ptr_vector_del(&tag->children, 0);
		www_tag_destroy(child);
	}

	if (tag->tag != NULL) {
		ptr_vector_apply(&tag->attribs, free);
		destroy_ptr_vector(&tag->attribs);
		ptr_vector_apply(&tag->values, free);
		destroy_ptr_vector(&tag->values);
	}
	destroy_ptr_vector(&tag->children);
} */

char *www_tag_destroy(struct www_tag *tag) {
    if (tag == NULL) return NULL;

    // 1. Recursively destroy all children first
    while (tag->children.len > 0) {
        struct www_tag *child = ptr_vector_del(&tag->children, 0);
        www_tag_destroy(child);
    }
    destroy_ptr_vector(&tag->children);

    // 2. Clean up Attributes and Values
    // ptr_vector_apply(..., free) handles the strings inside the vectors
    ptr_vector_apply(&tag->attribs, free);
    destroy_ptr_vector(&tag->attribs);
    
    ptr_vector_apply(&tag->values, free);
    destroy_ptr_vector(&tag->values);

    // 3. Clean up the strings created by strdup and sanatize
    if (tag->tag != NULL) {
        free(tag->tag);
    }
    if (tag->data != NULL) {
        free(tag->data);
    }

    // 4. Finally, free the struct itself
    free(tag);

    return NULL;
}

char *www_tag_unwravel(struct www_tag *tag) {
	stralloc thedata = EMPTY_STRALLOC;
	while (tag->children.len > 0) {
		struct www_tag *child = ptr_vector_del(&tag->children, 0);
		if (child->children.len > 0) {
			if (child->tag != NULL) {
				stralloc_append1(&thedata, '<');
				stralloc_cats(&thedata, child->tag);
				for (int i = 0; i < child->attribs.len; i++) {
					stralloc_append1(&thedata, ' ');
					stralloc_cats(&thedata, (char *)ptr_vector_get(&child->attribs, i));
					stralloc_append1(&thedata, '=');
					stralloc_append1(&thedata, '\"');
					stralloc_cats(&thedata, (char *)ptr_vector_get(&child->values, i));
					stralloc_append1(&thedata, '\"');
				}

				stralloc_append1(&thedata, '>');
			}
			char *data = www_tag_unwravel(child);
			stralloc_cats(&thedata, data);
			free(data);

			if (child->tag != NULL) {
				stralloc_cats(&thedata, "</");
				stralloc_cats(&thedata, child->tag);
				stralloc_append1(&thedata, '>');
				ptr_vector_apply(&child->attribs, free);
				destroy_ptr_vector(&child->attribs);
				ptr_vector_apply(&child->values, free);
				destroy_ptr_vector(&child->values);
			}
		} else {
			if (child->tag != NULL) {
				stralloc_append1(&thedata, '<');
				stralloc_cats(&thedata, child->tag);
				for (int i = 0; i < child->attribs.len; i++) {
					stralloc_append1(&thedata, ' ');
					stralloc_cats(&thedata, (char *)ptr_vector_get(&child->attribs, i));
					stralloc_append1(&thedata, '=');
					stralloc_append1(&thedata, '\"');
					stralloc_cats(&thedata, (char *)ptr_vector_get(&child->values, i));
					stralloc_append1(&thedata, '\"');
				}
				stralloc_cats(&thedata, " />");
				ptr_vector_apply(&child->attribs, free);
				destroy_ptr_vector(&child->attribs);
				ptr_vector_apply(&child->values, free);
				destroy_ptr_vector(&child->values);
			} else {
				stralloc_cats(&thedata, child->data);
			}
		}
		destroy_ptr_vector(&child->children);
/*                free(child); // <--- ADD THIS LINE HERE then removed after www_tag_destroy fix */  
	}

	stralloc_0(&thedata);

	return thedata.s;
}

#endif
