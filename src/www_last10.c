#if defined(ENABLE_WWW)

#include <time.h>
#include <stdlib.h>
#include <string.h>

#include "www_tree.h"
#include "bbs.h"

extern struct bbs_config conf;

char *www_last10(struct MHD_Connection *connection) {
	size_t n = 0;
	//stralloc page = EMPTY_STRALLOC;
	struct last10_callers callers[10];
	char last10_path[PATH_MAX];
	struct www_tag *page;
	struct www_tag *cur_tag;
	struct www_tag *child_tag;
	struct www_tag *child_child_tag;
	struct www_tag *child_child_child_tag;

	snprintf(last10_path, PATH_MAX, "%s/last10v2.dat", conf.bbs_path);

	FILE *fptr = fopen(last10_path, "rb");
	if (fptr != NULL) {
		for (; n < 10; ++n)
			if (fread(&callers[n], sizeof(callers[n]), 1, fptr) != 1)
				break;
		fclose(fptr);
	}

	page = www_tag_new(NULL, "");
	cur_tag = www_tag_new("div", NULL);
	www_tag_add_attrib(cur_tag, "class", "content-header");
	www_tag_add_child(page, cur_tag);

	child_tag = www_tag_new("h2", NULL);
	www_tag_add_child(cur_tag, child_tag);

	child_child_tag = www_tag_new(NULL, "Last 10 Callers");
	www_tag_add_child(child_tag, child_child_tag);

	cur_tag = www_tag_new("div", NULL);
	www_tag_add_attrib(cur_tag, "class", "div-table");
	www_tag_add_child(page, cur_tag);

	for (size_t i = 0; i < n; ++i) {
		struct tm called;
		char buffer[32];

		child_tag = www_tag_new("div", NULL);
		www_tag_add_attrib(child_tag, "class", "last10-row");
		www_tag_add_child(cur_tag, child_tag);

		child_child_tag = www_tag_new("div", NULL);
		www_tag_add_attrib(child_child_tag, "class", "last10-name");
		www_tag_add_child(child_tag, child_child_tag);

		child_child_child_tag = www_tag_new(NULL, callers[i].name);
		www_tag_add_child(child_child_tag, child_child_child_tag);

		child_child_tag = www_tag_new("div", NULL);
		www_tag_add_attrib(child_child_tag, "class", "last10-location");
		www_tag_add_child(child_tag, child_child_tag);

		child_child_child_tag = www_tag_new(NULL, callers[i].location);
		www_tag_add_child(child_child_tag, child_child_child_tag);

		child_child_tag = www_tag_new("div", NULL);
		www_tag_add_attrib(child_child_tag, "class", "last10-date");
		www_tag_add_child(child_tag, child_child_tag);

		localtime_r(&callers[i].time, &called);
		if (conf.date_style == 1)
			strftime(buffer, sizeof buffer, "%H:%M %m-%d-%y", &called);
		else
			strftime(buffer, sizeof buffer, "%H:%M %d-%m-%y", &called);

		child_child_child_tag = www_tag_new(NULL, buffer);
		www_tag_add_child(child_child_tag, child_child_child_tag);

		if (callers[i].calls == 1) {
			child_child_tag = www_tag_new("div", NULL);
			www_tag_add_attrib(child_child_tag, "class", "last10-new");
			www_tag_add_child(child_tag, child_child_tag);

			stralloc url = EMPTY_STRALLOC;

			stralloc_copys(&url, www_get_my_url(connection));
			stralloc_cats(&url, "static/newuser.png");
			stralloc_0(&url);

			child_child_child_tag = www_tag_new("img", NULL);
			www_tag_add_attrib(child_child_child_tag, "src", url.s);
			free(url.s);
			www_tag_add_child(child_child_tag, child_child_child_tag);
		}
	}

	return www_tag_unwravel(page);
}

#endif
