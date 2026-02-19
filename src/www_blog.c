#if defined(ENABLE_WWW)

#include <string.h>
#include <time.h>
#include <stdlib.h>
#include "www_tree.h"
#include "bbs.h"

extern struct bbs_config conf;

char *www_blog_rss(struct MHD_Connection *connection) {
	struct ptr_vector entries = blog_load();
	struct www_tag *page;
	struct www_tag *rss_tag;
	struct www_tag *channel_tag;
	struct www_tag *channel_sub_tag;
	struct www_tag *channel_sub_tag_content;

	stralloc str_a;

	page = www_tag_new(NULL, "");
	rss_tag = www_tag_new("rss", NULL);
	www_tag_add_attrib(rss_tag, "version", "2.0");
	www_tag_add_child(page, rss_tag);
	channel_tag = www_tag_new("channel", NULL);
	www_tag_add_child(rss_tag, channel_tag);

	channel_sub_tag = www_tag_new("title", NULL);
	www_tag_add_child(channel_tag, channel_sub_tag);
	str_a = EMPTY_STRALLOC;
	stralloc_cats(&str_a, conf.bbs_name);
	stralloc_cats(&str_a, " System Blog");
	stralloc_0(&str_a);
	channel_sub_tag_content = www_tag_new(NULL, str_a.s);
	free(str_a.s);
	www_tag_add_child(channel_sub_tag, channel_sub_tag_content);

	channel_sub_tag = www_tag_new("link", NULL);
	www_tag_add_child(channel_tag, channel_sub_tag);
	str_a = EMPTY_STRALLOC;
	stralloc_cats(&str_a, www_get_my_url(connection));
	stralloc_cats(&str_a, "blog/");
	stralloc_0(&str_a);
	channel_sub_tag_content = www_tag_new(NULL, str_a.s);
	free(str_a.s);
	www_tag_add_child(channel_sub_tag, channel_sub_tag_content);

	channel_sub_tag = www_tag_new("description", NULL);
	www_tag_add_child(channel_tag, channel_sub_tag);
	str_a = EMPTY_STRALLOC;
	stralloc_cats(&str_a, "News from ");
	stralloc_cats(&str_a, conf.bbs_name);
	stralloc_0(&str_a);
	channel_sub_tag_content = www_tag_new(NULL, str_a.s);
	free(str_a.s);
	www_tag_add_child(channel_sub_tag, channel_sub_tag_content);

	for (size_t i = 0; i < ptr_vector_len(&entries); i++) {
		struct blog_entry_t *entry = ptr_vector_get(&entries, i);
		struct www_tag *item_tag;
		struct www_tag *title_tag;
		struct www_tag *title_content;
		struct www_tag *description_tag;
		struct www_tag *description_content;
		struct www_tag *pubdate_tag;
		struct www_tag *pubdate_content;
		struct tm entry_time;
		char datebuf[30];

		item_tag = www_tag_new("item", NULL);
		www_tag_add_child(channel_tag, item_tag);

		title_tag = www_tag_new("title", NULL);
		www_tag_add_child(item_tag, title_tag);

		title_content = www_tag_new(NULL, entry->subject);
		www_tag_add_child(title_tag, title_content);

		description_tag = www_tag_new("description", NULL);
		www_tag_add_child(item_tag, description_tag);

		stralloc blog_body = EMPTY_STRALLOC;

		stralloc_cats(&blog_body, "<p>");
		for (char *p = entry->body; *p != '\0'; ++p) {
			if (*p != '\r') {
				stralloc_append1(&blog_body, *p);
				continue;
			}
			if (p[1] != '\0' && p[1] != '\r') {
				stralloc_append1(&blog_body, ' ');
				continue;
			} else if (p[1] != '\0') {
				if (blog_body.s != NULL) {
					stralloc_cats(&blog_body, "</p><p>");
				}
				++p;
			}
		}

		if (blog_body.s != NULL) {
			stralloc_cats(&blog_body, "</p>");
		} else {
			stralloc_cats(&blog_body, "Blank Entry");
		}

		stralloc_0(&blog_body);

		description_content = www_tag_new(NULL, blog_body.s);
		free(blog_body.s);
		www_tag_add_child(description_tag, description_content);

		gmtime_r(&entry->date, &entry_time);
		strftime(datebuf, sizeof datebuf, "%a, %d %b %Y %H:%M:%S GMT", &entry_time);

		pubdate_tag = www_tag_new("pubDate", NULL);
		www_tag_add_child(item_tag, pubdate_tag);

		pubdate_content = www_tag_new(NULL, datebuf);
		www_tag_add_child(pubdate_tag, pubdate_content);
	}
	ptr_vector_apply(&entries, free);
	destroy_ptr_vector(&entries);

	return www_tag_unwravel(page);
}

char *www_blog(struct MHD_Connection *connection) {
	struct ptr_vector entries = blog_load();
	struct www_tag *page;
	struct www_tag *cur_tag;
	struct www_tag *child_tag;
	struct www_tag *child_child_tag;
	struct www_tag *child_child_child_tag;

	page = www_tag_new(NULL, "");
	cur_tag = www_tag_new("div", NULL);
	www_tag_add_attrib(cur_tag, "class", "content-header");
	child_tag = www_tag_new("h2", NULL);
	www_tag_add_child(cur_tag, child_tag);
	www_tag_add_child(child_tag, www_tag_new(NULL, "System Blog"));
	www_tag_add_child(page, cur_tag);

	if (ptr_vector_len(&entries) == 0) {
		cur_tag = www_tag_new("p", NULL);
		www_tag_add_child(cur_tag, www_tag_new(NULL, "No Entries"));
		www_tag_add_child(page, cur_tag);

		return www_tag_unwravel(page);
	}
	for (size_t i = 0; i < ptr_vector_len(&entries); i++) {
		struct blog_entry_t *entry = ptr_vector_get(&entries, i);
		struct tm entry_time;
		int hour;
		char timebuf[16];
		char datebuf[24];

		localtime_r(&entry->date, &entry_time);
		hour = entry_time.tm_hour;
		strftime(timebuf, sizeof timebuf, "%l:%M", &entry_time);
		strftime(datebuf, sizeof datebuf, " %a, %e %b %Y", &entry_time);

		cur_tag = www_tag_new("div", NULL);
		www_tag_add_attrib(cur_tag, "class", "blog-header");
		www_tag_add_child(page, cur_tag);

		child_tag = www_tag_new("div", NULL);
		www_tag_add_attrib(child_tag, "class", "blog-title");
		www_tag_add_child(cur_tag, child_tag);

		child_child_tag = www_tag_new("h3", NULL);
		www_tag_add_child(child_tag, child_child_tag);

		child_child_child_tag = www_tag_new(NULL, entry->subject);
		www_tag_add_child(child_child_tag, child_child_child_tag);

		child_tag = www_tag_new("div", NULL);
		www_tag_add_attrib(child_tag, "class", "blog-date");
		www_tag_add_child(cur_tag, child_tag);

		child_child_tag = www_tag_new(NULL, timebuf);
		www_tag_add_child(child_tag, child_child_tag);

		child_child_tag = www_tag_new(NULL, hour >= 12 ? "pm" : "am");
		www_tag_add_child(child_tag, child_child_tag);

		child_child_tag = www_tag_new(NULL, datebuf);
		www_tag_add_child(child_tag, child_child_tag);

		child_tag = www_tag_new("div", NULL);
		www_tag_add_attrib(child_tag, "class", "blog-author");
		www_tag_add_child(cur_tag, child_tag);

		child_child_tag = www_tag_new(NULL, "by ");
		www_tag_add_child(child_tag, child_child_tag);

		child_child_tag = www_tag_new(NULL, entry->author);
		www_tag_add_child(child_tag, child_child_tag);

		cur_tag = www_tag_new("div", NULL);
		www_tag_add_attrib(cur_tag, "class", "blog-entry");
		www_tag_add_child(page, cur_tag);

		child_tag = www_tag_new("p", NULL);
		www_tag_add_child(cur_tag, child_tag);

		stralloc blog_body = EMPTY_STRALLOC;

		for (char *p = entry->body; *p != '\0'; ++p) {
			if (*p != '\r') {
				stralloc_append1(&blog_body, *p);
				continue;
			}
			if (p[1] != '\0' && p[1] != '\r') {
				stralloc_append1(&blog_body, ' ');
				continue;
			} else if (p[1] != '\0') {
				if (blog_body.s != NULL) {
					stralloc_0(&blog_body);
					child_child_tag = www_tag_new(NULL, blog_body.s);
					free(blog_body.s);
					www_tag_add_child(child_tag, child_child_tag);
					blog_body = EMPTY_STRALLOC;
					child_tag = www_tag_new("p", NULL);
					www_tag_add_child(cur_tag, child_tag);
				}
				++p;
			}
		}

		if (blog_body.s != NULL) {
			stralloc_0(&blog_body);
			child_child_tag = www_tag_new(NULL, blog_body.s);
			free(blog_body.s);
			www_tag_add_child(child_tag, child_child_tag);
		}
	}

	cur_tag = www_tag_new("a", NULL);

	stralloc rsslink = EMPTY_STRALLOC;

	stralloc_cats(&rsslink, www_get_my_url(connection));
	stralloc_cats(&rsslink, "blog/rss/");
	stralloc_0(&rsslink);

	www_tag_add_attrib(cur_tag, "href", rsslink.s);
	free(rsslink.s);

	www_tag_add_child(page, cur_tag);

	child_tag = www_tag_new(NULL, "RSS Feed");
	www_tag_add_child(cur_tag, child_tag);

	ptr_vector_apply(&entries, free);
	destroy_ptr_vector(&entries);

	return www_tag_unwravel(page);
}

#endif
