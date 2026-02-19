#if defined(ENABLE_WWW)
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <iconv.h>
#include <libgen.h>
#include "www_tree.h"
#include "msglib/msglib.h"
#include "libuuid/uuid.h"

#include "www_tree.h"

#include "bbs.h"
#include "mail_utils.h"

#define IN 0
#define OUT 1
extern struct bbs_config conf;
extern struct www_tag *aha(char *input, struct www_tag *parent, int dopipe);
static char *www_wordwrap(char *content, int cutoff);

extern void unmangle_ansi(char *body, int len, char **body_out, int *body_len, int dopipe);

char *www_msgs_arealist(struct MHD_Connection *connection, struct user_record *user) {
	stralloc page = EMPTY_STRALLOC;

	stralloc_copys(&page, "<div class=\"content-header\"><h2>Message Conferences</h2></div>\n");
	for (size_t i = 0; i < ptr_vector_len(&conf.mail_conferences); i++) {
		struct mail_conference *mc = get_conf(i);
		if (mc->sec_level <= user->sec_level) {
			stralloc_cats(&page, "<div class=\"conference-list-item\">");
			stralloc_cats(&page, mc->name);
			stralloc_cats(&page, "</div>\n");
			for (size_t j = 0; j < ptr_vector_len(&mc->mail_areas); j++) {
				struct mail_area *ma = get_area(i, j);
				if (ma->read_sec_level > user->sec_level) {
					continue;
				}
				stralloc_cats(&page, "<div class=\"area-list-");
				stralloc_cats(&page, (new_messages(user, i, j) > 0) ? "new" : "item");
				stralloc_cats(&page, "\"><a href=\"");
				stralloc_cats(&page, www_get_my_url(connection));
				stralloc_cats(&page, "msgs/");
				stralloc_cat_long(&page, i);
				stralloc_append1(&page, '/');
				stralloc_cat_long(&page, j);
				stralloc_cats(&page, "/\">");
				stralloc_cats(&page, ma->name);
				stralloc_cats(&page, "</a></div>\n");
			}
		}
	}
	stralloc_0(&page);
	return page.s;
}

char *www_msgs_messagelist(struct MHD_Connection *connection, struct user_record *user, int conference, int area, int skip) {
	struct msg_headers *mhrs;
	int i;
	struct tm msg_date;
	time_t date;
	int skip_f;
	int skip_t;
	char *to;
	char *from;
	char *subject;
	char datebuf[32];
	struct msg_base_t *mb;
	stralloc url;
	int high_read;
	struct www_tag *page;
	struct www_tag *cur_tag;
	struct www_tag *child_tag;
	struct www_tag *child_child_tag;
	struct www_tag *child_child_child_tag;
	struct www_tag *child_child_child_child_tag;

	if (conference < 0 || conference >= ptr_vector_len(&conf.mail_conferences))
		return NULL;
	struct mail_conference *mc = get_conf(conference);
	if (area < 0 || area >= ptr_vector_len(&mc->mail_areas))
		return NULL;
	struct mail_area *ma = get_area(conference, area);

	page = www_tag_new(NULL, "");
	cur_tag = www_tag_new("div", NULL);
	www_tag_add_attrib(cur_tag, "class", "content-header");
	www_tag_add_child(page, cur_tag);

	child_tag = www_tag_new("h2", NULL);
	www_tag_add_child(cur_tag, child_tag);

	child_child_tag = www_tag_new(NULL, mc->name);
	www_tag_add_child(child_tag, child_child_tag);

	child_child_tag = www_tag_new(NULL, " - ");
	www_tag_add_child(child_tag, child_child_tag);

	child_child_tag = www_tag_new(NULL, ma->name);
	www_tag_add_child(child_tag, child_child_tag);

	if (ma->type != TYPE_NETMAIL_AREA) {
		cur_tag = www_tag_new("div", NULL);
		www_tag_add_attrib(cur_tag, "class", "button");
		www_tag_add_child(page, cur_tag);

		child_tag = www_tag_new("a", NULL);

		url = EMPTY_STRALLOC;
		stralloc_cats(&url, www_get_my_url(connection));
		stralloc_cats(&url, "msgs/new/");
		stralloc_cat_long(&url, conference);
		stralloc_append1(&url, '/');
		stralloc_cat_long(&url, area);
		stralloc_0(&url);

		www_tag_add_attrib(child_tag, "href", url.s);
		free(url.s);

		www_tag_add_child(cur_tag, child_tag);

		child_child_tag = www_tag_new(NULL, "New Message");
		www_tag_add_child(child_tag, child_child_tag);
	}
	mhrs = read_message_headers(conference, area, user, 0);

	if (mhrs == NULL) {
		cur_tag = www_tag_new("h3", NULL);
		www_tag_add_child(page, cur_tag);

		child_tag = www_tag_new(NULL, "No Messages");
		www_tag_add_child(cur_tag, child_tag);
	} else {
		cur_tag = www_tag_new("div", NULL);
		www_tag_add_attrib(cur_tag, "class", "div-table");
		www_tag_add_child(page, cur_tag);

		mb = open_message_base(conference, area);
		if (!mb) {
			www_tag_destroy(page);
			free_message_headers(mhrs);
			return NULL;
		}
		high_read = get_message_highread(mb, user->id);
		if (high_read == -1) {
			high_read = 0;
		}
		close_message_base(mb);

		skip_f = mhrs->msg_count - skip;
		skip_t = mhrs->msg_count - skip - 50;
		if (skip_t < 0) {
			skip_t = 0;
		}

		for (i = skip_f - 1; i >= skip_t; i--) {
			date = (time_t)mhrs->msgs[i]->msgwritten;
			gmtime_r(&date, &msg_date);
			to = strdup(mhrs->msgs[i]->to);
			from = strdup(mhrs->msgs[i]->from);
			subject = strdup(mhrs->msgs[i]->subject);

			child_tag = www_tag_new("div", NULL);

			if (msgbase_is_flagged(user, conference, area, get_message_number(mhrs, i))) {
				www_tag_add_attrib(child_tag, "class", "msg-summary-flag");
			} else if (get_message_number(mhrs, i) > high_read) {
				www_tag_add_attrib(child_tag, "class", "msg-summary");
			} else {
				www_tag_add_attrib(child_tag, "class", "msg-summary-seen");
			}
			www_tag_add_child(cur_tag, child_tag);

			child_child_tag = www_tag_new("div", NULL);
			www_tag_add_attrib(child_child_tag, "class", "msg-summary-id");
			www_tag_add_child(child_tag, child_child_tag);

			url = EMPTY_STRALLOC;
			stralloc_cat_long(&url, i + 1);
			stralloc_0(&url);

			child_child_child_tag = www_tag_new(NULL, url.s);
			free(url.s);
			www_tag_add_child(child_child_tag, child_child_child_tag);

			child_child_tag = www_tag_new("div", NULL);
			www_tag_add_attrib(child_child_tag, "class", "msg-summary-subject");
			www_tag_add_child(child_tag, child_child_tag);

			url = EMPTY_STRALLOC;
			stralloc_cats(&url, www_get_my_url(connection));
			stralloc_cats(&url, "msgs/");
			stralloc_cat_long(&url, conference);
			stralloc_append1(&url, '/');
			stralloc_cat_long(&url, area);
			stralloc_append1(&url, '/');
			stralloc_cat_long(&url, get_message_number(mhrs, i));
			stralloc_0(&url);

			child_child_child_tag = www_tag_new("a", NULL);
			www_tag_add_attrib(child_child_child_tag, "href", url.s);
			free(url.s);
			www_tag_add_child(child_child_tag, child_child_child_tag);

			child_child_child_child_tag = www_tag_new(NULL, subject);
			www_tag_add_child(child_child_child_tag, child_child_child_child_tag);

			child_child_tag = www_tag_new("div", NULL);
			www_tag_add_attrib(child_child_tag, "class", "msg-summary-from");
			www_tag_add_child(child_tag, child_child_tag);

			child_child_child_tag = www_tag_new(NULL, from);
			www_tag_add_child(child_child_tag, child_child_child_tag);

			child_child_tag = www_tag_new("div", NULL);
			www_tag_add_attrib(child_child_tag, "class", "msg-summary-to");
			www_tag_add_child(child_tag, child_child_tag);

			child_child_child_tag = www_tag_new(NULL, to);
			www_tag_add_child(child_child_tag, child_child_child_tag);

			child_child_tag = www_tag_new("div", NULL);
			www_tag_add_attrib(child_child_tag, "class", "msg-summary-date");
			www_tag_add_child(child_tag, child_child_tag);

			if (conf.date_style == 1)
				strftime(datebuf, sizeof datebuf, "%H:%M %m-%d-%y", &msg_date);
			else
				strftime(datebuf, sizeof datebuf, "%H:%M %d-%m-%y", &msg_date);

			child_child_child_tag = www_tag_new(NULL, datebuf);
			www_tag_add_child(child_child_tag, child_child_child_tag);

			free(to);
			free(from);
			free(subject);
		}
		if (skip + 50 <= mhrs->msg_count) {
			cur_tag = www_tag_new("div", NULL);
			www_tag_add_attrib(cur_tag, "class", "msg-summary-next");
			www_tag_add_child(page, cur_tag);

			child_tag = www_tag_new("a", NULL);

			url = EMPTY_STRALLOC;

			stralloc_cats(&url, www_get_my_url(connection));
			stralloc_cats(&url, "msgs/");
			stralloc_cat_long(&url, conference);
			stralloc_append1(&url, '/');
			stralloc_cat_long(&url, area);
			stralloc_cats(&url, "/?skip=");
			stralloc_cat_long(&url, skip + 50);
			stralloc_0(&url);

			www_tag_add_attrib(child_tag, "href", url.s);
			free(url.s);
			www_tag_add_child(cur_tag, child_tag);
			child_child_tag = www_tag_new(NULL, "Next");
			www_tag_add_child(child_tag, child_child_tag);
		}

		if (skip > 0) {
			cur_tag = www_tag_new("div", NULL);
			www_tag_add_attrib(cur_tag, "class", "msg-summary-prev");
			www_tag_add_child(page, cur_tag);
			child_tag = www_tag_new("a", NULL);
			url = EMPTY_STRALLOC;
			if (skip - 50 < 0) {
				stralloc_cats(&url, www_get_my_url(connection));
				stralloc_cats(&url, "msgs/");
				stralloc_cat_long(&url, conference);
				stralloc_append1(&url, '/');
				stralloc_cat_long(&url, area);
				stralloc_append1(&url, '/');
			} else {
				stralloc_cats(&url, www_get_my_url(connection));
				stralloc_cats(&url, "msgs/");
				stralloc_cat_long(&url, conference);
				stralloc_append1(&url, '/');
				stralloc_cat_long(&url, area);
				stralloc_cats(&url, "/?skip=");
				stralloc_cat_long(&url, skip - 50);
			}
			stralloc_0(&url);
			www_tag_add_attrib(child_tag, "href", url.s);
			free(url.s);

			www_tag_add_child(cur_tag, child_tag);
			child_child_tag = www_tag_new(NULL, "Prev");
			www_tag_add_child(child_tag, child_child_tag);
		}
		free_message_headers(mhrs);
	}

/*	return www_tag_unwravel(page);  */
	char *final_html = www_tag_unwravel(page);
	www_tag_destroy(page); 
	return final_html;
}

char *www_msgs_messageview(struct MHD_Connection *connection, struct user_record *user, int conference, int area, int msg) {
	struct msg_base_t *mb;
	struct msg_t *hdr;
	char *body = NULL;
	char *body2 = NULL;
	char *replybody = NULL;
	int z;
	struct tm msg_date;
	time_t date;
	char buffer[4096];
	int chars;
	int i;
	char *from_s;
	char *subject_s;
	char *to_s;
	int l1, l2;
	char *aha_text;
	char *nodename;
	struct fido_addr *nodeno;
	int high_read;
	iconv_t ic;

	struct www_tag *page;
	struct www_tag *cur_tag;
	struct www_tag *child_tag;
	struct www_tag *child_child_tag;
	struct www_tag *child_child_child_tag;

	if (conference < 0 || conference >= ptr_vector_len(&conf.mail_conferences))
		return NULL;
	struct mail_conference *mc = get_conf(conference);
	if (area < 0 || area >= ptr_vector_len(&mc->mail_areas))
		return NULL;
	struct mail_area *ma = get_area(conference, area);

	mb = open_message_base(conference, area);
	if (!mb) {
		return NULL;
	}

	hdr = load_message_hdr(mb, msg);
	if (hdr == NULL) {
		close_message_base(mb);
		return NULL;
	}

	if (get_header_isprivate(mb, hdr)) {
		if (!msg_is_to(user, hdr->to, hdr->daddress, mc->nettype, ma->realnames, mc) &&
		    !msg_is_from(user, hdr->from, hdr->oaddress, mc->nettype, ma->realnames, mc) &&
		    !msg_is_to(user, hdr->to, hdr->daddress, mc->nettype, !ma->realnames, mc) &&
		    !msg_is_from(user, hdr->from, hdr->oaddress, mc->nettype, !ma->realnames, mc)) {

			free_message_hdr(hdr);
			close_message_base(mb);
			return NULL;
		}
	}

	body = load_message_text(mb, hdr);

	high_read = get_message_highread(mb, user->id);

	write_lasthighread(mb, user, msg, (high_read < msg ? msg : high_read));

	close_message_base(mb);

	page = www_tag_new(NULL, "");

	cur_tag = www_tag_new("div", NULL);
	www_tag_add_attrib(cur_tag, "class", "content-header");
	www_tag_add_child(page, cur_tag);

	child_tag = www_tag_new("a", NULL);

	stralloc url = EMPTY_STRALLOC;

	stralloc_cats(&url, www_get_my_url(connection));
	stralloc_cats(&url, "msgs/");
	stralloc_cat_long(&url, conference);
	stralloc_append1(&url, '/');
	stralloc_cat_long(&url, area);
	stralloc_0(&url);

	www_tag_add_attrib(child_tag, "href", url.s);
	free(url.s);
	www_tag_add_child(cur_tag, child_tag);

	child_child_tag = www_tag_new("h2", NULL);
	www_tag_add_child(child_tag, child_child_tag);

	child_child_child_tag = www_tag_new(NULL, mc->name);
	www_tag_add_child(child_child_tag, child_child_child_tag);

	child_child_child_tag = www_tag_new(NULL, " - ");
	www_tag_add_child(child_child_tag, child_child_child_tag);

	child_child_child_tag = www_tag_new(NULL, ma->name);
	www_tag_add_child(child_child_tag, child_child_child_tag);

	cur_tag = www_tag_new("div", NULL);

	if (msgbase_is_flagged(user, conference, area, msg)) {
		www_tag_add_attrib(cur_tag, "class", "msg-view-header-flagged");
	} else {
		www_tag_add_attrib(cur_tag, "class", "msg-view-header");
	}

	www_tag_add_child(page, cur_tag);

	child_tag = www_tag_new("div", NULL);
	www_tag_add_attrib(child_tag, "class", "msg-view-subject");
	www_tag_add_child(cur_tag, child_tag);

	child_child_tag = www_tag_new(NULL, hdr->subject);
	www_tag_add_child(child_tag, child_child_tag);

	child_tag = www_tag_new("div", NULL);
	www_tag_add_attrib(child_tag, "class", "msg-view-from");
	www_tag_add_child(cur_tag, child_tag);

	if (ma->type != TYPE_LOCAL_AREA && hdr->oaddress != NULL) {
		if (mc->nettype == NETWORK_MAGI) {
			snprintf(buffer, sizeof buffer, "From: %s (@%s)", hdr->from, hdr->oaddress);
			child_child_tag = www_tag_new(NULL, buffer);
			www_tag_add_child(child_tag, child_child_tag);
		} else if (mc->nettype == NETWORK_FIDO) {
			nodeno = parse_fido_addr(hdr->oaddress);
			if (nodeno != NULL) {
				nodename = nl_get_bbsname(nodeno, mc->domain);
				if (strcmp(nodename, "Unknown") == 0) {
					snprintf(buffer, sizeof buffer, "From: %s (%s)", hdr->from, hdr->oaddress);
					child_child_tag = www_tag_new(NULL, buffer);
					www_tag_add_child(child_tag, child_child_tag);
				} else {
					snprintf(buffer, sizeof buffer, "From: %s (", hdr->from);
					child_child_tag = www_tag_new(NULL, buffer);
					www_tag_add_child(child_tag, child_child_tag);

					child_child_tag = www_tag_new("span", NULL);
					www_tag_add_attrib(child_child_tag, "class", "bbsname");
					www_tag_add_child(child_tag, child_child_tag);

					child_child_child_tag = www_tag_new(NULL, nodename);
					www_tag_add_child(child_child_tag, child_child_child_tag);

					snprintf(buffer, sizeof buffer, " - %s)", hdr->oaddress);
					child_child_tag = www_tag_new(NULL, buffer);
					www_tag_add_child(child_tag, child_child_tag);
				}
				free(nodename);
				free(nodeno);
			} else {
				snprintf(buffer, sizeof buffer, "From: %s (%s)", hdr->from, hdr->oaddress);
				child_child_tag = www_tag_new(NULL, buffer);
				www_tag_add_child(child_tag, child_child_tag);
			}
		} else {
			snprintf(buffer, sizeof buffer, "From: %s (%s)", hdr->from, hdr->oaddress);
			child_child_tag = www_tag_new(NULL, buffer);
			www_tag_add_child(child_tag, child_child_tag);
		}
	} else {
		snprintf(buffer, sizeof buffer, "From: %s", hdr->from);
		child_child_tag = www_tag_new(NULL, buffer);
		www_tag_add_child(child_tag, child_child_tag);
	}

	child_tag = www_tag_new("div", NULL);
	www_tag_add_attrib(child_tag, "class", "msg-view-to");
	www_tag_add_child(cur_tag, child_tag);

	if (mc->nettype == NETWORK_FIDO && ma->type == TYPE_NETMAIL_AREA && hdr->daddress != NULL) {
		nodeno = parse_fido_addr(hdr->daddress);
		if (nodeno != NULL) {
			nodename = nl_get_bbsname(nodeno, mc->domain);
			if (strcmp(nodename, "Unknown") == 0) {
				snprintf(buffer, sizeof buffer, "To: %s (%s)", hdr->to, hdr->daddress);
				child_child_tag = www_tag_new(NULL, buffer);
				www_tag_add_child(child_tag, child_child_tag);
			} else {
				snprintf(buffer, sizeof buffer, "To: %s (", hdr->to);
				child_child_tag = www_tag_new(NULL, buffer);
				www_tag_add_child(child_tag, child_child_tag);

				child_child_tag = www_tag_new("span", NULL);
				www_tag_add_attrib(child_child_tag, "class", "bbsname");
				www_tag_add_child(child_tag, child_child_tag);

				child_child_child_tag = www_tag_new(NULL, nodename);
				www_tag_add_child(child_child_tag, child_child_child_tag);

				snprintf(buffer, sizeof buffer, " - %s)", hdr->daddress);
				child_child_tag = www_tag_new(NULL, buffer);
				www_tag_add_child(child_tag, child_child_tag);
			}
			free(nodename);
			free(nodeno);
		} else {
			snprintf(buffer, sizeof buffer, "To: %s (%s)", hdr->to, hdr->daddress);
			child_child_tag = www_tag_new(NULL, buffer);
			www_tag_add_child(child_tag, child_child_tag);
		}
	} else {
		child_child_tag = www_tag_new(NULL, "To : ");
		www_tag_add_child(child_tag, child_child_tag);

		child_child_tag = www_tag_new(NULL, hdr->to);
		www_tag_add_child(child_tag, child_child_tag);
	}

	child_tag = www_tag_new("div", NULL);
	www_tag_add_attrib(child_tag, "class", "msg-view-date");
	www_tag_add_child(cur_tag, child_tag);

	date = (time_t)hdr->msgwritten;
	gmtime_r(&date, &msg_date);

	int offhour = hdr->tz_offset / 3600;
	int offmin = (hdr->tz_offset % 3600) / 60;

	if (conf.date_style == 1) {
		snprintf(buffer, sizeof buffer, "Date: %.2d:%.2d %.2d-%.2d-%.2d %c%02d:%02d",
		         msg_date.tm_hour, msg_date.tm_min, msg_date.tm_mon + 1, msg_date.tm_mday, msg_date.tm_year - 100, (offhour < 0 ? '-' : '+'), abs(offhour), offmin);
	} else {
		snprintf(buffer, sizeof buffer, "Date: %.2d:%.2d %.2d-%.2d-%.2d %c%02d:%02d",
		         msg_date.tm_hour, msg_date.tm_min, msg_date.tm_mday, msg_date.tm_mon + 1, msg_date.tm_year - 100, (offhour < 0 ? '-' : '+'), abs(offhour), offmin);
	}

	child_child_tag = www_tag_new(NULL, buffer);
	www_tag_add_child(child_tag, child_child_tag);

	child_tag = www_tag_new("div", NULL);
	www_tag_add_attrib(child_tag, "class", "msg-view-options");
	www_tag_add_child(cur_tag, child_tag);

	child_child_tag = www_tag_new("a", NULL);

	url = EMPTY_STRALLOC;

	stralloc_cats(&url, www_get_my_url(connection));
	stralloc_cats(&url, "msgs/flag/");
	stralloc_cat_long(&url, conference);
	stralloc_append1(&url, '/');
	stralloc_cat_long(&url, area);
	stralloc_append1(&url, '/');
	stralloc_cat_long(&url, msg);
	stralloc_0(&url);

	www_tag_add_attrib(child_child_tag, "href", url.s);
	free(url.s);
	www_tag_add_child(child_tag, child_child_tag);

	child_child_child_tag = www_tag_new("img", NULL);

	url = EMPTY_STRALLOC;

	stralloc_cats(&url, www_get_my_url(connection));
	stralloc_cats(&url, "static/flag.png");
	stralloc_0(&url);
	www_tag_add_attrib(child_child_child_tag, "src", url.s);
	free(url.s);
	www_tag_add_child(child_child_tag, child_child_child_tag);

	if (hdr->prev_msg_no != 0) {

		child_child_tag = www_tag_new("a", NULL);

		url = EMPTY_STRALLOC;

		stralloc_cats(&url, www_get_my_url(connection));
		stralloc_cats(&url, "msgs/");
		stralloc_cat_long(&url, conference);
		stralloc_append1(&url, '/');
		stralloc_cat_long(&url, area);
		stralloc_append1(&url, '/');
		stralloc_cat_long(&url, hdr->prev_msg_no);
		stralloc_0(&url);

		www_tag_add_attrib(child_child_tag, "href", url.s);
		free(url.s);
		www_tag_add_child(child_tag, child_child_tag);

		child_child_child_tag = www_tag_new("img", NULL);

		url = EMPTY_STRALLOC;

		stralloc_cats(&url, www_get_my_url(connection));
		stralloc_cats(&url, "static/back.png");
		stralloc_0(&url);
		www_tag_add_attrib(child_child_child_tag, "src", url.s);
		free(url.s);
		www_tag_add_child(child_child_tag, child_child_child_tag);
	}


	if (hdr->next_msg_no != 0) {

		child_child_tag = www_tag_new("a", NULL);

		url = EMPTY_STRALLOC;

		stralloc_cats(&url, www_get_my_url(connection));
		stralloc_cats(&url, "msgs/");
		stralloc_cat_long(&url, conference);
		stralloc_append1(&url, '/');
		stralloc_cat_long(&url, area);
		stralloc_append1(&url, '/');
		stralloc_cat_long(&url, hdr->next_msg_no);
		stralloc_0(&url);

		www_tag_add_attrib(child_child_tag, "href", url.s);
		free(url.s);
		www_tag_add_child(child_tag, child_child_tag);

		child_child_child_tag = www_tag_new("img", NULL);

		url = EMPTY_STRALLOC;

		stralloc_cats(&url, www_get_my_url(connection));
		stralloc_cats(&url, "static/forward.png");
		stralloc_0(&url);
		www_tag_add_attrib(child_child_child_tag, "src", url.s);
		free(url.s);
		www_tag_add_child(child_child_tag, child_child_child_tag);
	}

	cur_tag = www_tag_new("div", NULL);

	www_tag_add_attrib(cur_tag, "id", "msgbody");
	www_tag_add_child(page, cur_tag);

	if (hdr->isutf8) {
		// convert body to cp437
		body2 = malloz(strlen(body) + 1);
		ic = iconv_open("CP437//TRANSLIT", "UTF-8");

		size_t inc = strlen(body);
		size_t ouc = strlen(body);

		char *inbuf = body;
		char *oubuf = body2;

		if (ic != -1) {
			if (iconv(ic, &inbuf, &inc, &oubuf, &ouc) == -1) {
				strcpy(oubuf, inbuf);
			}
			free(body);
			body = body2;
			iconv_close(ic);
		} else {
			free(body2);
		}
	}

	aha_text = strdup(body);
	aha(aha_text, cur_tag, user->dopipe);
	free(aha_text);

	if (ma->write_sec_level <= user->sec_level && ma->type != TYPE_NETMAIL_AREA) {
		cur_tag = www_tag_new("div", NULL);
		www_tag_add_attrib(cur_tag, "class", "msg-reply-form");
		www_tag_add_child(page, cur_tag);

		child_tag = www_tag_new("h3", NULL);
		www_tag_add_child(cur_tag, child_tag);

		child_child_tag = www_tag_new(NULL, "Reply");
		www_tag_add_child(child_tag, child_child_tag);

		child_tag = www_tag_new("form", NULL);
		url = EMPTY_STRALLOC;
		stralloc_cats(&url, www_get_my_url(connection));
		stralloc_cats(&url, "msgs/");
		stralloc_0(&url);

		www_tag_add_attrib(child_tag, "action", url.s);
		free(url.s);

		www_tag_add_attrib(child_tag, "method", "POST");
		www_tag_add_attrib(child_tag, "enctype", "application/x-www-form-urlencoded;charset=UTF-8");
		www_tag_add_child(cur_tag, child_tag);

		child_child_tag = www_tag_new("input", NULL);
		www_tag_add_attrib(child_child_tag, "type", "hidden");
		www_tag_add_attrib(child_child_tag, "name", "conference");
		snprintf(buffer, sizeof buffer, "%d", conference);
		www_tag_add_attrib(child_child_tag, "value", buffer);
		www_tag_add_child(child_tag, child_child_tag);

		child_child_tag = www_tag_new("input", NULL);
		www_tag_add_attrib(child_child_tag, "type", "hidden");
		www_tag_add_attrib(child_child_tag, "name", "area");
		snprintf(buffer, sizeof buffer, "%d", area);
		www_tag_add_attrib(child_child_tag, "value", buffer);
		www_tag_add_child(child_tag, child_child_tag);

		child_child_tag = www_tag_new("input", NULL);
		www_tag_add_attrib(child_child_tag, "type", "hidden");
		www_tag_add_attrib(child_child_tag, "name", "replyid");

		snprintf(buffer, sizeof buffer, "%d", msg);
		www_tag_add_attrib(child_child_tag, "value", buffer);

		www_tag_add_child(child_tag, child_child_tag);

		child_child_tag = www_tag_new(NULL, "To : ");
		www_tag_add_child(child_tag, child_child_tag);

		child_child_tag = www_tag_new("input", NULL);
		www_tag_add_attrib(child_child_tag, "type", "text");
		www_tag_add_attrib(child_child_tag, "name", "recipient");
		www_tag_add_attrib(child_child_tag, "value", hdr->from);
		www_tag_add_child(child_tag, child_child_tag);

		child_child_tag = www_tag_new("br", NULL);
		www_tag_add_child(child_tag, child_child_tag);

		child_child_tag = www_tag_new(NULL, "Subject : ");
		www_tag_add_child(child_tag, child_child_tag);

		child_child_tag = www_tag_new("input", NULL);
		www_tag_add_attrib(child_child_tag, "type", "text");
		www_tag_add_attrib(child_child_tag, "name", "subject");

		if (strncasecmp(hdr->subject, "re:", 3) != 0) {
			snprintf(buffer, sizeof buffer, "RE: %s", hdr->subject);
			www_tag_add_attrib(child_child_tag, "value", buffer);
		} else {
			www_tag_add_attrib(child_child_tag, "value", hdr->subject);
		}

		www_tag_add_child(child_tag, child_child_tag);

		child_child_tag = www_tag_new("br", NULL);
		www_tag_add_child(child_tag, child_child_tag);

		child_child_tag = www_tag_new("textarea", NULL);
		www_tag_add_attrib(child_child_tag, "name", "body");
		www_tag_add_attrib(child_child_tag, "rows", "25");
		www_tag_add_attrib(child_child_tag, "cols", "79");
		www_tag_add_attrib(child_child_tag, "wrap", "soft");
		www_tag_add_attrib(child_child_tag, "id", "replybody");
		www_tag_add_child(child_tag, child_child_tag);

		int rlen;

		unmangle_ansi(body, strlen(body), &replybody, &rlen, user->dopipe);
		free(body);

		// ADD THIS LINE: Manually null-terminate the new buffer
		replybody[rlen] = '\0'; 

		body = replybody;
		replybody = (char *)malloz(strlen(body) + 1); 

		l2 = 0;
		for (l1 = 0; l1 < strlen(body); l1++) {
			if (body[l1] == '\e' && body[l1 + 1] == '[') {
				while (strchr("ABCDEFGHIGJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", body[l1]) == NULL && l1 < strlen(body))
					l1++;
			} else {
				if (isalnum(body[l1]) || isspace(body[l1]) || ispunct(body[l1])) {
					replybody[l2++] = body[l1];
				} else {
					replybody[l2++] = '?';
				}
				replybody[l2] = '\0';
			}
		}

		free(body);
		chars = 0;

		char initial2;

		if (strchr(hdr->from, ' ') != NULL) {
			initial2 = *(strchr(hdr->from, ' ') + 1);
		} else {
			initial2 = hdr->from[1];
		}

		if (initial2 == '\0') {
			initial2 = hdr->from[0];
		}



		body = wrap_quotes(replybody, hdr->from[0], initial2);

		child_child_child_tag = www_tag_new(NULL, body);
		www_tag_add_child(child_child_tag, child_child_child_tag);

		child_child_tag = www_tag_new("br", NULL);
		www_tag_add_child(child_tag, child_child_tag);

		child_child_tag = www_tag_new("input", NULL);
		www_tag_add_attrib(child_child_tag, "type", "submit");
		www_tag_add_attrib(child_child_tag, "name", "submit");
		www_tag_add_attrib(child_child_tag, "value", "Reply");
		www_tag_add_child(child_tag, child_child_tag);
		child_child_tag = www_tag_new("br", NULL);
		www_tag_add_child(child_tag, child_child_tag);
	}
/*	free(body); */
        // Clean up the main buffers
        if (body)      free(body);
        if (body2)     free(body2);     // <--- ADD THIS (Plugs the malloz leak)
/*        if (replybody) free(replybody); // <--- ADD THIS (Plugs the malloz leak) = valgrind said duplicate */

        if (hdr) free_message_hdr(hdr);
/*	free_message_hdr(hdr); */

/*	return www_tag_unwravel(page);  */
        // Convert the tag tree to HTML string
        char *final_html = www_tag_unwravel(page);
        // Destroy the entire tag tree (page and all children)
	www_tag_destroy(page); 
	return final_html;
}

static char *www_wordwrap(char *content, int cutoff) {
	int len = strlen(content);
	int i;
	int line_count = 0;
	char *last_space = NULL;
	char *ret;
	int at = 0;
	int extra = 0;
	int quote_line = 0;
	int z;

	for (i = 0; i < len; i++) {
		if (content[i] == '\n') {
			continue;
		}
		content[at++] = content[i];
	}

	content[at] = '\0';
	at = 0;
	len = strlen(content);

	for (i = 0; i < len - 1; i++) {
		if (content[i] == '>' && line_count < 4) {
			quote_line = 1;
		}

		if (content[i] == '\r' && content[i + 1] != '\r') {
			if (content[i + 1] == ' ' && quote_line != 1) {
				content[at++] = '\r';
				line_count = 0;
				quote_line = 0;
			} else if (quote_line != 1) {
				for (z = i + 1; content[z] != ' ' && z < len; z++)
					;
				if (at > 0 && content[at - 1] != '\r' && content[at - 1] != ' ' && cutoff - line_count < z - i) {
					content[at++] = ' ';
					line_count++;
				} else {
					content[at++] = '\r';
					line_count = 0;
					quote_line = 0;
				}
			} else if (quote_line == 1) {
				content[at++] = '\r';
				line_count = 0;
				quote_line = 0;
			}
		} else if (i < len - 2 && content[i] == '\r' && content[i + 1] == '\r') {
			content[at++] = '\r';
			content[at++] = '\r';
			line_count = 0;
			quote_line = 0;
			i++;
		} else {
			content[at++] = content[i];
			line_count++;
		}
	}
	content[at++] = content[i];
	content[at] = '\0';

	at = 0;

	len = strlen(content);
	ret = (char *)malloz(len + 1);

	line_count = 0;
	quote_line = 0;

	for (i = 0; i < len; i++) {
		if (content[i] != '\r') {
			ret[at] = content[i];
			if (content[i] == ' ') {
				last_space = &ret[at];
			}
			at++;
			if (content[i] == '>' && line_count < 4) {
				quote_line = 1;
			}
		} else {
			ret[at++] = content[i];
		}
		ret[at] = '\0';

		if (content[i] == '\r') {
			line_count = 0;
			last_space = NULL;
			quote_line = 0;
		} else if (line_count == cutoff && !quote_line) {
			// wrap
			if (last_space != NULL) {
				*last_space = '\r';
				line_count = strlen(&last_space[1]);
				last_space = NULL;
				quote_line = 0;
			} else {
				extra++;
				ret = (char *)realloc(ret, strlen(content) + extra + 1);
				if (ret == NULL) {
					return NULL;
				}
				ret[at++] = '\r';
				ret[at] = '\0';
				last_space = NULL;
				line_count = 0;
				quote_line = 0;
			}
		} else {
			line_count++;
		}
	}
	return ret;
}

char *www_sent_msg_page(struct MHD_Connection *connection, int conference, int area) {
	struct www_tag *page;
	struct www_tag *cur_tag;
	struct www_tag *child_tag;
	struct www_tag *child_child_tag;
	struct www_tag *child_child_child_tag;
	stralloc str = EMPTY_STRALLOC;

	page = www_tag_new(NULL, "");
	cur_tag = www_tag_new("h2", NULL);
	www_tag_add_child(page, cur_tag);
	child_tag = www_tag_new(NULL, "Message Sent");
	www_tag_add_child(cur_tag, child_tag);

	cur_tag = www_tag_new("a", NULL);

	stralloc_cats(&str, www_get_my_url(connection));
	stralloc_cats(&str, "msgs/");
	stralloc_cat_long(&str, conference);
	stralloc_append1(&str, '/');
	stralloc_cat_long(&str, area);
	stralloc_append1(&str, '/');
	stralloc_0(&str);

	www_tag_add_attrib(cur_tag, "href", str.s);
	free(str.s);

	www_tag_add_child(page, cur_tag);

	str = EMPTY_STRALLOC;
	stralloc_cats(&str, "Back to ");
	stralloc_cats(&str, get_conf(conference)->name);
	stralloc_cats(&str, " -> ");
	stralloc_cats(&str, get_area(conference, area)->name);
	stralloc_0(&str);

	child_tag = www_tag_new(NULL, str.s);
	free(str.s);

	www_tag_add_child(cur_tag, child_tag);

	return www_tag_unwravel(page);
}

int www_send_msg(struct user_record *user, char *to, char *subj, int conference, int area, int replyid, char *body) {
	struct msg_base_t *mb;

	int z;
	int sem_fd;
	char *page;
	int max_len;
	int len;
	char buffer[256];
	char qwkuuid[38];
	char *body2;
	char *tagline;
	struct utsname name;
	char *body3;
	struct msg_t *rmsg;

	iconv_t ic;
	size_t inc;
	size_t ouc;
	size_t sz;
	char *inbuf, *oubuf;

	uuid_t magi_msgid, qwk_msgid;

	if (subj == NULL || to == NULL || body == NULL) {
		return 0;
	}

	if (conference < 0 || conference >= ptr_vector_len(&conf.mail_conferences))
		return 0;
	struct mail_conference *mc = get_conf(conference);
	if (area < 0 || area >= ptr_vector_len(&mc->mail_areas))
		return 0;
	struct mail_area *ma = get_area(conference, area);

	if (ma->type == TYPE_LOCAL_AREA && (strcasecmp(to, "all") != 0 && check_user(to) && check_fullname_j(to))) {
		return 0;
	}

	if (ma->write_sec_level <= user->sec_level && ma->type != TYPE_NETMAIL_AREA) {
		mb = open_message_base(conference, area);
		if (!mb) {
			return 0;
		}

		tagline = conf.default_tagline;
		if (mc->tagline != NULL) {
			tagline = mc->tagline;
		}

		uname(&name);

		if (mc->nettype == NETWORK_FIDO) {
			if (mc->fidoaddr->point == 0) {
				snprintf(buffer, sizeof buffer, "\r\r--- MagickaBBS v%d.%d%s (%s/%s)\r * Origin: %s (%d:%d/%d)\r",
				         VERSION_MAJOR, VERSION_MINOR, VERSION_STR, name.sysname, name.machine, tagline,
				         mc->fidoaddr->zone, mc->fidoaddr->net, mc->fidoaddr->node);
			} else {
				snprintf(buffer, sizeof buffer, "\r\r--- MagickaBBS v%d.%d%s (%s/%s)\r * Origin: %s (%d:%d/%d.%d)\r",
				         VERSION_MAJOR, VERSION_MINOR, VERSION_STR, name.sysname, name.machine, tagline,
				         mc->fidoaddr->zone, mc->fidoaddr->net, mc->fidoaddr->node, mc->fidoaddr->point);
			}
		} else if (mc->nettype == NETWORK_MAGI) {
			snprintf(buffer, sizeof buffer, "\r\r--- MagickaBBS v%d.%d%s (%s/%s)\r * Origin: %s (@%d)\r",
			         VERSION_MAJOR, VERSION_MINOR, VERSION_STR, name.sysname, name.machine, tagline, mc->maginode);
		} else if (mc->nettype == NETWORK_QWK) {
			snprintf(buffer, sizeof buffer, "\r\r---\r * MagickaBBS * %s\r",
			         tagline);
		} else {
			snprintf(buffer, sizeof buffer, "\r");
		}

		char *p = body;
		stralloc unhtmlized = EMPTY_STRALLOC;

		// remove nbsp
		while (*p != '\0') {
			if ((*p & 0xff) == 0xc2 && (*(p + 1) & 0xff) == 0xa0) {
				stralloc_append1(&unhtmlized, ' ');
				p++;
			} else {
				stralloc_append1(&unhtmlized, *p);
			}

			p++;
		}

		stralloc_0(&unhtmlized);

		body2 = www_wordwrap(unhtmlized.s, 72);
		free(unhtmlized.s);
		if (body2 == NULL) {
			close_message_base(mb);
			return 0;
		}

		body3 = str2dup(body2, buffer);
		if (body3 == NULL) {
			free(body2);
			close_message_base(mb);
			return 0;
		}

		free(body2);
		body2 = (char *)malloz(strlen(body3) + 1);

// openindiana does not support TRANSLIT
		ic = iconv_open("CP437//IGNORE//TRANSLIT", "UTF-8");

		inc = strlen(body3);
		ouc = strlen(body3);

		inbuf = body3;
		oubuf = body2;

		if (ic != -1) {
			sz = iconv(ic, &inbuf, &inc, &oubuf, &ouc);
			free(body3);
		} else {
			body2 = body3;
		}

		if (ma->realnames == 0) {
			strlcpy(buffer, user->loginname, sizeof buffer);
		} else {
			snprintf(buffer, sizeof buffer, "%s %s", user->firstname, user->lastname);
		}

		if (replyid != -1) {
			rmsg = load_message_hdr(mb, replyid);
		} else {
			rmsg = NULL;
		}

		if (!write_message(mb, to, buffer, subj, body2, NULL, rmsg, NULL, 1)) {
			free(body2);
			close_message_base(mb);
			if (ic != -1) {
				iconv_close(ic);
			}
			return 0;
		}

		free(body2);
		close_message_base(mb);
		if (ic != -1) {
			iconv_close(ic);
		}
		return 1;
	}
	return 0;
}

char *www_new_msg(struct MHD_Connection *connection, struct user_record *user, int conference, int area) {
	struct www_tag *page = www_tag_new(NULL, "");
	struct www_tag *cur_tag;
	struct www_tag *child_tag;
	struct www_tag *child_child_tag;

	char buffer[10];

	cur_tag = www_tag_new("div", NULL);
	www_tag_add_attrib(cur_tag, "class", "content-header");
	www_tag_add_child(page, cur_tag);

	child_tag = www_tag_new("h2", NULL);
	www_tag_add_child(cur_tag, child_tag);

	child_child_tag = www_tag_new(NULL, "New Message");
	www_tag_add_child(child_tag, child_child_tag);

	cur_tag = www_tag_new("form", NULL);

	stralloc url = EMPTY_STRALLOC;

	stralloc_cats(&url, www_get_my_url(connection));
	stralloc_cats(&url, "msgs/");
	stralloc_0(&url);

	www_tag_add_attrib(cur_tag, "action", url.s);
	free(url.s);

	www_tag_add_attrib(cur_tag, "method", "POST");
	www_tag_add_attrib(cur_tag, "onsubmit", "return validate()");
	www_tag_add_attrib(cur_tag, "enctype", "application/x-www-form-urlencoded;charset=UTF-8");
	www_tag_add_child(page, cur_tag);

	child_tag = www_tag_new("input", NULL);
	www_tag_add_attrib(child_tag, "type", "hidden");
	www_tag_add_attrib(child_tag, "name", "conference");
	snprintf(buffer, sizeof buffer, "%d", conference);
	www_tag_add_attrib(child_tag, "value", buffer);
	www_tag_add_child(cur_tag, child_tag);

	child_tag = www_tag_new("input", NULL);
	www_tag_add_attrib(child_tag, "type", "hidden");
	www_tag_add_attrib(child_tag, "name", "area");
	snprintf(buffer, sizeof buffer, "%d", area);
	www_tag_add_attrib(child_tag, "value", buffer);
	www_tag_add_child(cur_tag, child_tag);

	child_tag = www_tag_new("input", NULL);
	www_tag_add_attrib(child_tag, "type", "hidden");
	www_tag_add_attrib(child_tag, "name", "replyid");
	www_tag_add_attrib(child_tag, "value", "NULL");
	www_tag_add_child(cur_tag, child_tag);

	child_tag = www_tag_new(NULL, "To : ");
	www_tag_add_child(cur_tag, child_tag);

	child_tag = www_tag_new("input", NULL);
	www_tag_add_attrib(child_tag, "type", "text");
	www_tag_add_attrib(child_tag, "name", "recipient");
	www_tag_add_attrib(child_tag, "value", "All");
	www_tag_add_attrib(child_tag, "id", "recipient");
	www_tag_add_child(cur_tag, child_tag);

	child_tag = www_tag_new("br", NULL);
	www_tag_add_child(cur_tag, child_tag);

	child_tag = www_tag_new(NULL, "Subject : ");
	www_tag_add_child(cur_tag, child_tag);

	child_tag = www_tag_new("input", NULL);
	www_tag_add_attrib(child_tag, "type", "text");
	www_tag_add_attrib(child_tag, "name", "subject");
	www_tag_add_attrib(child_tag, "id", "subject");
	www_tag_add_child(cur_tag, child_tag);

	child_tag = www_tag_new("br", NULL);
	www_tag_add_child(cur_tag, child_tag);

	child_tag = www_tag_new("textarea", NULL);
	www_tag_add_attrib(child_tag, "name", "body");
	www_tag_add_attrib(child_tag, "id", "body");
	www_tag_add_attrib(child_tag, "rows", "25");
	www_tag_add_attrib(child_tag, "cols", "79");
	www_tag_add_attrib(child_tag, "wrap", "soft");
	www_tag_add_child(cur_tag, child_tag);

	child_child_tag = www_tag_new(NULL, "");
	www_tag_add_child(child_tag, child_child_tag);

	child_tag = www_tag_new("br", NULL);
	www_tag_add_child(cur_tag, child_tag);

	child_tag = www_tag_new("input", NULL);
	www_tag_add_attrib(child_tag, "type", "submit");
	www_tag_add_attrib(child_tag, "name", "submit");
	www_tag_add_attrib(child_tag, "value", "Send");
	www_tag_add_child(cur_tag, child_tag);

	child_tag = www_tag_new("br", NULL);
	www_tag_add_child(cur_tag, child_tag);

	return www_tag_unwravel(page);
}

#endif
