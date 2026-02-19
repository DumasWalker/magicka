#if defined(ENABLE_WWW)

#include <string.h>
#include <sqlite3.h>
#include <time.h>
#include <stdlib.h>
#include <sys/utsname.h>
#include "www_tree.h"
#include "bbs.h"

extern struct bbs_config conf;
extern struct www_tag *aha(char *input, struct www_tag *parent);

int www_email_delete(struct MHD_Connection *connection, struct user_record *user, int id) {
	char buffer[PATH_MAX];
	sqlite3 *db;
	sqlite3_stmt *res;
	int rc;
	char *csql = "CREATE TABLE IF NOT EXISTS email ("
	             "id INTEGER PRIMARY KEY,"
	             "sender TEXT COLLATE NOCASE,"
	             "recipient TEXT COLLATE NOCASE,"
	             "subject TEXT,"
	             "body TEXT,"
	             "date INTEGER,"
	             "seen INTEGER);";
	char *dsql = "DELETE FROM email WHERE id=? AND recipient LIKE ?";
	char *err_msg = 0;

	snprintf(buffer, sizeof buffer, "%s/email.sq3", conf.bbs_path);

	rc = sqlite3_open(buffer, &db);
	if (rc != SQLITE_OK) {
		sqlite3_close(db);

		return 0;
	}
	sqlite3_busy_timeout(db, 5000);
	rc = sqlite3_exec(db, csql, 0, 0, &err_msg);
	if (rc != SQLITE_OK) {
		sqlite3_free(err_msg);
		sqlite3_close(db);

		return 0;
	}

	rc = sqlite3_prepare_v2(db, dsql, -1, &res, 0);

	if (rc == SQLITE_OK) {
		sqlite3_bind_int(res, 1, id);
		sqlite3_bind_text(res, 2, user->loginname, -1, 0);
	} else {
		sqlite3_finalize(res);
		sqlite3_close(db);
		return 0;
	}
	sqlite3_step(res);

	sqlite3_finalize(res);
	sqlite3_close(db);
	return 1;
}

int www_send_email(struct user_record *user, char *recipient, char *subject, char *ibody) {
	char pathbuf[PATH_MAX];
	sqlite3 *db;
	sqlite3_stmt *res;
	int rc;
	char *csql = "CREATE TABLE IF NOT EXISTS email ("
	             "id INTEGER PRIMARY KEY,"
	             "sender TEXT COLLATE NOCASE,"
	             "recipient TEXT COLLATE NOCASE,"
	             "subject TEXT,"
	             "body TEXT,"
	             "date INTEGER,"
	             "seen INTEGER);";
	char *isql = "INSERT INTO email (sender, recipient, subject, body, date, seen) VALUES(?, ?, ?, ?, ?, 0)";
	char *err_msg = 0;
	stralloc sa = EMPTY_STRALLOC;
	char *body = NULL;
	struct utsname name;

	if (recipient == NULL || subject == NULL || ibody == NULL) {
		return 0;
	}

	if (check_user(recipient)) {
		return 0;
	}

	uname(&name);

	for (char *p = ibody; *p != '\0'; ++p) {
		if ((*p & 0xff) == 0xc2 && (*(p + 1) & 0xff) == 0xa0) {
			stralloc_append1(&sa, ' ');
			p++;
		} else if (*p != '\n') {
			stralloc_append1(&sa, *p);
		}
	}
	stralloc_append1(&sa, '\r');
	stralloc_0(&sa);
	body = sa.s;

	snprintf(pathbuf, sizeof pathbuf, "%s/email.sq3", conf.bbs_path);
	rc = sqlite3_open(pathbuf, &db);
	if (rc != SQLITE_OK) {
		sqlite3_close(db);
		free(body);
		return 0;
	}

	sqlite3_busy_timeout(db, 5000);
	rc = sqlite3_exec(db, csql, 0, 0, &err_msg);
	if (rc != SQLITE_OK) {
		sqlite3_free(err_msg);
		sqlite3_close(db);
		free(body);
		return 0;
	}

	rc = sqlite3_prepare_v2(db, isql, -1, &res, 0);
	if (rc != SQLITE_OK) {
		sqlite3_finalize(res);
		sqlite3_close(db);
		free(body);
		return 0;
	}
	sqlite3_bind_text(res, 1, user->loginname, -1, 0);
	sqlite3_bind_text(res, 2, recipient, -1, 0);
	sqlite3_bind_text(res, 3, subject, -1, 0);
	sqlite3_bind_text(res, 4, body, -1, 0);
	sqlite3_bind_int(res, 5, time(NULL));
	sqlite3_step(res);

	sqlite3_finalize(res);
	sqlite3_close(db);
	free(body);

	return 1;
}

char *www_new_email(struct MHD_Connection *connection) {
	struct www_tag *page = www_tag_new(NULL, "");
	struct www_tag *cur_tag;
	struct www_tag *child_tag;
	struct www_tag *child_child_tag;

	cur_tag = www_tag_new("div", NULL);
	www_tag_add_attrib(cur_tag, "class", "content-header");
	www_tag_add_child(page, cur_tag);

	child_tag = www_tag_new("h2", NULL);
	www_tag_add_child(cur_tag, child_tag);

	child_child_tag = www_tag_new(NULL, "New Email");
	www_tag_add_child(child_tag, child_child_tag);

	cur_tag = www_tag_new("form", NULL);

	stralloc url = EMPTY_STRALLOC;

	stralloc_cats(&url, www_get_my_url(connection));
	stralloc_cats(&url, "email/");
	stralloc_0(&url);

	www_tag_add_attrib(cur_tag, "action", url.s);
	free(url.s);

	www_tag_add_attrib(cur_tag, "method", "POST");
	www_tag_add_attrib(cur_tag, "onsubmit", "return validate()");
	www_tag_add_attrib(cur_tag, "enctype", "application/x-www-form-urlencoded");
	www_tag_add_child(page, cur_tag);

	child_tag = www_tag_new(NULL, "To : ");
	www_tag_add_child(cur_tag, child_tag);

	child_tag = www_tag_new("input", NULL);
	www_tag_add_attrib(child_tag, "type", "text");
	www_tag_add_attrib(child_tag, "name", "recipient");
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
	www_tag_add_attrib(child_tag, "wrap", "hard");
	www_tag_add_attrib(child_tag, "rows", "25");
	www_tag_add_attrib(child_tag, "cols", "79");
	www_tag_add_attrib(child_tag, "id", "body");
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

char *www_email_display(struct MHD_Connection *connection, struct user_record *user, int email) {
	struct www_tag *page;
	struct www_tag *cur_tag;
	struct www_tag *child_tag;
	struct www_tag *child_child_tag;
	struct www_tag *child_child_child_tag;
	char pathbuf[PATH_MAX];
	char datebuf[32];
	sqlite3 *db;
	sqlite3_stmt *res;
	int rc;
	struct tm msg_date;
	time_t date;
	char *from;
	char *subject;
	char *body;
	int id;
	int i;
	int chars;
	char *err_msg = 0;
	char *email_create_sql = "CREATE TABLE IF NOT EXISTS email ("
	                         "id INTEGER PRIMARY KEY,"
	                         "sender TEXT COLLATE NOCASE,"
	                         "recipient TEXT COLLATE NOCASE,"
	                         "subject TEXT,"
	                         "body TEXT,"
	                         "date INTEGER,"
	                         "seen INTEGER);";
	char *email_show_sql = "SELECT id,sender,subject,body,date FROM email WHERE recipient LIKE ? LIMIT ?, 1";

	char *update_seen_sql = "UPDATE email SET seen=1 WHERE id=?";

	snprintf(pathbuf, sizeof pathbuf, "%s/email.sq3", conf.bbs_path);
	rc = sqlite3_open(pathbuf, &db);
	if (rc != SQLITE_OK) {
		sqlite3_close(db);
		return NULL;
	}
	sqlite3_busy_timeout(db, 5000);
	rc = sqlite3_exec(db, email_create_sql, 0, 0, &err_msg);
	if (rc != SQLITE_OK) {
		sqlite3_free(err_msg);
		sqlite3_close(db);
		return NULL;
	}

	rc = sqlite3_prepare_v2(db, email_show_sql, -1, &res, 0);

	if (rc != SQLITE_OK) {
		sqlite3_finalize(res);
		sqlite3_close(db);
		return NULL;
	}
	sqlite3_bind_text(res, 1, user->loginname, -1, 0);
	sqlite3_bind_int(res, 2, email - 1);

	if (sqlite3_step(res) != SQLITE_ROW) {
		page = www_tag_new(NULL, "");

		cur_tag = www_tag_new("div", NULL);
		www_tag_add_attrib(cur_tag, "class", "content-header");
		www_tag_add_child(page, cur_tag);

		child_tag = www_tag_new("h2", NULL);
		www_tag_add_child(cur_tag, child_tag);

		child_child_tag = www_tag_new(NULL, "No such email!");
		www_tag_add_child(child_tag, child_child_tag);

		return www_tag_unwravel(page);
	}
	id = sqlite3_column_int(res, 0);
	from = (char *)sqlite3_column_text(res, 1);
	subject = (char *)sqlite3_column_text(res, 2);
	body = (char *)sqlite3_column_text(res, 3);
	date = (time_t)sqlite3_column_int(res, 4);
	localtime_r(&date, &msg_date);

	page = www_tag_new(NULL, "");

	cur_tag = www_tag_new("div", NULL);
	www_tag_add_attrib(cur_tag, "class", "content-header");
	www_tag_add_child(page, cur_tag);

	child_tag = www_tag_new("h2", NULL);
	www_tag_add_child(cur_tag, child_tag);

	child_child_tag = www_tag_new(NULL, "Your Email");
	www_tag_add_child(child_tag, child_child_tag);

	cur_tag = www_tag_new("div", NULL);
	www_tag_add_attrib(cur_tag, "class", "email-view-header");
	www_tag_add_child(page, cur_tag);

	child_tag = www_tag_new("div", NULL);
	www_tag_add_attrib(child_tag, "class", "email-view-subject");
	www_tag_add_child(cur_tag, child_tag);

	child_child_tag = www_tag_new(NULL, subject);
	www_tag_add_child(child_tag, child_child_tag);

	child_tag = www_tag_new("div", NULL);
	www_tag_add_attrib(child_tag, "class", "email-view-from");
	www_tag_add_child(cur_tag, child_tag);

	child_child_tag = www_tag_new(NULL, from);
	www_tag_add_child(child_tag, child_child_tag);

	child_tag = www_tag_new("div", NULL);
	www_tag_add_attrib(child_tag, "class", "email-view-date");
	www_tag_add_child(cur_tag, child_tag);

	child_child_tag = www_tag_new(NULL, "Date: ");
	www_tag_add_child(child_tag, child_child_tag);

	if (conf.date_style == 1)
		strftime(datebuf, sizeof datebuf, "%H:%M %m-%d-%y", &msg_date);
	else
		strftime(datebuf, sizeof datebuf, "%H:%M %d-%m-%y", &msg_date);

	child_child_tag = www_tag_new(NULL, datebuf);
	www_tag_add_child(child_tag, child_child_tag);

	cur_tag = www_tag_new("div", NULL);
	www_tag_add_attrib(cur_tag, "id", "msgbody");
	www_tag_add_child(page, cur_tag);

	aha(body, cur_tag);

	cur_tag = www_tag_new("div", NULL);
	www_tag_add_attrib(cur_tag, "class", "email-reply-form");
	www_tag_add_child(page, cur_tag);

	child_tag = www_tag_new("h3", NULL);
	www_tag_add_child(cur_tag, child_tag);

	child_child_tag = www_tag_new(NULL, "Reply");
	www_tag_add_child(child_tag, child_child_tag);

	child_tag = www_tag_new("form", NULL);

	stralloc url = EMPTY_STRALLOC;

	stralloc_cats(&url, www_get_my_url(connection));
	stralloc_cats(&url, "email/");
	stralloc_0(&url);

	www_tag_add_attrib(child_tag, "action", url.s);
	free(url.s);

	www_tag_add_attrib(child_tag, "method", "POST");
	www_tag_add_attrib(child_tag, "enctype", "application/x-www-form-urlencoded");
	www_tag_add_child(cur_tag, child_tag);

	child_child_tag = www_tag_new("input", NULL);
	www_tag_add_attrib(child_child_tag, "type", "hidden");
	www_tag_add_attrib(child_child_tag, "name", "recipient");
	www_tag_add_attrib(child_child_tag, "value", from);
	www_tag_add_child(child_tag, child_child_tag);

	child_child_tag = www_tag_new(NULL, "Subject : ");
	www_tag_add_child(child_tag, child_child_tag);

	child_child_tag = www_tag_new("input", NULL);
	www_tag_add_attrib(child_child_tag, "type", "text");
	www_tag_add_attrib(child_child_tag, "name", "subject");

	stralloc subj = EMPTY_STRALLOC;

	if (strncasecmp(subject, "re:", 3) != 0)
		stralloc_cats(&subj, "RE: ");
	stralloc_cats(&subj, subject);
	stralloc_0(&subj);
	www_tag_add_attrib(child_child_tag, "value", subj.s);
	free(subj.s);

	www_tag_add_child(child_tag, child_child_tag);

	child_child_tag = www_tag_new("br", NULL);
	www_tag_add_child(child_tag, child_child_tag);

	child_child_tag = www_tag_new("textarea", NULL);
	www_tag_add_attrib(child_child_tag, "name", "body");
	www_tag_add_attrib(child_child_tag, "wrap", "hard");
	www_tag_add_attrib(child_child_tag, "rows", "25");
	www_tag_add_attrib(child_child_tag, "cols", "79");
	www_tag_add_attrib(child_child_tag, "id", "replybody");
	www_tag_add_child(child_tag, child_child_tag);

	stralloc content = EMPTY_STRALLOC;

	stralloc_cats(&content, from);
	stralloc_cats(&content, " said....\n\n");
	stralloc_cats(&content, "> ");
	size_t column = 0;
	for (char *p = body; *p != '\0'; ++p) {
		if (*p == '\r') {
			stralloc_cats(&content, "\n> ");
			column = 0;
			continue;
		} else if (column >= 78) {
			stralloc_cats(&content, "\n> ");
			column = 0;
		}
		stralloc_append1(&content, *p);
		++column;
	}

	stralloc_0(&content);

	child_child_child_tag = www_tag_new(NULL, content.s);
	free(content.s);

	www_tag_add_child(child_child_tag, child_child_child_tag);

	child_child_tag = www_tag_new("br", NULL);
	www_tag_add_child(child_tag, child_child_tag);

	child_child_tag = www_tag_new("input", NULL);
	www_tag_add_attrib(child_child_tag, "type", "submit");
	www_tag_add_attrib(child_child_tag, "name", "submit");
	www_tag_add_attrib(child_child_tag, "value", "reply");
	www_tag_add_child(child_tag, child_child_tag);

	child_child_tag = www_tag_new("br", NULL);
	www_tag_add_child(child_tag, child_child_tag);

	sqlite3_finalize(res);
	rc = sqlite3_prepare_v2(db, update_seen_sql, -1, &res, 0);
	if (rc != SQLITE_OK) {
		sqlite3_finalize(res);
		sqlite3_close(db);
		www_tag_destroy(page);
		return NULL;
	}
	sqlite3_bind_int(res, 1, id);
	sqlite3_step(res);
	sqlite3_finalize(res);
	sqlite3_close(db);

	return www_tag_unwravel(page);
}

char *www_email_summary(struct MHD_Connection *connection, struct user_record *user) {
	struct www_tag *page;
	struct www_tag *cur_tag;
	struct www_tag *child_tag;
	struct www_tag *child_child_tag;
	struct www_tag *child_child_child_tag;
	struct www_tag *child_child_child_child_tag;
	char pathbuf[PATH_MAX];
	sqlite3 *db;
	sqlite3_stmt *res;
	int noemail = 1;
	int rc;
	char *email_summary_sql = "SELECT id,sender,subject,seen,date FROM email WHERE recipient LIKE ?";
	int msgid = 0;
	char *err_msg = 0;
	char *email_create_sql = "CREATE TABLE IF NOT EXISTS email ("
	                         "id INTEGER PRIMARY KEY,"
	                         "sender TEXT COLLATE NOCASE,"
	                         "recipient TEXT COLLATE NOCASE,"
	                         "subject TEXT,"
	                         "body TEXT,"
	                         "date INTEGER,"
	                         "seen INTEGER);";

	snprintf(pathbuf, sizeof pathbuf, "%s/email.sq3", conf.bbs_path);
	rc = sqlite3_open(pathbuf, &db);
	if (rc != SQLITE_OK) {
		sqlite3_close(db);
		return NULL;
	}
	sqlite3_busy_timeout(db, 5000);
	rc = sqlite3_exec(db, email_create_sql, 0, 0, &err_msg);
	if (rc != SQLITE_OK) {
		sqlite3_free(err_msg);
		sqlite3_close(db);
		return NULL;
	}

	rc = sqlite3_prepare_v2(db, email_summary_sql, -1, &res, 0);
	if (rc != SQLITE_OK) {
		sqlite3_finalize(res);
		sqlite3_close(db);
		return NULL;
	}
	sqlite3_bind_text(res, 1, user->loginname, -1, 0);

	page = www_tag_new(NULL, "");

	cur_tag = www_tag_new("div", NULL);
	www_tag_add_attrib(cur_tag, "class", "content-header");
	www_tag_add_child(page, cur_tag);

	child_tag = www_tag_new("h2", NULL);
	www_tag_add_child(cur_tag, child_tag);

	child_child_tag = www_tag_new(NULL, "Your Email");
	www_tag_add_child(child_tag, child_child_tag);

	cur_tag = www_tag_new("div", NULL);
	www_tag_add_attrib(cur_tag, "class", "button");
	www_tag_add_child(page, cur_tag);

	child_tag = www_tag_new("a", NULL);
	stralloc url = EMPTY_STRALLOC;

	stralloc_cats(&url, www_get_my_url(connection));
	stralloc_cats(&url, "email/new");
	stralloc_0(&url);

	www_tag_add_attrib(child_tag, "href", url.s);
	free(url.s);
	www_tag_add_child(cur_tag, child_tag);

	child_child_tag = www_tag_new(NULL, "New Email");
	www_tag_add_child(child_tag, child_child_tag);

	cur_tag = www_tag_new("div", NULL);
	www_tag_add_attrib(cur_tag, "class", "div-table");
	www_tag_add_child(page, cur_tag);

	while (sqlite3_step(res) == SQLITE_ROW) {
		char datebuf[32];
		++msgid;
		int id = sqlite3_column_int(res, 0);
		const char *from = (const char *)sqlite3_column_text(res, 1);
		const char *subject = (const char *)sqlite3_column_text(res, 2);
		int seen = sqlite3_column_int(res, 3);
		struct tm msg_date;

		time_t date = (time_t)sqlite3_column_int(res, 4);
		localtime_r(&date, &msg_date);
		noemail = 0;
		child_tag = www_tag_new("div", NULL);

		if (seen != 0) {
			www_tag_add_attrib(child_tag, "class", "email-summary-seen");
		} else {
			www_tag_add_attrib(child_tag, "class", "email-summary");
		}

		www_tag_add_child(cur_tag, child_tag);

		child_child_tag = www_tag_new("div", NULL);
		www_tag_add_attrib(child_child_tag, "class", "email-id");
		www_tag_add_child(child_tag, child_child_tag);

		url = EMPTY_STRALLOC;
		stralloc_cat_long(&url, msgid);
		stralloc_0(&url);

		child_child_child_tag = www_tag_new(NULL, url.s);
		free(url.s);

		www_tag_add_child(child_child_tag, child_child_child_tag);

		child_child_tag = www_tag_new("div", NULL);
		www_tag_add_attrib(child_child_tag, "class", "email-subject");
		www_tag_add_child(child_tag, child_child_tag);

		child_child_child_tag = www_tag_new("a", NULL);
		url = EMPTY_STRALLOC;
		stralloc_cats(&url, www_get_my_url(connection));
		stralloc_cats(&url, "email/");
		stralloc_cat_long(&url, msgid);
		stralloc_0(&url);

		www_tag_add_attrib(child_child_child_tag, "href", url.s);
		free(url.s);
		www_tag_add_child(child_child_tag, child_child_child_tag);

		child_child_child_child_tag = www_tag_new(NULL, subject);
		www_tag_add_child(child_child_child_tag, child_child_child_child_tag);

		child_child_tag = www_tag_new("div", NULL);
		www_tag_add_attrib(child_child_tag, "class", "email-from");
		www_tag_add_child(child_tag, child_child_tag);

		child_child_child_tag = www_tag_new(NULL, from);
		www_tag_add_child(child_child_tag, child_child_child_tag);

		child_child_tag = www_tag_new("div", NULL);
		www_tag_add_attrib(child_child_tag, "class", "email-date");
		www_tag_add_child(child_tag, child_child_tag);

		if (conf.date_style == 1)
			strftime(datebuf, sizeof datebuf, "%H:%M %m-%d-%y", &msg_date);
		else
			strftime(datebuf, sizeof datebuf, "%H:%M %d-%m-%y", &msg_date);

		child_child_child_tag = www_tag_new(NULL, datebuf);
		www_tag_add_child(child_child_tag, child_child_child_tag);

		child_child_tag = www_tag_new("a", NULL);
		url = EMPTY_STRALLOC;
		stralloc_cats(&url, www_get_my_url(connection));
		stralloc_cats(&url, "email/delete/");
		stralloc_cat_long(&url, id);
		stralloc_0(&url);
		www_tag_add_attrib(child_child_tag, "href", url.s);
		free(url.s);

		www_tag_add_child(child_tag, child_child_tag);

		child_child_child_tag = www_tag_new("div", NULL);
		www_tag_add_attrib(child_child_child_tag, "class", "email-delete");
		www_tag_add_child(child_child_tag, child_child_child_tag);

		child_child_child_child_tag = www_tag_new(NULL, "");
		www_tag_add_child(child_child_child_tag, child_child_child_child_tag);
	}

	if (noemail) {
		child_tag = www_tag_new(NULL, "No Email");
		www_tag_add_child(cur_tag, child_tag);
	}

	sqlite3_finalize(res);
	sqlite3_close(db);

	return www_tag_unwravel(page);
}

#endif
