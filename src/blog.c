#include <sqlite3.h>
#include <time.h>
#include <string.h>
#include "bbs.h"

extern struct bbs_config conf;
extern struct user_record *gUser;

static int open_blog_database(sqlite3 **db) {
	static char buffer[PATH_MAX];
	int rc;

	snprintf(buffer, PATH_MAX, "%s/blog.sq3", conf.bbs_path);

	rc = sqlite3_open(buffer, db);

	if (rc != SQLITE_OK) {
		dolog("Cannot open database: %s", sqlite3_errmsg(*db));
		return 0;
	}
	sqlite3_busy_timeout(*db, 5000);
	return 1;
}

struct ptr_vector blog_load(void) {
	struct ptr_vector entries = EMPTY_PTR_VECTOR;
	const char *sql = "SELECT author, title, body, date FROM blog ORDER BY date DESC";
	int rc;
	sqlite3 *db;
	sqlite3_stmt *res;

	if (!open_blog_database(&db)) {
		return EMPTY_PTR_VECTOR;
	}

	rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);

	if (rc != SQLITE_OK) {
		dolog("Failed to execute statement: %s", sqlite3_errmsg(db));
		sqlite3_close(db);
		return EMPTY_PTR_VECTOR;
	}
	init_ptr_vector(&entries);
	while (sqlite3_step(res) == SQLITE_ROW) {
		struct blog_entry_t *entry = (struct blog_entry_t *)malloz(sizeof(struct blog_entry_t));
		entry->author = strdup(sqlite3_column_text(res, 0));
		entry->subject = strdup(sqlite3_column_text(res, 1));
		entry->body = strdup(sqlite3_column_text(res, 2));
		entry->date = sqlite3_column_int(res, 3);
		ptr_vector_append(&entries, entry);
	}

	sqlite3_finalize(res);
	sqlite3_close(db);

	return entries;
}

int blog_get_entry_count() {
	const char *sql = "SELECT COUNT(*) FROM blog;";
	sqlite3 *db;
	sqlite3_stmt *res;
	int rc;
	int ret = 0;
	if (!open_blog_database(&db)) {
		return 0;
	}
	rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
	if (rc != SQLITE_OK) {
		sqlite3_close(db);
		return 0;
	}

	if (sqlite3_step(res) == SQLITE_ROW) {
		ret = sqlite3_column_int(res, 0);
	}
	sqlite3_finalize(res);
	sqlite3_close(db);
	return ret;
}

char *blog_get_entry(int i) {
	const char *sql = "SELECT body FROM blog ORDER BY DATE DESC LIMIT ?,1";
	sqlite3 *db;
	sqlite3_stmt *res;
	int rc;
	char *entry = NULL;

	if (!open_blog_database(&db)) {
		return NULL;
	}
	rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
	if (rc != SQLITE_OK) {
		sqlite3_close(db);
		return 0;
	}
	sqlite3_bind_int(res, 1, i);

	if (sqlite3_step(res) == SQLITE_ROW) {
		entry = strdup(sqlite3_column_text(res, 0));
	}
	sqlite3_finalize(res);
	sqlite3_close(db);

	return entry;
}


char *blog_get_author(int i) {
	const char *sql = "SELECT author FROM blog ORDER BY DATE DESC LIMIT ?,1";
	sqlite3 *db;
	sqlite3_stmt *res;
	int rc;
	char *entry = NULL;

	if (!open_blog_database(&db)) {
		return NULL;
	}
	rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
	if (rc != SQLITE_OK) {
		sqlite3_close(db);
		return 0;
	}
	sqlite3_bind_int(res, 1, i);

	if (sqlite3_step(res) == SQLITE_ROW) {
		entry = strdup(sqlite3_column_text(res, 0));
	}
	sqlite3_finalize(res);
	sqlite3_close(db);

	return entry;
}


char *blog_get_title(int i) {
	const char *sql = "SELECT title FROM blog ORDER BY DATE DESC LIMIT ?,1";
	sqlite3 *db;
	sqlite3_stmt *res;
	int rc;
	char *entry = NULL;

	if (!open_blog_database(&db)) {
		return NULL;
	}
	rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
	if (rc != SQLITE_OK) {
		sqlite3_close(db);
		return 0;
	}
	sqlite3_bind_int(res, 1, i);

	if (sqlite3_step(res) == SQLITE_ROW) {
		entry = strdup(sqlite3_column_text(res, 0));
	}
	sqlite3_finalize(res);
	sqlite3_close(db);

	return entry;
}

time_t blog_get_date(int i) {
	const char *sql = "SELECT date FROM blog ORDER BY DATE DESC LIMIT ?,1";
	sqlite3 *db;
	sqlite3_stmt *res;
	int rc;
	time_t entry = 0;

	if (!open_blog_database(&db)) {
/*		return NULL; */
		return 0;
	}
	rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
	if (rc != SQLITE_OK) {
		sqlite3_close(db);
		return 0;
	}
	sqlite3_bind_int(res, 1, i);

	if (sqlite3_step(res) == SQLITE_ROW) {
		entry = sqlite3_column_int(res, 0);
	}
	sqlite3_finalize(res);
	sqlite3_close(db);

	return entry;
}

void blog_display() {
	struct ptr_vector entries = blog_load();
	struct tm thetime;
	static const char *const days[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "???"};
	static const char *const months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec", "???"};
	char c;
	int hour;
	int j;
	int lines = 2;
	s_printf("\e[2J\e[1;1H");
	s_printf(get_string(280));
	s_printf(get_string(281));

	if (ptr_vector_len(&entries) == 0) {
		s_printf(get_string(282));
		s_printf(get_string(6));
		s_getchar();
		return;
	}

	c = 'y';

	for (size_t i = 0; i < ptr_vector_len(&entries); i++) {
		struct blog_entry_t *entry = ptr_vector_get(&entries, i);
		localtime_r(&entry->date, &thetime);

		s_printf(get_string(283), entry->subject, entry->author);
		lines++;
		if (lines == 22 && tolower(c) != 'c') {
			s_printf("\r\n");
			s_printf(get_string(223));
			c = s_getchar();
			if (tolower(c) == 'n') {
				break;
			}
			s_printf("\r\n\r\n");
			lines = 0;
		}
		if (thetime.tm_hour >= 12) {
			hour = thetime.tm_hour - 12;
		} else {
			hour = thetime.tm_hour;
		}
		s_printf(get_string(284), (hour == 0 ? 12 : hour), thetime.tm_min, (thetime.tm_hour >= 12 ? "pm" : "am"), days[thetime.tm_wday], months[thetime.tm_mon], thetime.tm_mday, thetime.tm_year + 1900);

		lines++;
		if (lines == 22 && tolower(c) != 'c') {
			s_printf("\r\n");
			s_printf(get_string(223));
			c = s_getchar();
			if (tolower(c) == 'n') {
				break;
			}
			s_printf("\r\n\r\n");
			lines = 0;
		}

		s_printf("\r\n\e[0m");
		lines++;
		if (lines == 22 && tolower(c) != 'c') {
			s_printf("\r\n");
			s_printf(get_string(223));
			c = s_getchar();
			if (tolower(c) == 'n') {
				break;
			}
			s_printf("\r\n\r\n");
			lines = 0;
		}
		for (j = 0; j < strlen(entry->body); j++) {
			if (entry->body[j] == '\r') {
				s_printf("\r\n");
				lines++;
				if (lines == 22 && tolower(c) != 'c') {
					s_printf("\r\n");
					s_printf(get_string(223));
					c = s_getchar();
					if (tolower(c) == 'n') {
						break;
					}
					s_printf("\r\n\r\n");
					lines = 0;
				}
			} else {
				s_printf("%c", entry->body[j]);
			}
		}

		if (tolower(c) == 'n') {
			break;
		}
		s_printf("\r\n");
		lines++;
		if (lines == 22 && tolower(c) != 'c') {
			s_printf("\r\n");
			s_printf(get_string(223));
			c = s_getchar();
			if (tolower(c) == 'n') {
				break;
			}
			s_printf("\r\n\r\n");
			lines = 0;
		}
	}

	for (size_t i = 0; i < ptr_vector_len(&entries); i++) {
		struct blog_entry_t *entry = ptr_vector_get(&entries, i);
		free(entry->subject);
		free(entry->author);
		free(entry->body);
	}

	ptr_vector_apply(&entries, free);

	destroy_ptr_vector(&entries);

	s_printf(get_string(6));
	s_getchar();
}

void blog_write() {
	char *csql = "CREATE TABLE IF NOT EXISTS blog ("
	             "id INTEGER PRIMARY KEY,"
	             "author TEXT COLLATE NOCASE,"
	             "title TEXT,"
	             "body TEXT,"
	             "date INTEGER);";

	char *isql = "INSERT INTO blog (author, title, body, date) VALUES(?, ?, ?, ?)";
	int rc;
	sqlite3 *db;
	sqlite3_stmt *res;
	char *blog_entry;
	char buffer[PATH_MAX];
	char *blog_subject;
	char *err_msg = 0;

	s_printf(get_string(285));
	s_readstring(buffer, 64);
	s_printf("\r\n");

	if (strlen(buffer) == 0) {
		s_printf(get_string(39));
		return;
	}

	blog_subject = strdup(buffer);

	blog_entry = external_editor(gUser, "No-One", "No-One", NULL, 0, "No-One", "Blog Editor", 0, 1);

	if (blog_entry != NULL) {
		snprintf(buffer, PATH_MAX, "%s/blog.sq3", conf.bbs_path);
		rc = sqlite3_open(buffer, &db);

		if (rc != SQLITE_OK) {
			dolog("Cannot open database: %s", sqlite3_errmsg(db));
			free(blog_entry);
			free(blog_subject);
			return;
		}
		sqlite3_busy_timeout(db, 5000);
		rc = sqlite3_exec(db, csql, 0, 0, &err_msg);
		if (rc != SQLITE_OK) {
			dolog("SQL error: %s", err_msg);
			sqlite3_free(err_msg);
			sqlite3_close(db);
			free(blog_entry);
			free(blog_subject);
			return;
		}

		rc = sqlite3_prepare_v2(db, isql, -1, &res, 0);

		if (rc == SQLITE_OK) {
			sqlite3_bind_text(res, 1, gUser->loginname, -1, 0);
			sqlite3_bind_text(res, 2, blog_subject, -1, 0);
			sqlite3_bind_text(res, 3, blog_entry, -1, 0);
			sqlite3_bind_int(res, 4, time(NULL));
		} else {
			dolog("Failed to execute statement: %s", sqlite3_errmsg(db));
			sqlite3_finalize(res);
			sqlite3_close(db);
			free(blog_entry);
			free(blog_subject);
			return;
		}
		sqlite3_step(res);

		sqlite3_finalize(res);
		sqlite3_close(db);
		free(blog_entry);
		free(blog_subject);
		return;
	}
	free(blog_subject);
}
