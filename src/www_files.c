#if defined(ENABLE_WWW)

#include <string.h>
#include <time.h>
#include <sqlite3.h>
#include <libgen.h>

#include "../deps/hashids/hashids.h"

#include "www_tree.h"
#include "bbs.h"

extern struct bbs_config conf;
extern struct user_record *gUser;
extern struct www_tag *aha(char *input, struct www_tag *parent);

static int digit2nibble(int digit) {
	static const char *const hex = "0123456789abcdef";
	static const char *const Hex = "0123456789ABCDEF";

	char *p;
	p = strchr(hex, digit);
	if (p != NULL)
		return p - hex;
	p = strchr(Hex, digit);
	if (p != NULL)
		return p - Hex;
	return -1;
}

static char *www_decode(char *clean_url) {
	stralloc url = EMPTY_STRALLOC;

	assert(clean_url != NULL);
	for (char *s = clean_url; *s != '\0'; ++s) {
		if (*s == '+')
			stralloc_append1(&url, ' ');
		else if (*s != '%')
			stralloc_append1(&url, *s);
		else {
			int hn = 0, ln = 0, ch = 0;
			if (s[1] == '\0' || (hn = digit2nibble(s[1])) < 0) {
				free(url.s);
				return NULL;
			}
			if (s[2] == '\0' || (ln = digit2nibble(s[2])) < 0) {
				free(url.s);
				return NULL;
			}
			stralloc_append1(&url, hn * 16 + ln);
		}
	}
	stralloc_0(&url);

	return url.s;
}

static void www_encode(stralloc *clean, char *url) {
	assert(clean != NULL);
	assert(url != NULL);
	for (char *s = url; *s != '\0'; ++s) {
		if (isalnum(*s) || *s == '~' || *s == '.' || *s == '_')
			stralloc_append1(clean, *s);
		else if (*s == ' ')
			stralloc_append1(clean, '+');
		else {
			stralloc_append1(clean, '%');
			stralloc_cat_Byte(clean, *s);
		}
	}
}

void www_expire_old_links() {
	char pathbuf[PATH_MAX];
	sqlite3 *db;
	sqlite3_stmt *res;
	int rc;
	char sql[] = "delete from wwwhash where expiry <= ?";
	char *ret;
	time_t now = time(NULL);

	snprintf(pathbuf, PATH_MAX, "%s/www_file_hashes.sq3", conf.bbs_path);

	rc = sqlite3_open(pathbuf, &db);
	if (rc != SQLITE_OK) {
		dolog("Cannot open database: %s", sqlite3_errmsg(db));
		return;
	}
	sqlite3_busy_timeout(db, 5000);
	rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
	if (rc != SQLITE_OK) {
		sqlite3_close(db);
		return;
	}
	sqlite3_bind_int(res, 1, now);
	sqlite3_step(res);
	sqlite3_finalize(res);
	sqlite3_close(db);
}

int www_check_hash_expired(char *hash) {
	char pathbuf[PATH_MAX];
	sqlite3 *db;
	sqlite3_stmt *res;
	int rc;
	time_t now = time(NULL);
	char sql[] = "select id from wwwhash where hash = ? and expiry > ?";
	snprintf(pathbuf, PATH_MAX, "%s/www_file_hashes.sq3", conf.bbs_path);
	rc = sqlite3_open(pathbuf, &db);
	if (rc != SQLITE_OK) {
		return 1;
	}
	sqlite3_busy_timeout(db, 5000);
	rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
	if (rc != SQLITE_OK) {
		sqlite3_close(db);
		return 0;
	}

	sqlite3_bind_text(res, 1, hash, -1, 0);
	sqlite3_bind_int(res, 2, now);

	if (sqlite3_step(res) == SQLITE_ROW) {
		sqlite3_finalize(res);
		sqlite3_close(db);
		return 0;
	}
	sqlite3_finalize(res);
	sqlite3_close(db);
	return 1;
}

void www_add_hash_to_db(char *hash, time_t expiry) {
	char pathbuf[PATH_MAX];
	sqlite3 *db;
	sqlite3_stmt *res;
	int rc;
	char csql[] = "create table if not exists wwwhash (id INTEGER PRIMARY KEY, hash TEXT, expiry INTEGER)";
	char chsql[] = "select id from wwwhash where hash = ?";
	char usql[] = "update wwwhash SET expiry = ? WHERE hash = ?";
	char isql[] = "insert into wwwhash (hash, expiry) values(?, ?)";

	char *ret;
	char *err_msg = 0;

	snprintf(pathbuf, PATH_MAX, "%s/www_file_hashes.sq3", conf.bbs_path);

	rc = sqlite3_open(pathbuf, &db);
	if (rc != SQLITE_OK) {
		return;
	}
	sqlite3_busy_timeout(db, 5000);

	rc = sqlite3_exec(db, csql, 0, 0, &err_msg);
	if (rc != SQLITE_OK) {

		dolog("SQL error: %s", err_msg);

		sqlite3_free(err_msg);
		sqlite3_close(db);
		return;
	}

	// first check if hash is in database
	rc = sqlite3_prepare_v2(db, chsql, -1, &res, 0);
	if (rc != SQLITE_OK) {
		sqlite3_close(db);
		return;
	}
	sqlite3_bind_text(res, 1, hash, -1, 0);
	rc = sqlite3_step(res);
	if (rc == SQLITE_ROW) {
		// if so, update hash
		sqlite3_finalize(res);
		rc = sqlite3_prepare_v2(db, usql, -1, &res, 0);
		if (rc != SQLITE_OK) {
			sqlite3_close(db);
			return;
		}
		sqlite3_bind_int(res, 1, expiry);
		sqlite3_bind_text(res, 2, hash, -1, 0);
		sqlite3_step(res);
		sqlite3_finalize(res);
		sqlite3_close(db);

		return;
	}
	// if not add hash
	sqlite3_finalize(res);
	rc = sqlite3_prepare_v2(db, isql, -1, &res, 0);
	if (rc != SQLITE_OK) {
		sqlite3_close(db);
		return;
	}
	sqlite3_bind_text(res, 1, hash, -1, 0);
	sqlite3_bind_int(res, 2, expiry);
	sqlite3_step(res);
	sqlite3_finalize(res);
	sqlite3_close(db);
}

char *www_decode_hash(char *hash) {
	unsigned long long numbers[4];
	int dir, sub, fid, uid;
	hashids_t *hashids = hashids_init(conf.bbs_name);
	char pathbuf[PATH_MAX];
	sqlite3 *db;
	sqlite3_stmt *res;
	int rc;
	char sql[] = "select filename from files where approved = 1 and id = ?";
	char *ret;

	if (www_check_hash_expired(hash)) {
		return NULL;
	}

	if (hashids_decode(hashids, hash, numbers) != 4) {
		hashids_free(hashids);
		return NULL;
	}
	hashids_free(hashids);

	uid = (int)numbers[0];
	dir = (int)numbers[1];
	sub = (int)numbers[2];
	fid = (int)numbers[3];

	if (dir >= ptr_vector_len(&conf.file_directories))
		return NULL;
	struct file_directory *fdir = ptr_vector_get(&conf.file_directories, dir);
	assert(fdir != NULL);
	if (sub >= ptr_vector_len(&fdir->file_subs))
		return NULL;
	struct file_sub *fsub = ptr_vector_get(&fdir->file_subs, sub);
	assert(fsub != NULL);

	// get filename from database
	snprintf(pathbuf, sizeof pathbuf, "%s/%s.sq3", conf.bbs_path, fsub->database);
	rc = sqlite3_open(pathbuf, &db);
	if (rc != SQLITE_OK) {
		return NULL;
	}
	sqlite3_busy_timeout(db, 5000);
	rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
	if (rc != SQLITE_OK) {
		sqlite3_close(db);
		return NULL;
	}
	sqlite3_bind_int(res, 1, fid);
	if (sqlite3_step(res) == SQLITE_ROW) {
		ret = strdup(sqlite3_column_text(res, 0));
		sqlite3_finalize(res);
		sqlite3_close(db);

		return ret;
	}
	sqlite3_finalize(res);
	sqlite3_close(db);
	return NULL;
}

char *www_create_link(int dir, int sub, int fid) {
	char url[PATH_MAX];
	char *ret;
	char *hashid;
	int sizereq;
	time_t expiry;

	hashids_t *hashids = hashids_init(conf.bbs_name);

	sizereq = hashids_estimate_encoded_size_v(hashids, 4, (unsigned long long)gUser->id,
	                                          (unsigned long long)dir, (unsigned long long)sub, (unsigned long long)fid);

	hashid = (char *)malloz(sizereq + 1);

	if (hashids_encode_v(hashids, hashid, 4, (unsigned long long)gUser->id,
	                     (unsigned long long)dir, (unsigned long long)sub, (unsigned long long)fid) == 0) {
		hashids_free(hashids);
		free(hashid);
		return NULL;
	}

	hashids_free(hashids);

	if (conf.ssl_only || conf.www_redirect_ssl) {
		snprintf(url, sizeof url, "%sfiles/%s", conf.ssl_url, hashid);
	} else {
		snprintf(url, sizeof url, "%sfiles/%s", conf.www_url, hashid);
	}

	// add link into hash database
	expiry = time(NULL) + 86400;
	www_add_hash_to_db(hashid, expiry);

	free(hashid);

	ret = strdup(url);

	return ret;
}

char *www_files_display_listing(struct MHD_Connection *connection, int dir, int sub) {
	static const char *sql = "select id, filename, description, size, dlcount, uploaddate from files where approved=1 ORDER BY filename";
	struct www_tag *page = www_tag_new(NULL, "");
	struct www_tag *cur_tag;
	struct www_tag *child_tag;
	struct www_tag *child_child_tag;
	struct www_tag *child_child_child_tag;
	struct www_tag *child_child_child_child_tag;
	struct www_tag *child_child_child_child_child_tag;
	//stralloc page = EMPTY_STRALLOC;
	char pathbuf[PATH_MAX];
	sqlite3 *db = NULL;
	sqlite3_stmt *res = NULL;
	int rc = 0;

	if (dir >= ptr_vector_len(&conf.file_directories))
		return NULL;
	struct file_directory *fdir = ptr_vector_get(&conf.file_directories, dir);
	assert(fdir != NULL);
	if (sub >= ptr_vector_len(&fdir->file_subs))
		return NULL;
	struct file_sub *fsub = ptr_vector_get(&fdir->file_subs, sub);
	assert(fsub != NULL);

	cur_tag = www_tag_new("div", NULL);
	www_tag_add_attrib(cur_tag, "class", "content-header");
	www_tag_add_child(page, cur_tag);

	child_tag = www_tag_new("h2", NULL);
	www_tag_add_child(cur_tag, child_tag);

	child_child_tag = www_tag_new(NULL, "Files: ");
	www_tag_add_child(child_tag, child_child_tag);

	child_child_tag = www_tag_new(NULL, fdir->name);
	www_tag_add_child(child_tag, child_child_tag);

	child_child_tag = www_tag_new(NULL, " - ");
	www_tag_add_child(child_tag, child_child_tag);

	child_child_tag = www_tag_new(NULL, fsub->name);
	www_tag_add_child(child_tag, child_child_tag);

	snprintf(pathbuf, sizeof pathbuf, "%s/%s.sq3", conf.bbs_path, fsub->database);
	rc = sqlite3_open(pathbuf, &db);
	if (rc != SQLITE_OK) {
		www_tag_destroy(page);
		return NULL;
	}
	sqlite3_busy_timeout(db, 5000);
	rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
	if (rc != SQLITE_OK) {
		sqlite3_close(db);
		www_tag_destroy(page);
		return NULL;
	}

	cur_tag = www_tag_new("table", NULL);
	www_tag_add_attrib(cur_tag, "class", "fileentry");
	www_tag_add_child(page, cur_tag);

	child_tag = www_tag_new("thead", NULL);
	www_tag_add_child(cur_tag, child_tag);

	child_child_tag = www_tag_new("tr", NULL);
	www_tag_add_child(child_tag, child_child_tag);

	child_child_child_tag = www_tag_new("td", NULL);
	www_tag_add_child(child_child_tag, child_child_child_tag);

	child_child_child_child_tag = www_tag_new(NULL, "Filename");
	www_tag_add_child(child_child_child_tag, child_child_child_child_tag);

	child_child_child_tag = www_tag_new("td", NULL);
	www_tag_add_child(child_child_tag, child_child_child_tag);

	child_child_child_child_tag = www_tag_new(NULL, "Size");
	www_tag_add_child(child_child_child_tag, child_child_child_child_tag);

	child_child_child_tag = www_tag_new("td", NULL);
	www_tag_add_child(child_child_tag, child_child_child_tag);

	child_child_child_child_tag = www_tag_new(NULL, "Description");
	www_tag_add_child(child_child_child_tag, child_child_child_child_tag);

	child_tag = www_tag_new("tbody", NULL);
	www_tag_add_child(cur_tag, child_tag);

	while (sqlite3_step(res) == SQLITE_ROW) {
		char *filename = strdup((char *)sqlite3_column_text(res, 1));
		char *base_filename = basename(filename);
		child_child_tag = www_tag_new("tr", NULL);
		www_tag_add_child(child_tag, child_child_tag);

		child_child_child_tag = www_tag_new("td", NULL);
		www_tag_add_attrib(child_child_child_tag, "class", "filename");
		www_tag_add_child(child_child_tag, child_child_child_tag);

		child_child_child_child_tag = www_tag_new("a", NULL);
		www_tag_add_child(child_child_child_tag, child_child_child_child_tag);

		stralloc url = EMPTY_STRALLOC;

		stralloc_cats(&url, www_get_my_url(connection));
		stralloc_cats(&url, "files/areas/");
		stralloc_cat_long(&url, dir);
		stralloc_append1(&url, '/');
		stralloc_cat_long(&url, sub);
		stralloc_append1(&url, '/');
		www_encode(&url, base_filename);

		stralloc_0(&url);

		www_tag_add_attrib(child_child_child_child_tag, "href", url.s);
		free(url.s);

		child_child_child_child_child_tag = www_tag_new(NULL, base_filename);
		www_tag_add_child(child_child_child_child_tag, child_child_child_child_child_tag);

		int size = sqlite3_column_int(res, 3);
		child_child_child_tag = www_tag_new("td", NULL);
		www_tag_add_attrib(child_child_child_tag, "class", "filesize");
		www_tag_add_child(child_child_tag, child_child_child_tag);

		int c = 'b';
		if (size > 1024) {
			size /= 1024;
			c = 'K';
		}
		if (size > 1024) {
			size /= 1024;
			c = 'M';
		}
		if (size > 1024) {
			size /= 1024;
			c = 'G';
		}

		stralloc size_str = EMPTY_STRALLOC;

		stralloc_cat_long(&size_str, size);
		stralloc_append1(&size_str, c);

		child_child_child_child_tag = www_tag_new(NULL, size_str.s);
		www_tag_add_child(child_child_child_tag, child_child_child_child_tag);
		free(size_str.s);

		child_child_child_tag = www_tag_new("td", NULL);
		www_tag_add_attrib(child_child_child_tag, "class", "filedesc");
		www_tag_add_child(child_child_tag, child_child_child_tag);

		char *description = strdup((char *)sqlite3_column_text(res, 2));
		for (char *p = description; *p != '\0'; ++p) {
			if (*p == '\n')
				*p = '\r';
		}
		aha(description, child_child_child_tag);

		free(description);
		free(filename);
	}

	sqlite3_finalize(res);
	sqlite3_close(db);

	return www_tag_unwravel(page);
}

char *www_files_areas(struct MHD_Connection *connection) {
	struct www_tag *page = www_tag_new(NULL, "");
	struct www_tag *cur_tag;
	struct www_tag *child_tag;
	struct www_tag *child_child_tag;

	cur_tag = www_tag_new("div", NULL);
	www_tag_add_attrib(cur_tag, "class", "content-header");
	www_tag_add_child(page, cur_tag);

	child_tag = www_tag_new("h2", NULL);
	www_tag_add_child(cur_tag, child_tag);

	child_child_tag = www_tag_new(NULL, "File Directories");
	www_tag_add_child(child_tag, child_child_tag);

	for (size_t i = 0; i < ptr_vector_len(&conf.file_directories); ++i) {
		struct file_directory *dir = ptr_vector_get(&conf.file_directories, i);
		if (dir->display_on_web == 0)
			continue;

		cur_tag = www_tag_new("div", NULL);
		if (dir->display_on_web == 2) {
			www_tag_add_attrib(cur_tag, "class", "restricted-conference-list-item");
		} else {
			www_tag_add_attrib(cur_tag, "class", "conference-list-item");
		}
		www_tag_add_child(page, cur_tag);

		child_tag = www_tag_new(NULL, dir->name);
		www_tag_add_child(cur_tag, child_tag);

		for (size_t j = 0; j < ptr_vector_len(&dir->file_subs); ++j) {
			struct file_sub *sub = ptr_vector_get(&dir->file_subs, j);
			if (sub->display_on_web != 0) {
				cur_tag = www_tag_new("div", NULL);
				if (sub->display_on_web == 2) {
					www_tag_add_attrib(cur_tag, "class", "restricted-area-list-item");
				} else {
					www_tag_add_attrib(cur_tag, "class", "area-list-item");
				}
				www_tag_add_child(page, cur_tag);

				child_tag = www_tag_new("a", NULL);

				stralloc url = EMPTY_STRALLOC;

				stralloc_cats(&url, www_get_my_url(connection));
				stralloc_cats(&url, "files/areas/");
				stralloc_cat_long(&url, i);
				stralloc_append1(&url, '/');
				stralloc_cat_long(&url, j);
				stralloc_0(&url);

				www_tag_add_attrib(child_tag, "href", url.s);
				free(url.s);
				www_tag_add_child(cur_tag, child_tag);

				child_child_tag = www_tag_new(NULL, sub->name);
				www_tag_add_child(child_tag, child_child_tag);
				if (sub->display_on_web == 2) {
					child_tag = www_tag_new("span", NULL);
					www_tag_add_attrib(child_tag, "class", "restricted-text");
					www_tag_add_child(cur_tag, child_tag);
					child_child_tag = www_tag_new(NULL, "Restricted");
					www_tag_add_child(child_tag, child_child_tag);
				}
			}
		}
	}

	return www_tag_unwravel(page);
}

char *www_files_get_from_area(int dir, int sub, char *clean_file) {
	static const char *sql = "SELECT filename FROM files WHERE approved=1 AND filename LIKE ? ESCAPE \"^\"";

	stralloc filenamelike = EMPTY_STRALLOC;
	sqlite3 *db = NULL;
	sqlite3_stmt *res = NULL;
	int rc = 0;
	char pathbuf[PATH_MAX];
	char *ret = NULL;
	char *file = NULL;

	file = www_decode(clean_file);
	stralloc_copys(&filenamelike, "%");
	for (char *p = file; *p != '\0'; ++p) {
		if (*p == '^' || *p == '_' || *p == '%')
			stralloc_append1(&filenamelike, '^');
		stralloc_append1(&filenamelike, *p);
	}
	stralloc_0(&filenamelike);
	free(file);

	if (dir >= ptr_vector_len(&conf.file_directories))
		return NULL;
	struct file_directory *fdir = ptr_vector_get(&conf.file_directories, dir);
	assert(fdir != NULL);
	if (sub >= ptr_vector_len(&fdir->file_subs))
		return NULL;
	struct file_sub *fsub = ptr_vector_get(&fdir->file_subs, sub);
	assert(fsub != NULL);

	snprintf(pathbuf, sizeof pathbuf, "%s/%s.sq3", conf.bbs_path, fsub->database);
	rc = sqlite3_open(pathbuf, &db);
	if (rc != SQLITE_OK) {
		free(filenamelike.s);
		return NULL;
	}
	sqlite3_busy_timeout(db, 5000);
	rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
	if (rc != SQLITE_OK) {
		sqlite3_close(db);
		free(filenamelike.s);
		return NULL;
	}
	sqlite3_bind_text(res, 1, filenamelike.s, -1, 0);
	rc = sqlite3_step(res);
	if (rc == SQLITE_ROW) {
		ret = strdup(sqlite3_column_text(res, 0));
	}

	free(filenamelike.s);
	sqlite3_finalize(res);
	sqlite3_close(db);
	return ret;
}

#endif
