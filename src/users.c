#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <ctype.h>
#include <openssl/evp.h>
#include "bbs.h"
#include "inih/ini.h"

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)
#define EVP_MD_CTX_new EVP_MD_CTX_create
#define EVP_MD_CTX_free EVP_MD_CTX_destroy
#endif

extern struct bbs_config conf;
extern struct user_record *gUser;

static void open_users_db_or_die(sqlite3 **db) {
	char *err_msg = NULL;
	int rc = 0;
	static const char *create_sql =
	    "CREATE TABLE IF NOT EXISTS users ("
	    "Id INTEGER PRIMARY KEY,"
	    "loginname TEXT COLLATE NOCASE,"
	    "password TEXT,"
	    "salt TEXT,"
	    "firstname TEXT,"
	    "lastname TEXT,"
	    "email TEXT,"
	    "location TEXT,"
	    "sec_level INTEGER,"
	    "last_on INTEGER,"
	    "time_left INTEGER,"
	    "cur_mail_conf INTEGER,"
	    "cur_mail_area INTEGER,"
	    "cur_file_sub INTEGER,"
	    "cur_file_dir INTEGER,"
	    "times_on INTEGER,"
	    "bwavepktno INTEGER,"
	    "archiver INTEGER,"
	    "protocol INTEGER,"
	    "nodemsgs INTEGER,"
	    "codepage INTEGER,"
	    "exteditor INTEGER,"
	    "bwavestyle INTEGER,"
	    "signature TEXT,"
	    "autosig INTEGER,"
	    "dopipe INTEGER,"
	    "qwke INTEGER);";
	char buffer[PATH_MAX];
	snprintf(buffer, PATH_MAX, "%s/users.sq3", conf.bbs_path);
	if (sqlite3_open(buffer, db) != SQLITE_OK) {
		dolog("Cannot open database: %s", sqlite3_errmsg(*db));
		sqlite3_close(*db);
		exit(1);
	}
	assert(db != NULL);
	sqlite3_busy_timeout(*db, 5000);
	rc = sqlite3_exec(*db, create_sql, 0, 0, &err_msg);
	if (rc != SQLITE_OK) {
		dolog("SQL error: %s", err_msg);
		sqlite3_free(err_msg);
		sqlite3_close(*db);
		exit(1);
	}
}

char *hash_sha256(char *pass, char *salt) {
	char *buffer = NULL;
	char *shash = NULL;
	unsigned char hash[EVP_MAX_MD_SIZE];
	unsigned int length_of_hash = 0;
	int i;

	buffer = str2dup(pass, salt);

	EVP_MD_CTX *context = EVP_MD_CTX_new();

	if (context != NULL) {
		if (EVP_DigestInit_ex(context, EVP_sha256(), NULL)) {
			if (EVP_DigestUpdate(context, buffer, strlen(buffer))) {
				if (EVP_DigestFinal_ex(context, hash, &length_of_hash)) {
					stralloc shash = EMPTY_STRALLOC;
					for (i = 0; i < length_of_hash; i++)
						stralloc_cat_byte(&shash, hash[i]);
					stralloc_0(&shash);
					EVP_MD_CTX_free(context);
					free(buffer);
					return shash.s;
				}
			}
		}
		EVP_MD_CTX_free(context);
	}

	free(buffer);
	dolog("Error creating hash!");
	exit(-1);
}

void gen_salt(char **s) {
	FILE *fptr;
	int i;
	char c;
	*s = (char *)malloz(11);

	char *salt = *s;

	if (!salt) {
		dolog("Out of memory..");
		exit(-1);
	}
	fptr = fopen("/dev/urandom", "rb");
	if (!fptr) {
		dolog("Unable to open /dev/urandom!");
		exit(-1);
	}
	for (i = 0; i < 10; i++) {
		fread(&c, 1, 1, fptr);
		salt[i] = (char)((abs(c) % 93) + 33);
	}
	fclose(fptr);
	salt[10] = '\0';
}

static int secLevel(void *user, const char *section, const char *name,
                    const char *value) {
	struct sec_level_t *conf = (struct sec_level_t *)user;

	if (strcasecmp(section, "main") == 0) {
		if (strcasecmp(name, "time per day") == 0) {
			conf->timeperday = atoi(value);
		} else if (strcasecmp(name, "idle timeout") == 0) {
			conf->idle_timeout = atoi(value);
		}
	}
	return 1;
}

int save_user(struct user_record *user) {
	sqlite3 *db = NULL;
	sqlite3_stmt *res = NULL;
	int rc = 0;

	const char *update_sql =
	    "UPDATE users SET password=?, salt=?, firstname=?,"
	    "lastname=?, email=?, location=?, sec_level=?, last_on=?, "
	    "time_left=?, cur_mail_conf=?, cur_mail_area=?, "
	    "cur_file_dir=?, cur_file_sub=?, times_on=?, bwavepktno=?, "
	    "archiver=?, protocol=?,nodemsgs=?,codepage=?,exteditor=?,"
	    "bwavestyle=?,signature=?,autosig=?,dopipe=?,qwke=? where loginname LIKE ?";

	open_users_db_or_die(&db);

	rc = sqlite3_prepare_v2(db, update_sql, -1, &res, 0);
	if (rc != SQLITE_OK) {
		dolog("Failed to prepare statement: %s", sqlite3_errmsg(db));
		sqlite3_close(db);
		exit(1);
	}
	sqlite3_bind_text(res, 1, user->password, -1, 0);
	sqlite3_bind_text(res, 2, user->salt, -1, 0);
	sqlite3_bind_text(res, 3, user->firstname, -1, 0);
	sqlite3_bind_text(res, 4, user->lastname, -1, 0);
	sqlite3_bind_text(res, 5, user->email, -1, 0);
	sqlite3_bind_text(res, 6, user->location, -1, 0);
	sqlite3_bind_int(res, 7, user->sec_level);
	sqlite3_bind_int(res, 8, user->laston);
	sqlite3_bind_int(res, 9, user->timeleft);
	sqlite3_bind_int(res, 10, user->cur_mail_conf);
	sqlite3_bind_int(res, 11, user->cur_mail_area);
	sqlite3_bind_int(res, 12, user->cur_file_dir);
	sqlite3_bind_int(res, 13, user->cur_file_sub);
	sqlite3_bind_int(res, 14, user->timeson);
	sqlite3_bind_int(res, 15, user->bwavepktno);
	sqlite3_bind_int(res, 16, user->defarchiver);
	sqlite3_bind_int(res, 17, user->defprotocol);
	sqlite3_bind_int(res, 18, user->nodemsgs);
	sqlite3_bind_int(res, 19, user->codepage);
	sqlite3_bind_int(res, 20, user->exteditor);
	sqlite3_bind_int(res, 21, user->bwavestyle);
	sqlite3_bind_text(res, 22, user->signature, -1, 0);
	sqlite3_bind_int(res, 23, user->autosig);
	sqlite3_bind_int(res, 24, user->dopipe);
	sqlite3_bind_int(res, 25, user->qwke);
	sqlite3_bind_text(res, 26, user->loginname, -1, 0);

	rc = sqlite3_step(res);
	if (rc != SQLITE_DONE) {
		sqlite3_finalize(res);
		dolog("execution failed: %s", sqlite3_errmsg(db));
		sqlite3_close(db);
		exit(1);
	}
	sqlite3_finalize(res);
	sqlite3_close(db);
	return 1;
}

int user_check_flag(struct user_record *user, char *flag) {
	sqlite3 *db = NULL;
	sqlite3_stmt *res = NULL;
	int rc = 0;
	char *err_msg = NULL;

	static const char *check_sql = "SELECT COUNT(*) FROM user_flags WHERE userid = ? and flag = ?";
	static const char *create_sql = "CREATE TABLE IF NOT EXISTS user_flags (userid INTEGER, flag TEXT COLLATE NOCASE);";

	open_users_db_or_die(&db);
	rc = sqlite3_exec(db, create_sql, 0, 0, &err_msg);

	if (rc != SQLITE_OK) {
		dolog("SQL error: %s", err_msg);
		sqlite3_free(err_msg);
		sqlite3_close(db);
		return 0;
	}

	rc = sqlite3_prepare_v2(db, check_sql, -1, &res, 0);
	if (rc != SQLITE_OK) {
		dolog("Error preparing sql");
		sqlite3_close(db);
		return 0;
	}

	sqlite3_bind_int(res, 1, user->id);
	sqlite3_bind_text(res, 2, flag, -1, 0);
	if (sqlite3_step(res) == SQLITE_ROW) {
		if (sqlite3_column_int(res, 0) != 0) {
			sqlite3_finalize(res);
			sqlite3_close(db);
			return 1;
		}
	}
	sqlite3_finalize(res);
	sqlite3_close(db);
	return 0;
}

int msgbase_flag_unflag(struct user_record *user, int conference, int msgbase, int msgid) {
	sqlite3 *db = NULL;
	sqlite3_stmt *res = NULL;
	int rc = 0;
	char *err_msg = NULL;
	int flagunflag = 0;

	static const char *create_sql =
	    "CREATE TABLE IF NOT EXISTS msg_flags (conference INTEGER, msgbase INTEGER, uid INTEGER, msg INTEGER);";

	flagunflag = msgbase_is_flagged(user, conference, msgbase, msgid);

	open_users_db_or_die(&db);

	rc = sqlite3_exec(db, create_sql, 0, 0, &err_msg);
	if (rc != SQLITE_OK) {

		dolog("SQL error: %s", err_msg);

		sqlite3_free(err_msg);
		sqlite3_close(db);

		return 0;
	}
	if (flagunflag == 1) {
		static const char *unflag_buf =
		    "DELETE FROM msg_flags WHERE conference=? AND msgbase=? AND uid=? AND msg=?";
		rc = sqlite3_prepare_v2(db, unflag_buf, -1, &res, 0);
	} else {
		static const char *flag_buf =
		    "INSERT INTO msg_flags (conference, msgbase, uid, msg) VALUES(?, ?, ?, ?)";
		rc = sqlite3_prepare_v2(db, flag_buf, -1, &res, 0);
	}

	sqlite3_bind_int(res, 1, conference);
	sqlite3_bind_int(res, 2, msgbase);
	sqlite3_bind_int(res, 3, user->id);
	sqlite3_bind_int(res, 4, msgid);

	rc = sqlite3_step(res);

	sqlite3_finalize(res);
	sqlite3_close(db);

	return 1;
}

int msgbase_is_flagged(struct user_record *user, int conference, int msgbase, int msgid) {
	sqlite3 *db = NULL;
	sqlite3_stmt *res = NULL;
	int rc = 0;

	static const char *sql_buf =
	    "SELECT * FROM msg_flags WHERE conference=? AND msgbase=? AND uid=? AND msg=?";

	open_users_db_or_die(&db);

	rc = sqlite3_prepare_v2(db, sql_buf, -1, &res, 0);
	if (rc != SQLITE_OK) {
		sqlite3_close(db);
		return 0;
	}

	sqlite3_bind_int(res, 1, conference);
	sqlite3_bind_int(res, 2, msgbase);
	sqlite3_bind_int(res, 3, user->id);
	sqlite3_bind_int(res, 4, msgid);

	if (sqlite3_step(res) != SQLITE_ROW) {
		sqlite3_finalize(res);
		sqlite3_close(db);
		return 0;
	}
	sqlite3_finalize(res);
	sqlite3_close(db);
	return 1;
}

int msgbase_sub_unsub(int conference, int msgbase) {
	sqlite3 *db = NULL;
	sqlite3_stmt *res = NULL;
	int rc = 0;
	static const char *create_sql =
	    "CREATE TABLE IF NOT EXISTS msg_subs (conference INTEGER, msgbase INTEGER, uid INTEGER);";
	char *err_msg = NULL;
	int subunsub = msgbase_is_subscribed(conference, msgbase);

	open_users_db_or_die(&db);

	rc = sqlite3_exec(db, create_sql, 0, 0, &err_msg);
	if (rc != SQLITE_OK) {
		dolog("SQL error: %s", err_msg);
		sqlite3_free(err_msg);
		sqlite3_close(db);
		return 0;
	}
	if (subunsub == 1) {
		static char *unsub_buf =
		    "DELETE FROM msg_subs WHERE conference=? AND msgbase=? AND uid=?";
		rc = sqlite3_prepare_v2(db, unsub_buf, -1, &res, 0);
	} else {
		static const char *sub_buf =
		    "INSERT INTO msg_subs (conference, msgbase, uid) VALUES(?, ?, ?)";
		rc = sqlite3_prepare_v2(db, sub_buf, -1, &res, 0);
	}

	sqlite3_bind_int(res, 1, conference);
	sqlite3_bind_int(res, 2, msgbase);
	sqlite3_bind_int(res, 3, gUser->id);

	rc = sqlite3_step(res);

	sqlite3_finalize(res);
	sqlite3_close(db);

	return 1;
}

int msgbase_is_subscribed(int conference, int msgbase) {
	sqlite3 *db = NULL;
	sqlite3_stmt *res = NULL;
	int rc = 0;

	static const char *sql_buf =
	    "SELECT * FROM msg_subs WHERE conference=? AND msgbase=? AND uid=?";

	open_users_db_or_die(&db);

	rc = sqlite3_prepare_v2(db, sql_buf, -1, &res, 0);
	if (rc != SQLITE_OK) {
		sqlite3_close(db);
		return 0;
	}

	sqlite3_bind_int(res, 1, conference);
	sqlite3_bind_int(res, 2, msgbase);
	sqlite3_bind_int(res, 3, gUser->id);

	if (sqlite3_step(res) != SQLITE_ROW) {
		sqlite3_finalize(res);
		sqlite3_close(db);
		return 0;
	}
	sqlite3_finalize(res);
	sqlite3_close(db);

	return 1;
}

int inst_user(struct user_record *user) {
	sqlite3 *db = NULL;
	sqlite3_stmt *res = NULL;
	char *err_msg = NULL;
	int rc = 0;

	static const char *insert_sql =
	    "INSERT INTO users (loginname, password, salt, firstname,"
	    "lastname, email, location, sec_level, last_on, time_left, "
	    "cur_mail_conf, cur_mail_area, cur_file_dir, cur_file_sub, "
	    "times_on, bwavepktno, archiver, protocol, nodemsgs, "
	    "codepage, exteditor, bwavestyle, signature, autosig, dopipe, qwke) "
	    "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

	open_users_db_or_die(&db);

	rc = sqlite3_prepare_v2(db, insert_sql, -1, &res, 0);
	if (rc != SQLITE_OK) {
		dolog("Failed to execute statement: %s", sqlite3_errmsg(db));
		sqlite3_close(db);
		exit(1);
	}
	sqlite3_bind_text(res, 1, user->loginname, -1, 0);
	sqlite3_bind_text(res, 2, user->password, -1, 0);
	sqlite3_bind_text(res, 3, user->salt, -1, 0);
	sqlite3_bind_text(res, 4, user->firstname, -1, 0);
	sqlite3_bind_text(res, 5, user->lastname, -1, 0);
	sqlite3_bind_text(res, 6, user->email, -1, 0);
	sqlite3_bind_text(res, 7, user->location, -1, 0);
	sqlite3_bind_int(res, 8, user->sec_level);
	sqlite3_bind_int(res, 9, user->laston);
	sqlite3_bind_int(res, 10, user->timeleft);
	sqlite3_bind_int(res, 11, user->cur_mail_conf);
	sqlite3_bind_int(res, 12, user->cur_mail_area);
	sqlite3_bind_int(res, 13, user->cur_file_dir);
	sqlite3_bind_int(res, 14, user->cur_file_sub);
	sqlite3_bind_int(res, 15, user->timeson);
	sqlite3_bind_int(res, 16, user->bwavepktno);
	sqlite3_bind_int(res, 17, user->defarchiver);
	sqlite3_bind_int(res, 18, user->defprotocol);
	sqlite3_bind_int(res, 19, user->nodemsgs);
	sqlite3_bind_int(res, 20, user->codepage);
	sqlite3_bind_int(res, 21, user->exteditor);
	sqlite3_bind_int(res, 22, user->bwavestyle);
	sqlite3_bind_text(res, 23, user->signature, -1, 0);
	sqlite3_bind_int(res, 24, user->autosig);
	sqlite3_bind_int(res, 25, user->dopipe);
	sqlite3_bind_int(res, 26, user->qwke);

	rc = sqlite3_step(res);
	if (rc != SQLITE_DONE) {
		dolog("execution failed: %s", sqlite3_errmsg(db));
		sqlite3_close(db);
		exit(1);
	}

	user->id = sqlite3_last_insert_rowid(db);

	sqlite3_finalize(res);
	sqlite3_close(db);

	return 1;
}

struct user_record *check_user_pass(char *loginname, char *password) {
	sqlite3 *db = NULL;
	sqlite3_stmt *res = NULL;
/*	int rc = NULL; */
	int rc = 0;
	int pass_ok = 0;
	char pathbuf[PATH_MAX];

	static const char *sql =
	    "SELECT Id, loginname, password, salt, firstname,"
	    "lastname, email, location, sec_level, last_on, time_left, "
	    "cur_mail_conf, cur_mail_area, cur_file_dir, cur_file_sub, "
	    "times_on, bwavepktno, archiver, protocol,nodemsgs, "
	    "codepage, exteditor, bwavestyle, signature, autosig, dopipe, qwke "
	    "FROM users WHERE loginname LIKE ?";

	open_users_db_or_die(&db);
	rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
	if (rc != SQLITE_OK) {
		dolog("Failed to execute statement: %s", sqlite3_errmsg(db));
		sqlite3_finalize(res);
		sqlite3_close(db);
		return NULL;
	}
	sqlite3_bind_text(res, 1, loginname, -1, 0);
	int step = sqlite3_step(res);
	if (step != SQLITE_ROW) {
		sqlite3_finalize(res);
		sqlite3_close(db);
		return NULL;
	}
	struct user_record *user = malloz(sizeof(struct user_record));
	user->id = sqlite3_column_int(res, 0);
	user->loginname = strdup((char *)sqlite3_column_text(res, 1));
	user->password = strdup((char *)sqlite3_column_text(res, 2));
	user->salt = strdup((char *)sqlite3_column_text(res, 3));
	user->firstname = strdup((char *)sqlite3_column_text(res, 4));
	user->lastname = strdup((char *)sqlite3_column_text(res, 5));
	user->email = strdup((char *)sqlite3_column_text(res, 6));
	user->location = strdup((char *)sqlite3_column_text(res, 7));
	user->sec_level = sqlite3_column_int(res, 8);
	user->laston = (time_t)sqlite3_column_int(res, 9);
	user->timeleft = sqlite3_column_int(res, 10);
	user->cur_mail_conf = sqlite3_column_int(res, 11);
	user->cur_mail_area = sqlite3_column_int(res, 12);
	user->cur_file_dir = sqlite3_column_int(res, 13);
	user->cur_file_sub = sqlite3_column_int(res, 14);
	user->timeson = sqlite3_column_int(res, 15);
	user->bwavepktno = sqlite3_column_int(res, 16);
	user->defarchiver = sqlite3_column_int(res, 17);
	user->defprotocol = sqlite3_column_int(res, 18);
	user->nodemsgs = sqlite3_column_int(res, 19);
	user->codepage = sqlite3_column_int(res, 20);
	user->exteditor = sqlite3_column_int(res, 21);
	user->bwavestyle = sqlite3_column_int(res, 22);
	user->signature = strdup((char *)sqlite3_column_text(res, 23));
	user->autosig = sqlite3_column_int(res, 24);
	user->dopipe = sqlite3_column_int(res, 25);
	user->qwke = sqlite3_column_int(res, 26);
	char *pass_hash = hash_sha256(password, user->salt);

	if (strcmp(pass_hash, user->password) != 0) {
		free(user->loginname);
		free(user->firstname);
		free(user->lastname);
		free(user->email);
		free(user->location);
		free(user->salt);
		free(user->signature);
		free(user);
		free(pass_hash);
		sqlite3_finalize(res);
		sqlite3_close(db);
		return NULL;
	}
	free(pass_hash);

	sqlite3_finalize(res);
	sqlite3_close(db);

	user->sec_info = (struct sec_level_t *)malloz(sizeof(struct sec_level_t));
	user->sec_info->idle_timeout = conf.idletimeout;
	snprintf(pathbuf, sizeof pathbuf, "%s/s%d.ini", conf.config_path, user->sec_level);
	if (ini_parse(pathbuf, secLevel, user->sec_info) < 0) {
		dolog("Unable to load sec Level ini (%s)!", pathbuf);
		exit(-1);
	}
	if (user->cur_mail_conf >= ptr_vector_len(&conf.mail_conferences)) {
		user->cur_mail_conf = 0;
	}
	if (user->cur_file_dir >= ptr_vector_len(&conf.file_directories)) {
		user->cur_file_dir = 0;
	}
	struct mail_conference *mc = ptr_vector_get(&conf.mail_conferences, user->cur_mail_conf);
	assert(mc != NULL);
	if (user->cur_mail_area >= ptr_vector_len(&mc->mail_areas)) {
		user->cur_mail_area = 0;
	}
	struct file_directory *dir = ptr_vector_get(&conf.file_directories, user->cur_file_dir);
	assert(dir != NULL);
	if (user->cur_file_sub >= ptr_vector_len(&dir->file_subs)) {
		user->cur_file_sub = 0;
	}

	return user;
}

void list_users(struct user_record *user) {
	sqlite3 *db = NULL;
	sqlite3_stmt *res = NULL;
	int rc = 0;

	static const char *sql = "SELECT loginname,location,times_on FROM users";

	open_users_db_or_die(&db);

	rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
	if (rc != SQLITE_OK) {
		dolog("Cannot prepare statement: %s", sqlite3_errmsg(db));
		sqlite3_close(db);
		exit(1);
	}
	s_printf(get_string(161));
	s_printf(get_string(162));
	s_printf(get_string(163));
	for (int i = 0; sqlite3_step(res) == SQLITE_ROW; ++i) {
		s_printf(get_string(164), sqlite3_column_text(res, 0), sqlite3_column_text(res, 1), sqlite3_column_int(res, 2));
		if (i == 20) {
			s_printf(get_string(6));
			s_getc();
			i = 0;
		}
	}
	s_printf(get_string(165));
	sqlite3_finalize(res);
	sqlite3_close(db);

	s_printf(get_string(6));
	s_getc();
}

char *get_username_from_fullname_j(char *firstandlastname) {
	char *username = NULL;

	char *firstname = strdup(firstandlastname);

	if (!firstname) {
		return 0;
	}

	char *lastname = strchr(firstname, ' ');
	int ret;

	if (lastname == NULL) {
		return 0;
	}
	*lastname = '\0';
	lastname++;
	username = get_username_from_fullname(firstname, lastname);
	free(firstname);

	return username;
}

char *get_username_from_fullname(char *firstname, char *lastname) {
	sqlite3 *db = NULL;
	sqlite3_stmt *res = NULL;
	int rc = 0;
	static const char *sql = "SELECT loginname FROM users WHERE firstname = ? AND lastname = ?";
	char *username = NULL;

	open_users_db_or_die(&db);
	rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
	if (rc != SQLITE_OK) {
		dolog("Failed to execute statement: %s", sqlite3_errmsg(db));
		sqlite3_close(db);
		return NULL;
	}
	sqlite3_bind_text(res, 1, firstname, -1, 0);
	sqlite3_bind_text(res, 2, lastname, -1, 0);
	if (sqlite3_step(res) == SQLITE_ROW) {
		username = strdup(sqlite3_column_text(res, 0));
	}

	sqlite3_finalize(res);
	sqlite3_close(db);
	return username;
}

int check_fullname_j(char *firstandlastname) {
	char *firstname = strdup(firstandlastname);

	if (!firstname) {
		return 0;
	}

	char *lastname = strchr(firstname, ' ');
	int ret;

	if (lastname == NULL) {
		free(firstname);
		return 0;
	}
	*lastname = '\0';
	lastname++;
	ret = check_fullname(firstname, lastname);

	free(firstname);
	return ret;
}

int check_fullname(char *firstname, char *lastname) {
	sqlite3 *db = NULL;
	sqlite3_stmt *res = NULL;
	int rc = 0;

	static const char *sql =
	    "SELECT * FROM users WHERE firstname = ? AND lastname = ?";

	open_users_db_or_die(&db);
	rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
	if (rc != SQLITE_OK) {
		dolog("Failed to prepare statement: %s", sqlite3_errmsg(db));
		sqlite3_close(db);
		return 0;
	}
	sqlite3_bind_text(res, 1, firstname, -1, 0);
	sqlite3_bind_text(res, 2, lastname, -1, 0);
	int step = sqlite3_step(res);
	sqlite3_finalize(res);
	sqlite3_close(db);

	return (step != SQLITE_ROW);
}

int check_user(char *loginname) {
	sqlite3 *db = NULL;
	sqlite3_stmt *res = NULL;
	int rc = 0;

	static const char *sql = "SELECT * FROM users WHERE loginname = ?";

	open_users_db_or_die(&db);
	rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
	if (rc != SQLITE_OK) {
		dolog("Failed to execute statement: %s", sqlite3_errmsg(db));
		sqlite3_close(db);
		return 0;
	}
	sqlite3_bind_text(res, 1, loginname, -1, 0);
	int step = sqlite3_step(res);
	sqlite3_finalize(res);
	sqlite3_close(db);

	return (step != SQLITE_ROW);
}

char *get_username(int id) {
	sqlite3 *db = NULL;
	sqlite3_stmt *res = NULL;
	int rc = 0;
	static const char *sql = "SELECT loginname FROM users WHERE Id = ?";
	char *username = NULL;
	open_users_db_or_die(&db);
	rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
	if (rc != SQLITE_OK) {
		dolog("Failed to execute statement: %s", sqlite3_errmsg(db));
		sqlite3_close(db);
		return NULL;
	}
	sqlite3_bind_int(res, 1, id);
	if (sqlite3_step(res) == SQLITE_ROW) {
		username = strdup(sqlite3_column_text(res, 0));
	}

	sqlite3_finalize(res);
	sqlite3_close(db);
	return username;
}

struct user_record *new_user() {
	char buffer[PATH_MAX];
	struct user_record *user;
	int done = 0;
	char c;
	int nameok = 0;
	int passok = 0;
	int i;
	int fullnameok = 0;

	if (conf.new_user_pass != NULL) {
		s_printf("\r\n\r\n");
		s_displayansi("prenup");
		s_printf(get_string(297));
		s_printf(get_string(298));
		s_readpass(buffer, 32);
		if (strcmp(buffer, conf.new_user_pass) != 0) {
			s_printf(get_string(299));
			return NULL;
		}
		s_printf("\r\n\r\n");
	}

	user = (struct user_record *)malloz(sizeof(struct user_record));
	s_printf("\r\n\r\n");
	s_displayansi("newuser");

	do {
		passok = 0;
		nameok = 0;
		do {
			s_printf(get_string(166));
			s_readstring(buffer, 16);
			s_printf("\r\n");
			if (strlen(buffer) < 2) {
				s_printf(get_string(167));
				continue;
			}
			if (buffer[0] == ' ' || buffer[strlen(buffer) - 1] == ' ') {
				s_printf(get_string(240));
				continue;
			}
			for (const char *p = buffer; *p != '\0'; ++p) {
				if (!(tolower(*p) >= 97 && tolower(*p) <= 122) && *p != 32 && !(*p >= '0' && *p <= '9')) {
					s_printf(get_string(168));
					nameok = 1;
					break;
				}
			}
			if (nameok == 1) {
				nameok = 0;
				continue;
			}
			if (strcasecmp(buffer, "unknown") == 0) {
				s_printf(get_string(169));
				continue;
			}
			if (strcasecmp(buffer, "all") == 0) {
				s_printf(get_string(169));
				continue;
			}
			if (strcasecmp(buffer, "new") == 0) {
				s_printf(get_string(169));
				continue;
			}
			if (strcasecmp(buffer, "anonymous") == 0) {
				s_printf(get_string(169));
				continue;
			}
			if (strcasecmp(buffer, "ftp") == 0) {
				s_printf(get_string(169));
				continue;
			}
			user->loginname = strdup(buffer);
			nameok = check_user(user->loginname);
			if (!nameok) {
				s_printf(get_string(170));
				free(user->loginname);
				memset(buffer, 0, 256);
			}
		} while (!nameok);
		do {
			nameok = 0;
			do {
				s_printf(get_string(171));
				memset(buffer, 0, 256);
				s_readstring(buffer, 32);
				if (buffer[0] == ' ' || buffer[strlen(buffer) - 1] == ' ') {
					s_printf(get_string(241));
					continue;
				}
				if (strlen(buffer) == 0) {
					s_printf(get_string(167));
					continue;
				}
				if (strchr(buffer, ' ') != NULL) {
					s_printf(get_string(244));
					continue;
				}
				s_printf("\r\n");
				user->firstname = strdup(buffer);
				nameok = 1;
			} while (!nameok);
			nameok = 0;

			do {
				s_printf(get_string(172));
				memset(buffer, 0, 256);
				s_readstring(buffer, 32);
				if (buffer[0] == ' ' || buffer[strlen(buffer) - 1] == ' ') {
					s_printf(get_string(242));
					continue;
				}
				if (strlen(buffer) == 0) {
					s_printf(get_string(167));
					continue;
				}
				if (strchr(buffer, ' ') != NULL) {
					s_printf(get_string(244));
					continue;
				}
				s_printf("\r\n");
				nameok = 1;
				user->lastname = strdup(buffer);
			} while (!nameok);
			fullnameok = check_fullname(user->firstname, user->lastname);
			if (!fullnameok) {
				free(user->firstname);
				free(user->lastname);
				s_printf(get_string(243));
			}
		} while (!fullnameok);
		s_printf(get_string(173));
		memset(buffer, 0, 256);
		s_readstring(buffer, 64);
		s_printf("\r\n");
		user->email = strdup(buffer);

		s_printf(get_string(174));
		memset(buffer, 0, 256);
		s_readstring(buffer, 32);
		s_printf("\r\n");
		user->location = strdup(buffer);

		do {
			s_printf(get_string(175));
			memset(buffer, 0, 256);
			s_readstring(buffer, 16);
			s_printf("\r\n");
			if (strlen(buffer) >= 8) {
				passok = 1;
			} else {
				s_printf(get_string(158));
			}
		} while (!passok);
		gen_salt(&user->salt);
		user->password = hash_sha256(buffer, user->salt);

		s_printf(get_string(176));
		s_printf(get_string(177));
		s_printf(get_string(178));
		s_printf(user->loginname);
		s_printf(get_string(179));
		s_printf(user->firstname);
		s_printf(get_string(180));
		s_printf(user->lastname);
		s_printf(get_string(181));
		s_printf(user->email);
		s_printf(get_string(182));
		s_printf(user->location);
		s_printf(get_string(183));
		s_printf(get_string(184));
		c = s_getchar();
		while (tolower(c) != 'y' && tolower(c) != 'n') {
			c = s_getchar();
		}

		if (tolower(c) == 'y') {
			done = 1;
		}
	} while (!done);
	user->sec_level = conf.newuserlvl;
	user->bwavepktno = 0;
	user->sec_info = (struct sec_level_t *)malloz(sizeof(struct sec_level_t));
	snprintf(buffer, PATH_MAX, "%s/s%d.ini", conf.config_path, user->sec_level);
	user->sec_info->idle_timeout = conf.idletimeout;
	if (ini_parse(buffer, secLevel, user->sec_info) < 0) {
		dolog("Unable to load sec Level ini (%s)!", buffer);
		exit(-1);
	}

	user->laston = time(NULL);
	user->timeleft = user->sec_info->timeperday;
	user->cur_file_dir = 0;
	user->cur_file_sub = 0;
	user->cur_mail_area = 0;
	user->cur_mail_conf = 0;
	user->timeson = 0;
	user->defprotocol = 1;
	user->defarchiver = 1;
	user->nodemsgs = 1;
	user->codepage = conf.codepage;
	user->exteditor = 2;
	user->bwavestyle = 0;
	user->signature = strdup("");
	user->autosig = 0;
	user->dopipe = 0;
	user->qwke = 0;
	inst_user(user);

	return user;
}
