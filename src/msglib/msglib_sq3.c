#include <sqlite3.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include "msglib.h"
#include "msglib_sq3.h"
#include "../bbs.h"
#include "../../deps/libuuid/uuid.h"
#include <unistd.h>

extern struct bbs_config conf;

char *safe_strdup(const char *str) {
	if (str == NULL) {
		return NULL;
	}

	return strdup(str);
}

static int open_sq3_database(const char *path, sqlite3 **db) {
	const char *create_sql = "CREATE TABLE IF NOT EXISTS msgs(id INTEGER PRIMARY KEY, sender TEXT, recipient TEXT, subject TEXT, date INTEGER, mattribs INTEGER, daddress TEXT, oaddress TEXT, msgid TEXT, replyid TEXT, body TEXT);";
	const char *create_sql2 = "CREATE TABLE IF NOT EXISTS lastread(userid INTEGER, messageid INTEGER);";
	const char *create_sql3 = "CREATE TABLE IF NOT EXISTS seenbys(msgid INTEGER, seenby TEXT);";
	int rc;
	char *err_msg;

	char fpath[PATH_MAX];

	snprintf(fpath, sizeof fpath, "%s.sq3", path);

	if (sqlite3_open(fpath, db) != SQLITE_OK) {
		dolog("Unable to open sq3 mail database");
		return 0;
	}
	sqlite3_busy_timeout(*db, 5000);

	rc = sqlite3_exec(*db, create_sql, 0, 0, &err_msg);
	if (rc != SQLITE_OK) {
		dolog("Unable to create msgs table: %s", err_msg);
		free(err_msg);
		sqlite3_close(*db);
		return 0;
	}
	rc = sqlite3_exec(*db, create_sql2, 0, 0, &err_msg);
	if (rc != SQLITE_OK) {
		dolog("Unable to create lastread table: %s", err_msg);
		free(err_msg);
		sqlite3_close(*db);
		return 0;
	}

	rc = sqlite3_exec(*db, create_sql3, 0, 0, &err_msg);
	if (rc != SQLITE_OK) {
		dolog("Unable to create seenbys table: %s", err_msg);
		free(err_msg);
		sqlite3_close(*db);
		return 0;
	}

	return 1;
}

struct msg_headers *sq3_read_message_headers(int msgconf, int msgarea, struct user_record *user, int personal) {
	struct msg_t *msg;
	struct ptr_vector vec;
	int to_us;
	int i;
	int z;
	int j;
	int k;
	char buffer[256];
	const char *sql = "SELECT id, sender, recipient, subject, date, mattribs, daddress, oaddress, msgid, replyid FROM msgs";
	const char *sql2 = "SELECT id, sender, recipient, subject, date, mattribs, daddress, oaddress, msgid, replyid FROM msgs WHERE recipient = ? or recipient = ? COLLATE NOCASE";
	const char *sql3 = "SELECT seenby FROM seenbys WHERE msgid = ?";

	sqlite3 *dbase;
	sqlite3_stmt *res;
	sqlite3_stmt *res2;

	struct fido_addr *dest;
	struct msg_headers *msghs = NULL;
	struct mail_conference *mc = ptr_vector_get(&conf.mail_conferences, msgconf);
	assert(mc != NULL);
	struct mail_area *area = ptr_vector_get(&mc->mail_areas, msgarea);
	assert(area != NULL);

	if (!open_sq3_database(area->path, &dbase)) {
		return NULL;
	}

	if (!personal) {
		if (sqlite3_prepare_v2(dbase, sql, strlen(sql), &res, NULL) != SQLITE_OK) {
			dolog("Error prepareing sql line 81");
			sqlite3_close(dbase);
			return NULL;
		}
	} else {
		snprintf(buffer, sizeof buffer, "%s %s", user->firstname, user->lastname);
		if (sqlite3_prepare_v2(dbase, sql2, strlen(sql2), &res, NULL) != SQLITE_OK) {
			dolog("Error prepareing sql line 88");
			sqlite3_close(dbase);
			return NULL;
		}
		sqlite3_bind_text(res, 1, user->loginname, -1, 0);
		sqlite3_bind_text(res, 2, buffer, -1, 0);
	}

	init_ptr_vector(&vec);
	msghs = (struct msg_headers *)malloz(sizeof(struct msg_headers));
	msghs->msg_count = 0;
	msghs->base_type = BASE_TYPE_SQ3;
	while (sqlite3_step(res) == SQLITE_ROW) {
		uint32_t mattrib = sqlite3_column_int(res, 5);
		msg = (struct msg_t *)malloz(sizeof(struct msg_t));
		msg->msg_no = sqlite3_column_int(res, 0);
		msg->from = safe_strdup(sqlite3_column_text(res, 1));
		msg->to = safe_strdup(sqlite3_column_text(res, 2));
		msg->subject = safe_strdup(sqlite3_column_text(res, 3));
		msg->msgwritten = sqlite3_column_int(res, 4);
		msg->msg_h = (uint32_t *)malloz(sizeof(uint32_t));
		*(uint32_t *)(msg->msg_h) = mattrib;
		msg->oaddress = safe_strdup(sqlite3_column_text(res, 7));
		msg->daddress = safe_strdup(sqlite3_column_text(res, 6));
		msg->msgid = safe_strdup(sqlite3_column_text(res, 8));
		msg->replyid = safe_strdup(sqlite3_column_text(res, 9));
		msg->tz_offset = 0;
		msg->seenby = NULL;
		msg->isutf8 = 0;

		if (mattrib & SQ3_MSG_PRIVATE) {
			if (!msg_is_to(user, msg->to, msg->daddress, mc->nettype, area->realnames, mc) &&
			    !msg_is_from(user, msg->from, msg->oaddress, mc->nettype, area->realnames, mc) &&
			    !msg_is_to(user, msg->to, msg->daddress, mc->nettype, !area->realnames, mc) &&
			    !msg_is_from(user, msg->from, msg->oaddress, mc->nettype, !area->realnames, mc)) {

				free(msg->replyid);
				free(msg->msgid);
				free(msg->daddress);
				free(msg->oaddress);
				free(msg->msg_h);
				free(msg->subject);
				free(msg->to);
				free(msg->from);
				free(msg);
				continue;
			}
		}

		if (sqlite3_prepare_v2(dbase, sql3, strlen(sql3), &res2, NULL) != SQLITE_OK) {
			dolog("Error preparing SQL for seenbys");
			free(msg->replyid);
			free(msg->msgid);
			free(msg->daddress);
			free(msg->oaddress);
			free(msg->msg_h);
			free(msg->subject);
			free(msg->to);
			free(msg->from);
			free(msg);
			continue;
		}
		sqlite3_bind_int(res2, 1, msg->msg_no);
		if (sqlite3_step(res2) == SQLITE_ROW) {
			msg->seenby = safe_strdup(sqlite3_column_text(res2, 0));
		}
		sqlite3_finalize(res2);
		ptr_vector_append(&vec, msg);
	}

	sqlite3_finalize(res);
	sqlite3_close(dbase);

	if (ptr_vector_len(&vec) == 0) {
		destroy_ptr_vector(&vec);
		free(msghs);
		return NULL;
	}

	msghs->msg_count = ptr_vector_len(&vec);
	msghs->msgs = (struct msg_t **)consume_ptr_vector(&vec);

	return msghs;
}

int sq3_message_lastread(const char *db, int uid) {
	sqlite3 *dbase;
	sqlite3_stmt *res;
	int ret;

	static const char *sql = "SELECT messageid FROM lastread WHERE userid = ?";

	if (!open_sq3_database(db, &dbase)) {
		return -1;
	}

	if (sqlite3_prepare_v2(dbase, sql, strlen(sql), &res, NULL) != SQLITE_OK) {
		dolog("Error prepareing sql line 144");
		sqlite3_close(dbase);
		return -1;
	}

	sqlite3_bind_int(res, 1, uid);

	ret = -1;

	if (sqlite3_step(res) == SQLITE_ROW) {
		ret = sqlite3_column_int(res, 0);
	}

	sqlite3_finalize(res);
	sqlite3_close(dbase);

	return ret;
}

int sq3_message_highread(const char *db, int uid) {
	return sq3_message_lastread(db, uid);
}

void sq3_write_lasthighread(const char *db, struct user_record *user, int lastread, int highread) {
	sqlite3 *dbase;
	sqlite3_stmt *res;
	static const char *sql1 = "UPDATE lastread SET messageid=? WHERE userid = ?";
	static const char *sql2 = "INSERT INTO lastread (userid, messageid) VALUES(?, ?)";
	int lr = sq3_message_lastread(db, user->id);

	if (!open_sq3_database(db, &dbase)) {
		return;
	}

	if (lr == -1) {
		if (sqlite3_prepare_v2(dbase, sql2, strlen(sql2), &res, NULL) != SQLITE_OK) {
			dolog("Error prepareing sql line 180");
			sqlite3_close(dbase);
			return;
		}
		sqlite3_bind_int(res, 1, user->id);
		sqlite3_bind_int(res, 2, highread);
	} else {
		if (sqlite3_prepare_v2(dbase, sql1, strlen(sql1), &res, NULL) != SQLITE_OK) {
			dolog("Error prepareing sql line 188");
			sqlite3_close(dbase);
			return;
		}
		sqlite3_bind_int(res, 1, highread);
		sqlite3_bind_int(res, 2, user->id);
	}

	sqlite3_step(res);

	sqlite3_finalize(res);
	sqlite3_close(dbase);
}

int sq3_write_message(struct msg_base_t *mb, const char *to, const char *from, const char *subj, const char *body, const char *destaddr, struct msg_t *inreplyto, time_t *dwritten, int dosem) {
	char buffer[256];
	uuid_t magi_msgid;
	uuid_t qwk_msgid;
	char qwkuuid[38];
	int z;
	int sem_fd;
	time_t msgdate;
	uint32_t attribs;
	char *oaddress = NULL;
	char *daddress = NULL;
	char *msgid = NULL;
	char *replyid = NULL;
	sqlite3 *dbase;
	sqlite3_stmt *res;
	const char *sql = "INSERT INTO msgs(sender, recipient, subject, date, mattribs, daddress, oaddress, msgid, replyid, body) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";

	if (dwritten == NULL) {
		msgdate = utc_to_local(time(NULL));
	} else {
		msgdate = *dwritten;
	}

	attribs = 0;

	attribs |= SQ3_MSG_LOCAL;

	if (mb->ma->type == TYPE_ECHOMAIL_AREA || mb->ma->type == TYPE_NEWSGROUP_AREA) {
		if (mb->mc->nettype == NETWORK_FIDO) {
			if (mb->mc->fidoaddr->point) {
				snprintf(buffer, sizeof buffer, "%d:%d/%d.%d",
				         mb->mc->fidoaddr->zone, mb->mc->fidoaddr->net, mb->mc->fidoaddr->node,
				         mb->mc->fidoaddr->point);
			} else {
				snprintf(buffer, sizeof buffer, "%d:%d/%d",
				         mb->mc->fidoaddr->zone, mb->mc->fidoaddr->net, mb->mc->fidoaddr->node);
			}
			oaddress = strdup(buffer);
			snprintf(buffer, sizeof buffer, "%d:%d/%d.%d %08lx",
			         mb->mc->fidoaddr->zone,
			         mb->mc->fidoaddr->net,
			         mb->mc->fidoaddr->node,
			         mb->mc->fidoaddr->point,
			         generate_msgid());

			msgid = strdup(buffer);

			if (inreplyto != NULL && inreplyto->msgid != NULL) {
				replyid = strdup(inreplyto->msgid);
			}

		} else if (mb->mc->nettype == NETWORK_MAGI) {
			snprintf(buffer, sizeof buffer, "%d", mb->mc->maginode);
			oaddress = strdup(buffer);

			memset(buffer, 0, sizeof buffer);
			uuid_generate(magi_msgid);
			uuid_unparse_lower(magi_msgid, buffer);

			msgid = strdup(buffer);

			if (inreplyto != NULL && inreplyto->msgid != NULL) {
				replyid = strdup(inreplyto->msgid);
			}

		} else if (mb->mc->nettype == NETWORK_QWK) {
			oaddress = safe_strdup(conf.bwave_name);

			if (conf.external_address != NULL) {
				memset(qwkuuid, 0, sizeof qwkuuid);
				uuid_generate(qwk_msgid);
				uuid_unparse_lower(qwk_msgid, qwkuuid);
				snprintf(buffer, sizeof buffer, "<%s@%s>", qwkuuid, conf.external_address);

				msgid = strdup(buffer);

				if (inreplyto != NULL && inreplyto->msgid != NULL) {
					replyid = strdup(inreplyto->msgid);
				}
			}
		}
	} else if (mb->ma->type == TYPE_NETMAIL_AREA) {
		attribs |= SQ3_MSG_PRIVATE;

		if (mb->mc->nettype == NETWORK_FIDO) {
			if (mb->mc->fidoaddr->point) {
				snprintf(buffer, sizeof buffer, "%d:%d/%d.%d",
				         mb->mc->fidoaddr->zone, mb->mc->fidoaddr->net, mb->mc->fidoaddr->node,
				         mb->mc->fidoaddr->point);
			} else {
				snprintf(buffer, sizeof buffer, "%d:%d/%d",
				         mb->mc->fidoaddr->zone, mb->mc->fidoaddr->net, mb->mc->fidoaddr->node);
			}

			oaddress = strdup(buffer);

			if (destaddr != NULL) {
				daddress = strdup(destaddr);
			}
		}
	}

	if (!open_sq3_database(mb->ma->path, &dbase)) {
		free(oaddress);
		free(daddress);
		free(msgid);
		free(replyid);
		return 0;
	}

	if (sqlite3_prepare_v2(dbase, sql, strlen(sql), &res, NULL) != SQLITE_OK) {
		dolog("Error prepareing sql line 314");
		sqlite3_close(dbase);
		free(oaddress);
		free(daddress);
		free(msgid);
		free(replyid);
		return 0;
	}

	sqlite3_bind_text(res, 1, from, -1, 0);
	sqlite3_bind_text(res, 2, to, -1, 0);
	sqlite3_bind_text(res, 3, subj, -1, 0);
	sqlite3_bind_int(res, 4, msgdate);
	sqlite3_bind_int(res, 5, attribs);
	sqlite3_bind_text(res, 6, daddress, -1, 0);
	sqlite3_bind_text(res, 7, oaddress, -1, 0);
	sqlite3_bind_text(res, 8, msgid, -1, 0);
	sqlite3_bind_text(res, 9, replyid, -1, 0);
	sqlite3_bind_text(res, 10, body, -1, 0);

	if (sqlite3_step(res) != SQLITE_DONE) {
		dolog("Failed to add message");
	} else {
		if (dosem) {
			if (mb->ma->type == TYPE_NETMAIL_AREA) {
				if (conf.netmail_sem != NULL) {
					sem_fd = open(conf.netmail_sem, O_RDWR | O_CREAT | O_TRUNC, S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH);
					close(sem_fd);
				}
			} else if (mb->ma->type == TYPE_ECHOMAIL_AREA || mb->ma->type == TYPE_NEWSGROUP_AREA) {
				if (mb->mc->semaphore != NULL) {
					sem_fd = open(mb->mc->semaphore, O_RDWR | O_CREAT | O_TRUNC, S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH);
					close(sem_fd);
				} else if (conf.echomail_sem != NULL) {
					sem_fd = open(conf.echomail_sem, O_RDWR | O_CREAT | O_TRUNC, S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH);
					close(sem_fd);
				}
			}
		}
	}

	sqlite3_finalize(res);
	sqlite3_close(dbase);
	return 1;
}

struct msg_t *sq3_message_header(const char *db, int id, int offset) {
	static const char *sql = "SELECT id, sender, recipient, subject, date, mattribs, daddress, oaddress, msgid, replyid FROM msgs WHERE id=?";
	static const char *sql2 = "SELECT id, sender, recipient, subject, date, mattribs, daddress, oaddress, msgid, replyid FROM msgs ORDER BY ID LIMIT ?, 1";
	static const char *sql3 = "SELECT seenby FROM seenbys WHERE msgid = ?";

	sqlite3 *dbase;
	sqlite3_stmt *res;
	sqlite3_stmt *res2;
	struct msg_t *msg = NULL;
	uint32_t mattrib;
	int offid = id - 1;
	if (!open_sq3_database(db, &dbase)) {
		return NULL;
	}

	if (offset) {
		if (sqlite3_prepare_v2(dbase, sql2, strlen(sql2), &res, NULL) != SQLITE_OK) {
			dolog("Error prepareing sql line 373");
			sqlite3_close(dbase);
			return NULL;
		}
		sqlite3_bind_int(res, 1, offid);
	} else {
		if (sqlite3_prepare_v2(dbase, sql, strlen(sql), &res, NULL) != SQLITE_OK) {
			dolog("Error prepareing sql line 373");
			sqlite3_close(dbase);
			return NULL;
		}
		sqlite3_bind_int(res, 1, id);
	}

	if (sqlite3_step(res) == SQLITE_ROW) {
		msg = (struct msg_t *)malloz(sizeof(struct msg_t));
		msg->msg_no = sqlite3_column_int(res, 0);
		msg->from = safe_strdup(sqlite3_column_text(res, 1));
		msg->to = safe_strdup(sqlite3_column_text(res, 2));
		msg->subject = safe_strdup(sqlite3_column_text(res, 3));
		msg->msgwritten = sqlite3_column_int(res, 4);
		msg->msg_h = (uint32_t *)malloz(sizeof(uint32_t));
		mattrib = sqlite3_column_int(res, 5);
		*(uint32_t *)(msg->msg_h) = mattrib;
		msg->oaddress = safe_strdup(sqlite3_column_text(res, 7));
		msg->daddress = safe_strdup(sqlite3_column_text(res, 6));
		msg->msgid = safe_strdup(sqlite3_column_text(res, 8));
		msg->replyid = safe_strdup(sqlite3_column_text(res, 9));
		msg->seenby = NULL;
		msg->tz_offset = 0;

		if (sqlite3_prepare_v2(dbase, sql3, strlen(sql3), &res2, NULL) != SQLITE_OK) {
			dolog("Error preparing SQL for seenbys");
			free(msg->replyid);
			free(msg->msgid);
			free(msg->daddress);
			free(msg->oaddress);
			free(msg->msg_h);
			free(msg->subject);
			free(msg->to);
			free(msg->from);
			free(msg);
			sqlite3_finalize(res);
			sqlite3_close(dbase);
			return NULL;
		}

		sqlite3_bind_int(res2, 1, msg->msg_no);
		if (sqlite3_step(res2) == SQLITE_ROW) {
			msg->seenby = safe_strdup(sqlite3_column_text(res2, 0));
		}
		sqlite3_finalize(res2);
	}
	sqlite3_finalize(res);
	sqlite3_close(dbase);

	return msg;
}

char *sq3_fetch_body(const char *db, int mid) {
	static const char *sql = "SELECT body FROM msgs WHERE id=?";
	char *body = NULL;
	sqlite3 *dbase;
	sqlite3_stmt *res;
	struct msg_t *msg = NULL;

	if (!open_sq3_database(db, &dbase)) {
		return NULL;
	}

	if (sqlite3_prepare_v2(dbase, sql, strlen(sql), &res, NULL) != SQLITE_OK) {
		dolog("Error prepareing sql line 413");
		sqlite3_close(dbase);
		return NULL;
	}

	sqlite3_bind_int(res, 1, mid);

	if (sqlite3_step(res) == SQLITE_ROW) {
		body = safe_strdup(sqlite3_column_text(res, 0));
	}

	sqlite3_finalize(res);
	sqlite3_close(dbase);

	return body;
}

int sq3_new_message_count(struct msg_base_t *mb, struct user_record *user) {
	static const char *sql = "SELECT sender, recipient, oaddress, daddress, mattribs FROM msgs WHERE id > ?";
	sqlite3 *dbase;
	sqlite3_stmt *res;
	int count = 0;
	int last_read = sq3_message_lastread(mb->ma->path, user->id);
	if (!open_sq3_database(mb->ma->path, &dbase)) {
		return 0;
	}
	if (sqlite3_prepare_v2(dbase, sql, strlen(sql), &res, NULL) != SQLITE_OK) {
		sqlite3_close(dbase);
		dolog("SQL PREPARE Failed");
		return 0;
	}
	sqlite3_bind_int(res, 1, last_read);
	while (sqlite3_step(res) == SQLITE_ROW) {
		const char *to = sqlite3_column_text(res, 1);
		const char *from = sqlite3_column_text(res, 0);
		const char *oaddress = sqlite3_column_text(res, 2);
		const char *daddress = sqlite3_column_text(res, 3);
		if (sqlite3_column_int(res, 4) & SQ3_MSG_PRIVATE) {
			if (!(!msg_is_to(user, to, daddress, mb->mc->nettype, mb->ma->realnames, mb->mc) &&
			      !msg_is_from(user, from, oaddress, mb->mc->nettype, mb->ma->realnames, mb->mc) &&
			      !msg_is_to(user, to, daddress, mb->mc->nettype, !mb->ma->realnames, mb->mc) &&
			      !msg_is_from(user, from, oaddress, mb->mc->nettype, !mb->ma->realnames, mb->mc))) {

				count++;
			}
		} else {
			count++;
		}
	}

	sqlite3_finalize(res);
	sqlite3_close(dbase);

	return count;
}

int sq3_get_active_msg_count(const char *dbpath) {
	static const char *sql = "SELECT COUNT(*) FROM msgs";
	sqlite3 *dbase;
	sqlite3_stmt *res;
	int count;
	if (!open_sq3_database(dbpath, &dbase)) {
		return 0;
	}
	if (sqlite3_prepare_v2(dbase, sql, strlen(sql), &res, NULL) != SQLITE_OK) {
		sqlite3_close(dbase);
		dolog("SQL PREPARE Failed");
		return 0;
	}

	if (sqlite3_step(res) == SQLITE_ROW) {
		count = sqlite3_column_int(res, 0);
	} else {
		count = 0;
	}

	sqlite3_finalize(res);
	sqlite3_close(dbase);

	return count;
}
