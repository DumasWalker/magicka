#include <stdio.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sqlite3.h>
#include "bbs.h"
#include "qwk.h"
#include "mail_utils.h"
#include "libuuid/uuid.h"

extern struct bbs_config conf;
extern struct user_record *gUser;
extern int mynode;
extern int sshBBS;
extern int bbs_stdin;
extern int bbs_stdout;
extern int bbs_stderr;
extern char upload_filename[PATH_MAX];

struct last_read_t {
	int conf;
	int area;
	int last_read;
	int high_read;
};

static struct ptr_vector qwk_last_read;

/*
Microsoft binary (by Jeffery Foy):

   31 - 24    23     22 - 0        <-- bit position
+-----------------+----------+
| exponent | sign | mantissa |
+----------+------+----------+

IEEE (C/Pascal/etc.):

   31     30 - 23    22 - 0        <-- bit position
+----------------------------+
| sign | exponent | mantissa |
+------+----------+----------+
*/

static int safe_atoi(const char *str, int len) {
	int ret = 0;

	for (int i = 0; i < len; i++) {
		if (str[i] < '0' || str[i] > '9') {
			break;
		}
		ret = ret * 10 + (str[i] - '0');
	}
	return ret;
}

int ieee_to_msbin(float *src4, float *dest4) {
	unsigned char *ieee = (unsigned char *)src4;
	unsigned char *msbin = (unsigned char *)dest4;
	unsigned char sign = 0x00;
	unsigned char msbin_exp = 0x00;
	int i;
	/* See _fmsbintoieee() for details of formats   */
	sign = ieee[3] & 0x80;
	msbin_exp |= ieee[3] << 1;
	msbin_exp |= ieee[2] >> 7;
	/* An ieee exponent of 0xfe overflows in MBF    */
	if (msbin_exp == 0xfe) return 1;
	msbin_exp += 2; /* actually, -127 + 128 + 1 */
	for (i = 0; i < 4; i++) msbin[i] = 0;
	msbin[3] = msbin_exp;
	msbin[2] |= sign;
	msbin[2] |= ieee[2] & 0x7f;
	msbin[1] = ieee[1];
	msbin[0] = ieee[0];
	return 0;
}

size_t trimwhitespace(char *out, size_t len, const char *str) {
	if (len == 0)
		return 0;

	const char *end;
	size_t out_size;

	// Trim trailing space
	end = str + strlen(str) - 1;
	while (end > str && isspace((unsigned char)*end)) end--;
	end++;

	// Set output size to minimum of trimmed string length and buffer size minus 1
	out_size = (end - str) < len - 1 ? (end - str) : len - 1;

	// Copy trimmed string and add null terminator
	memcpy(out, str, out_size);
	out[out_size] = 0;

	return out_size;
}

int qwk_scan_email(FILE *messages_dat_fptr, FILE *conf_ndx_fptr, FILE *pers_ndx_fptr, int last_tot) {
	sqlite3 *db;
	sqlite3_stmt *res;
	int rc;
	char *sql = "SELECT sender,subject,date,body,id FROM email WHERE recipient LIKE ? AND seen = 0";
	char *sqlseen = "UPDATE email SET seen = 1 WHERE recipient LIKE ?";
	char buffer[PATH_MAX];
	int z;
	uint32_t ndx;
	float mndx;
	uint8_t zero;
	struct QwkHeader msg_hdr;
	struct tm msgtm;
	uint32_t len, lenbytes;
	float fndx;
	char *msgbuf;
	char *extended_subject = NULL;
	char *extended_from = NULL;
	char *extended_to = NULL;
	char *ptr;
	int tot_msgs = 0;

	snprintf(buffer, PATH_MAX, "%s/email.sq3", conf.bbs_path);
	rc = sqlite3_open(buffer, &db);
	if (rc != SQLITE_OK) {
		dolog("Cannot open database: %s", sqlite3_errmsg(db));
		sqlite3_close(db);
		return tot_msgs;
	}
	sqlite3_busy_timeout(db, 5000);
	rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);

	if (rc == SQLITE_OK) {
		sqlite3_bind_text(res, 1, gUser->loginname, -1, 0);
	} else {
		dolog("Failed to execute statement: %s", sqlite3_errmsg(db));
		sqlite3_finalize(res);
		sqlite3_close(db);
		return tot_msgs;
	}

	while (sqlite3_step(res) == SQLITE_ROW) {
		// write index;
		char *from = strdup(sqlite3_column_text(res, 0));
		int msgno = sqlite3_column_int(res, 4);
		time_t date = sqlite3_column_int(res, 2);
		char *subj = strdup(sqlite3_column_text(res, 1));
		char *body = strdup(sqlite3_column_text(res, 3));

		ndx = ftell(messages_dat_fptr) / 128;
		ndx++;
		fndx = (float)ndx;
		ieee_to_msbin(&fndx, &mndx);
		zero = 0;

		fwrite(&mndx, 4, 1, conf_ndx_fptr);
		fwrite(&zero, 1, 1, conf_ndx_fptr);

		fwrite(&mndx, 4, 1, pers_ndx_fptr);
		fwrite(&zero, 1, 1, pers_ndx_fptr);

		msg_hdr.Msgstat = ' ';

		snprintf(buffer, 7, "%d", msgno);

		memset(msg_hdr.Msgnum, ' ', 7);
		memcpy(msg_hdr.Msgnum, buffer, strlen(buffer));

		localtime_r(&date, &msgtm);

		snprintf(buffer, sizeof buffer, "%02d-%02d-%02d", msgtm.tm_mon + 1, msgtm.tm_mday, msgtm.tm_year - 100);
		memcpy(msg_hdr.Msgdate, buffer, 8);

		snprintf(buffer, sizeof buffer, "%02d:%02d", msgtm.tm_hour, msgtm.tm_min);
		memcpy(msg_hdr.Msgtime, buffer, 5);

		memset(msg_hdr.Msgpass, ' ', 12);
		memset(msg_hdr.Msgrply, ' ', 8);

		memset(msg_hdr.MsgSubj, ' ', 25);
		if (subj != NULL) {
			if (strlen(subj) > 24) {
				if (gUser->qwke) {
					extended_subject = subj;
				}
				memcpy(msg_hdr.MsgSubj, subj, 24);
			} else {
				memcpy(msg_hdr.MsgSubj, subj, strlen(subj));
			}
		} else {
			snprintf(buffer, sizeof buffer, "(Missing Subject)");
			memcpy(msg_hdr.MsgSubj, buffer, strlen(buffer));
		}
		memset(msg_hdr.MsgFrom, ' ', 25);
		if (from != NULL) {
			if (strlen(from) > 24) {
				if (gUser->qwke) {
					extended_from = from;
				}
				memcpy(msg_hdr.MsgFrom, from, 24);
			} else {
				memcpy(msg_hdr.MsgFrom, from, strlen(from));
			}
		} else {
			snprintf(buffer, sizeof buffer, "(Missing From)");
			memcpy(msg_hdr.MsgFrom, buffer, strlen(buffer));
		}
		memset(msg_hdr.MsgTo, ' ', 25);
		if (strlen(gUser->loginname) > 24) {
				if (gUser->qwke) {
					extended_to = gUser->loginname;
				}
				memcpy(msg_hdr.MsgTo, gUser->loginname, 24);
			} else {
				memcpy(msg_hdr.MsgTo, gUser->loginname, strlen(gUser->loginname));
			}

		if (gUser->qwke && (extended_to != NULL || extended_from != NULL || extended_subject != NULL)) {
			stralloc qwkestr = EMPTY_STRALLOC;

			if (extended_to != NULL) {
				stralloc_cats(&qwkestr, "To:");
				stralloc_cats(&qwkestr, extended_to);
				stralloc_append1(&qwkestr, '\r');
				extended_to = NULL;
			}
			if (extended_from != NULL) {
				stralloc_cats(&qwkestr, "From:");
				stralloc_cats(&qwkestr, extended_from);
				stralloc_append1(&qwkestr, '\r');
				extended_from = NULL;
			}
			if (extended_subject != NULL) {
				stralloc_cats(&qwkestr, "Subject:");
				stralloc_cats(&qwkestr, extended_subject);
				stralloc_append1(&qwkestr, '\r');
				extended_subject = NULL;
			}
			stralloc_append1(&qwkestr, '\r');

			ptr = body;

			stralloc_cats(&qwkestr, ptr);
			stralloc_0(&qwkestr);
			free(ptr);
			len = qwkestr.len / 128 + 2;
			lenbytes = len * 128;
			msgbuf = (char *)malloz(lenbytes);
			memset(msgbuf, ' ', lenbytes);
			memcpy(msgbuf, qwkestr.s, qwkestr.len);
			free(qwkestr.s);
		} else {
			ptr = body;

			len = strlen(ptr) / 128 + 2;
			lenbytes = len * 128;
			msgbuf = (char *)malloz(lenbytes);
			memset(msgbuf, ' ', lenbytes);
			memcpy(msgbuf, ptr, strlen(ptr));
			free(ptr);
		}

		for (int h = 0; h < lenbytes; h++) {
			if (msgbuf[h] == '\r') {
				msgbuf[h] = '\xe3';
			}
		}

		for (z = 0; z < lenbytes; z++) {
			if (msgbuf[z] == '\0') {
				msgbuf[z] = ' ';
			}
		}

		snprintf(buffer, 7, "%d", len);
		memset(msg_hdr.Msgrecs, ' ', 6);
		memcpy(msg_hdr.Msgrecs, buffer, strlen(buffer));

		msg_hdr.Msglive = 0xE1;
		msg_hdr.Msgarealo = 0;
		msg_hdr.Msgareahi = 0;

		msg_hdr.Msgoffhi = (ndx >> 8) & 0xff;
		msg_hdr.Msgofflo = ndx & 0xff;

		msg_hdr.Msgtagp = ' ';

		fwrite(&msg_hdr, sizeof(struct QwkHeader), 1, messages_dat_fptr);
		fwrite(msgbuf, lenbytes - 128, 1, messages_dat_fptr);

		free(msgbuf);
		free(from);
		free(subj);
		tot_msgs++;
	}
	sqlite3_finalize(res);
	sqlite3_close(db);

	return tot_msgs;
}

int qwk_scan_area(int confid, int areaid, FILE *messages_dat_fptr, FILE *conf_ndx_fptr, FILE *pers_ndx_fptr, int last_tot) {
	int tot_msgs = 0;
	int all_unread;
	struct msg_base_t *mb;
	int high_read;
	int last_read;
	int i;
	int k;
	int z;
	struct msg_headers *msghs = read_message_headers(confid, areaid, gUser, 0);
	uint32_t ndx;
	float mndx;
	uint8_t zero;
	struct QwkHeader msg_hdr;
	char realname[66];
	char buffer[256];
	struct tm msgtm;
	uint32_t len, lenbytes;
	float fndx;
	char *msgbuf;
	char *extended_subject = NULL;
	char *extended_from = NULL;
	char *extended_to = NULL;
	char *ptr;

	if (msghs == NULL) {
		return tot_msgs;
	}

	snprintf(realname, 65, "%s %s", gUser->firstname, gUser->lastname);

	struct mail_area *ma = get_area(confid, areaid);

	mb = open_message_base(confid, areaid);

	if (!mb) {
		dolog("Error opening message base ... %s", ma->path);
		free_message_headers(msghs);
		return tot_msgs;
	}
	all_unread = 0;

	high_read = get_message_highread(mb, gUser->id);

	if (high_read == -1) {
		high_read = 0;
		all_unread = 1;
	} else if (high_read == 0) {
		all_unread = 1;
	}

	if (all_unread == 0) {
		k = high_read;
		for (i = 0; i < msghs->msg_count; i++) {
			if (get_message_number(msghs, i) == k) {
				break;
			}
		}
		i += 1;
	} else {
		i = 0;
	}

	for (k = i; k < msghs->msg_count; k++) {
		// write index;
		ndx = ftell(messages_dat_fptr) / 128;
		ndx++;
		fndx = (float)ndx;
		ieee_to_msbin(&fndx, &mndx);
		zero = 0;

		fwrite(&mndx, 4, 1, conf_ndx_fptr);
		fwrite(&zero, 1, 1, conf_ndx_fptr);
		if (msghs->msgs[k]->to != NULL) {
			if (strcasecmp(msghs->msgs[k]->to, gUser->loginname) == 0 || strncasecmp(msghs->msgs[k]->to, realname, 42) == 0) {
				fwrite(&mndx, 4, 1, pers_ndx_fptr);
				fwrite(&zero, 1, 1, pers_ndx_fptr);
			}
		}
		msg_hdr.Msgstat = ' ';
		snprintf(buffer, 7, "%d", msghs->msgs[k]->msg_no);
		memset(msg_hdr.Msgnum, ' ', 7);
		memcpy(msg_hdr.Msgnum, buffer, strlen(buffer));

		localtime_r(&msghs->msgs[k]->msgwritten, &msgtm);

		snprintf(buffer, sizeof buffer, "%02d-%02d-%02d", msgtm.tm_mon + 1, msgtm.tm_mday, msgtm.tm_year - 100);
		memcpy(msg_hdr.Msgdate, buffer, 8);

		snprintf(buffer, sizeof buffer, "%02d:%02d", msgtm.tm_hour, msgtm.tm_min);
		memcpy(msg_hdr.Msgtime, buffer, 5);

		memset(msg_hdr.Msgpass, ' ', 12);
		memset(msg_hdr.Msgrply, ' ', 8);

		memset(msg_hdr.MsgSubj, ' ', 25);
		if (msghs->msgs[k]->subject != NULL) {
			if (strlen(msghs->msgs[k]->subject) > 24) {
				if (gUser->qwke) {
					extended_subject = msghs->msgs[k]->subject;
				}
				memcpy(msg_hdr.MsgSubj, msghs->msgs[k]->subject, 24);
			} else {
				memcpy(msg_hdr.MsgSubj, msghs->msgs[k]->subject, strlen(msghs->msgs[k]->subject));
			}
		} else {
			snprintf(buffer, sizeof buffer, "(Missing Subject)");
			memcpy(msg_hdr.MsgSubj, buffer, strlen(buffer));
		}
		memset(msg_hdr.MsgFrom, ' ', 25);
		if (msghs->msgs[k]->from != NULL) {
			if (strlen(msghs->msgs[k]->from) > 24) {
				if (gUser->qwke) {
					extended_from = msghs->msgs[k]->from;
				}
				memcpy(msg_hdr.MsgFrom, msghs->msgs[k]->from, 24);
			} else {
				memcpy(msg_hdr.MsgFrom, msghs->msgs[k]->from, strlen(msghs->msgs[k]->from));
			}
		} else {
			snprintf(buffer, sizeof buffer, "(Missing From)");
			memcpy(msg_hdr.MsgFrom, buffer, strlen(buffer));
		}
		memset(msg_hdr.MsgTo, ' ', 25);
		if (msghs->msgs[k]->to != NULL) {
			if (strlen(msghs->msgs[k]->to) > 24) {
				if (gUser->qwke) {
					extended_to = msghs->msgs[k]->to;
				}
				memcpy(msg_hdr.MsgTo, msghs->msgs[k]->to, 24);
			} else {
				memcpy(msg_hdr.MsgTo, msghs->msgs[k]->to, strlen(msghs->msgs[k]->to));
			}
		} else {
			snprintf(buffer, sizeof buffer, "(Missing To)");
			memcpy(msg_hdr.MsgTo, buffer, strlen(buffer));
		}

		if (gUser->qwke && (extended_to != NULL || extended_from != NULL || extended_subject != NULL)) {
			stralloc qwkestr = EMPTY_STRALLOC;

			if (extended_to != NULL) {
				stralloc_cats(&qwkestr, "To:");
				stralloc_cats(&qwkestr, extended_to);
				stralloc_append1(&qwkestr, '\r');
				extended_to = NULL;
			}
			if (extended_from != NULL) {
				stralloc_cats(&qwkestr, "From:");
				stralloc_cats(&qwkestr, extended_from);
				stralloc_append1(&qwkestr, '\r');
				extended_from = NULL;
			}
			if (extended_subject != NULL) {
				stralloc_cats(&qwkestr, "Subject:");
				stralloc_cats(&qwkestr, extended_subject);
				stralloc_append1(&qwkestr, '\r');
				extended_subject = NULL;
			}
			stralloc_append1(&qwkestr, '\r');

			ptr = load_message_text(mb, msghs->msgs[k]);

			stralloc_cats(&qwkestr, ptr);
			stralloc_0(&qwkestr);
			free(ptr);
			len = qwkestr.len / 128 + 2;
			lenbytes = len * 128;
			msgbuf = (char *)malloz(lenbytes);
			memset(msgbuf, ' ', lenbytes);
			memcpy(msgbuf, qwkestr.s, qwkestr.len);
			free(qwkestr.s);
		} else {
			ptr = load_message_text(mb, msghs->msgs[k]);

			len = strlen(ptr) / 128 + 2;
			lenbytes = len * 128;
			msgbuf = (char *)malloz(lenbytes);
			memset(msgbuf, ' ', lenbytes);
			memcpy(msgbuf, ptr, strlen(ptr));
			free(ptr);
		}

		for (int h = 0; h < lenbytes; h++) {
			if (msgbuf[h] == '\r') {
				msgbuf[h] = '\xe3';
			}
		}

		for (z = 0; z < lenbytes; z++) {
			if (msgbuf[z] == '\0') {
				msgbuf[z] = ' ';
			}
		}

		snprintf(buffer, 7, "%d", len);
		memset(msg_hdr.Msgrecs, ' ', 6);
		memcpy(msg_hdr.Msgrecs, buffer, strlen(buffer));

		msg_hdr.Msglive = 0xE1;
		msg_hdr.Msgarealo = ma->qwkconfno & 0xff;
		msg_hdr.Msgareahi = (ma->qwkconfno >> 8) & 0xff;

		msg_hdr.Msgoffhi = (ndx >> 8) & 0xff;
		msg_hdr.Msgofflo = ndx & 0xff;

		msg_hdr.Msgtagp = ' ';

		fwrite(&msg_hdr, sizeof(struct QwkHeader), 1, messages_dat_fptr);
		fwrite(msgbuf, lenbytes - 128, 1, messages_dat_fptr);

		last_read = get_message_number(msghs, k);
		if (high_read < last_read) {
			high_read = last_read;
		}

		free(msgbuf);
		tot_msgs++;
		if (tot_msgs + last_tot == conf.bwave_max_msgs) {
			break;
		}
	}

	struct last_read_t *qwklr = malloz(sizeof(struct last_read_t));

	qwklr->conf = confid;
	qwklr->area = areaid;
	qwklr->last_read = last_read;
	qwklr->high_read = high_read;

	ptr_vector_append(&qwk_last_read, qwklr);

	close_message_base(mb);
	free_message_headers(msghs);
	return tot_msgs;
}

void qwk_create_packet() {
	char buffer[PATH_MAX];
	char archive[PATH_MAX];
	// char filelist[PATH_MAX];
	sqlite3 *db;
	sqlite3_stmt *res;
	int rc;
	char *sqlseen = "UPDATE email SET seen = 1 WHERE recipient LIKE ?";
	struct ptr_vector flist;
	FILE *fptr;
	FILE *messages_dat_fptr;
	FILE *conf_ndx_fptr;
	FILE *pers_ndx_fptr;
	struct tm timetm;
	time_t thetime;
	int tot_areas = 0;
	int tot_msgs = 0;
	int last_tot;
	struct stat s;
	static const char *chdr = "Produced by Qmail...Copyright (c) 1987 by Sparkware.  All Rights Reserved";
	int stout;
	int stin;
	int sterr;
	int ret;
	char **args;
	char *cmd;
	pid_t pid;
	struct msg_base_t *mb;

	for (size_t i = 0; i < ptr_vector_len(&conf.mail_conferences); i++) {
		struct mail_conference *mc = ptr_vector_get(&conf.mail_conferences, i);
		for (size_t j = 0; j < ptr_vector_len(&mc->mail_areas); j++) {
			if (msgbase_is_subscribed(i, j)) {
				tot_areas++;
			}
		}
	}

	s_printf("\r\n");


	if (tot_areas == 0) {
		s_printf(get_string(224));
		s_printf(get_string(6));
		s_getchar();
		return;
	}

	snprintf(buffer, sizeof buffer, "%s/node%d", conf.bbs_path, mynode);

	if (stat(buffer, &s) != 0) {
		mkdir(buffer, 0755);
	}

	snprintf(buffer, sizeof buffer, "%s/node%d/qwk/", conf.bbs_path, mynode);

	if (stat(buffer, &s) == 0) {
		recursive_delete(buffer);
	}
	mkdir(buffer, 0755);

	snprintf(buffer, sizeof buffer, "%s/node%d/qwk/MESSAGES.DAT", conf.bbs_path, mynode);
	messages_dat_fptr = fopen(buffer, "wb");
	if (!messages_dat_fptr) {
		// ERROR!
		return;
	}

	init_ptr_vector(&flist);
	ptr_vector_append(&flist, strdup(buffer));

	memset(buffer, ' ', 128);
	memcpy(buffer, chdr, strlen(chdr));

	fwrite(buffer, 128, 1, messages_dat_fptr);

	snprintf(buffer, sizeof buffer, "%s/node%d/qwk/PERSONAL.NDX", conf.bbs_path, mynode);

	ptr_vector_append(&flist, strdup(buffer));

	pers_ndx_fptr = fopen(buffer, "wb");
	if (!pers_ndx_fptr) {
		// ERROR
		ptr_vector_apply(&flist, free);
		destroy_ptr_vector(&flist);
		fclose(messages_dat_fptr);
		return;
	}

	init_ptr_vector(&qwk_last_read);

	// create MESSAGES.DAT
	snprintf(buffer, sizeof buffer, "%s/node%d/qwk/000.NDX", conf.bbs_path, mynode);
	ptr_vector_append(&flist, strdup(buffer));
	conf_ndx_fptr = fopen(buffer, "wb");
	if (!conf_ndx_fptr) {
		// ERROR
		fclose(pers_ndx_fptr);
		fclose(messages_dat_fptr);
		ptr_vector_apply(&flist, free);
		destroy_ptr_vector(&flist);
		ptr_vector_apply(&qwk_last_read, free);
		destroy_ptr_vector(&qwk_last_read);
		return;
	}
	tot_msgs = qwk_scan_email(messages_dat_fptr, conf_ndx_fptr, pers_ndx_fptr, 0);
	s_printf(get_string(195), "Private Email", "Private Email", tot_msgs);
	fclose(conf_ndx_fptr);
	size_t i;
	size_t j;

	for (i = 0; i < ptr_vector_len(&conf.mail_conferences); i++) {
		struct mail_conference *mc = ptr_vector_get(&conf.mail_conferences, i);
		for (j = 0; j < ptr_vector_len(&mc->mail_areas); j++) {
			struct mail_area *ma = ptr_vector_get(&mc->mail_areas, j);
			if (check_security(gUser, ma->read_sec_level, &ma->rd_req_flags, &ma->rd_not_flags) && ma->qwkconfno > 0 && ma->type != TYPE_NETMAIL_AREA && msgbase_is_subscribed(i, j)) {
				snprintf(buffer, sizeof buffer, "%s/node%d/qwk/%03d.NDX", conf.bbs_path, mynode, ma->qwkconfno);
				ptr_vector_append(&flist, strdup(buffer));
				conf_ndx_fptr = fopen(buffer, "wb");
				if (!conf_ndx_fptr) {
					// ERROR
					fclose(pers_ndx_fptr);
					fclose(messages_dat_fptr);
					ptr_vector_apply(&flist, free);
					destroy_ptr_vector(&flist);
					ptr_vector_apply(&qwk_last_read, free);
					destroy_ptr_vector(&qwk_last_read);
					return;
				}
				last_tot = tot_msgs;
				tot_msgs += qwk_scan_area(i, j, messages_dat_fptr, conf_ndx_fptr, pers_ndx_fptr, last_tot);
				s_printf(get_string(195), mc->name, ma->name, tot_msgs - last_tot);
				fclose(conf_ndx_fptr);

			}
			if (tot_msgs == conf.bwave_max_msgs) {
				break;
			}
		}
		if (j != ptr_vector_len(&mc->mail_areas)) {
			for (j=j+1; j < ptr_vector_len(&mc->mail_areas);j++) {
				struct mail_area *ma = ptr_vector_get(&mc->mail_areas, j);
				if (check_security(gUser, ma->read_sec_level, &ma->rd_req_flags, &ma->rd_not_flags) && ma->qwkconfno > 0 && ma->type != TYPE_NETMAIL_AREA && msgbase_is_subscribed(i, j)) {
					snprintf(buffer, sizeof buffer, "%s/node%d/qwk/%03d.NDX", conf.bbs_path, mynode, ma->qwkconfno);
					ptr_vector_append(&flist, strdup(buffer));
					conf_ndx_fptr = fopen(buffer, "wb");
					if (!conf_ndx_fptr) {
						// ERROR
						fclose(pers_ndx_fptr);
						fclose(messages_dat_fptr);
						ptr_vector_apply(&flist, free);
						destroy_ptr_vector(&flist);
						ptr_vector_apply(&qwk_last_read, free);
						destroy_ptr_vector(&qwk_last_read);
						return;
					}
					fclose(conf_ndx_fptr);
				}
			}
		}
		if (tot_msgs == conf.bwave_max_msgs) {
			break;
		}
	}
	if (i != ptr_vector_len(&conf.mail_conferences)) {
		for (i = i + 1; i < ptr_vector_len(&conf.mail_conferences); i++) {
			struct mail_conference *mc = ptr_vector_get(&conf.mail_conferences, i);
			for (j=0; j < ptr_vector_len(&mc->mail_areas);j++) {
				struct mail_area *ma = ptr_vector_get(&mc->mail_areas, j);
				if (check_security(gUser, ma->read_sec_level, &ma->rd_req_flags, &ma->rd_not_flags) && ma->qwkconfno > 0 && ma->type != TYPE_NETMAIL_AREA && msgbase_is_subscribed(i, j)) {
					snprintf(buffer, sizeof buffer, "%s/node%d/qwk/%03d.NDX", conf.bbs_path, mynode, ma->qwkconfno);
					ptr_vector_append(&flist, strdup(buffer));
					conf_ndx_fptr = fopen(buffer, "wb");
					if (!conf_ndx_fptr) {
						// ERROR
						fclose(pers_ndx_fptr);
						fclose(messages_dat_fptr);
						ptr_vector_apply(&flist, free);
						destroy_ptr_vector(&flist);
						ptr_vector_apply(&qwk_last_read, free);
						destroy_ptr_vector(&qwk_last_read);
						return;
					}
					fclose(conf_ndx_fptr);
				}
			}
		}
	}
	fclose(pers_ndx_fptr);
	fclose(messages_dat_fptr);

	if (gUser->qwke) {
		snprintf(buffer, sizeof buffer, "%s/node%d/qwk/TOREADER.EXT", conf.bbs_path, mynode);
		ptr_vector_append(&flist, strdup(buffer));
		fptr = fopen(buffer, "w");
		if (!fptr) {
			// error
			ptr_vector_apply(&flist, free);
			destroy_ptr_vector(&flist);
			ptr_vector_apply(&qwk_last_read, free);
			destroy_ptr_vector(&qwk_last_read);
			return;
		}
		fprintf(fptr, "ALIAS %s\r\n", gUser->loginname);
		fprintf(fptr, "AREA 0 LPH\r\n");
		for (size_t i = 0; i < ptr_vector_len(&conf.mail_conferences); i++) {
			struct mail_conference *mc = ptr_vector_get(&conf.mail_conferences, i);
			for (size_t j = 0; j < ptr_vector_len(&mc->mail_areas); j++) {
				struct mail_area *ma = ptr_vector_get(&mc->mail_areas, j);
				if (check_security(gUser, ma->read_sec_level, &ma->rd_req_flags, &ma->rd_not_flags) && ma->qwkconfno > 0 && ma->type != TYPE_NETMAIL_AREA && msgbase_is_subscribed(i, j)) {
					stralloc areaopts = EMPTY_STRALLOC;
					if (check_security(gUser, ma->write_sec_level, &ma->wr_req_flags, &ma->wr_not_flags)) {
						stralloc_append1(&areaopts, 'O');
					} else {
						stralloc_append1(&areaopts, 'R');
					}
					if (ma->type == TYPE_ECHOMAIL_AREA || ma->type == TYPE_NEWSGROUP_AREA) {
						stralloc_append1(&areaopts, 'E');
					} else {
						stralloc_append1(&areaopts, 'L');
					}
					stralloc_0(&areaopts);

					fprintf(fptr, "AREA %d %s\r\n", ma->qwkconfno, areaopts.s);
					free(areaopts.s);
				}
			}
		}
		fclose(fptr);
	}

	snprintf(buffer, sizeof buffer, "%s/node%d/qwk/DOOR.ID", conf.bbs_path, mynode);
	ptr_vector_append(&flist, strdup(buffer));
	fptr = fopen(buffer, "w");
	if (!fptr) {
		// error
		ptr_vector_apply(&flist, free);
		destroy_ptr_vector(&flist);
		ptr_vector_apply(&qwk_last_read, free);
		destroy_ptr_vector(&qwk_last_read);
		return;
	}

	fprintf(fptr, "DOOR = Magicka\r\n");
	fprintf(fptr, "VERSION = %d.%d-%s\r\n", VERSION_MAJOR, VERSION_MINOR, VERSION_STR);
	fprintf(fptr, "SYSTEM = Magicka BBS %d.%d\r\n", VERSION_MAJOR, VERSION_MINOR);
	fprintf(fptr, "MIXEDCASE = YES\r\n");

	fclose(fptr);

	snprintf(buffer, sizeof buffer, "%s/node%d/qwk/CONTROL.DAT", conf.bbs_path, mynode);
	ptr_vector_append(&flist, strdup(buffer));

	fptr = fopen(buffer, "w");
	if (!fptr) {
		// error
		ptr_vector_apply(&flist, free);
		destroy_ptr_vector(&flist);
		ptr_vector_apply(&qwk_last_read, free);
		destroy_ptr_vector(&qwk_last_read);
		return;
	}

	fprintf(fptr, "%s\r\n", conf.bbs_name);
	if (conf.bbs_location == NULL) {
		fprintf(fptr, "Somewhere, The World\r\n");
	} else {
		fprintf(fptr, "%s\r\n", conf.bbs_location);
	}
	fprintf(fptr, "000-000-0000\r\n");
	fprintf(fptr, "%s\r\n", conf.sysop_name);
	fprintf(fptr, "99999,%s\r\n", conf.bwave_name);
	thetime = time(NULL);
	localtime_r(&thetime, &timetm);
	fprintf(fptr, "%02d-%02d-%04d,%02d:%02d:%02d\r\n", timetm.tm_mon + 1, timetm.tm_mday, timetm.tm_year + 1900, timetm.tm_hour, timetm.tm_min, timetm.tm_sec);

	fprintf(fptr, "%s\r\n", gUser->loginname);

	fprintf(fptr, "\r\n");
	fprintf(fptr, "0\r\n");
	fprintf(fptr, "%d\r\n", tot_msgs);
	fprintf(fptr, "%d\r\n", tot_areas + 1);

	fprintf(fptr, "0\r\n");
	if (gUser->qwke) {
		fprintf(fptr, "Private Email\r\n");
	} else {
		fprintf(fptr, "EMAIL\r\n");
	}

	for (size_t i = 0; i < ptr_vector_len(&conf.mail_conferences); i++) {
		struct mail_conference *mc = ptr_vector_get(&conf.mail_conferences, i);
		for (size_t j = 0; j < ptr_vector_len(&mc->mail_areas); j++) {
			struct mail_area *ma = ptr_vector_get(&mc->mail_areas, j);
			if (check_security(gUser, ma->read_sec_level, &ma->rd_req_flags, &ma->rd_not_flags) && ma->qwkconfno > 0 && ma->type != TYPE_NETMAIL_AREA && msgbase_is_subscribed(i, j)) {
				fprintf(fptr, "%d\r\n", ma->qwkconfno);
				if (gUser->qwke) {
					fprintf(fptr, "%s: %s\r\n", mc->name, ma->name);
				} else {
					fprintf(fptr, "%s\r\n", ma->qwkname);
				}
			}
		}
	}

	fclose(fptr);

	if (tot_msgs > 0) {
		// create archive
		snprintf(archive, sizeof archive, "%s/node%d/%s.QWK", conf.bbs_path, mynode, conf.bwave_name);

		struct archiver *arc = ptr_vector_get(&conf.archivers, gUser->defarchiver - 1);
		assert(arc != NULL);


		for (size_t file = 0; file < ptr_vector_len(&flist); file++) {
			char *b = buffer;
			size_t blen = sizeof buffer;
			for (const char *p = arc->pack; *p != '\0' && blen >= 1; ++p) {
				if (*p != '*') {
					*b++ = *p;
					--blen;
					continue;
				}
				p++;
				size_t alen = 0;
				if (*p == 'a') {
					strlcpy(b, archive, blen);
					alen = strlen(archive);
				} else if (*p == 'f') {
					snprintf(b, blen, "%s", ptr_vector_get(&flist, file));
					alen = strlen(b);
				} else if (*p == '*') {
					*b++ = '*';
					alen = 1;
				}
				b += alen;
				blen -= alen;
			}
			*b = '\0';

			//printf("Buffer %s\n", buffer);

			if (sshBBS) {
				stout = dup(STDOUT_FILENO);
				stin = dup(STDIN_FILENO);
				sterr = dup(STDERR_FILENO);

				dup2(bbs_stdout, STDOUT_FILENO);
				dup2(bbs_stderr, STDERR_FILENO);
				dup2(bbs_stdin, STDIN_FILENO);
			}

			args = split_args(buffer, NULL);
			cmd = args[0];
			pid = fork();
			if (pid == 0) {
			//	printf("EXECUTING! %s\n", cmd);
				execvp(cmd, args);
				exit(0);
			} else if (pid > 0) {
				waitpid(pid, &ret, 0);
			} else {
				ret = -1;
			}
			free(args);

			if (sshBBS) {

				dup2(stout, STDOUT_FILENO);
				dup2(sterr, STDERR_FILENO);
				dup2(stin, STDIN_FILENO);

				close(stin);
				close(stout);
				close(sterr);
			}

			if (ret == -1 || ret >> 8 == 127) {
				s_printf(get_string(274));
				snprintf(buffer, sizeof buffer, "%s/node%d/qwk", conf.bbs_path, mynode);
				recursive_delete(buffer);

				unlink(archive);
				s_printf(get_string(6));
				s_getc();
				ptr_vector_apply(&flist, free);
				destroy_ptr_vector(&flist);
				ptr_vector_apply(&qwk_last_read, free);
				destroy_ptr_vector(&qwk_last_read);
				return;
			}
		}

		do_download(gUser, archive);

		snprintf(buffer, sizeof buffer, "%s/node%d/qwk", conf.bbs_path, mynode);
		recursive_delete(buffer);

		unlink(archive);
	}

	char yn;

	s_printf(get_string(323));
	yn = s_getchar();

	while (tolower(yn) != 'y' && tolower(yn) != 'n') {
		s_printf(get_string(323));
		yn = s_getchar();
	}

	s_printf("\r\n\r\n");

	if (tolower(yn) == 'y') {
		for (size_t i=0;i<ptr_vector_len(&qwk_last_read);i++) {
			struct last_read_t *lr = ptr_vector_get(&qwk_last_read, i);
			mb = open_message_base(lr->conf, lr->area);
			write_lasthighread(mb, gUser, lr->last_read, lr->high_read);
			close_message_base(mb);
		}

		snprintf(buffer, PATH_MAX, "%s/email.sq3", conf.bbs_path);
		rc = sqlite3_open(buffer, &db);
		if (rc == SQLITE_OK) {
			sqlite3_busy_timeout(db, 5000);

			rc = sqlite3_prepare_v2(db, sqlseen, -1, &res, 0);
			if (rc == SQLITE_OK) {
				sqlite3_bind_text(res, 1, gUser->loginname, -1, 0);
				sqlite3_step(res);
			}
			sqlite3_finalize(res);
		}
		sqlite3_close(db);
	}

	ptr_vector_apply(&flist, free);
	destroy_ptr_vector(&flist);
	ptr_vector_apply(&qwk_last_read, free);
	destroy_ptr_vector(&qwk_last_read);
	s_printf(get_string(6));
	s_getc();
}

void qwk_upload_reply() {
	char buffer[PATH_MAX];
	struct msg_base_t *mb;
	FILE *message_dat_fptr;
	struct stat s;
	int stout;
	int stin;
	int sterr;
	int ret;
	char **args;
	char *cmd;
	pid_t pid;
	struct QwkHeader qhdr;
	int msgrecs;
	char *msgbody;
	char mbuf[129];
	int i;
	struct tm thedate;
	time_t msgdate;
	int year;
	char msgto[26];
	char msgfrom[26];
	char msgsubj[26];
	int msgconf;
	int basefound;
	struct mail_area *ma;
	struct mail_conference *mc;
	int j;
	struct ptr_vector semaphore_list = EMPTY_PTR_VECTOR;
	char *tagline;
	struct utsname name;
	char originlinebuffer[256];
	int sem_fd;
	int msg_tot = 0;
	int linebreaks;
	char *extended_to;
	char *extended_from;
	char *extended_subject;
	char *ptr;
	struct msg_t *rmsg;
	int repto;
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

	init_ptr_vector(&semaphore_list);

	stralloc msgandorig = EMPTY_STRALLOC;
	uname(&name);

	snprintf(buffer, sizeof buffer, "%s/node%d", conf.bbs_path, mynode);

	if (stat(buffer, &s) != 0) {
		mkdir(buffer, 0755);
	}

	snprintf(buffer, sizeof buffer, "%s/node%d/qwk/", conf.bbs_path, mynode);

	if (stat(buffer, &s) == 0) {
		recursive_delete(buffer);
	}
	mkdir(buffer, 0755);

	if (!do_upload(gUser, buffer)) {
		s_printf(get_string(211));
		recursive_delete(buffer);
		return;
	}

	snprintf(buffer, sizeof buffer, "%s.REP", conf.bwave_name);

	if (strcasecmp(&upload_filename[strlen(upload_filename) - strlen(buffer)], buffer) != 0) {
		s_printf(get_string(211));
		unlink(upload_filename);
		return;
	}

	struct archiver *arc = ptr_vector_get(&conf.archivers, gUser->defarchiver - 1);
	assert(arc != NULL);
	char *b = buffer;
	size_t blen = sizeof buffer;
	for (const char *p = arc->unpack; *p != '\0' && blen > 1; ++p) {
		if (*p != '*') {
			*b++ = *p;
			--blen;
			continue;
		}
		p++;
		size_t alen = 0;
		if (*p == 'a') {
			strlcpy(b, upload_filename, blen);
			alen = strlen(upload_filename);
		} else if (*p == 'd') {
			snprintf(b, blen, "%s/node%d/qwk/", conf.bbs_path, mynode);
			alen = strlen(b);
		} else if (*p == '*') {
			*b++ = '*';
			alen = 1;
		}
		b += alen;
		blen -= alen;
	}
	*b = '\0';
	if (sshBBS) {
		stout = dup(STDOUT_FILENO);
		stin = dup(STDIN_FILENO);
		sterr = dup(STDERR_FILENO);

		dup2(bbs_stdout, STDOUT_FILENO);
		dup2(bbs_stderr, STDERR_FILENO);
		dup2(bbs_stdin, STDIN_FILENO);
	}
	args = split_args(buffer, NULL);
	cmd = args[0];
	pid = fork();
	if (pid == 0) {
		execvp(cmd, args);
		exit(0);
	} else if (pid > 0) {
		waitpid(pid, &ret, 0);
	} else {
		ret = -1;
	}
	free(args);
	if (sshBBS) {

		dup2(stout, STDOUT_FILENO);
		dup2(sterr, STDERR_FILENO);
		dup2(stin, STDIN_FILENO);

		close(stin);
		close(stout);
		close(sterr);
	}

	unlink(upload_filename);
	snprintf(buffer, sizeof buffer, "%s/node%d/qwk/%s.MSG", conf.bbs_path, mynode, conf.bwave_name);
	message_dat_fptr = fopen(buffer, "rb");
	if (!message_dat_fptr) {
		snprintf(buffer, sizeof buffer, "%s/node%d/qwk/", conf.bbs_path, mynode);
		s_printf(get_string(211));
		recursive_delete(buffer);
		return;
	}

	fread(&qhdr, sizeof(struct QwkHeader), 1, message_dat_fptr);

	while (!feof(message_dat_fptr)) {
		if (fread(&qhdr, sizeof(struct QwkHeader), 1, message_dat_fptr) != 1) {
			break;
		}

		msgrecs = safe_atoi(qhdr.Msgrecs, 6);
		msgbody = (char *)malloz((msgrecs * 128) + 1);
		memset(msgbody, 0, (msgrecs * 128) + 1);
		for (i = 1; i < msgrecs; i++) {
			fread(mbuf, 1, 128, message_dat_fptr);
			if (i == msgrecs - 1) {
				trimwhitespace(msgbody + ((i - 1) * 128), 128, mbuf);
			} else {
				memcpy(msgbody + ((i - 1) * 128), mbuf, 128);
			}
		}

		for (i = 0; i < strlen(msgbody); i++) {
			if (msgbody[i] == '\xe3') {
				msgbody[i] = '\r';
			}
		}

		memset(&thedate, 0, sizeof(struct tm));

		thedate.tm_mday = (qhdr.Msgdate[3] - '0') * 10 + (qhdr.Msgdate[4] - '0');
		thedate.tm_mon = ((qhdr.Msgdate[0] - '0') * 10 + (qhdr.Msgdate[1] - '0')) - 1;
		year = (qhdr.Msgdate[6] - '0') * 10 + (qhdr.Msgdate[7] - '0');
		if (year < 80) {
			year += 100;
		}
		thedate.tm_year = year;

		thedate.tm_hour = (qhdr.Msgtime[0] - '0') * 10 + (qhdr.Msgtime[1] - '0');
		thedate.tm_min = (qhdr.Msgtime[3] - '0') * 10 + (qhdr.Msgtime[4] - '0');

		msgdate = mktime(&thedate);

		extended_to = NULL;
		extended_from = NULL;
		extended_subject = NULL;
		ptr = NULL;

		if (gUser->qwke) {
			for (ptr = msgbody; *ptr != '\0';) {
				if (strncmp(ptr, "To: ", 4) == 0) {
					extended_to = &ptr[4];
					while (*ptr != '\r' && *ptr != '\0') ptr++;
					if (*ptr == '\r') {
						*ptr = '\0';
						ptr++;
					}
					continue;
				}
				if (strncmp(ptr, "From: ", 6) == 0) {
					extended_from = &ptr[6];
					while (*ptr != '\r' && *ptr != '\0') ptr++;
					if (*ptr == '\r') {
						*ptr = '\0';
						ptr++;
					}
					continue;
				}
				if (strncmp(ptr, "Subject: ", 9) == 0) {
					extended_subject = &ptr[9];
					while (*ptr != '\r' && *ptr != '\0') ptr++;
					if (*ptr == '\r') {
						*ptr = '\0';
						ptr++;
					}
					continue;
				}
				if (*ptr == '\r') {
					ptr++;
					break;
				}
				break;
			}
		}
		memset(buffer, 0, PATH_MAX);
		memset(msgto, 0, 26);
		strncpy(buffer, qhdr.MsgTo, 25);
		trimwhitespace(msgto, 25, buffer);

		memset(buffer, 0, PATH_MAX);
		memset(msgfrom, 0, 26);
		strncpy(buffer, qhdr.MsgFrom, 25);
		trimwhitespace(msgfrom, 25, buffer);

		memset(buffer, 0, PATH_MAX);
		memset(msgsubj, 0, 26);
		strncpy(buffer, qhdr.MsgSubj, 25);
		trimwhitespace(msgsubj, 25, buffer);
		msgconf = ((qhdr.Msgareahi & 0xff) << 8) | qhdr.Msgarealo;



		if (msgconf == 0) {
			char *to;
			if (extended_to) {
				if (check_user(extended_to) != 0) {
					if (strchr(extended_to, ' ') == NULL || check_fullname_j(extended_to) != 0) {
						free(msgbody);
						s_printf(get_string(322), extended_to);
						continue;
					} else {
						to = get_username_from_fullname_j(extended_to);
					}
				} else {
					to = strdup(extended_to);
				}
			} else {
				if (check_user(msgto) != 0) {
					if (strchr(msgto, ' ') == NULL || check_fullname_j(msgto) != 0) {
						free(msgbody);
						s_printf(get_string(322), msgto);
						continue;
					} else {
						to = get_username_from_fullname_j(msgto);
					}
				} else {
					to = strdup(msgto);
				}
			}
			// got email
			snprintf(buffer, sizeof buffer, "%s/email.sq3", conf.bbs_path);

			rc = sqlite3_open(buffer, &db);

			if (rc != SQLITE_OK) {
				dolog("Cannot open database: %s", sqlite3_errmsg(db));
				sqlite3_close(db);
				free(msgbody);
				free(to);
				continue;
			}
			sqlite3_busy_timeout(db, 5000);

			rc = sqlite3_exec(db, csql, 0, 0, &err_msg);
			if (rc != SQLITE_OK) {

				dolog("SQL error: %s", err_msg);

				sqlite3_free(err_msg);
				sqlite3_close(db);

				free(msgbody);
				free(to);
				continue;
			}

			rc = sqlite3_prepare_v2(db, isql, -1, &res, 0);



			if (rc == SQLITE_OK) {
				sqlite3_bind_text(res, 1, gUser->loginname, -1, 0);
				sqlite3_bind_text(res, 2, to, -1, 0);
				sqlite3_bind_text(res, 3, (extended_subject == NULL ? msgsubj : extended_subject), -1, 0);
				sqlite3_bind_text(res, 4, msgbody, -1, 0);
				sqlite3_bind_int(res, 5, msgdate);
			} else {
				dolog("Failed to execute statement: %s", sqlite3_errmsg(db));
				sqlite3_finalize(res);
				sqlite3_close(db);
				free(msgbody);
				free(to);
				continue;
			}
			sqlite3_step(res);

			sqlite3_finalize(res);
			sqlite3_close(db);
			free(msgbody);
			free(to);
			msg_tot++;
		} else {
			basefound = 0;
			for (i = 0; i < ptr_vector_len(&conf.mail_conferences); i++) {
				mc = ptr_vector_get(&conf.mail_conferences, i);
				for (j = 0; j < ptr_vector_len(&mc->mail_areas); j++) {
					ma = ptr_vector_get(&mc->mail_areas, j);
					if (ma->qwkconfno == msgconf && check_security(gUser, ma->write_sec_level, &ma->wr_req_flags, &ma->wr_not_flags)) {
						basefound = 1;
						break;
					}
				}
				if (basefound) break;
			}

			if (!basefound) {
				free(msgbody);
				continue;
			}

			mb = open_message_base(i, j);
			if (!mb) {
				dolog("Unable to open message base: %s", buffer);
				free(msgbody);
				continue;
			}

			if (ma->type == TYPE_ECHOMAIL_AREA || ma->type == TYPE_NEWSGROUP_AREA) {
				if (mc->semaphore != NULL) {
					ptr_vector_append_if_unique(&semaphore_list, mc->semaphore);
				} else if (conf.echomail_sem != NULL) {
					ptr_vector_append_if_unique(&semaphore_list, conf.echomail_sem);
				}

				tagline = conf.default_tagline;
				if (mc->tagline != NULL) {
					tagline = mc->tagline;
				}
				if (mc->nettype == NETWORK_FIDO) {
					if (mc->fidoaddr->point == 0) {
						snprintf(originlinebuffer, sizeof originlinebuffer, "\r--- MagickaBBS/QWK v%d.%d%s (%s/%s)\r * Origin: %s (%d:%d/%d)\r",
								VERSION_MAJOR, VERSION_MINOR, VERSION_STR, name.sysname, name.machine, tagline,
								mc->fidoaddr->zone, mc->fidoaddr->net, mc->fidoaddr->node);
					} else {

						snprintf(originlinebuffer, sizeof originlinebuffer, "\r--- MagickaBBS/QWK v%d.%d%s (%s/%s)\r * Origin: %s (%d:%d/%d.%d)\r",
								VERSION_MAJOR, VERSION_MINOR, VERSION_STR, name.sysname, name.machine, tagline,
								mc->fidoaddr->zone,
								mc->fidoaddr->net,
								mc->fidoaddr->node,
								mc->fidoaddr->point);
					}

				} else if (mc->nettype == NETWORK_MAGI) {
					snprintf(originlinebuffer, sizeof originlinebuffer, "\r--- MagickaBBS/QWK v%d.%d%s (%s/%s)\r * Origin: %s (@%d)\r",
							VERSION_MAJOR, VERSION_MINOR, VERSION_STR, name.sysname, name.machine, tagline, mc->maginode);
				} else if (mc->nettype == NETWORK_QWK) {
					snprintf(originlinebuffer, sizeof originlinebuffer, "\r---\r * MagickaBBS/QWK * %s\r",
							tagline);
				}
				linebreaks = 0;
				for (i = strlen(msgbody) - 4; i > 0; i--) {
					if (strncmp(&msgbody[i], "\r---", 3) == 0) {
						msgbody[i + 1] = '_';
						msgbody[i + 2] = '_';
						msgbody[i + 3] = '_';
						break;
					}
					if (msgbody[i] == '\r') {
						linebreaks++;
					}
					if (linebreaks == 3) {
						break;
					}
				}

				msgandorig = EMPTY_STRALLOC;
				if (gUser->qwke && ptr) {
					stralloc_cats(&msgandorig, ptr);
				} else {
					stralloc_cats(&msgandorig, msgbody);
				}
				stralloc_cats(&msgandorig, originlinebuffer);
				stralloc_0(&msgandorig);
				free(msgbody);

				msgbody = msgandorig.s;
			} else {
				if (gUser->qwke && ptr) {
					char *ptr2 = strdup(ptr);
					free(msgbody);
					msgbody = ptr2;
				}
			}

			if (ma->realnames) {
				snprintf(buffer, sizeof buffer, "%s %s", gUser->firstname, gUser->lastname);
			} else {
				snprintf(buffer, sizeof buffer, "%s", gUser->loginname);
			}

			rmsg = NULL;
			repto = 0;
			repto = safe_atoi(qhdr.Msgrply, 8);
			if (repto != 0) {
				rmsg = load_message_hdr(mb, repto);
			}

			if (!write_message(mb, (ma->type == TYPE_NEWSGROUP_AREA ? "All" : (extended_to == NULL ? msgto : extended_to)), buffer, (extended_subject == NULL ? msgsubj : extended_subject), msgbody, NULL, rmsg, &msgdate, 0)) {
				dolog("Failed to add message");
				close_message_base(mb);
				free(msgbody);
				fclose(message_dat_fptr);
				snprintf(buffer, sizeof buffer, "%s/node%d/qwk/", conf.bbs_path, mynode);
				s_printf(get_string(211));
				recursive_delete(buffer);
				return;
			} else {
				close_message_base(mb);
				free(msgbody);
				if (rmsg != NULL) {
					free_message_hdr(rmsg);
				}
				msg_tot++;
			}
		}
	}
	fclose(message_dat_fptr);
	snprintf(buffer, sizeof buffer, "%s/node%d/qwk/", conf.bbs_path, mynode);
	recursive_delete(buffer);
	for (i = 0; i < ptr_vector_len(&semaphore_list); i++) {
		sem_fd = open(ptr_vector_get(&semaphore_list, i), O_RDWR | O_CREAT, S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH);
		close(sem_fd);
	}
	destroy_ptr_vector(&semaphore_list);

	s_printf("\r\n");

	if (msg_tot > 0) {
		s_printf(get_string(204), msg_tot);
	}

	s_printf(get_string(6));
	s_getc();
	return;
}
