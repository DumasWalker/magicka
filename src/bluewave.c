#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <termios.h>
#include <fcntl.h>
#include <sqlite3.h>
#include <sys/wait.h>
#include <libgen.h>

#include "jamlib/jam.h"
#include "libuuid/uuid.h"

#include "bluewave.h"
#include "bbs.h"
#include "mail_utils.h"

extern struct bbs_config conf;
extern struct user_record *gUser;
extern int mynode;
extern char upload_filename[PATH_MAX];
extern int sshBBS;
extern int bbs_stdin;
extern int bbs_stdout;
extern int bbs_stderr;

struct last_read_t {
	int conf;
	int area;
	int last_read;
	int high_read;
};

static struct ptr_vector bwave_last_read;

tLONG convertl(tLONG l) {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	unsigned char result_bytes[4];
	unsigned int result;
	result_bytes[0] = (unsigned char)((l >> 24) & 0xFF);
	result_bytes[1] = (unsigned char)((l >> 16) & 0xFF);
	result_bytes[2] = (unsigned char)((l >> 8) & 0xFF);
	result_bytes[3] = (unsigned char)(l & 0xFF);
	memcpy(&result, result_bytes, 4);
	return result;
#else
	return l;
#endif
}

tWORD converts(tWORD s) {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	unsigned char result_bytes[2];
	unsigned short result;
	result_bytes[0] = (unsigned char)((s >> 8) & 0xFF);
	result_bytes[1] = (unsigned char)(s & 0xFF);
	memcpy(&result, result_bytes, 4);
	return result;
#else
	return s;
#endif
}

int bwave_scan_email(int areano, int totmsgs, FILE *fti_file, FILE *mix_file, FILE *dat_file, int *last_ptr) {
	sqlite3 *db;
	sqlite3_stmt *res;
	int rc;
	char *sql = "SELECT sender,subject,date,body,id FROM email WHERE recipient LIKE ? AND seen = 0";
	char *sqlseen = "UPDATE email SET seen = 1 WHERE recipient LIKE ?";
	char buffer[PATH_MAX];
	MIX_REC mix;
	FTI_REC fti;
	long mixptr;
	struct tm timeStruct;
	char *month_name[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
	time_t thetime;
	char *body;
	int area_msgs = 0;

	snprintf(buffer, PATH_MAX, "%s/email.sq3", conf.bbs_path);
	rc = sqlite3_open(buffer, &db);
	if (rc != SQLITE_OK) {
		dolog("Cannot open database: %s", sqlite3_errmsg(db));
		sqlite3_close(db);
		return totmsgs;
	}
	sqlite3_busy_timeout(db, 5000);
	rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);

	if (rc == SQLITE_OK) {
		sqlite3_bind_text(res, 1, gUser->loginname, -1, 0);
	} else {
		dolog("Failed to execute statement: %s", sqlite3_errmsg(db));
		sqlite3_finalize(res);
		sqlite3_close(db);
		return totmsgs;
	}

	mixptr = ftell(fti_file);

	while (sqlite3_step(res) == SQLITE_ROW) {
		memset(&fti, 0, sizeof(FTI_REC));
		strlcpy(fti.from, sqlite3_column_text(res, 0), sizeof fti.from);
		strlcpy(fti.to, gUser->loginname, sizeof fti.to);
		strlcpy(fti.subject, sqlite3_column_text(res, 1), sizeof fti.subject);
		thetime = sqlite3_column_int(res, 2);
		localtime_r((time_t *)&thetime, &timeStruct);

		snprintf(fti.date, sizeof fti.date, "%02d-%s-%04d %02d:%02d", timeStruct.tm_mday, month_name[timeStruct.tm_mon], timeStruct.tm_year + 1900, timeStruct.tm_hour, timeStruct.tm_min);
		fti.msgnum = converts((tWORD)sqlite3_column_int(res, 4));
		body = strdup(sqlite3_column_text(res, 3));
		fti.replyto = 0;
		fti.replyat = 0;
		fti.msgptr = convertl(*last_ptr);
		fti.msglength = convertl(strlen(body));

		*last_ptr += strlen(body);
		fti.flags |= FTI_MSGLOCAL;
		fti.flags = converts(fti.flags);
		fti.orig_zone = 0;
		fti.orig_net = 0;
		fti.orig_node = 0;
		fwrite(body, 1, strlen(body), dat_file);
		fwrite(&fti, sizeof(FTI_REC), 1, fti_file);
		free(body);
		area_msgs++;
		totmsgs++;
	}

	sqlite3_finalize(res);

	rc = sqlite3_prepare_v2(db, sqlseen, -1, &res, 0);
	if (rc == SQLITE_OK) {
		sqlite3_bind_text(res, 1, gUser->loginname, -1, 0);
		sqlite3_step(res);
	}
	sqlite3_finalize(res);
	sqlite3_close(db);

	memset(&mix, 0, sizeof(MIX_REC));

	snprintf(mix.areanum, 6, "%d", 1);
	mix.totmsgs = converts(area_msgs);
	mix.numpers = converts(area_msgs);
	mix.msghptr = convertl(mixptr);
	fwrite(&mix, sizeof(MIX_REC), 1, mix_file);

	return totmsgs;
}

int bwave_scan_area(int confr, int area, int areano, int totmsgs, FILE *fti_file, FILE *mix_file, FILE *dat_file, int *last_ptr) {
	struct msg_headers *msghs = read_message_headers(confr, area, gUser, 0);
	int all_unread = 1;
	struct msg_base_t *mb;
	int high_read;
	int last_read;
	int i;
	int k;
	MIX_REC mix;
	int area_msgs;
	int personal_msgs;
	long mixptr;
	FTI_REC fti;
	struct fido_addr *fido;
	char *body;
	struct tm timeStruct;
	char realname[66];
	char *month_name[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

	snprintf(realname, 65, "%s %s", gUser->firstname, gUser->lastname);
	if (msghs == NULL) {
		return totmsgs;
	}

	struct mail_area *ma = get_area(confr, area);
	mb = open_message_base(confr, area);
	if (!mb) {
		dolog("Error opening message base.. %s", ma->path);
		if (msghs != NULL) {
			free_message_headers(msghs);
		}
		return totmsgs;
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

	mixptr = ftell(fti_file);
	area_msgs = 0;
	personal_msgs = 0;

	for (k = i; k < msghs->msg_count; k++) {

		if (totmsgs == conf.bwave_max_msgs) {
			break;
		}

		if (msghs->msgs[k]->to != NULL) {
			if (strcasecmp(msghs->msgs[k]->to, gUser->loginname) == 0 || strncasecmp(msghs->msgs[k]->to, realname, 42) == 0) {
				personal_msgs++;
			}
		}

		memset(&fti, 0, sizeof(FTI_REC));

		if (msghs->msgs[k]->from != NULL) {
			strlcpy(fti.from, msghs->msgs[k]->from, sizeof fti.from);
		} else {
			strlcpy(fti.from, "(Missing From)", sizeof fti.from);
		}
		if (msghs->msgs[k]->to != NULL) {
			strlcpy(fti.to, msghs->msgs[k]->to, sizeof fti.to);
		} else {
			strlcpy(fti.to, "(Missing To)", sizeof fti.to);
		}

		if (msghs->msgs[k]->subject != NULL) {
			strlcpy(fti.subject, msghs->msgs[k]->subject, sizeof fti.subject);
		} else {
			strlcpy(fti.subject, "(Missing Subject)", sizeof fti.subject);
		}

		localtime_r((time_t *)&msghs->msgs[k]->msgwritten, &timeStruct);

		snprintf(fti.date, sizeof fti.date, "%02d-%s-%04d %02d:%02d", timeStruct.tm_mday, month_name[timeStruct.tm_mon], timeStruct.tm_year + 1900, timeStruct.tm_hour, timeStruct.tm_min);
		fti.msgnum = converts((tWORD)get_message_number(msghs, k));
		fti.replyto = 0;
		fti.replyat = 0;
		fti.msgptr = convertl(*last_ptr);

		body = load_message_text(mb, msghs->msgs[k]);

		fti.msglength = convertl(strlen(body));

		*last_ptr += strlen(body) + 1;

		if (get_message_islocal(msghs, k)) {
			fti.flags |= FTI_MSGLOCAL;
		}

		fti.flags = converts(fti.flags);

		fido = parse_fido_addr(msghs->msgs[k]->oaddress);
		if (fido != NULL) {
			fti.orig_zone = converts(fido->zone);
			fti.orig_net = converts(fido->net);
			fti.orig_node = converts(fido->node);
			free(fido);
		} else {
			fti.orig_zone = 0;
			fti.orig_net = 0;
			fti.orig_node = 0;
		}
		// write msg data
		fwrite(" ", 1, 1, dat_file);
		fwrite(body, 1, strlen(body), dat_file);
		fwrite(&fti, sizeof(FTI_REC), 1, fti_file);

		free(body);

		last_read = get_message_number(msghs, k);
		if (high_read < last_read) {
			high_read = last_read;
		}

		area_msgs++;
		totmsgs++;
	}

	struct last_read_t *bwavelr = malloz(sizeof(struct last_read_t));

	bwavelr->conf = confr;
	bwavelr->area = area;
	bwavelr->last_read = last_read;
	bwavelr->high_read = high_read;

	ptr_vector_append(&bwave_last_read, bwavelr);

	//if (area_msgs) {

	memset(&mix, 0, sizeof(MIX_REC));

	snprintf(mix.areanum, 6, "%d", areano);
	mix.totmsgs = converts(area_msgs);
	mix.numpers = converts(personal_msgs);
	mix.msghptr = convertl(mixptr);
	fwrite(&mix, sizeof(MIX_REC), 1, mix_file);
	//}
	close_message_base(mb);
	free_message_headers(msghs);
	return totmsgs;
}

void bwave_create_packet() {
	struct msg_base_t *mb;
	sqlite3 *db;
	sqlite3_stmt *res;
	int rc;
	char *sqlseen = "UPDATE email SET seen = 1 WHERE recipient LIKE ?";
	char buffer[PATH_MAX];
	char archive[PATH_MAX];
	INF_HEADER hdr;
	struct ptr_vector areas;
	INF_AREA_INFO *area = NULL;
	int i;
	int j;
	int area_count;
	tWORD flags;
	int lasttot;
	int last_ptr = 0;
	int stout;
	int stin;
	int sterr;
	char *weekday[] = {"SU", "MO", "TU", "WE", "TH", "FR", "SA"};
	struct stat s;
	struct termios oldit;
	struct termios oldot;
	struct tm time_tm;
	time_t thetime;
	FILE *mix_file;
	FILE *fti_file;
	FILE *dat_file;
	FILE *inf_file;
	int tot_areas = 0;
	int totmsgs = 0;
	int ret;
	char **args, *arg;
	char *cmd;
	pid_t pid;

	init_ptr_vector(&areas);

	for (size_t i = 0; i < ptr_vector_len(&conf.mail_conferences); i++) {
		struct mail_conference *mc = ptr_vector_get(&conf.mail_conferences, i);
		for (size_t j = 0; j < ptr_vector_len(&mc->mail_areas); j++) {
			if (msgbase_is_subscribed(i, j)) {
				tot_areas++;
			}
		}
	}

	if (tot_areas == 0) {
		s_printf(get_string(224));
		s_printf(get_string(6));
		s_getchar();
		return;
	}

	area_count = 0;

	memset(&hdr, 0, sizeof(INF_HEADER));
	hdr.ver = PACKET_LEVEL;
	strlcpy(hdr.loginname, gUser->loginname, sizeof hdr.loginname);
	//strlcpy(hdr.aliasname, gUser->loginname, sizeof hdr.aliasname);
	snprintf(hdr.aliasname, sizeof hdr.aliasname, "%s %s", gUser->firstname, gUser->lastname);
	hdr.zone = converts(conf.main_aka->zone);
	hdr.node = converts(conf.main_aka->node);
	hdr.net = converts(conf.main_aka->net);
	hdr.point = converts(conf.main_aka->point);
	strlcpy(hdr.sysop, conf.sysop_name, sizeof hdr.sysop);

	strlcpy(hdr.systemname, conf.bbs_name, sizeof hdr.systemname);
	hdr.inf_header_len = converts(sizeof(INF_HEADER));
	hdr.inf_areainfo_len = converts(sizeof(INF_AREA_INFO));
	hdr.mix_structlen = converts(sizeof(MIX_REC));
	hdr.fti_structlen = converts(sizeof(FTI_REC));
	hdr.uses_upl_file = 1;
	hdr.from_to_len = 35;
	hdr.subject_len = 71;
	memcpy(hdr.packet_id, conf.bwave_name, strlen(conf.bwave_name));

	snprintf(buffer, sizeof buffer, "%s/node%d", conf.bbs_path, mynode);

	if (stat(buffer, &s) != 0) {
		mkdir(buffer, 0755);
	}

	snprintf(buffer, sizeof buffer, "%s/node%d/bwave/", conf.bbs_path, mynode);

	if (stat(buffer, &s) == 0) {
		recursive_delete(buffer);
	}
	mkdir(buffer, 0755);

	snprintf(buffer, sizeof buffer, "%s/node%d/bwave/%s.FTI", conf.bbs_path, mynode, conf.bwave_name);

	fti_file = fopen(buffer, "wb");

	snprintf(buffer, sizeof buffer, "%s/node%d/bwave/%s.MIX", conf.bbs_path, mynode, conf.bwave_name);
	mix_file = fopen(buffer, "wb");

	snprintf(buffer, sizeof buffer, "%s/node%d/bwave/%s.DAT", conf.bbs_path, mynode, conf.bwave_name);
	dat_file = fopen(buffer, "wb");

	s_printf("\r\n");



	totmsgs = bwave_scan_email(area_count + 1, totmsgs, fti_file, mix_file, dat_file, &last_ptr);
	s_printf(get_string(195), "Private Email", "Private Email", totmsgs);

	flags = 0;
	area = (INF_AREA_INFO *)malloz(sizeof(INF_AREA_INFO));

	snprintf(area->areanum, 6, "%d", area_count + 1);

	memcpy(area->echotag, "PRIVATE_EMAIL", 13);

	strlcpy(area->title, "Private Email", 49);
	flags |= INF_POST;
	flags |= INF_NO_PUBLIC;
	flags |= INF_SCANNING;

	area->area_flags = converts(flags);
	area->network_type = INF_NET_FIDONET;
	ptr_vector_append(&areas, area);

	area_count++;

	init_ptr_vector(&bwave_last_read);

	if (totmsgs < conf.bwave_max_msgs) {
		for (size_t i = 0; i < ptr_vector_len(&conf.mail_conferences); i++) {
			struct mail_conference *mc = ptr_vector_get(&conf.mail_conferences, i);
			for (size_t j = 0; j < ptr_vector_len(&mc->mail_areas); j++) {
				struct mail_area *ma = get_area(i, j);
				if (check_security(gUser, ma->read_sec_level, &ma->rd_req_flags, &ma->rd_not_flags) && ma->qwkname != NULL && msgbase_is_subscribed(i, j)) {
					lasttot = totmsgs;
					totmsgs = bwave_scan_area(i, j, area_count + 1, totmsgs, fti_file, mix_file, dat_file, &last_ptr);
					s_printf(get_string(195), mc->name, ma->name, totmsgs - lasttot);

					area = (INF_AREA_INFO *)malloz(sizeof(INF_AREA_INFO));

					snprintf(area->areanum, sizeof area->areanum, "%d", area_count + 1);
					strlcpy(area->echotag, ma->qwkname, sizeof area->echotag);
					strlcpy(area->title, ma->name, sizeof area->title);

					flags = 0;
					if (check_security(gUser, ma->write_sec_level, &ma->wr_req_flags, &ma->wr_not_flags)) {
						flags |= INF_POST;
					}

					if (ma->type == TYPE_NETMAIL_AREA) {
						flags |= INF_NO_PUBLIC;
						flags |= INF_NETMAIL;
						flags |= INF_ECHO;
					}

					if (ma->type == TYPE_ECHOMAIL_AREA || ma->type == TYPE_NEWSGROUP_AREA) {
						flags |= INF_NO_PRIVATE;
						flags |= INF_ECHO;
					}

					if (ma->type == TYPE_LOCAL_AREA) {
						flags |= INF_NO_PRIVATE;
					}

					flags |= INF_SCANNING;

					area->area_flags = converts(flags);
					area->network_type = INF_NET_FIDONET;

					ptr_vector_append(&areas, area);
					area_count++;
					if (totmsgs == conf.bwave_max_msgs) {
						break;
					}
				}
			}
			if (totmsgs == conf.bwave_max_msgs) {
				break;
			}
		}
	}

	fclose(dat_file);
	fclose(mix_file);
	fclose(fti_file);

	snprintf(buffer, sizeof buffer, "%s/node%d/bwave/%s.INF", conf.bbs_path, mynode, conf.bwave_name);

	inf_file = fopen(buffer, "wb");
	fwrite(&hdr, sizeof(INF_HEADER), 1, inf_file);

	for (i = 0; i < area_count; i++) {
		fwrite(ptr_vector_get(&areas, i), sizeof(INF_AREA_INFO), 1, inf_file);
	}

	fclose(inf_file);

	ptr_vector_apply(&areas, free);
	destroy_ptr_vector(&areas);

	if (totmsgs > 0) {
		// create archive
		if (gUser->bwavestyle) {
			thetime = time(NULL);
			localtime_r(&thetime, &time_tm);

			if (gUser->bwavepktno / 10 != time_tm.tm_wday) {
				gUser->bwavepktno = time_tm.tm_wday * 10;
			}

			snprintf(archive, sizeof archive, "%s/node%d/%s.%s%d",
			         conf.bbs_path, mynode, conf.bwave_name, weekday[time_tm.tm_wday], gUser->bwavepktno % 10);
		} else {
			snprintf(archive, sizeof archive, "%s/node%d/%s.%03d", conf.bbs_path, mynode, conf.bwave_name, gUser->bwavepktno);
		}

		struct archiver *arc = ptr_vector_get(&conf.archivers, gUser->defarchiver - 1);
		assert(arc != NULL);
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
				snprintf(b, blen, "%s/node%d/bwave/%s.INF %s/node%d/bwave/%s.MIX %s/node%d/bwave/%s.FTI %s/node%d/bwave/%s.DAT",
				         conf.bbs_path, mynode, conf.bwave_name, conf.bbs_path, mynode, conf.bwave_name, conf.bbs_path,
				         mynode, conf.bwave_name, conf.bbs_path, mynode, conf.bwave_name);
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

		if (ret != -1 && ret >> 8 != 127) {
			do_download(gUser, archive);
		} else {
			s_printf(get_string(274));
		}

		snprintf(buffer, sizeof buffer, "%s/node%d/bwave", conf.bbs_path, mynode);
		recursive_delete(buffer);

		unlink(archive);
		gUser->bwavepktno++;
		if (gUser->bwavepktno > 999) {
			gUser->bwavepktno = 0;
		}
		save_user(gUser);
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
		for (size_t i=0;i<ptr_vector_len(&bwave_last_read);i++) {
			struct last_read_t *lr = ptr_vector_get(&bwave_last_read, i);
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
	ptr_vector_apply(&bwave_last_read, free);
	destroy_ptr_vector(&bwave_last_read);
	s_printf(get_string(6));
	s_getc();
}

int bwave_add_message(int confr, int area, unsigned int dwritten, char *to, char *subject, int replyto, struct fido_addr *destaddr, char *msg) { 
/* fix code that had to be reverted
int bwave_add_message(int confr, int area, unsigned int *dwritten, char *to, char *subject, int replyto, struct fido_addr *destaddr, char *msg) { */
	struct msg_base_t *mb;
	int z;
	char buffer[256];
	char qwkuuid[38];
	uuid_t magi_msgid;
	uuid_t qwk_msgid;
	struct mail_area *ma = get_area(confr, area);
	char destbuffer[256];
	struct msg_t *rmsg;

	mb = open_message_base(confr, area);
	if (!mb) {
		dolog("Error opening message base.. %s", ma->path);
		return 1;
	}

	struct mail_conference *mc = get_conf(confr);
	if (ma->realnames == 0) {
		strlcpy(buffer, gUser->loginname, sizeof buffer);
	} else {
		snprintf(buffer, sizeof buffer, "%s %s", gUser->firstname, gUser->lastname);
	}

	if (destaddr != NULL) {
		if (destaddr->point) {
			snprintf(destbuffer, sizeof destbuffer, "%d:%d/%d.%d",
			         destaddr->zone,
			         destaddr->net,
			         destaddr->node,
			         destaddr->point);
		} else {
			snprintf(destbuffer, sizeof destbuffer, "%d:%d/%d",
			         destaddr->zone,
			         destaddr->net,
			         destaddr->node);
		}
	}

	rmsg = NULL;

	if (replyto != 0) {
		rmsg = load_message_hdr(mb, replyto);
	}

/*	if (!write_message(mb, (ma->type == TYPE_NEWSGROUP_AREA ? "ALL" : to), buffer, subject, msg, (destaddr == NULL ? NULL : destbuffer), rmsg, dwritten, 0)) { */
	if (!write_message(mb, (ma->type == TYPE_NEWSGROUP_AREA ? "ALL" : to), buffer, subject, msg, (destaddr == NULL ? NULL : destbuffer), rmsg, (void *)&dwritten, 0)) {
		dolog("Failed to add Message");
		close_message_base(mb);
		return -1;
	}

	if (rmsg != NULL) {
		free_message_hdr(rmsg);
	}

	close_message_base(mb);

	return 0;
}

void bwave_upload_reply() {
	char buffer[PATH_MAX];
	char msgbuffer[PATH_MAX];
	char originlinebuffer[256];
	int i;
	UPL_HEADER upl_hdr;
	UPL_REC upl_rec;
	int j;
	int confr;
	int area;
	tWORD msg_attr;
	struct fido_addr addr;
	stralloc sa = EMPTY_STRALLOC;
	char *body;
	char *tagline;
	struct stat s;
	FILE *upl_file;
	FILE *msg_file;
	int sem_fd;
	int msg_count;
	int stout;
	int stin;
	int sterr;
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
	char **args, *arg;
	char *cmd;
	pid_t pid;
	int ret;
	msg_count = 0;
	struct ptr_vector semaphore_list = EMPTY_PTR_VECTOR;

	init_ptr_vector(&semaphore_list);

	snprintf(buffer, sizeof buffer, "%s/node%d", conf.bbs_path, mynode);

	if (stat(buffer, &s) != 0) {
		mkdir(buffer, 0755);
	}

	snprintf(buffer, sizeof buffer, "%s/node%d/bwave/", conf.bbs_path, mynode);

	if (stat(buffer, &s) == 0) {
		recursive_delete(buffer);
	}
	mkdir(buffer, 0755);

	if (!do_upload(gUser, buffer)) {
		s_printf(get_string(211));
		recursive_delete(buffer);
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
			snprintf(b, blen, "%s/node%d/bwave/", conf.bbs_path, mynode);
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

	snprintf(buffer, sizeof buffer, "%s/node%d/bwave/%s.UPL", conf.bbs_path, mynode, conf.bwave_name);

	upl_file = fopen(buffer, "r");

	if (!upl_file) {
		snprintf(buffer, sizeof buffer, "%s/node%d/bwave/%s.upl", conf.bbs_path, mynode, conf.bwave_name);
		upl_file = fopen(buffer, "r");
		if (!upl_file) {
			s_printf(get_string(196));
			return;
		}
	}

	if (!fread(&upl_hdr, sizeof(UPL_HEADER), 1, upl_file)) {
		s_printf(get_string(196));
		fclose(upl_file);
		return;
	}

	while (fread(&upl_rec, sizeof(UPL_REC), 1, upl_file)) {
		if (strcmp("PRIVATE_EMAIL", upl_rec.echotag) == 0) {
			if (msg_attr & UPL_INACTIVE) {
				continue;
			}

			if (strcasecmp(upl_rec.from, gUser->loginname) != 0) {
				continue;
			}

			snprintf(msgbuffer, sizeof buffer, "%s/node%d/bwave/%s", conf.bbs_path, mynode, upl_rec.filename);
			body = file2str(msgbuffer);
			if (body == NULL) {
				continue;
			}

			char *b = body;
			for (char *p = body; *p != '\0'; ++p) {
				if (*p != '\n')
					*b++ = *p;
			}
			*b = '\0';

			snprintf(buffer, sizeof buffer, "%s/email.sq3", conf.bbs_path);

			rc = sqlite3_open(buffer, &db);

			if (rc != SQLITE_OK) {
				dolog("Cannot open database: %s", sqlite3_errmsg(db));
				sqlite3_close(db);
				free(body);
				continue;
			}
			sqlite3_busy_timeout(db, 5000);

			rc = sqlite3_exec(db, csql, 0, 0, &err_msg);
			if (rc != SQLITE_OK) {

				dolog("SQL error: %s", err_msg);

				sqlite3_free(err_msg);
				sqlite3_close(db);

				free(body);
				continue;
			}

			rc = sqlite3_prepare_v2(db, isql, -1, &res, 0);

			if (rc == SQLITE_OK) {
				sqlite3_bind_text(res, 1, gUser->loginname, -1, 0);
				sqlite3_bind_text(res, 2, upl_rec.to, -1, 0);
				sqlite3_bind_text(res, 3, upl_rec.subj, -1, 0);
				sqlite3_bind_text(res, 4, body, -1, 0);
				sqlite3_bind_int(res, 5, convertl(upl_rec.unix_date));
			} else {
				dolog("Failed to execute statement: %s", sqlite3_errmsg(db));
				sqlite3_finalize(res);
				sqlite3_close(db);
				free(body);
				continue;
			}
			sqlite3_step(res);

			sqlite3_finalize(res);
			sqlite3_close(db);
			free(body);
			msg_count++;
		} else {
			// find area
			confr = -1;
			area = -1;

			for (i = 0; i < ptr_vector_len(&conf.mail_conferences); i++) {
				struct mail_conference *mc = ptr_vector_get(&conf.mail_conferences, i);
				for (j = 0; j < ptr_vector_len(&mc->mail_areas); j++) {
					struct mail_area *ma = ptr_vector_get(&mc->mail_areas, j);
					if (strcmp(ma->qwkname, upl_rec.echotag) == 0) {
						confr = i;
						area = j;
						break;
					}
				}
				if (confr != -1) {
					break;
				}
			}

			if (confr != -1 && area != -1) {
				// import message
				struct mail_area *ma = get_area(confr, area);
				if (check_security(gUser, ma->write_sec_level, &ma->wr_req_flags, &ma->wr_not_flags)) {
					msg_attr = converts(upl_rec.msg_attr);

					if (msg_attr & UPL_INACTIVE) {
						continue;
					}

					if (strcasecmp(upl_rec.from, gUser->loginname) != 0) {
						continue;
					}

					addr.zone = 0;
					addr.net = 0;
					addr.node = 0;
					addr.point = 0;

					if (ma->type == TYPE_NETMAIL_AREA) {
						if (!(msg_attr & UPL_NETMAIL)) {
							continue;
						}
						addr.zone = converts(upl_rec.destzone);
						addr.net = converts(upl_rec.destnet);
						addr.node = converts(upl_rec.destnode);
						addr.point = converts(upl_rec.destpoint);
						if (get_conf(confr)->semaphore != NULL) {
							ptr_vector_append_if_unique(&semaphore_list, get_conf(confr)->semaphore);
						} else if (conf.netmail_sem != NULL) {
							ptr_vector_append_if_unique(&semaphore_list, conf.netmail_sem);
						}
					} else if (ma->type == TYPE_ECHOMAIL_AREA || ma->type == TYPE_NEWSGROUP_AREA) {
						if (msg_attr & UPL_PRIVATE) {
							continue;
						}
						if (get_conf(confr)->semaphore != NULL) {
							ptr_vector_append_if_unique(&semaphore_list, get_conf(confr)->semaphore);
						} else if (conf.echomail_sem != NULL) {
							ptr_vector_append_if_unique(&semaphore_list, conf.echomail_sem);
						}
					} else { // Local area
						if (msg_attr & UPL_PRIVATE) {
							continue;
						}
					}

					snprintf(msgbuffer, sizeof buffer, "%s/node%d/bwave/%s", conf.bbs_path, mynode, upl_rec.filename);

					tagline = conf.default_tagline;
					struct mail_conference *mc = get_conf(confr);
					if (mc->tagline != NULL) {
						tagline = mc->tagline;
					}

					if (mc->nettype == NETWORK_FIDO) {
						if (mc->fidoaddr->point == 0) {
							snprintf(originlinebuffer, sizeof originlinebuffer, "\r--- %s\r * Origin: %s (%d:%d/%d)\r",
							         upl_hdr.reader_tear, tagline,
							         mc->fidoaddr->zone, mc->fidoaddr->net, mc->fidoaddr->node);
						} else {

							snprintf(originlinebuffer, sizeof originlinebuffer, "\r--- %s\r * Origin: %s (%d:%d/%d.%d)\r",
							         upl_hdr.reader_tear, tagline,
							         mc->fidoaddr->zone,
							         mc->fidoaddr->net,
							         mc->fidoaddr->node,
							         mc->fidoaddr->point);
						}
					} else if (mc->nettype == NETWORK_MAGI) {
						snprintf(originlinebuffer, sizeof originlinebuffer, "\r--- %s\r * Origin: %s (@%d)\r",
						         upl_hdr.reader_tear, tagline, mc->maginode);
					} else if (mc->nettype == NETWORK_QWK) {
						snprintf(originlinebuffer, sizeof originlinebuffer, "\r---\r * MagickaBBS * %s\r",
						         tagline);
					} else {
						snprintf(originlinebuffer, sizeof originlinebuffer, "\r");
					}

					sa = file2stralloc(msgbuffer);
					if (sa.s == NULL) {
						continue;
					}
					stralloc_cats(&sa, originlinebuffer);
					stralloc_0(&sa);
					body = sa.s;
					char *p, *s;

					for (p = s = body; *p != '\0'; ++p) {
						if (*p != '\n')
							*s++ = *p;
					}
					*s = '\0';

					if (bwave_add_message(confr, area, convertl(upl_rec.unix_date), upl_rec.to, upl_rec.subj, convertl(upl_rec.replyto), &addr, body) != 0) {
                                        /* 1. Create a temporary variable to hold the converted date 
                                        unsigned int temp_date = (unsigned int)convertl(upl_rec.unix_date);

                                        /* 2. Pass the address of that variable (&temp_date) 
                                        if (bwave_add_message(confr, area, &temp_date, upl_rec.to, upl_rec.subj,
                                                              convertl(upl_rec.replyto), &addr, body) != 0) { */
						// failed to add message
						s_printf(get_string(197));
					} else {
						msg_count++;
					}

					free(body);
				}
			}
		}
	}

	snprintf(buffer, sizeof buffer, "%s/node%d/bwave/", conf.bbs_path, mynode);
	recursive_delete(buffer);

	for (i = 0; i < ptr_vector_len(&semaphore_list); i++) {
		sem_fd = open(ptr_vector_get(&semaphore_list, i), O_RDWR | O_CREAT, S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH);
		close(sem_fd);
	}
	destroy_ptr_vector(&semaphore_list);

	s_printf("\r\n");

	if (msg_count > 0) {
		s_printf(get_string(204), msg_count);
	}

	s_printf(get_string(6));
	s_getc();
}
