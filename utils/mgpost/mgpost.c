#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <sys/file.h>
#include <sqlite3.h>
#include <limits.h>
#include "../../deps/jamlib/jam.h"
#include "../../src/inih/ini.h"
#include "../../deps/libuuid/uuid.h"

s_JamBase *open_jam_base(char *path) {
	int ret;
	s_JamBase *jb;

	ret = JAM_OpenMB((char *)path, &jb);

	if (ret != 0) {
		if (ret == JAM_IO_ERROR) {
			free(jb);
			ret = JAM_CreateMB((char *)path, 1, &jb);
			if (ret != 0) {
				free(jb);
				return NULL;
			}
		}
	}
	return jb;
}

#ifdef __sun
static long difftm(struct tm *a, struct tm *b) {
	int ay = a->tm_year + (TM_YEAR_ORIGIN - 1);
	int by = b->tm_year + (TM_YEAR_ORIGIN - 1);
	long days = (a->tm_yday - b->tm_yday + ((ay >> 2) - (by >> 2)) - (ay / 100 - by / 100) + ((ay / 100 >> 2) - (by / 100 >> 2)) + (long)(ay - by) * 365);

	return (60 * (60 * (24 * days + (a->tm_hour - b->tm_hour)) + (a->tm_min - b->tm_min)) + (a->tm_sec - b->tm_sec));
}

long gmtoff(time_t value) {
	struct tm gmt;
	gmtime_r(&value, &gmt);
	return difftm(localtime(&value), &gmt);
}
#endif

time_t utc_to_local(time_t utc) {
	time_t local;
	struct tm date_time;

	localtime_r(&utc, &date_time);

#ifdef __sun
	local = utc + gmtoff(utc);
#else
	local = utc + date_time.tm_gmtoff;
#endif
	return local;
}

time_t gettz() {
	time_t offset;
	struct tm date_time;
	time_t utc = time(NULL);
	localtime_r(&utc, &date_time);

#ifdef __sun
	offset = gmtoff(utc);
#else
	offset = date_time.tm_gmtoff;
#endif
	return offset;
}

static int open_sq3_database(const char *path, sqlite3 **db) {
    const char *create_sql = "CREATE TABLE IF NOT EXISTS msgs(id INTEGER PRIMARY KEY, sender TEXT, recipient TEXT, subject TEXT, date INTEGER, mattribs INTEGER, daddress TEXT, oaddress TEXT, msgid TEXT, replyid TEXT, body TEXT);";
    const char *create_sql2 = "CREATE TABLE IF NOT EXISTS lastread(userid INTEGER, messageid INTEGER);";
    int rc;
    char *err_msg;

    char fpath[PATH_MAX];
    snprintf(fpath, sizeof fpath, "%s.sq3", path);
    if (sqlite3_open(fpath, db) != SQLITE_OK) {
           fprintf(stderr, "Unable to open sq3 mail databasei\n");
           return 0;
    }
    sqlite3_busy_timeout(*db, 5000);

    rc = sqlite3_exec(*db, create_sql, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Unable to create msgs table: %s\n", err_msg);
        free(err_msg);
        sqlite3_close(*db);
        return 0;
    }
    rc = sqlite3_exec(*db, create_sql2, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Unable to create lastread table: %s\n", err_msg);
        free(err_msg);
        sqlite3_close(*db);
        return 0;
    }

    return 1;
}

struct fido_addr {
	unsigned short zone;
	unsigned short net;
	unsigned short node;
	unsigned short point;
};

struct fido_addr *parse_fido_addr(const char *str) {
	struct fido_addr *ret = (struct fido_addr *)malloc(sizeof(struct fido_addr));
	int c;
	int state = 0;

	ret->zone = 0;
	ret->net = 0;
	ret->node = 0;
	ret->point = 0;

	for (c=0;c<strlen(str);c++) {
		switch(str[c]) {
			case ':':
				state = 1;
				break;
			case '/':
				state = 2;
				break;
			case '.':
				state = 3;
				break;
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
				{
					switch (state) {
						case 0:
							ret->zone = ret->zone * 10 + (str[c] - '0');
							break;
						case 1:
							ret->net = ret->net * 10 + (str[c] - '0');
							break;
						case 2:
							ret->node = ret->node * 10 + (str[c] - '0');
							break;
						case 3:
							ret->point = ret->point * 10 + (str[c] - '0');
							break;
					}
				}
				break;
			default:
				free(ret);
				return NULL;
		}
	}
	return ret;
}


struct msg_t {
	int echo;
	char *bbs_path;
	char *filename;
	char *msgbase;
	int basetype;
	char *from;
	char *subject;
	char *origin;
	struct fido_addr *localAddress;
	int maginode;
};

static int handler(void* user, const char* section, const char* name,
                   const char* value)
{
	struct msg_t *msg = (struct msg_t *)user;
	
	if (strcasecmp(section, "main") == 0) {
		if (strcasecmp(name, "echomail") == 0) {
			if (strcasecmp(value, "true") == 0) {
				msg->echo = 1;
			} else if (strcasecmp(value, "magi") == 0) {
				msg->echo = 2;
			} else {
				msg->echo = 0;
			}
		} else if (strcasecmp(name, "BBS Path") == 0) {
			msg->bbs_path = strdup(value);
		} else if (strcasecmp(name, "Message File") == 0) {
			msg->filename = strdup(value);
		} else if (strcasecmp(name, "JAM Base") == 0) {
			msg->msgbase = strdup(value);
			msg->basetype = 1;
		} else if (strcasecmp(name, "Message Base") == 0) {
			msg->msgbase = strdup(value);
		} else if (strcasecmp(name, "Base Type") == 0) {
			if (strcasecmp(value, "JAM") == 0) {
				msg->basetype = 1;
			} else if (strcasecmp(value, "SQ3") == 0) {
				msg->basetype = 2;
			}
		} else if (strcasecmp(name, "From") == 0) {
			msg->from = strdup(value);
		} else if (strcasecmp(name, "Subject") == 0) {
			msg->subject = strdup(value);
		} else if (strcasecmp(name, "Local AKA") == 0) {
			msg->localAddress = parse_fido_addr(value);
		} else if (strcasecmp(name, "Origin Line") == 0) {
			msg->origin = strdup(value);
		} else if (strcasecmp(name, "Magi Node") == 0) {
			msg->maginode = atoi(value);
		}
	}
	return 1;
}

unsigned long generate_msgid(char *bbs_path) {
	char buffer[1024];

	unsigned long lastid;
	FILE *fptr;
	time_t unixtime;
	snprintf(buffer, 1024, "%s/msgserial", bbs_path);
	
	unixtime = time(NULL);

	fptr = fopen(buffer, "r+");
	if (fptr) {
		flock(fileno(fptr), LOCK_EX);
		fread(&lastid, sizeof(unsigned long), 1, fptr);
		
		if (unixtime > lastid) {
			lastid = unixtime;
		} else {
			lastid++;
		}

		rewind(fptr);
		fwrite(&lastid, sizeof(unsigned long), 1, fptr);
		flock(fileno(fptr), LOCK_UN);
		fclose(fptr);
	} else {
		fptr = fopen(buffer, "w");
		if (fptr) {
			lastid = unixtime;
			flock(fileno(fptr), LOCK_EX);
			fwrite(&lastid, sizeof(unsigned long), 1, fptr);
			flock(fileno(fptr), LOCK_UN);
			fclose(fptr);
		} else {
			printf("Unable to open message id log\n");
			return 0;
		}
	}
	

	
	return lastid;
}

int main(int argc, char **argv) {
	char buffer[1024];
	char *body;
	char *subject;
	char *from;
	FILE *fptr;
	int len;
	int totlen;
	time_t thetime;
	int z;
	int i;
	uuid_t myuuid;
	struct msg_t msg;
	char *msg_id = NULL;
	char *oaddress = NULL;

	if (argc < 2) {
		printf("Usage: %s inifile\n", argv[0]);
		exit(1);
	}

	msg.basetype = 0;

	if (ini_parse(argv[1], handler, &msg) <0) {
		fprintf(stderr, "Unable to load configuration ini (%s)!\n", argv[1]);
		exit(-1);
	}

	if (msg.basetype == 0) {
		fprintf(stderr, "Message Base Type must be specified\n");
		exit(-1);
	}


	fptr = fopen(msg.filename, "r");

	if (!fptr) {
		printf("Unable to open %s\n", msg.filename);
		exit(1);
	}
	body = NULL;
	totlen = 0;

	len = fread(buffer, 1, 1024, fptr);
	while (len > 0) {
		totlen += len;
		if (body == NULL) {
			body = (char *)malloc(totlen + 1);
		} else {
			body = (char *)realloc(body, totlen + 1);
		}
		memcpy(&body[totlen - len], buffer, len);
		body[totlen] = '\0';
		len = fread(buffer, 1, 1024, fptr);
	}

	fclose(fptr);

	for (i=0;i<totlen;i++) {
		if (body[i] == '\n') {
			body[i] = '\r';
		}
	}
	
	if (msg.echo == 1) {
		if (msg.localAddress->point == 0) {
			snprintf(buffer, 1024, "\r--- mgpost\r * Origin: %s (%d:%d/%d)\r", msg.origin, msg.localAddress->zone, msg.localAddress->net, msg.localAddress->node);
		} else {
			snprintf(buffer, 1024, "\r--- mgpost\r * Origin: %s (%d:%d/%d.%d)\r", msg.origin, msg.localAddress->zone, msg.localAddress->net, msg.localAddress->node, msg.localAddress->point);
		}
	} else if (msg.echo == 2) {
		snprintf(buffer, 1024, "\r--- mgpost\r * Origin: %s (@%d)\r", msg.origin, msg.maginode);
	}

	if (msg.echo != 0) {
		totlen += strlen(buffer);

		body = (char *)realloc(body, totlen + 1);
	
		memcpy(&body[totlen - strlen(buffer)], buffer, strlen(buffer));
		body[totlen] = '\0';
	}

	thetime = time(NULL);

	if (msg.echo == 1) {
		if (msg.localAddress->point == 0) {
			sprintf(buffer, "%d:%d/%d", msg.localAddress->zone, msg.localAddress->net, msg.localAddress->node);
		} else {
			sprintf(buffer, "%d:%d/%d.%d", msg.localAddress->zone, msg.localAddress->net, msg.localAddress->node, msg.localAddress->point);
		}
		
		oaddress = strdup(buffer);

		sprintf(buffer, "%d:%d/%d.%d %08lx", msg.localAddress->zone,
												msg.localAddress->net,
												msg.localAddress->node,
												msg.localAddress->point,
												generate_msgid(msg.bbs_path));


		msg_id = strdup(buffer);
	} else if (msg.echo == 2) {
		sprintf(buffer, "%d", msg.maginode);
		oaddress = strdup(buffer);

	    memset(buffer, 0, 1024);
	    uuid_generate(myuuid);
	    uuid_unparse_lower(myuuid, buffer);
		msg_id = strdup(buffer);
	}
	
	if (msg.basetype == 1) {
	    s_JamBase *jb;
	    s_JamMsgHeader jmh;
	    s_JamSubPacket* jsp;
	    s_JamSubfield jsf;

	    jb = open_jam_base(msg.msgbase);
	    if (!jb) {
	        printf("Unable to open JAM base %s\n", msg.msgbase);
	        exit(1);
	    }
	    JAM_ClearMsgHeader( &jmh );
		jmh.DateWritten = utc_to_local(thetime);

		jmh.Attribute |= JAM_MSG_LOCAL;

		if (!msg.echo) {
			jmh.Attribute |= JAM_MSG_TYPELOCAL;
		} else {
			jmh.Attribute |= JAM_MSG_TYPEECHO;
		}
	    jsp = JAM_NewSubPacket();
	    jsf.LoID   = JAMSFLD_SENDERNAME;
		jsf.HiID   = 0;
		jsf.DatLen = strlen(msg.from);
		jsf.Buffer = (char *)msg.from;
		JAM_PutSubfield(jsp, &jsf);
		
		jsf.LoID   = JAMSFLD_RECVRNAME;
		jsf.HiID   = 0;
		jsf.DatLen = 3;
		jsf.Buffer = "ALL";
		JAM_PutSubfield(jsp, &jsf);
		
		jsf.LoID   = JAMSFLD_SUBJECT;
		jsf.HiID   = 0;
		jsf.DatLen = strlen(msg.subject);
		jsf.Buffer = (char *)msg.subject;
		JAM_PutSubfield(jsp, &jsf);

		time_t offset = gettz();
		int offhour = offset / 3600;
		int offmin = (offset % 3600) / 60;


		if (offhour < 0) {
			snprintf(buffer, sizeof buffer, "TZUTC: -%02d%02d", abs(offhour), offmin);
		} else {
			snprintf(buffer, sizeof buffer, "TZUTC: %02d%02d", offhour, offmin);
		}

		jsf.LoID = JAMSFLD_FTSKLUDGE;
		jsf.HiID = 0;
		jsf.DatLen = strlen(buffer);
		jsf.Buffer = (char *)buffer;
		JAM_PutSubfield(jsp, &jsf);

		if (msg_id != NULL) {
	              jsf.LoID   = JAMSFLD_MSGID;
                      jsf.HiID   = 0;
	              jsf.DatLen = strlen(msg_id);
	              jsf.Buffer = (char *)msg_id;
	              JAM_PutSubfield(jsp, &jsf);
 		}
		if (oaddress != NULL) {
		      jsf.LoID   = JAMSFLD_OADDRESS;
                      jsf.HiID   = 0;
                      jsf.DatLen = strlen(oaddress);
                      jsf.Buffer = (char *)oaddress;
                      JAM_PutSubfield(jsp, &jsf);
		}

		while (1) {
			z = JAM_LockMB(jb, 100);
			if (z == 0) {
				break;
			} else if (z == JAM_LOCK_FAILED) {
				sleep(1);
			} else {
				printf("Failed to lock msg base!\n");
				break;
			}
		}
		if (z == 0) {
			if (JAM_AddMessage(jb, &jmh, jsp, (char *)body, strlen(body))) {
				printf("Failed to add message\n");
			}
	
			JAM_UnlockMB(jb);
			JAM_DelSubPacket(jsp);
		}
		JAM_CloseMB(jb);
	} else if (msg.basetype == 2) {
		// todo
		sqlite3 *dbase;
		sqlite3_stmt *res;
		uint32_t attribs = 1; // LOCAL
		char *to = "ALL";
		const char *sql = "INSERT INTO msgs(sender, recipient, subject, date, mattribs, daddress, oaddress, msgid, replyid, body) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";

		if (!open_sq3_database(msg.msgbase, &dbase)) {
        		exit(-1);
    		}

		if (sqlite3_prepare_v2(dbase, sql, strlen(sql), &res, NULL) != SQLITE_OK) {
		        fprintf(stderr, "Error prepareing sql\n");
	        	sqlite3_close(dbase);
        		return 0;
		}

		sqlite3_bind_text(res, 1, msg.from, -1, 0);
		sqlite3_bind_text(res, 2, to, -1, 0);
		sqlite3_bind_text(res, 3, msg.subject, -1, 0);
		sqlite3_bind_int(res, 4, thetime);
		sqlite3_bind_int(res, 5, attribs);
		sqlite3_bind_null(res, 6);
		sqlite3_bind_text(res, 7, oaddress, -1, 0);
		sqlite3_bind_text(res, 8, msg_id, -1, 0);
		sqlite3_bind_null(res, 9);
		sqlite3_bind_text(res, 10, body, -1, 0);

		if (sqlite3_step(res) != SQLITE_DONE) {
			fprintf(stderr, "error adding message\n");
			sqlite3_finalize(res);
			sqlite3_close(dbase);
			exit(-1);
		}
		sqlite3_finalize(res);
		sqlite3_close(dbase);
	}

	free(oaddress);
	free(msg_id);
	return 0;
}
