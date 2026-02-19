#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <limits.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>
#include <fts.h>
#include <errno.h>
#include <sqlite3.h>

#include "qwk.h"
#include "../../deps/jamlib/jam.h"
#include "../../src/inih/ini.h"

#define TM_YEAR_ORIGIN 1900

char *outbound_path;
char *message_base_path;
char *temp_dir;
char *pack_cmd;
char *config_file;
char *hostid;
int format = BASE_TYPE_JAM;

static long difftm(struct tm *a, struct tm *b) {
        int ay = a->tm_year + (TM_YEAR_ORIGIN - 1);
        int by = b->tm_year + (TM_YEAR_ORIGIN - 1);
        long days = (a->tm_yday - b->tm_yday + ((ay >> 2) - (by >> 2)) - (ay / 100 - by / 100) + ((ay / 100 >> 2) - (by / 100 >> 2)) + (long)(ay - by) * 365);

        return (60 * (60 * (24 * days + (a->tm_hour - b->tm_hour)) + (a->tm_min - b->tm_min)) + (a->tm_sec - b->tm_sec));
}

long gmtoff(time_t value) {
        struct tm gmt = *gmtime(&value);
        return difftm(localtime(&value), &gmt);
}


int bases_exists = 0;

struct msg_bases {
	int baseno;
	char *path;
};

struct msg_bases **msgbases;
int msgbasecount = 0;

char *safe_strdup(const char *str) {
    if (str == NULL) {
        return NULL;
    }

    return strdup(str);
}

int recursive_delete(const char *dir) {
    int ret = 0;
    FTS *ftsp = NULL;
    FTSENT *curr;

    char *files[] = { (char *) dir, NULL };

    ftsp = fts_open(files, FTS_NOCHDIR | FTS_PHYSICAL | FTS_XDEV, NULL);
    if (!ftsp) {
        fprintf(stderr, "%s: fts_open failed: %s\n", dir, strerror(errno));
        ret = -1;
        goto finish;
    }

    while ((curr = fts_read(ftsp))) {
        switch (curr->fts_info) {
        case FTS_NS:
        case FTS_DNR:
        case FTS_ERR:
            fprintf(stderr, "%s: fts_read error: %s\n", curr->fts_accpath, strerror(curr->fts_errno));
            break;

        case FTS_DC:
        case FTS_DOT:
        case FTS_NSOK:
            break;

        case FTS_D:
            break;

        case FTS_DP:
        case FTS_F:
        case FTS_SL:
        case FTS_SLNONE:
        case FTS_DEFAULT:
            if (remove(curr->fts_accpath) < 0) {
                fprintf(stderr, "%s: Failed to remove: %s", curr->fts_path, strerror(errno));
                ret = -1;
            }
            break;
        }
    }

finish:
    if (ftsp) {
        fts_close(ftsp);
    }

    return ret;
}

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
		} else {
			free(jb);
			return NULL;
		}
	}
	return jb;
}

static int handler(void* user, const char* section, const char* name,
                   const char* value)
{
    if (strcasecmp(section, "main") == 0) {
        if (strcasecmp(name, "message path") == 0) {
            message_base_path = strdup(value);
        } else if (strcasecmp(name, "outbound") == 0) {
            outbound_path = strdup(value);
        } else if (strcasecmp(name, "temp dir") == 0) {
            temp_dir = strdup(value);
        } else if (strcasecmp(name, "pack command") == 0) {
            pack_cmd = strdup(value);
        } else if (strcasecmp(name, "host") == 0) {
            hostid = strdup(value);
        } else if (strcasecmp(name, "format") == 0) {
            if (strcasecmp(value, "jam") == 0) {
                format = BASE_TYPE_JAM;
            } else if (strcasecmp(name, "format") == 0) {
                format = BASE_TYPE_SQ3;
            }
        }
    } else if (strcasecmp(section, "bases") == 0) {
		bases_exists = 1;
		if (msgbasecount == 0) {
			msgbases = (struct msg_bases **)malloc(sizeof(struct msg_bases *));
		} else {
			msgbases = (struct msg_bases **)realloc(msgbases, sizeof(struct msg_bases *) * (msgbasecount + 1));
		}
		
		msgbases[msgbasecount] = (struct msg_bases *)malloc(sizeof(struct msg_bases));
		
		msgbases[msgbasecount]->baseno = atoi(name);
		msgbases[msgbasecount]->path = strdup(value);
		msgbasecount++;
	}
    return 1;
}

long sq3_utcoffset = 0xcafebabe;

static int open_sq3_database(const char *path, sqlite3 **db) {
    const char *create_sql = "CREATE TABLE IF NOT EXISTS msgs(id INTEGER PRIMARY KEY, sender TEXT, recipient TEXT, subject TEXT, date INTEGER, mattribs INTEGER, daddress TEXT, oaddress TEXT, msgid TEXT, replyid TEXT, body TEXT);";
    const char *create_sql2 = "CREATE TABLE IF NOT EXISTS lastread(userid INTEGER, messageid INTEGER);";
    int rc;
    char *err_msg;

    char fpath[PATH_MAX];

    snprintf(fpath, sizeof fpath, "%s.sq3", path);

    if (sqlite3_open(fpath, db) != SQLITE_OK) {
        return 0;
    }
    sqlite3_busy_timeout(*db, 5000);
    
    rc = sqlite3_exec(*db, create_sql, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        free(err_msg);
        sqlite3_close(*db);
        return 0;
    }
    rc = sqlite3_exec(*db, create_sql2, 0, 0, &err_msg);
    if (rc != SQLITE_OK) {
        free(err_msg);
        sqlite3_close(*db);
        return 0;
    }

    return 1;
}

int export_messages(int baseno, char *basefilename, int qwkidx) {
    int msgcount = 0;
    s_JamBase *jb;
    s_JamBaseHeader jbh;
	s_JamMsgHeader jmh;
	s_JamSubPacket* jsp;
    s_JamSubfield jsf;

    sqlite3 *db;
    sqlite3_stmt *res;
    sqlite3_stmt *res2;
    time_t datewritten;
    char *body;

    static const char *sql1 = "SELECT id, sender, recipient, subject, date, mattribs, msgid, replyid, body FROM msgs WHERE mattribs = 1";
    static const char *sql2 = "UPDATE msgs SET mattribs=? WHERE id=?";
    int id;
    int attrib;
    int i;
    int z;
    int len;
    int lenbytes;
    char buffer[PATH_MAX];
    
    struct QwkHeader qh;
    struct tm msgtm;
    FILE *fptr;
    FILE *hdrptr;
    char text[128];
    char *msgbuf;
    char *msgptr;
    
    long offset;

    char *msgsubj = NULL;
    char *msgto = NULL;
    char *msgfrom = NULL;
    char *msgid = NULL;
    char *msgreplyid = NULL;

    snprintf(buffer, PATH_MAX, "%s/%s", message_base_path, basefilename);

   if(sq3_utcoffset == 0xcafebabe) 
   {
      time_t t1,t2;
      struct tm *tp;

      t1=time(NULL);
      tp=gmtime(&t1);
      tp->tm_isdst=-1;
      t2=mktime(tp);
      sq3_utcoffset=t2-t1;
   }

    if (format == BASE_TYPE_JAM) {
        jb = open_jam_base(buffer);
        if (jb) {
            JAM_ReadMBHeader(jb, &jbh);
            if (jbh.ActiveMsgs > 0) {
                int k = 0;
                for (i=0;k<jbh.ActiveMsgs;i++) {
                    memset(&jmh, 0, sizeof(s_JamMsgHeader));
                    z = JAM_ReadMsgHeader(jb, i, &jmh, &jsp);

                    if (z != 0) {
                        k++;
                        continue;
                    }

                    if (jmh.Attribute & JAM_MSG_DELETED) {
                        JAM_DelSubPacket(jsp);
                        continue;
                    }

                    if ((jmh.Attribute & JAM_MSG_SENT) || !(jmh.Attribute & JAM_MSG_LOCAL)) {
                        k++;
                        JAM_DelSubPacket(jsp);
                        continue;                
                    } else {
                        // export message        
                        for (z=0;z<jsp->NumFields;z++) {
                            if (jsp->Fields[z]->LoID == JAMSFLD_SUBJECT) {
                                msgsubj = (char *)malloc(jsp->Fields[z]->DatLen + 1);
                                memset(msgsubj, 0, jsp->Fields[z]->DatLen + 1);
                                memcpy(msgsubj, jsp->Fields[z]->Buffer, jsp->Fields[z]->DatLen);

                                if (jsp->Fields[z]->DatLen > 24) {
                                    len = 24;
                                } else {
                                    len = jsp->Fields[z]->DatLen;
                                }
                                memset(qh.MsgSubj, ' ', 25);
                                memcpy(qh.MsgSubj, jsp->Fields[z]->Buffer, len);
                            }
                            if (jsp->Fields[z]->LoID == JAMSFLD_SENDERNAME) {
                                msgfrom = (char *)malloc(jsp->Fields[z]->DatLen + 1);
                                memset(msgfrom, 0, jsp->Fields[z]->DatLen + 1);
                                memcpy(msgfrom, jsp->Fields[z]->Buffer, jsp->Fields[z]->DatLen);                            
                                if (jsp->Fields[z]->DatLen > 24) {
                                    len = 24;
                                } else {
                                    len = jsp->Fields[z]->DatLen;
                                }
                                memset(qh.MsgFrom, ' ', 25);              
                                memcpy(qh.MsgFrom, jsp->Fields[z]->Buffer, len);
                            }
                            if (jsp->Fields[z]->LoID == JAMSFLD_RECVRNAME) {
                                msgto = (char *)malloc(jsp->Fields[z]->DatLen + 1);
                                memset(msgto, 0, jsp->Fields[z]->DatLen + 1);
                                memcpy(msgto, jsp->Fields[z]->Buffer, jsp->Fields[z]->DatLen);
                                if (jsp->Fields[z]->DatLen > 24) {
                                    len = 24;
                                } else {
                                    len = jsp->Fields[z]->DatLen;
                                }            
                                memset(qh.MsgTo, ' ', 25);          
                                memcpy(qh.MsgTo, jsp->Fields[z]->Buffer, len);
                            }
                            if (jsp->Fields[z]->LoID == JAMSFLD_MSGID) {
                                msgid = (char *)malloc(jsp->Fields[z]->DatLen + 1);
                                memset(msgid, 0, jsp->Fields[z]->DatLen + 1);
                                memcpy(msgid, jsp->Fields[z]->Buffer, jsp->Fields[z]->DatLen);
                            }
                            if (jsp->Fields[z]->LoID == JAMSFLD_REPLYID) {
                                msgreplyid = (char *)malloc(jsp->Fields[z]->DatLen + 1);
                                memset(msgreplyid, 0, jsp->Fields[z]->DatLen + 1);
                                memcpy(msgreplyid, jsp->Fields[z]->Buffer, jsp->Fields[z]->DatLen);
                            }                        
                        }
                        qh.Msgstat = ' ';
                        snprintf(buffer, 7, "%d", baseno);
                        memset(qh.Msgnum, ' ', 7);
                        memcpy(qh.Msgnum, buffer, strlen(buffer));

			            datewritten = jmh.DateWritten - gmtoff(jmh.DateWritten);

                        gmtime_r(&datewritten, &msgtm);

                        snprintf(buffer, PATH_MAX, "%02d-%02d-%02d", msgtm.tm_mon + 1, msgtm.tm_mday, msgtm.tm_year - 100);
                        memcpy(qh.Msgdate, buffer, 8);

                        snprintf(buffer, PATH_MAX, "%02d:%02d", msgtm.tm_hour, msgtm.tm_min);
                        memcpy(qh.Msgtime, buffer, 5);

                        memset(qh.Msgpass, ' ', 12);
                        memset(qh.Msgrply, ' ', 8);

                        len = jmh.TxtLen / 128 + 2;
                        lenbytes = len * 128;
                        
                        msgbuf = (char *)malloc(lenbytes);

                        memset(msgbuf, ' ', lenbytes);

                        JAM_ReadMsgText(jb, jmh.TxtOffset, jmh.TxtLen, msgbuf);

                        for (int h=0;h <= lenbytes;h++) {
                            if (msgbuf[h] == '\r') {
                                msgbuf[h] = '\xe3';
                            }
                        }

                        for (z=0;z<lenbytes;z++) {
                            if (msgbuf[z] == '\0') {
                                msgbuf[z] = ' ';
                            }
                        }

                        snprintf(buffer, 7, "%d", len);
                        memset(qh.Msgrecs, ' ', 6);
                        memcpy(qh.Msgrecs, buffer, strlen(buffer));

                        qh.Msglive = 0xE1;
                        qh.Msgarealo = baseno & 0xff;
                        qh.Msgareahi = (baseno >> 8) & 0xff;

                        qh.Msgoffhi = ((qwkidx + msgcount + 1) >> 8) & 0xff;
                        qh.Msgofflo = (qwkidx + msgcount + 1) & 0xff;

                        qh.Msgtagp = '*';


                        snprintf(buffer, PATH_MAX, "%s/%s.MSG", temp_dir, hostid);
                        fptr = fopen(buffer, "r+");
                        if (!fptr) {
                            fptr = fopen(buffer, "w");
                            if (fptr) {
                                memset(text, ' ', 128);
                                memcpy(text, hostid, strlen(hostid));
                                fwrite(text, 128, 1, fptr);
                            } else {
                                fprintf(stderr, "UNABLE TO OPEN %s!!\n", buffer);
                                JAM_CloseMB(jb);
                                free(jb);
                                exit(-1);
                            }
                        } else {
                            fseek(fptr, 0, SEEK_END);
                        }

                        offset = ftell(fptr);

                        snprintf(buffer, PATH_MAX, "%s/HEADERS.DAT", temp_dir);
                        hdrptr = fopen(buffer, "a");

                        fprintf(hdrptr, "[%lx]\n", offset);
                        if (msgid != NULL) {
                            fprintf(hdrptr, "Message-ID: %s\n", msgid);
                            free(msgid);
                            msgid = NULL;
                        }        
                        if (msgreplyid != NULL) {
                            fprintf(hdrptr, "In-Reply-To: %s\n", msgreplyid);
                            free(msgreplyid);
                            msgreplyid = NULL;
                        }            
                        if (msgsubj != NULL) {
                            fprintf(hdrptr, "Subject: %s\n", msgsubj);
                            free(msgsubj);
                            msgsubj = NULL;
                        }
                        if (msgto != NULL) {
                            fprintf(hdrptr, "To: %s\n", msgto);
                            free(msgto);
                            msgto = NULL;
                        }        
                        if (msgfrom != NULL) {
                            fprintf(hdrptr, "Sender: %s\n", msgfrom);
                            free(msgfrom);
                            msgfrom = NULL;
                        }                                

                        fprintf(hdrptr, "\n");
                        fclose(hdrptr);

                        fwrite(&qh, 128, 1, fptr);
                        fwrite(msgbuf, lenbytes - 128, 1, fptr);
                        fclose(fptr);
                        jmh.Attribute |= JAM_MSG_SENT;
                        while (1) {
                            z = JAM_LockMB(jb, 100);
                            if (z == 0) {
                                break;
                            } else if (z == JAM_LOCK_FAILED) {
                                sleep(1);
                            } else {
                                JAM_DelSubPacket(jsp);
                                JAM_CloseMB(jb);
                                free(jb);
                                fprintf(stderr, "Error locking JAM base!\n");
                                exit(-1);
                            }
                        }
                        z =JAM_ChangeMsgHeader(jb, i, &jmh);
                        JAM_UnlockMB(jb);
                        JAM_DelSubPacket(jsp);
                        free(msgbuf);
                        msgcount++;
                    }
                    k++;
                }
            }
            JAM_CloseMB(jb);
            free(jb);
        }
    } else if (format == BASE_TYPE_SQ3) {
        if (open_sq3_database(buffer, &db)) {
            if (sqlite3_prepare_v2(db, sql1, strlen(sql1), &res, NULL) != SQLITE_OK) {
                sqlite3_close(db);
                return msgcount;
            }

            while (sqlite3_step(res) == SQLITE_ROW) {
                id = sqlite3_column_int(res, 0);


                msgfrom = safe_strdup(sqlite3_column_text(res, 1));
                if (strlen(msgfrom) > 24) {
                    len = 24;
                } else {
                    len = strlen(msgfrom);
                }

                memset(qh.MsgFrom, ' ', 25);
                memcpy(qh.MsgFrom, msgfrom, len);

                msgto = safe_strdup(sqlite3_column_text(res, 2));
                if (strlen(msgto) > 24) {
                    len = 24;
                } else {
                    len = strlen(msgto);
                }

                memset(qh.MsgTo, ' ', 25);
                memcpy(qh.MsgTo, msgto, len);

                msgsubj = safe_strdup(sqlite3_column_text(res, 3));
                if (strlen(msgsubj) > 24) {
                    len = 24;
                } else {
                    len = strlen(msgsubj);
                }

                memset(qh.MsgSubj, ' ', 25);
                memcpy(qh.MsgSubj, msgsubj, len);

                msgid = safe_strdup(sqlite3_column_text(res, 6));
                msgreplyid = safe_strdup(sqlite3_column_text(res, 7));

                qh.Msgstat = ' ';
                
                snprintf(buffer, 7, "%d", baseno);
                memset(qh.Msgnum, ' ', 7);
                memcpy(qh.Msgnum, buffer, strlen(buffer));

                datewritten = sqlite3_column_int(res, 4) + sq3_utcoffset;
                attrib = sqlite3_column_int(res, 5);



                gmtime_r(&datewritten, &msgtm);

                snprintf(buffer, PATH_MAX, "%02d-%02d-%02d", msgtm.tm_mon + 1, msgtm.tm_mday, msgtm.tm_year - 100);
                memcpy(qh.Msgdate, buffer, 8);

                snprintf(buffer, PATH_MAX, "%02d:%02d", msgtm.tm_hour, msgtm.tm_min);
                memcpy(qh.Msgtime, buffer, 5);

                memset(qh.Msgpass, ' ', 12);
                memset(qh.Msgrply, ' ', 8);

                body = safe_strdup(sqlite3_column_text(res, 8));

                len = strlen(body) / 128 + 2;
                lenbytes = len * 128;
                        
                msgbuf = (char *)malloc(lenbytes);

                memset(msgbuf, ' ', lenbytes);

                memcpy(msgbuf, body, strlen(body));
    
                free(body);

                for (int h=0;h <= lenbytes;h++) {
                    if (msgbuf[h] == '\r') {
                        msgbuf[h] = '\xe3';
                    }
                }

                for (z=0;z<lenbytes;z++) {
                    if (msgbuf[z] == '\0') {
                        msgbuf[z] = ' ';
                    }
                }

                snprintf(buffer, 7, "%d", len);
                memset(qh.Msgrecs, ' ', 6);
                memcpy(qh.Msgrecs, buffer, strlen(buffer));

                qh.Msglive = 0xE1;
                qh.Msgarealo = baseno & 0xff;
                qh.Msgareahi = (baseno >> 8) & 0xff;

                qh.Msgoffhi = ((qwkidx + msgcount + 1) >> 8) & 0xff;
                qh.Msgofflo = (qwkidx + msgcount + 1) & 0xff;

                qh.Msgtagp = '*';

                snprintf(buffer, PATH_MAX, "%s/%s.MSG", temp_dir, hostid);
                fptr = fopen(buffer, "r+");
                if (!fptr) {
                    fptr = fopen(buffer, "w");
                    if (fptr) {
                        memset(text, ' ', 128);
                        memcpy(text, hostid, strlen(hostid));
                        fwrite(text, 128, 1, fptr);
                    } else {
                        fprintf(stderr, "UNABLE TO OPEN %s!!\n", buffer);

                        exit(-1);
                    }
                } else {
                    fseek(fptr, 0, SEEK_END);
                }

                offset = ftell(fptr);

                snprintf(buffer, PATH_MAX, "%s/HEADERS.DAT", temp_dir);
                hdrptr = fopen(buffer, "a");

                fprintf(hdrptr, "[%lx]\n", offset);
                if (msgid != NULL) {
                    fprintf(hdrptr, "Message-ID: %s\n", msgid);
                    free(msgid);
                    msgid = NULL;
                }        
                if (msgreplyid != NULL) {
                    fprintf(hdrptr, "In-Reply-To: %s\n", msgreplyid);
                    free(msgreplyid);
                    msgreplyid = NULL;
                }            
                if (msgsubj != NULL) {
                    fprintf(hdrptr, "Subject: %s\n", msgsubj);
                    free(msgsubj);
                    msgsubj = NULL;
                }
                if (msgto != NULL) {
                    fprintf(hdrptr, "To: %s\n", msgto);
                    free(msgto);
                    msgto = NULL;
                }        
                if (msgfrom != NULL) {
                    fprintf(hdrptr, "Sender: %s\n", msgfrom);
                    free(msgfrom);
                    msgfrom = NULL;
                }                                

                fprintf(hdrptr, "\n");
                fclose(hdrptr);

                fwrite(&qh, 128, 1, fptr);
                fwrite(msgbuf, lenbytes - 128, 1, fptr);
                fclose(fptr);
                
                attrib |= SQ3_MSG_SENT;
                if (sqlite3_prepare_v2(db, sql2, strlen(sql2), &res2, NULL) != SQLITE_OK) {
                    fprintf(stderr, "Failed to mark message as sent!\n");
                } else {
                    sqlite3_bind_int(res2, 1, attrib);
                    sqlite3_bind_int(res2, 2, id);

                    sqlite3_step(res2);
                    sqlite3_finalize(res2);
                }
                free(msgbuf);
                msgcount++;
            }
            sqlite3_finalize(res);
            sqlite3_close(db);
        }
    }
    return msgcount;
}

int main(int argc, char **argv) {
    int i;
    message_base_path = NULL;
    outbound_path = NULL;
    temp_dir = NULL;
    int qwkidx = 0;
    int msgcount = 0;
    char buffer[PATH_MAX];
    char archive[PATH_MAX];
    int ret;
    struct stat st;

    if (argc < 2) {
        fprintf(stderr, "Usage:\n    ./qwkscan config.ini\n");
        return -1;
    }

	config_file = argv[1];

	if (ini_parse(config_file, handler, NULL) <0) {
		fprintf(stderr, "Unable to load configuration ini (%s)!\n", config_file);
		exit(-1);
	}

    if (temp_dir == NULL || message_base_path == NULL || outbound_path == NULL) {
        fprintf(stderr, "Outbound Path & Temp dir must both be set\n");
        exit(-1);
    }

    mkdir(temp_dir, 0755);

    for (i=0;i<msgbasecount;i++) {
        msgcount = export_messages(msgbases[i]->baseno, msgbases[i]->path, qwkidx);
        qwkidx += msgcount;
        fprintf(stderr, "Exporting from base %d... %d exported\n", msgbases[i]->baseno, msgcount);
    }

    if (qwkidx > 0) {

        snprintf(archive, PATH_MAX, "%s/%s.REP", outbound_path, hostid);
        i = 1;
        while (stat(archive, &st) == 0) {
            snprintf(archive, PATH_MAX, "%s/%s.REP.%d", outbound_path, hostid, i);
            i++;
        }

        char *b = buffer;
        size_t blen = sizeof buffer;
        for (const char *p = pack_cmd; *p != '\0' && blen >= 1; ++p) {
            if (*p != '*') {
                *b++ = *p;
                --blen;
                continue;
            }
            p++;
            size_t alen = 0;
            if (*p == 'a') {
                strncpy(b, archive, blen);
                alen = strlen(archive);
            } else if (*p == 'f') {
                snprintf(b, blen, "%s/%s.MSG %s/HEADERS.DAT", temp_dir, hostid, temp_dir);
                alen = strlen(b);
            } else if (*p == '*') {
                *b++ = '*';
                alen = 1;
            }
            b += alen;
            blen -= alen;
        }
        *b = '\0';

        ret = system(buffer);
        if (ret == -1 || ret >> 8 == 127) {
            fprintf(stderr, "Failed to run archiver!\n");
            return -1;
        }
    }
    recursive_delete(temp_dir);
}
