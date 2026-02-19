#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sqlite3.h>
#include "../../deps/jamlib/jam.h"
#include "../../src/inih/ini.h"

char *dbase;
char *msgbase;
int basetype;

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


static int handler(void* user, const char* section, const char* name,
                   const char* value)
{
	if (strcasecmp(section, "main") == 0) {
		if (strcasecmp(name, "bbslist database") == 0) {
            dbase = strdup(value);
		} else if (strcasecmp(name, "message base") == 0) {
			msgbase = strdup(value);
		} else if (strcasecmp(name, "message base type") == 0) {
            if (strcasecmp(value, "SQ3") == 0) {
                basetype = 1;
            }
        }
	}
	return 1;
}

int do_add_bbs_entry(char *bbsname, char *sysopname, char *location, char *software, char *address, int tport, int sport, char *comment) {
	sqlite3 *db;
	sqlite3_stmt *res;
	int rc;
	char *create_sql = "CREATE TABLE IF NOT EXISTS bbslist ("
	                   "id INTEGER PRIMARY KEY,"
	                   "bbsname TEXT,"
	                   "sysop TEXT,"
					   "location TEXT,"
					   "software TEXT,"
	                   "url TEXT,"
					   "tport INGEGER,"
					   "sport INTEGER,"
					   "comment TEXT,"
					   "verified INTEGER,"
	                   "owner INTEGER);";

	char *insert_sql = "INSERT INTO bbslist (bbsname, sysop, location, software, url, tport, sport, comment, verified, owner) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, -1)";
	char *check_sql = "SELECT id FROM bbslist WHERE bbsname=? and owner=-1";
    char *update_sql = "UPDATE bbslist SET sysop=?, location=?, software=?, url=?, tport=?, sport=?, comment=?, verified=? WHERE id =?";
    time_t ver = time(NULL);
	char *err_msg = 0;
    int id;

	rc = sqlite3_open(dbase, &db);

	if (rc != SQLITE_OK) {
		return 0;
	}
	sqlite3_busy_timeout(db, 5000);
	rc = sqlite3_exec(db, create_sql, 0, 0, &err_msg);
	if (rc != SQLITE_OK) {
		sqlite3_free(err_msg);
		sqlite3_close(db);
		return 0;
	}
    rc = sqlite3_prepare_v2(db, check_sql, -1, &res, 0);
	if (rc == SQLITE_OK) {
		sqlite3_bind_text(res, 1, bbsname, -1, 0);
    } else {
        sqlite3_close(db);
        return 0;
    }
    if (sqlite3_step(res) == SQLITE_ROW) {
        id = sqlite3_column_int(res, 0);
        sqlite3_finalize(res);
        rc = sqlite3_prepare_v2(db, update_sql, -1, &res, 0);
        if (rc == SQLITE_OK) {
            sqlite3_bind_text(res, 1, sysopname, -1, 0);
            sqlite3_bind_text(res, 2, location, -1, 0);
            sqlite3_bind_text(res, 3, software, -1, 0);
            sqlite3_bind_text(res, 4, address, -1, 0);
            sqlite3_bind_int(res, 5, tport);
            sqlite3_bind_int(res, 6, sport);
            sqlite3_bind_text(res, 7, comment, -1, 0);
            sqlite3_bind_int(res, 8, ver);
            sqlite3_bind_int(res, 9, id);
        } else {
            sqlite3_close(db);
            return 0;
        }
        sqlite3_step(res);
        sqlite3_finalize(res);
        sqlite3_close(db);
        return 1;
    } else {
        sqlite3_finalize(res);
        rc = sqlite3_prepare_v2(db, insert_sql, -1, &res, 0);
        if (rc == SQLITE_OK) {
            sqlite3_bind_text(res, 1, bbsname, -1, 0);
            sqlite3_bind_text(res, 2, sysopname, -1, 0);
            sqlite3_bind_text(res, 3, location, -1, 0);
            sqlite3_bind_text(res, 4, software, -1, 0);
            sqlite3_bind_text(res, 5, address, -1, 0);
            sqlite3_bind_int(res, 6, tport);
            sqlite3_bind_int(res, 7, sport);
            sqlite3_bind_text(res, 8, comment, -1, 0);
            sqlite3_bind_int(res, 9, ver);
        } else {
            sqlite3_close(db);
            return 0;            
        }
        sqlite3_step(res);
        sqlite3_finalize(res);
        sqlite3_close(db);
        return 1;
    }
}

int add_bbs_entry(char *msgtext) {
    char **lines;
    int linecount = 0;
    int lastpos = 0;

    for (int i = 0;i < strlen(msgtext); i++) {
        if (msgtext[i] == '\r' && lastpos != i) {
            if (linecount == 0) {
                lines = (char **)malloc(sizeof(char *));
            } else {
                lines = (char **)realloc(lines, sizeof(char *) * (linecount + 1));
            }
            lines[linecount] = (char *)malloc(i - lastpos + 1);
            int x = 0;
            for (int z = lastpos; z < i;z++) {
                lines[linecount][x++] = msgtext[z];
                lines[linecount][x] = '\0';
            }

            lastpos = i+1;
            linecount++;
        }
    }

    for (int i=0;i<linecount;i++) {
        if (strcmp(lines[i], "BEGIN BBSENTRY >>>") == 0) {
            if (i + 9 <= linecount && strcmp(lines[i+9], "END BBSENTRY >>>") == 0) {
                do_add_bbs_entry(lines[i+1], lines[i+2], lines[i+3], lines[i+4],lines[i+5], atoi(lines[i+6]), atoi(lines[i+7]), lines[i+8]);
            }
            break;
        }
    }
    for (int i=0;i<linecount;i++) {
        free(lines[i]);
    }
    free(lines);
}

int main(int argc, char **argv) {
    FILE *fptr;
    uint32_t lastread;

	if (argc < 2) {
		printf("Usage: %s inifile\n", argv[0]);
		exit(1);
	}

    basetype = 0;
    dbase = NULL;
    msgbase = NULL;

	if (ini_parse(argv[1], handler, NULL) <0) {
		fprintf(stderr, "Unable to load configuration ini (%s)!\n", argv[1]);
		exit(-1);
	}

    lastread = 0;
    fptr = fopen("bbslist_lr.dat", "rb");
    if (fptr) {
        if (fread(&lastread, sizeof(uint32_t), 1, fptr) != 1) {
            lastread = 0;
        }
        fclose(fptr);
    }

    if (basetype == 0) { /* JAM */
        s_JamBase *jb;
        s_JamBaseHeader jbh;
        s_JamMsgHeader jmh;
        s_JamSubPacket *jsp;
        jb = open_jam_base(msgbase);
        if (jb == NULL) {
            fprintf(stderr, "Unable to open msgbase: %s\n", msgbase);
            exit(-1);
        }
        int k = 0;
        int z = 0;
        int failed = 0;
        int gotentry;
        char *msgbuf;

	    JAM_ReadMBHeader(jb, &jbh);

        for (int i=0;k < jbh.ActiveMsgs;i++) {
            z = JAM_ReadMsgHeader(jb, i, &jmh, &jsp);
            if (z != 0) {
                failed++;
                k++;
                if (failed == 5000) {
                    break;
                }
                continue;
            }
		    if (jmh.Attribute & JAM_MSG_DELETED) {
			    JAM_DelSubPacket(jsp);
			    continue;
		    }
            if (jmh.MsgNum <= lastread) {
			    JAM_DelSubPacket(jsp);
                k++;
			    continue;
            }
            gotentry = 0;
            for (z = 0; z < jsp->NumFields;z++) {
                if (jsp->Fields[z]->LoID == JAMSFLD_SUBJECT) {
                    if (strncmp(jsp->Fields[z]->Buffer, "MBBSLIST", jsp->Fields[z]->DatLen) == 0) {
                        gotentry = 1;
                    }
                    break;
                }
            }
            JAM_DelSubPacket(jsp);
            k++;
            if (!gotentry) {
                continue;
            }
            // got message

            lastread = jmh.MsgNum;
            msgbuf = (char *)malloc(jmh.TxtLen + 1);
            if (!msgbuf) {
                fprintf(stderr, "Out of Memory!\n");
                return -1;
            }
            memset(msgbuf, 0, jmh.TxtLen + 1);
            JAM_ReadMsgText(jb, jmh.TxtOffset, jmh.TxtLen, (char *)msgbuf);
            add_bbs_entry(msgbuf);
            free(msgbuf);
        }
        JAM_CloseMB(jb);
        free(jb);
    } else if (basetype == 1) { /* SQ3 */

    }
    fptr = fopen("bbslist_lr.dat", "wb");
    if (fptr) {
        fwrite(&lastread, sizeof(uint32_t), 1, fptr);
        fclose(fptr);
    }    
}