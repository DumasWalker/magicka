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



char *inbound_path;
char *message_base_path;
char *temp_dir;
char *unpack_cmd;
char *config_file;
int format;

int bases_exists = 0;

struct msg_bases {
	int baseno;
	char *path;
};

struct header_t {
    char *key;
    char *value;
};

struct msg_headers_t {
    long offset;
    struct header_t **headers;
    int header_count;
};

struct msg_headers_t **msg_headers;
int msg_count = 0;

struct msg_bases **msgbases;
int msgbasecount = 0;

static int safe_atoi(const char *str, int len) {
    int ret = 0;

    for (int i=0;i<len;i++) {
        if (str[i] < '0' || str[i] > '9') {
            break;
        }
        ret = ret * 10 + (str[i] - '0');
    }
    return ret;
}

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

static char *get_key_value(struct msg_headers_t *header, char *key) {
    if (header == NULL) return NULL;
    for (int i=0;i<header->header_count;i++) {
        if (strcmp(key, header->headers[i]->key) == 0) {
            return header->headers[i]->value;
        }
    }
    return NULL;
}

static struct msg_headers_t *get_header(long offset) {
    for (int i=0;i<msg_count;i++) {
        if (msg_headers[i]->offset == offset) {
            return msg_headers[i];
        }
    }

    return NULL;
}

static int header_handler(void* user, const char* section, const char* name,
                   const char* value)
{
    for (int i=0;i<msg_count;i++) {
        if (msg_headers[i]->offset == strtol(section, NULL, 16)) {
            msg_headers[i]->headers = (struct header_t **)realloc(msg_headers[i]->headers, sizeof(struct header_t *) * (msg_headers[i]->header_count + 1));
            msg_headers[i]->headers[msg_headers[i]->header_count] = (struct header_t *)malloc(sizeof(struct header_t));
            msg_headers[i]->headers[msg_headers[i]->header_count]->key = strdup(name);
            msg_headers[i]->headers[msg_headers[i]->header_count]->value = strdup(value);
            msg_headers[i]->header_count++;
            return 1;
        }
    }
    if (msg_count == 0) {
        msg_headers = (struct msg_headers_t **)malloc(sizeof(struct msg_headers_t *));
    } else {
        msg_headers = (struct msg_headers_t **)realloc(msg_headers, sizeof(struct msg_headers_t *) * (msg_count + 1));
    }

    msg_headers[msg_count] = (struct msg_headers_t *)malloc(sizeof(struct msg_headers_t));
    msg_headers[msg_count]->offset = strtol(section, NULL, 16);
    msg_headers[msg_count]->header_count = 1;
    msg_headers[msg_count]->headers = (struct header_t **)malloc(sizeof(struct header_t *));
    msg_headers[msg_count]->headers[0] = (struct header_t *)malloc(sizeof(struct header_t));
    msg_headers[msg_count]->headers[0]->key = strdup(name);
    msg_headers[msg_count]->headers[0]->value = strdup(value);

    msg_count++;

    return 1;
}

static int handler(void* user, const char* section, const char* name,
                   const char* value)
{
    if (strcasecmp(section, "main") == 0) {
        if (strcasecmp(name, "message path") == 0) {
            message_base_path = strdup(value);
        } else if (strcasecmp(name, "inbound") == 0) {
            inbound_path = strdup(value);
        } else if (strcasecmp(name, "temp dir") == 0) {
            temp_dir = strdup(value);
        } else if (strcasecmp(name, "unpack command") == 0) {
            unpack_cmd = strdup(value);
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

size_t trimwhitespace(char *out, size_t len, const char *str) {
    if(len == 0)
        return 0;

    const char *end;
    size_t out_size;

    // Trim trailing space
    end = str + strlen(str) - 1;
    while(end > str && isspace((unsigned char)*end)) end--;
    end++;

    // Set output size to minimum of trimmed string length and buffer size minus 1
    out_size = (end - str) < len-1 ? (end - str) : len-1;

    // Copy trimmed string and add null terminator
    memcpy(out, str, out_size);
    out[out_size] = 0;

    return out_size;
}

int process_msgs_dat(char *msgsdat) {
    FILE *fptr;
    FILE *cfgfptr;

    char buffer[PATH_MAX];
    char headerfile[PATH_MAX];
    struct QwkHeader qhdr;
    int msgrecs;
    char *msgbody;
    char mbuf[129];
    int i;
    time_t msgdate;
    struct tm thedate;
    int year;
    char msgto[26];
    char msgfrom[26];
    char msgsubj[26];
    unsigned int msgconf;
	s_JamBase *jb;
	s_JamMsgHeader jmh;
	s_JamSubPacket* jsp;
	s_JamSubfield jsf;
    int z;
	int basefound = 0;
	long offset;
    char *ptr;
    char *sptr;
    char *rptr;
    char *idptr;
    char *ridptr;

    sqlite3 *db;
    sqlite3_stmt *res;
    static const char *sql = "INSERT INTO msgs (sender, recipient, subject, date, mattribs, msgid, replyid, body) VALUES(?, ?, ?, ?, 0, ?, ?, ?)";

    struct msg_headers_t *header = NULL;


    snprintf(headerfile, PATH_MAX, "%s/HEADERS.DAT", temp_dir);

    ini_parse(headerfile, header_handler, NULL);
    
    snprintf(buffer, PATH_MAX, "%s/%s", temp_dir, msgsdat);

    fptr = fopen(buffer, "rb");

    if (!fptr) {
        return -1;
    }


    fread(&qhdr, sizeof(struct QwkHeader), 1, fptr);
    while (!feof(fptr)) {
        offset = ftell(fptr);
        header = get_header(offset);
        if (fread(&qhdr, sizeof(struct QwkHeader), 1, fptr) != 1) {
            break;
        }

        msgrecs = safe_atoi(qhdr.Msgrecs, 6);
        msgbody = (char *)malloc((msgrecs * 128) + 1);
        memset(msgbody, 0, (msgrecs * 128) + 1);
        for (i=1;i<msgrecs;i++) {
            fread(mbuf, 1, 128, fptr);
            if (i == msgrecs - 1) {
                trimwhitespace(msgbody + ((i-1) * 128), 128, mbuf);
            } else {
                memcpy(msgbody + ((i-1) * 128), mbuf, 128);
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

        thedate.tm_hour = (qhdr.Msgtime[0] -'0') * 10 + (qhdr.Msgtime[1] - '0');
        thedate.tm_min = (qhdr.Msgtime[3] -'0') * 10 + (qhdr.Msgtime[4] - '0');
        
        msgdate = mktime(&thedate);

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

		basefound = 0;
		for (i=0;i<msgbasecount;i++) {
			if (msgbases[i]->baseno == msgconf) {
				basefound = 1;
				snprintf(buffer, PATH_MAX, "%s/%s", message_base_path, msgbases[i]->path);
				break;
			}
		}
		
		if (!basefound) {

			
			cfgfptr = fopen(config_file, "a");
			
			if (!bases_exists) {
				fprintf(cfgfptr, "[bases]\n");
				bases_exists = 1;
			}
			
			fprintf(cfgfptr, "%d = %d\n", msgconf, msgconf);
			fclose(cfgfptr);
			
			if (msgbasecount == 0) {
				msgbases = (struct msg_bases **)malloc(sizeof(struct msg_bases *));
			} else {
				msgbases = (struct msg_bases **)realloc(msgbases, sizeof(struct msg_bases *) * (msgbasecount + 1));
			}
			
			msgbases[msgbasecount] = (struct msg_bases *)malloc(sizeof(struct msg_bases));
			msgbases[msgbasecount]->baseno = msgconf;
			snprintf(buffer, PATH_MAX, "%d", msgconf);
			msgbases[msgbasecount]->path = strdup(buffer);
			msgbasecount++;
			snprintf(buffer, PATH_MAX, "%s/%d", message_base_path, msgconf);
		}

        if (format == BASE_TYPE_JAM) {
            jb = open_jam_base(buffer);
            if (!jb) {
                fprintf(stderr, "Unable to open JAM base: %s\n", buffer);
                free(msgbody);
                fclose(fptr);
                return -1;
            }
            JAM_ClearMsgHeader( &jmh );
            jmh.DateWritten = msgdate;

            jsp = JAM_NewSubPacket();

            jsf.LoID   = JAMSFLD_SENDERNAME;
            jsf.HiID   = 0;

            ptr = get_key_value(header, "Sender");
            if (ptr != NULL) {
                jsf.DatLen = strlen(ptr);
                jsf.Buffer = ptr;
            } else {
                jsf.DatLen = strlen(msgfrom);
                jsf.Buffer = (char *)msgfrom;
            }
            JAM_PutSubfield(jsp, &jsf);        

            jsf.LoID   = JAMSFLD_RECVRNAME;
            jsf.HiID   = 0;

            ptr = get_key_value(header, "To");
            if (ptr != NULL) {
                jsf.DatLen = strlen(ptr);
                jsf.Buffer = (char *)ptr;
            } else {
                jsf.DatLen = strlen(msgto);
                jsf.Buffer = (char *)msgto;
            }
            JAM_PutSubfield(jsp, &jsf);       

            jsf.LoID   = JAMSFLD_SUBJECT;
            jsf.HiID   = 0;
            ptr = get_key_value(header, "Subject");
            if (ptr != NULL) {
                jsf.DatLen = strlen(ptr);
                jsf.Buffer = (char *)ptr;
            } else {
                jsf.DatLen = strlen(msgsubj);
                jsf.Buffer = (char *)msgsubj;
            }
            JAM_PutSubfield(jsp, &jsf);

            ptr = get_key_value(header, "Message-ID");
            if (ptr != NULL) {
                jsf.LoID   = JAMSFLD_MSGID;
                jsf.HiID   = 0;
                jsf.DatLen = strlen(ptr);
                jsf.Buffer = (char *)ptr;
                JAM_PutSubfield(jsp, &jsf);
            }

            ptr = get_key_value(header, "In-Reply-To");
            if (ptr != NULL) {
                jsf.LoID   = JAMSFLD_REPLYID;
                jsf.HiID   = 0;
                jsf.DatLen = strlen(ptr);
                jsf.Buffer = (char *)ptr;
                JAM_PutSubfield(jsp, &jsf);
            }

            jmh.Attribute |= JAM_MSG_TYPEECHO;

            while (1) {
                z = JAM_LockMB(jb, 100);
                if (z == 0) {
                    break;
                } else if (z == JAM_LOCK_FAILED) {
                    sleep(1);
                } else {
                    fprintf(stderr, "Failed to lock msg base!\n");
                    fclose(fptr);
                    JAM_CloseMB(jb);
                    free(jb);	
                    free(msgbody);
                    return 1;
                }
            }
            if (JAM_AddMessage(jb, &jmh, jsp, (char *)msgbody, strlen(msgbody))) {
                fprintf(stderr, "Failed to add message\n");
                JAM_UnlockMB(jb);
                
                JAM_DelSubPacket(jsp);
                JAM_CloseMB(jb);
                free(jb);
                free(msgbody);
                fclose(fptr);
                return -1;
            } else {
                JAM_UnlockMB(jb);

                JAM_DelSubPacket(jsp);
                JAM_CloseMB(jb);
                free(jb);
                free(msgbody);
            }
        } else if (format == BASE_TYPE_SQ3) {
            if (!open_sq3_database(buffer, &db)) {
                fprintf(stderr, "Unable to open SQ3 base: %s\n", buffer);
                free(msgbody);
                fclose(fptr);
                return -1;
            }

            if (sqlite3_prepare_v2(db, sql, strlen(sql), &res, NULL) != SQLITE_OK) {
                fprintf(stderr, "Error preparing SQL\n");
                sqlite3_close(db);
                free(msgbody);
                fclose(fptr);
                return -1;
            }

            sptr = get_key_value(header, "Sender");
            if (sptr != NULL) {
                sqlite3_bind_text(res, 1, sptr, -1, 0);
            } else {
                sqlite3_bind_text(res, 1, msgfrom, -1, 0);
            }

            rptr = get_key_value(header, "To");
            if (rptr != NULL) {
                sqlite3_bind_text(res, 2, rptr, -1, 0);
            } else {
                sqlite3_bind_text(res, 2, msgto, -1, 0);
            }

            ptr = get_key_value(header, "Subject");
            if (ptr != NULL) {
                sqlite3_bind_text(res, 3, ptr, -1, 0);
            } else {
                sqlite3_bind_text(res, 3, msgsubj, -1, 0);
            }

            sqlite3_bind_int(res, 4, msgdate);

            idptr = get_key_value(header, "Message-ID");
            if (idptr != NULL) {
                sqlite3_bind_text(res, 5, idptr, -1, 0);
            } else {
                sqlite3_bind_null(res, 5);
            }


            ridptr = get_key_value(header, "In-Reply-To");
            if (idptr != NULL) {
                sqlite3_bind_text(res, 6, ridptr, -1, 0);
            } else {
                sqlite3_bind_null(res, 6);
            }

            sqlite3_bind_text(res, 7, msgbody, -1, 0);

            sqlite3_step(res);

            sqlite3_finalize(res);
            sqlite3_close(db);
        }         
    }
    fclose(fptr);
    return 0;
}

int process_qwk_file(char *qwkfile) {
    // unpack file
    int i;
    char buffer[PATH_MAX];
    int bpos = 0;
    struct stat st;
    int ret;
    DIR *tmpb;
    struct dirent *dent;

    for (i=0;i<strlen(unpack_cmd);i++) {
		if (unpack_cmd[i] == '*') {
			i++;
			if (unpack_cmd[i] == 'a') {
				sprintf(&buffer[bpos], "%s/%s", inbound_path, qwkfile);
				bpos = strlen(buffer);
			} else if (unpack_cmd[i] == 'd') {
				sprintf(&buffer[bpos], "%s", temp_dir);
				bpos = strlen(buffer);				
			} else if (unpack_cmd[i] == '*') {
				buffer[bpos++] = '*';
				buffer[bpos] = '\0';
			}
		} else {
			buffer[bpos++] = unpack_cmd[i];
			buffer[bpos] = '\0';
		}
	}

    // check if tempdir exists

    if (stat(temp_dir, &st) == 0) {
        fprintf(stderr, "Temp Path exists! Please delete it first\n");
        return -1;
    }

    mkdir(temp_dir, 0755);

    ret = system(buffer);
    if (ret == -1 || ret >> 8 == 127) {
        return -1;
    }
    // process NDXs
	tmpb = opendir(temp_dir);
	if (!tmpb) {
		fprintf(stderr, "Error opening temp directory\n");
		return -1;
	}
	while ((dent = readdir(tmpb)) != NULL) {
        if (strcasecmp(dent->d_name, "messages.dat") == 0) {
	    	// process tic file
            ret = process_msgs_dat(dent->d_name);
        }
	}
	closedir(tmpb);

    // delete temp dir
    recursive_delete(temp_dir);
    snprintf(buffer, PATH_MAX, "%s/%s", inbound_path, qwkfile);
    remove(buffer);
    return ret;
}

int main(int argc, char **argv) {
    // read ini file
    DIR *inb;
    struct dirent *dent;


    message_base_path = NULL;
    inbound_path = NULL;
    temp_dir = NULL;
    format = BASE_TYPE_JAM;

    if (argc < 2) {
        fprintf(stderr, "Usage:\n    ./qwktoss config.ini\n");
        return -1;
    }

	config_file = argv[1];

	if (ini_parse(config_file, handler, NULL) <0) {
		fprintf(stderr, "Unable to load configuration ini (%s)!\n", config_file);
		exit(-1);
	}

    if (temp_dir == NULL || message_base_path == NULL || inbound_path == NULL) {
        fprintf(stderr, "Message Base Path and Inbound Path must be set\n");
        exit(-1);
    }

    // scan for QWK files
	inb = opendir(inbound_path);
	if (!inb) {
		fprintf(stderr, "Error opening inbound directory\n");
		return -1;
	}
	while ((dent = readdir(inb)) != NULL) {
		if (dent->d_name[strlen(dent->d_name) - 4] == '.' &&
				tolower(dent->d_name[strlen(dent->d_name) - 3]) == 'q' &&
				tolower(dent->d_name[strlen(dent->d_name) - 2]) == 'w' &&
				tolower(dent->d_name[strlen(dent->d_name) - 1]) == 'k'
			) {
				// process qwk file
				fprintf(stderr, "Processing QWK file %s\n", dent->d_name);
				if (process_qwk_file(dent->d_name) != -1) {
                    
					rewinddir(inb);
				}
			}
	}
	closedir(inb);

    return 0;
}
