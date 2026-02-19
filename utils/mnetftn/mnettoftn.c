#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/file.h>
#include <time.h>
#include <arpa/inet.h>
#include "jamlib/jam.h"

char *baseindir = NULL;
char *baseoutdir = NULL;

char *config_file;
char *fido_addr;

int imhub = 0;

struct msgarea_t {
    int id;
    int hub;
    char *basedir;
    int *links;
    int link_count;
};

struct msg_t {
    uint32_t area;
    char from[32];
    char to[32];
    char subject[64];
    uint32_t timedate;
    uint32_t oaddr;
    uint32_t daddr;
    uint32_t type;
    char reply[36];
} __attribute__ ((packed));

struct msgarea_t **areas;
int area_count;
int mynode = 0;
int hubnode = 0;

void msg_to_hl(struct msg_t *msg) {
    msg->area = ntohl(msg->area);
    msg->timedate = ntohl(msg->timedate);
    msg->oaddr = ntohl(msg->oaddr);
    msg->daddr = ntohl(msg->daddr);
    msg->type = ntohl(msg->type);
}

void msg_to_nl(struct msg_t *msg) {
    msg->area = htonl(msg->area);
    msg->timedate = htonl(msg->timedate);
    msg->oaddr = htonl(msg->oaddr);
    msg->daddr = htonl(msg->daddr);
    msg->type = htonl(msg->type);
}

unsigned long generate_msgid() {
	
	char buffer[1024];
	time_t unixtime;

	unsigned long msgid;
	unsigned long lastid;
	FILE *fptr;

	snprintf(buffer, 1024, "msgserial");
	
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
			lastid = unixtime;
        }
	}
	sprintf(buffer, "%lX", lastid);
	return strtoul(&buffer[strlen(buffer) - 8], NULL, 16);
}

int copy_file(char *src, char *dest) {
	FILE *src_file;
	FILE *dest_file;

	char c;

	src_file = fopen(src, "rb");
	if (!src_file) {
		return -1;
	}
	dest_file = fopen(dest, "wb");
	if (!dest_file) {
		fclose(src_file);
		return -1;
	}

	while(1) {
		c = fgetc(src_file);
		if (!feof(src_file)) {
			fputc(c, dest_file);
		} else {
			break;
		}
	}

	fclose(src_file);
	fclose(dest_file);
	return 0;
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

size_t trimwhitespace(char *out, size_t len, const char *str) {
    if(len == 0)
        return 0;

    const char *end;
    size_t out_size;

    // Trim leading space
    while(isspace((unsigned char)*str)) str++;

    if(*str == 0) {
        *out = 0;
        return 1;
    }

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

int parse_config_file(char *filename) {
    FILE *fptr;
    char buffer[256];
    char bufferw[256];
    char *ptr;
    struct msgarea_t *newarea;

    area_count = 0;

    fptr = fopen(filename, "r");
    if (!fptr) {
        return 0;
    }

    fgets(buffer, 256, fptr);
    while (!feof(fptr)) {
        if (buffer[0] != ';') {
            if (buffer[strlen(buffer) - 1] == '\n'){
                buffer[strlen(buffer) - 1] = '\0';
                if (strncasecmp(buffer, "IMHUB", 5) == 0) {
                    trimwhitespace(bufferw, 256, &buffer[6]);
                    if (strcasecmp(bufferw, "TRUE") == 0) {
                        imhub = 1;
                    }
                } else if (strncasecmp(buffer, "UPLINK", 6) == 0) {
                    trimwhitespace(bufferw, 256, &buffer[7]);
                    hubnode = atoi(bufferw);
                } else if (strncasecmp(buffer, "INDIR", 5) == 0) {
                    trimwhitespace(bufferw, 256, &buffer[6]);
                    baseindir = strdup(bufferw);
                } else if (strncasecmp(buffer, "OUTDIR", 6) == 0) {
                    trimwhitespace(bufferw, 256, &buffer[7]);
                    baseoutdir = strdup(bufferw);
                } else if (strncasecmp(buffer, "MYNODE", 6) == 0) {
                    trimwhitespace(bufferw, 256, &buffer[7]);
                    mynode = atoi(bufferw);
                } else if (strncasecmp(buffer, "MSGAREA", 7) == 0) {
                    newarea = NULL;
                    ptr = strtok(&buffer[8], ",");
                    
                    if (ptr != NULL) {
                        newarea = (struct msgarea_t *)malloc(sizeof(struct msgarea_t));
                        trimwhitespace(bufferw, 256, ptr);
                        newarea->id = atoi(bufferw);
                        newarea->link_count = 0;
                        ptr = strtok(NULL, ",");

                        if (ptr != NULL) {
                            trimwhitespace(bufferw, 256, ptr);
                            newarea->hub = atoi(bufferw);
                            ptr = strtok(NULL, ",");
                            if (ptr != NULL) {
                        
                                trimwhitespace(bufferw, 256, ptr);
                                newarea->basedir = strdup(bufferw);
                                ptr = strtok(NULL, ",");
                                while (ptr != NULL) {
                                    trimwhitespace(bufferw, 256, ptr);
                                    if (newarea->link_count == 0) {
                                        newarea->links = (int *)malloc(sizeof(int));
                                    } else {
                                        newarea->links = (int *)realloc(newarea->links, sizeof(int) * (newarea->link_count + 1));
                                    }
                                    newarea->links[newarea->link_count] = atoi(bufferw);
                                    newarea->link_count++;
                                    ptr = strtok(NULL, ",");
                                }
                            }
                        }
                    }
                    if (newarea != NULL) {
                        if (area_count == 0) {
                            areas = (struct msgarea_t **)malloc(sizeof(struct msgarea_t *));
                        } else {
                            areas = (struct msgarea_t **)realloc(areas, sizeof(struct msgarea_t *) * (area_count + 1));
                        }
                        areas[area_count] = newarea;
                        area_count++;
                    }
                }
            } else {
                fclose(fptr);
                return 0;
            }
        }
        fgets(buffer, 256, fptr);
    }

    fclose(fptr);
    return 1;
}

int isdupe(struct msg_t *msg, char *uuid) {
    int areaid;
    int i;
    int z;
    char buffer[PATH_MAX];
    FILE *fptr;

    for (i=0;i<area_count;i++) {
        if (msg->area == areas[i]->id) {
            areaid = i;
            break;
        }
    }

    snprintf(buffer, PATH_MAX, "%s.msgids", areas[areaid]->basedir);

    fptr = fopen(buffer, "r");
    if (!fptr) {
        return 0;
    }

    fgets(buffer, 1024, fptr);

    while (!feof(fptr)) {
        if (strncasecmp(buffer, uuid, 36) == 0) {
            fclose(fptr);
            return 1;
        }
        fgets(buffer, 1024, fptr);
    }

    fclose(fptr);

    return 0;            
}

void update_config_file_area(int areaid) {
    char backup[PATH_MAX];
    char buffer[256];
    char bufferc[256];
    char bufferw[256];
    FILE *fptr1;
    FILE *fptr2;
    char *ptr;
    int id;
    int i;

    snprintf(backup, PATH_MAX, "%s.bak", config_file);
    fptr1 = fopen(config_file, "r");
    fptr2 = fopen(backup, "w");

    fgets(buffer, 256, fptr1);
    while (!feof(fptr1)) {
        if (strncasecmp(buffer, "MSGAREA", 7) == 0) {
            strcpy(bufferc, buffer);
            ptr = strtok(&bufferc[8], ",");
            if (ptr != NULL) {
                trimwhitespace(bufferw, 256, ptr);
                id = atoi(bufferw);
                if (id == areas[areaid]->id) {
                    fprintf(fptr2, "MSGAREA %d, %d, %s", areas[areaid]->id, areas[areaid]->hub, areas[areaid]->basedir);
                    for (i=0;i<areas[areaid]->link_count;i++) {
                        fprintf(fptr2, ", %d", areas[areaid]->links[i]);
                    }
                    fprintf(fptr2, "\n");
                } else {
                    fputs(buffer, fptr2);
                }
            }
        } else {
            fputs(buffer, fptr2);
        }
        fgets(buffer, 256, fptr1);
    }
    fclose(fptr1);
    fclose(fptr2);
    unlink(config_file);
    rename(backup, config_file);
}

int import(char *filename) {
    FILE *fptr;
    char buffer[PATH_MAX];
    char buffer2[PATH_MAX];
    char uuid[37];
    struct msg_t msg;
    int ret;
    int areaid;
    struct stat st;
    int z;
    int i;
    int j;
    char *body;
    s_JamBase *jb;
	s_JamBaseHeader jbh;
	s_JamMsgHeader jmh;
	s_JamSubPacket* jsp;
	s_JamSubfield jsf;

    snprintf(buffer, PATH_MAX, "%s/%s", baseindir, filename);
    strncpy(uuid, strchr(filename, '-') + 1, 36);
    
    uuid[36] = '\0';

    if (stat(buffer, &st) != 0) {
        return 0;
    }

    fptr = fopen(buffer, "rb");
    if (!fptr) {
        return 0;
    }

    fread(&msg, sizeof(struct msg_t), 1, fptr);

    msg_to_hl(&msg);

    body = malloc(st.st_size - sizeof(struct msg_t) + 1 + strlen(fido_addr));

    memset(body, 0, st.st_size - sizeof(struct msg_t) + 1 + strlen(fido_addr));

    fread(body, st.st_size - sizeof(struct msg_t), 1, fptr);

    fclose(fptr);


    if (msg.daddr != mynode) {
        if (imhub) {
            snprintf(buffer2, PATH_MAX, "%s/%d/%s", baseoutdir, msg.daddr, filename);
            copy_file(buffer, buffer2);
        }
        return 1;
    } else {

        areaid = -1;

        for (i=0;i<area_count;i++) {
            if (msg.area == areas[i]->id) {
                areaid = i;
                break;
            }
        }

        if (areaid == -1) {
            return 1;
        }

        if (areas[areaid]->hub == mynode) {
            if (msg.type == 1) {
                if (strncasecmp(body, "ADD", 3) == 0) {
                    for (i=0;i<areas[areaid]->link_count;i++) {
                        if (areas[areaid]->links[i] == msg.oaddr) {
                            // already subscribed
                            return 1;
                        }
                    }

                    if (areas[areaid]->link_count == 0) {
                        areas[areaid]->links = (int *)malloc(sizeof(int));
                    } else {
                        areas[areaid]->links = (int *)realloc(areas[areaid]->links, sizeof(int) * (areas[areaid]->link_count + 1));
                    }

                    areas[areaid]->links[areas[areaid]->link_count] = msg.oaddr;
                    areas[areaid]->link_count++;

                    //
                    update_config_file_area(areaid);

                } else if (strncasecmp(body, "REMOVE", 6) == 0) {
                    for (i=0;i<areas[areaid]->link_count;i++) {
                        if (areas[areaid]->links[i] == msg.oaddr) {

                            if (areas[areaid]->link_count == 1) {
                                free(areas[areaid]->links);
                                areas[areaid]->link_count = 0;
                            } else {
                                for (j=i;j<areas[areaid]->link_count-1;j++) {
                                    areas[areaid]->links[j] = areas[areaid]->links[j+1];
                                }

                                areas[areaid]->links = (int *)realloc(areas[areaid]->links, sizeof(int) * (areas[areaid]->link_count - 1));
                                areas[areaid]->link_count--;

                                
                            }
                            update_config_file_area(areaid);
                            return 1;
                        }
                    }
                }
                return 1;
            }

            for (i=0;i<areas[areaid]->link_count;i++) {
                if (areas[areaid]->links[i] == msg.oaddr) {
                    continue;
                }

                if (imhub) {
                    snprintf(buffer2, PATH_MAX, "%s/%d/", baseoutdir, areas[areaid]->links[i]);
                } else {
                    snprintf(buffer2, PATH_MAX, "%s/%d/", baseoutdir, hubnode);
                }
                if (stat(buffer2, &st) != 0) {
                    if (mkdir(buffer2, 0755) != 0) {
                        fprintf(stderr, "Error making directory %s\n", buffer2);
                        continue;
                    }
                }
                if (imhub) {
                    snprintf(buffer2, PATH_MAX, "%s/%d/%d-%s.message", baseoutdir, areas[areaid]->links[i], areas[areaid]->links[i], uuid);
                } else {
                    snprintf(buffer2, PATH_MAX, "%s/%d/%d-%s.message", baseoutdir, hubnode, areas[areaid]->links[i], uuid);
                }
                msg.daddr = areas[areaid]->links[i];
                msg_to_nl(&msg);

                fptr = fopen(buffer2, "wb");
                fwrite(&msg, sizeof(struct msg_t), 1, fptr);
                fwrite(body, strlen(body), 1, fptr);
                fclose(fptr);

                msg_to_hl(&msg);
            }
        }
    }    
    

    ret = isdupe(&msg, uuid);
    if (ret == -1) {
        free(body);
        fclose(fptr);
        return 0;
    } else if (ret == 1) {
        free(body);
        fclose(fptr);
        return 1;
    }


    for (i=strlen(body) -2; i > 0; i--) {
        if (body[i] == '\r') {
            sprintf(buffer, "\r * Origin: mnet->ftn (%s)\r", fido_addr);
            body = realloc(body, strlen(body) + strlen(buffer) + 1);
            strcpy(&body[i], buffer);
            break;
        }
    }

    JAM_ClearMsgHeader(&jmh);
    jmh.DateWritten = msg.timedate;
    jmh.Attribute |= JAM_MSG_TYPEECHO;
    jmh.Attribute |= JAM_MSG_LOCAL;

    jsp = JAM_NewSubPacket();

    jsf.LoID = JAMSFLD_SENDERNAME;
    jsf.HiID = 0;
    jsf.DatLen = strlen(msg.from);
    jsf.Buffer = msg.from;
   	JAM_PutSubfield(jsp, &jsf); 

	jsf.LoID   = JAMSFLD_RECVRNAME;
	jsf.HiID   = 0;
	jsf.DatLen = strlen(msg.to);
	jsf.Buffer = msg.to;
	JAM_PutSubfield(jsp, &jsf);

	jsf.LoID   = JAMSFLD_SUBJECT;
	jsf.HiID   = 0;
	jsf.DatLen = strlen(msg.subject);
	jsf.Buffer = msg.subject;
	JAM_PutSubfield(jsp, &jsf);

    sprintf(buffer, "%s", fido_addr);
	jsf.LoID   = JAMSFLD_OADDRESS;
	jsf.HiID   = 0;
	jsf.DatLen = strlen(buffer);
	jsf.Buffer = buffer;
	JAM_PutSubfield(jsp, &jsf);    

	sprintf(buffer, "%s %08lx", fido_addr, generate_msgid());
	jsf.LoID   = JAMSFLD_MSGID;
	jsf.HiID   = 0;
	jsf.DatLen = strlen(buffer);
	jsf.Buffer = buffer;
	JAM_PutSubfield(jsp, &jsf);

    jb = open_jam_base(areas[areaid]->basedir);
	if (!jb) {
		return 0;
	}
    while (1) {
        z = JAM_LockMB(jb, 100);
        if (z == 0) {
            break;
        } else if (z == JAM_LOCK_FAILED) {
            sleep(1);
        } else {
            free(body);
            JAM_DelSubPacket(jsp);
            JAM_CloseMB(jb);
            free(jb);
            fprintf(stderr, "Error locking JAM base!\n");
            return 0;
        }
    }

    snprintf(buffer, PATH_MAX, "%s.msgids", areas[areaid]->basedir);
    fptr = fopen(buffer, "a");
    if (!fptr) {
        fprintf(stderr, "Error writing msgid to base\n");
    } else {
        fputs(uuid, fptr);
        fputc('\n', fptr);
        fclose(fptr);
    }

    if (JAM_AddMessage(jb, &jmh, jsp, body, strlen(body))) {
	    JAM_UnlockMB(jb);
        JAM_DelSubPacket(jsp);
        JAM_CloseMB(jb);
        free(jb);
        fprintf(stderr, "Error Adding Message!\n");
        free(body);
        return 0;
	}
    JAM_UnlockMB(jb);
    JAM_DelSubPacket(jsp);
    JAM_CloseMB(jb);
    free(jb);

    free(body);

    return 1;
}

int main(int argc, char **argv) {
    int i;
    int l;
    int processed = 0;
    DIR *indir;
    struct dirent *dent;
    char buffer[PATH_MAX];

    if (argc < 3) {
        fprintf(stderr, "Usage ./mnettoftn mnetftn.cfg FTN_ADDR\n");
        return -1;
    }

    if (!parse_config_file(argv[1])) {
        fprintf(stderr, "Error parsing config file: %s\n", argv[1]);
        return -1;
    }
    
    config_file = argv[1];
    fido_addr = argv[2];

    if (baseoutdir == NULL) {
        fprintf(stderr, "OUTDIR must be defined\n");
        return -1;        
    }

    if (baseindir == NULL) {
        fprintf(stderr, "INDIR must be defined\n");
        return -1;        
    }

    printf("In Base Dir: %s\n", baseindir);

    indir = opendir(baseindir);
    if (!indir) {
        fprintf(stderr, "Error opening inbound directory!\n");
        return -1;
    }

    while ((dent = readdir(indir)) != NULL) {
        if (strlen(dent->d_name) < 8) {
            continue;
        }

        if (strcasecmp(&dent->d_name[strlen(dent->d_name) - 8], ".message") == 0) {
            if (import(dent->d_name)) {
                processed++;
                snprintf(buffer, PATH_MAX, "%s/%s", baseindir, dent->d_name);
                unlink(buffer);
                rewinddir(indir);
            }
        }
    }
    closedir(indir);

    printf("Processed %d Messages\n", processed);
    return 0;
}
