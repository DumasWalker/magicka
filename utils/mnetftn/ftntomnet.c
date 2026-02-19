#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "libuuid/uuid.h"
#include "jamlib/jam.h"

char *baseoutdir = NULL;

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
int imhub = 0;

void msg_to_nl(struct msg_t *msg) {
    msg->area = htonl(msg->area);
    msg->timedate = htonl(msg->timedate);
    msg->oaddr = htonl(msg->oaddr);
    msg->daddr = htonl(msg->daddr);
    msg->type = htonl(msg->type);
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

                if (strncasecmp(buffer, "MYNODE", 6) == 0) {
                    trimwhitespace(bufferw, 256, &buffer[7]);
                    mynode = atoi(bufferw);
                } else if (strncasecmp(buffer, "IMHUB", 5) == 0) {
                    trimwhitespace(bufferw, 256, &buffer[6]);
                    if (strcasecmp(bufferw, "TRUE") == 0) {
                        imhub = 1;
                    }
                } else if (strncasecmp(buffer, "UPLINK", 6) == 0) {
                    trimwhitespace(bufferw, 256, &buffer[7]);
                    hubnode = atoi(bufferw);                    
                } else if (strncasecmp(buffer, "OUTDIR", 6) == 0) {
                    trimwhitespace(bufferw, 256, &buffer[7]);
                    baseoutdir = strdup(bufferw);
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

int export_messages(int area) {
    s_JamBase *jb;
	s_JamBaseHeader jbh;
	s_JamMsgHeader jmh;
	s_JamSubPacket* jsp;
    
    FILE *fptr;

    char buffer[PATH_MAX];

    int i;
    int z;
    int len;
    int n;
    int scanned = 0;

    struct msg_t msg;

    char *body;
    struct stat st;
    uuid_t myuuid;
    char msgid[37];

    jb = open_jam_base(areas[area]->basedir);
	if (!jb) {
		return 0;
	}
	JAM_ReadMBHeader(jb, &jbh);
	if (jbh.ActiveMsgs > 0) {
        for (i=0;i<jbh.ActiveMsgs;i++) {
            memset(&msg, 0, sizeof(struct msg_t));
            memset(&jmh, 0, sizeof(s_JamMsgHeader));
			z = JAM_ReadMsgHeader(jb, i, &jmh, &jsp);

            if (z != 0) {
                continue;
            }

            if (jmh.Attribute & JAM_MSG_DELETED) {
                JAM_DelSubPacket(jsp);
                continue;
            }

            if (jmh.Attribute & JAM_MSG_LOCAL) {
                JAM_DelSubPacket(jsp);
                continue;                
            } else {
                for (z=0;z<jsp->NumFields;z++) {
                    if (jsp->Fields[z]->LoID == JAMSFLD_SUBJECT) {
                        if (jsp->Fields[z]->DatLen > 63) {
                            len = 64;
                        } else {
                            len = jsp->Fields[z]->DatLen;
                        }
                        memcpy(msg.subject, jsp->Fields[z]->Buffer, len);
                    }
                    if (jsp->Fields[z]->LoID == JAMSFLD_SENDERNAME) {
                        if (jsp->Fields[z]->DatLen > 61) {
                            len = 32;
                        } else {
                            len = jsp->Fields[z]->DatLen;
                        }                    
                        memcpy(msg.from, jsp->Fields[z]->Buffer, len);
                    }
                    if (jsp->Fields[z]->LoID == JAMSFLD_RECVRNAME) {
                        if (jsp->Fields[z]->DatLen > 61) {
                            len = 32;
                        } else {
                            len = jsp->Fields[z]->DatLen;
                        }                      
                        memcpy(msg.to, jsp->Fields[z]->Buffer, len);
                    }
                }
                msg.oaddr = mynode;
                msg.timedate = jmh.DateWritten;
		        body = (char *)malloc(jmh.TxtLen + 1);
                memset(body, 0, jmh.TxtLen + 1);
		        JAM_ReadMsgText(jb, jmh.TxtOffset, jmh.TxtLen, (char *)body);

                jmh.Attribute |= JAM_MSG_LOCAL;

                memset(msgid, 0, 37);
                uuid_generate(myuuid);
                uuid_unparse_lower(myuuid, msgid);

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
                        return scanned;
                    }
                }
                n =JAM_ChangeMsgHeader(jb, i, &jmh);

                snprintf(buffer, PATH_MAX, "%s.msgids", areas[area]->basedir);
                fptr = fopen(buffer, "a");
                if (!fptr) {
                    fprintf(stderr, "Error writing msgid to base\n");
                } else {
                    fputs(msgid, fptr);
                    fputc('\n', fptr);
                    fclose(fptr);
                }      

                if (n != 0) {
                    fprintf(stderr, "Error updating message header %d %d\n", n, JAM_Errno(jb));
                }
		        JAM_UnlockMB(jb);
		        JAM_DelSubPacket(jsp);

                msg.area = areas[area]->id;
                msg.type = 0;

                for (i=strlen(body) -2; i > 0; i--) {
                    if (body[i] == '\r') {
                        sprintf(buffer, "\r * Origin: ftn->mnet (@%d)\r", mynode);
                        body = realloc(body, strlen(body) + strlen(buffer) + 1);
                        strcpy(&body[i], buffer);
                        break;
                    }
                }

                if (areas[area]->hub == mynode) {
                    msg_to_nl(&msg);
                    for (n = 0; n < areas[area]->link_count; n++) {
                        if (imhub) {
                            snprintf(buffer, PATH_MAX, "%s/%d/", baseoutdir, areas[area]->links[n]);
                        } else {
                            snprintf(buffer, PATH_MAX, "%s/%d/", baseoutdir, hubnode);
                        }
                        if (stat(buffer, &st) != 0) {
                            if (mkdir(buffer, 0755) != 0) {
                                fprintf(stderr, "Error making directory %s\n", buffer);
                                continue;
                            }
                        }
                        if (imhub) {
                            snprintf(buffer, PATH_MAX, "%s/%d/%d-%s.message", baseoutdir, areas[area]->links[n], areas[area]->links[n], msgid);
                        } else {
                            snprintf(buffer, PATH_MAX, "%s/%d/%d-%s.message", baseoutdir, hubnode, areas[area]->links[n], msgid);
                        }
                        msg.daddr = htonl(areas[area]->links[n]);
                        fptr = fopen(buffer, "wb");
                        if (fptr == NULL) {
                            fprintf(stderr, "Error creating file %s\n", buffer);
                            continue;
                        }

                        

                        fwrite(&msg, sizeof(struct msg_t), 1, fptr);
                        fwrite(body, strlen(body), 1, fptr);
                        fclose(fptr);
                    }
                } else {
                    if (imhub) {
                        snprintf(buffer, PATH_MAX, "%s/%d/", baseoutdir, areas[area]->hub);
                    } else {
                        snprintf(buffer, PATH_MAX, "%s/%d/", baseoutdir, hubnode);
                    }
                    if (stat(buffer, &st) != 0) {
                        if (mkdir(buffer, 0755) != 0) {
                            fprintf(stderr, "Error making directory %s\n", buffer);
                            continue;
                        }
                    }
                    if (imhub) {
                        snprintf(buffer, PATH_MAX, "%s/%d/%d-%s.message", baseoutdir, areas[area]->hub, areas[area]->hub, msgid);
                    } else {
                        snprintf(buffer, PATH_MAX, "%s/%d/%d-%s.message", baseoutdir, hubnode, areas[area]->hub, msgid);
                    }

                    msg.daddr = areas[area]->hub;
                    fptr = fopen(buffer, "wb");
                    if (fptr == NULL) {
                        fprintf(stderr, "Error creating file %s\n", buffer);
                        continue;
                    }

                    msg_to_nl(&msg);

                    fwrite(&msg, sizeof(struct msg_t), 1, fptr);
                    fwrite(body, strlen(body), 1, fptr);
                    fclose(fptr); 
                }
                scanned++;
            }
        }
    }
    JAM_CloseMB(jb);
	free(jb);

    return scanned;
}

int main(int argc, char **argv) {
    int i;
    int l;

    if (argc < 2) {
        fprintf(stderr, "Usage ./ftntomnet mnet.cfg\n");
        return -1;
    }

    if (!parse_config_file(argv[1])) {
        fprintf(stderr, "Error parsing config file: %s\n", argv[1]);
        return -1;
    }

    if (baseoutdir == NULL) {
        fprintf(stderr, "OUTDIR must be defined\n");
        return -1;        
    }

    printf("Out Base Dir: %s\n", baseoutdir);

    for (i=0;i<area_count;i++) {
        printf("MsgArea: %d\n", areas[i]->id);
        printf(" - path %s\n", areas[i]->basedir);
        printf(" - links: ");
        for (l=0;l<areas[i]->link_count;l++) {
            printf("%d, ", areas[i]->links[l]);
        }
        printf("\n");

        printf("\nExported %d messages\n", export_messages(i));
    }
    return 0;
}