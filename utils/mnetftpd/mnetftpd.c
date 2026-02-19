#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <dirent.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <sys/wait.h>
#include "mnetftpd.h"
#include "../../src/inih/ini.h"

static struct ftpclient **clients;
static int client_count = 0;

static struct user_t **users;
static int user_count = 0;

char *logfile = NULL;

struct dllist {
    char *data;
    struct dllist *prev;
    struct dllist *next;
};

void dolog(char *fmt, ...) {
	char buffer[PATH_MAX];
	struct tm time_now;
	time_t timen;
	FILE *logfptr;
	int mypid = getpid();

	if (logfile == NULL) return;

	timen = time(NULL);

	localtime_r(&timen, &time_now);

	logfptr = fopen(logfile, "a");
    if (!logfptr) {
		return;
	}
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buffer, PATH_MAX, fmt, ap);
	va_end(ap);

	fprintf(logfptr, "%04d-%02d-%02d %02d:%02d:%02d [%d] %s\n", time_now.tm_year + 1900, time_now.tm_mon + 1, time_now.tm_mday, time_now.tm_hour, time_now.tm_min, time_now.tm_sec, mypid, buffer);

	fclose(logfptr);
}

void sigchld_handler(int s)
{
    // waitpid() might overwrite errno, so we save and restore it:
    int saved_errno = errno;

    while(waitpid(-1, NULL, WNOHANG) > 0);

    errno = saved_errno;
}

static void parse_path(struct ftpclient *client, char *path, char **result) {
    struct dllist *proot;
    struct dllist *pptr;
    char *rescpy;
    char *ptr;
    char *newpath = *result;

    proot = (struct dllist *)malloc(sizeof(struct dllist));

    if (!proot) {
        fprintf(stderr, "Out of memory\n");
        exit(-1);
    }

    proot->next = NULL;
    proot->prev = NULL;
    proot->data = NULL;

    pptr = proot;

    if (path[0] == '/') {
        rescpy = strdup(path);
    } else {
        if (client->current_path == NULL) {
            rescpy = (char *)malloc(strlen(path + 2));
        } else if (strcmp(client->current_path, client->user->indir) == 0) {
            rescpy = (char *)malloc(strlen(path) + 4);
        } else if (strcmp(client->current_path, client->user->outdir) == 0) {
            rescpy = (char *)malloc(strlen(path) + 5);
        }
        if (!rescpy) {
            fprintf(stderr, "Out of memory\n");
            exit(-1);
        
        }
        if (client->current_path == NULL) {
            sprintf(rescpy, "/%s",path);
        } else if (strcmp(client->current_path, client->user->indir) == 0) {
            sprintf(rescpy, "in/%s",path);
        } else if (strcmp(client->current_path, client->user->outdir) == 0) {
            sprintf(rescpy, "out/%s",path);
        }
        
    }
    ptr = strtok(rescpy, "/");

    while (ptr != NULL) {
        if (strcmp(ptr, "..") == 0) {
            if (pptr->prev != NULL) {
                pptr = pptr->prev;
                free(pptr->next);
                pptr->next = NULL;
                pptr->data = NULL;
            }
        } else if (strcmp(ptr, ".") != 0) {
            pptr->data = ptr;
            pptr->next = (struct dllist *)malloc(sizeof(struct dllist));
            if (!pptr->next) {
                fprintf(stderr, "Out of memory\n");
                exit(-1);
            }
            pptr->next->data = NULL;
            pptr->next->prev = pptr;
            pptr->next->next = NULL;

            pptr = pptr->next;
        }

        ptr = strtok(NULL, "/");
    }

    newpath[0] = '\0';   
    pptr = proot;

    int i = 0;

    while (pptr != NULL && pptr->data != NULL) {
        if (i + strlen(pptr->data) + 2 > PATH_MAX) {
            break;
        }
        newpath[i++] = '/';
        memcpy(&newpath[i], pptr->data, strlen(pptr->data));
        i += strlen(pptr->data);
        newpath[i] = '\0';
        pptr = pptr->next;
    }

    pptr = proot;

    while (pptr != NULL) {
        if (pptr->next != NULL) {
            pptr = pptr->next;
            free(pptr->prev);
        } else {
            free(pptr);
            pptr = NULL;
        }
    }
    free(rescpy);
}

static int handler(void* user, const char* section, const char* name, const char* value) {
	struct ftpserver *cfg = (struct ftpserver *)user;
	struct user_t *newuser;
    int i;

	if (strcasecmp(section, "main") == 0) {
		if (strcasecmp(name, "port") == 0) {
            cfg->port = atoi(value);
        } else if (strcasecmp(name, "min passive port") == 0) {
            cfg->min_passive_port = atoi(value);
        } else if (strcasecmp(name, "max passive port") == 0) {
            cfg->max_passive_port = atoi(value);
        } else if (strcasecmp(name, "enable ipv6") == 0) {
            if (strcasecmp(value, "true") == 0) {
                cfg->ipv6 = 1;
            } else {
                cfg->ipv6 = 0;
            }
        } else if (strcasecmp(name, "log file") == 0) {
            logfile = strdup(value);
        }
	} else {
        newuser = NULL;
        for (i=0;i<user_count;i++) {
            if (strcmp(users[i]->username, section) == 0) {
                newuser = users[i];
                break;
            }
        }

        if (newuser == NULL) {
            if (user_count == 0) {
                users = (struct user_t **)malloc(sizeof(struct user_t *));
            } else {
                users = (struct user_t **)realloc(users, sizeof(struct user_t *) * (user_count + 1));
            }
            users[user_count] = (struct user_t *)malloc(sizeof(struct user_t));

            newuser = users[user_count];
            newuser->username = strdup(section);
            newuser->password = NULL;
            newuser->indir = NULL;
            newuser->outdir = NULL;
            user_count++;
        }

        if (strcasecmp(name, "Password") == 0) {
            newuser->password = strdup(value);
        } else if (strcasecmp(name, "In Directory") == 0) {
            newuser->indir = strdup(value);
        } else if (strcasecmp(name, "Out Directory") == 0) {
            newuser->outdir = strdup(value);
        }
    }
	return 1;
}

void send_data(struct ftpclient *client, char *msg, int len) {
    int n = 0;

    while (len > 0) {
        n = send(client->data_socket, msg + n, len, 0);
        len -= n;
    }
}

void send_msg(struct ftpclient *client, char *msg) {
    int len = strlen(msg);
    int n = 0;

    while (len > 0) {
        n = send(client->fd, msg + n, len, 0);
        len -= n;
    }
}

void close_tcp_connection(struct ftpclient* client) {
	if (client->data_srv_socket > 0) {
		close(client->data_srv_socket);
		client->data_srv_socket = -1;
	}
	if (client->data_socket > 0) {
		close(client->data_socket);
		client->data_socket = -1;
	}
	if (strlen(client->data_ip) > 0) {
		memset(client->data_ip, 0, INET6_ADDRSTRLEN);
		client->data_port = 0;
	}
}

int open_tcp_connection(struct ftpserver *cfg, struct ftpclient *client) {
    if (client->ipver == 6) {
        if (strlen(client->data_ip) != 0) {
            client->data_socket = socket(AF_INET6, SOCK_STREAM, 0);
            struct sockaddr_in6 servaddr;
            servaddr.sin6_family = AF_INET6;
            servaddr.sin6_port = htons(client->data_port);
            if (inet_pton(AF_INET6, client->data_ip, &(servaddr.sin6_addr)) <= 0) {
                fprintf(stderr, "Error in port command\n");
                return 0;
            }
            if (connect(client->data_socket, (struct sockaddr *) &servaddr, sizeof(servaddr)) == -1) {
                perror("Connect");
                fprintf(stderr, "Error connecting to client\n");
                return 0;
            }
        } else if (client->data_srv_socket != 0) {
            socklen_t sock = sizeof(struct sockaddr);
            struct sockaddr_in6 data_client;
            client->data_socket = accept(client->data_srv_socket, (struct sockaddr*) &data_client, &sock);

            if (client->data_socket < 0) {
                fprintf(stderr, "Accept Error\n");
                return 0;
            } 
        }
    } else {
        if (strlen(client->data_ip) != 0) {
            client->data_socket = socket(AF_INET, SOCK_STREAM, 0);
            struct sockaddr_in servaddr;
            servaddr.sin_family = AF_INET;
            servaddr.sin_port = htons(client->data_port);
            if (inet_pton(AF_INET, client->data_ip, &(servaddr.sin_addr)) <= 0) {
                fprintf(stderr, "Error in port command\n");
                return 0;
            }
            if (connect(client->data_socket, (struct sockaddr *) &servaddr, sizeof(servaddr)) == -1) {
                perror("Connect");
                fprintf(stderr, "Error connecting to client\n");
                return 0;
            }
        } else if (client->data_srv_socket != 0) {
            socklen_t sock = sizeof(struct sockaddr);
            struct sockaddr_in data_client;
            client->data_socket = accept(client->data_srv_socket, (struct sockaddr*) &data_client, &sock);

            if (client->data_socket < 0) {
                fprintf(stderr, "Accept Error\n");
                return 0;
            } 
        }    
    }
    return 1;
}

void handle_STOR(struct ftpserver *cfg, struct ftpclient *client, char *path) {
    char *newpath;
    struct stat s;
    pid_t pid;
    char buffer[1024];
    char fullpath[PATH_MAX];
    char fullpathpart[PATH_MAX];
    int j;
    FILE *fptr;

    newpath = (char *)malloc(PATH_MAX);
    parse_path(client, path, &newpath);

    if (newpath[0] == '/') {
        if (strncmp(newpath, "/in", 3) == 0) {
            send_msg(client, "532 Access Denied.\n");   
            free(newpath);
            return;
        } else if (strncmp(newpath, "/out", 4) == 0) {            
            snprintf(fullpath, PATH_MAX, "%s/%s", client->current_path, &newpath[5]);
        } else {
            send_msg(client, "532 Access Denied.\n");   
            free(newpath);
            return;
        }

    } else {
        if (strcmp(client->current_path, client->user->outdir) == 0) {
            snprintf(fullpath, PATH_MAX, "%s/%s", client->current_path, newpath);
        } else {
            send_msg(client, "532 Access Denied.\n");   
            free(newpath);
            return;            
        }
    }

    snprintf(fullpathpart, PATH_MAX, "%s.part", fullpath);

    if (stat(fullpathpart, &s) != 0 && stat(fullpath, &s) != 0) {
        pid = fork();
        if (pid == 0) {
            
            fptr = fopen(fullpathpart, "wb");
            if (fptr) {
                if (open_tcp_connection(cfg, client)) {
                    send_msg(client, "150 Data connection accepted; transfer starting.\r\n");
		            while (1) {
			            j = recv(client->data_socket, buffer, 1024, 0);
			            if (j == 0) {
				            break;
			            }
			            if (j < 0) {
				            send_msg(client, "426 TCP connection was established but then broken\r\n");
				            fclose(fptr);
                            unlink(fullpathpart);
                            close_tcp_connection(client);
                            exit(0);
			            }
			            fwrite(buffer, 1, j, fptr);
                    }
                    fclose(fptr);
                    close_tcp_connection(client);
                    send_msg(client, "226 Transfer OK.\r\n");
                    rename(fullpathpart, fullpath);
                    exit(0);
                } else {
                    send_msg(client, "425 TCP connection cannot be established.\r\n");
                    fclose(fptr);
                    exit(0);
                }
            }
        } else if (pid < 0) {
            send_msg(client, "451 STOR Failed.\r\n");
        } else {
            close_tcp_connection(client);
        }
    } else {
        send_msg(client, "553 File Exists.\n");    
    }
}

void handle_EPSV(struct ftpserver *cfg, struct ftpclient *client) {
    struct sockaddr_in6 server;
    struct sockaddr_in server4;

    if (client->data_socket > 0) {
		close(client->data_socket);
		client->data_socket = -1;
	}

	if (client->data_srv_socket > 0) {
		close(client->data_srv_socket);
	}

    if (client->ipver == 6) {
	    client->data_srv_socket = socket(AF_INET6, SOCK_STREAM, 0);
    } else {
        client->data_srv_socket = socket(AF_INET, SOCK_STREAM, 0);
    }
	if (client->data_srv_socket < 0) {
		send_msg(client, "500 EPSV failure.\r\n");
		return;
	}
	
    if (client->ipver == 6) {
    	server.sin6_family = AF_INET6;
	    server.sin6_addr = in6addr_any;
    } else {
        server4.sin_family = AF_INET;
        server4.sin_addr.s_addr = INADDR_ANY;
    }

    cfg->last_passive_port++;
    if (cfg->last_passive_port == cfg->max_passive_port) {
        cfg->last_passive_port = cfg->min_passive_port;
    }

    int port = cfg->last_passive_port;

    if (client->ipver == 6) {
    	server.sin6_port = htons(port);
        if (bind(client->data_srv_socket, (struct sockaddr*) &server, sizeof(server)) < 0) {
            send_msg(client, "500 EPSV failure\r\n");
            return;
        }        
    } else {
        server4.sin_port = htons(port);
        if (bind(client->data_srv_socket, (struct sockaddr*) &server4, sizeof(server4)) < 0) {
    		send_msg(client, "500 EPSV failure\r\n");
	    	return;
	    }
    }



	if (listen(client->data_srv_socket, 1) < 0) {
		send_msg(client, "500 EPSV failure\r\n");
        return;
	}
	
    char buffer[256];
    sprintf(buffer, "229 Entering Extended Passive Mode (|||%d|)\r\n", port);

	send_msg(client, buffer);
}

void handle_PASV(struct ftpserver *cfg, struct ftpclient *client) {
    char buffer[200];
    char *ipcpy;
    char *ipptr;
    if (client->data_socket > 0) {
		close(client->data_socket);
		client->data_socket = -1;
	}

	if (client->data_srv_socket > 0) {
		close(client->data_srv_socket);
	}

	client->data_srv_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (client->data_srv_socket < 0) {
		send_msg(client, "426 PASV failure.\r\n");
		return;
	}
	struct sockaddr_in server;
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;

    cfg->last_passive_port++;
    if (cfg->last_passive_port == cfg->max_passive_port) {
        cfg->last_passive_port = cfg->min_passive_port;
    }

    int port = cfg->last_passive_port;

	server.sin_port = htons(port);

	if (bind(client->data_srv_socket, (struct sockaddr*) &server, sizeof(server)) < 0) {
		send_msg(client, "426 PASV failure\r\n");
		return;
	}

	if (listen(client->data_srv_socket, 1) < 0) {
		send_msg(client, "426 PASV failure\r\n");
        return;
	}
	
    struct sockaddr_in file_addr;
	socklen_t file_sock_len = sizeof(struct sockaddr_in);
	getsockname(client->data_srv_socket, (struct sockaddr*) &file_addr, &file_sock_len);

    ipcpy = strdup(client->hostip);

    ipptr = strtok(ipcpy, ".");

    strcpy(buffer, "227 Entering Passive Mode (");
    while (ipptr != NULL) {
        sprintf(buffer, "%s%s,", buffer, ipptr);
        ipptr = strtok(NULL, ".");
    }

    sprintf(buffer, "%s%d,%d)\r\n", buffer, port / 256, port % 256);    
	send_msg(client, buffer);
	free(ipcpy);
}

void handle_DELE(struct ftpserver *cfg, struct ftpclient *client, char *file) {
    char *newpath;
    char fullpath[PATH_MAX];

    if (client->current_path == NULL) {
        send_msg(client, "451 RETR Failed.\r\n");
        return;
    }

    newpath = (char *)malloc(PATH_MAX);
    parse_path(client, file, &newpath);

    if (newpath[0] == '/') {
        if (strncmp(newpath, "/in", 3) == 0) {
            snprintf(fullpath, PATH_MAX, "%s/%s", client->current_path, &newpath[4]);
        } else if (strncmp(newpath, "/out", 4) == 0) {
            send_msg(client, "451 DELE Failed.\r\n");
            free(newpath);
            return;
        } else {
            send_msg(client, "451 DELE Failed.\r\n");
            free(newpath);
            return;
        }

    } else {
        snprintf(fullpath, PATH_MAX, "%s/%s", client->current_path, newpath);
    }

    if (unlink(fullpath) != 0) {
        send_msg(client, "451 DELE Failed.\r\n");
    } else {
        send_msg(client, "213 Delete Successful.\r\n");
    }
    free(newpath);
    return; 
}

void handle_RETR(struct ftpserver *cfg, struct ftpclient *client, char *file) {
    char *newpath;
    char fullpath[PATH_MAX];
    FILE *fptr;
    char buffer[1024];

    if (client->current_path == NULL) {
        send_msg(client, "451 RETR Failed.\r\n");
        return;
    }

    newpath = (char *)malloc(PATH_MAX);
    parse_path(client, file, &newpath);


    if (newpath[0] == '/') {
        if (strncmp(newpath, "/in", 3) == 0) {
            snprintf(fullpath, PATH_MAX, "%s/%s", client->current_path, &newpath[4]);
        } else if (strncmp(newpath, "/out", 4) == 0) {
            snprintf(fullpath, PATH_MAX, "%s/%s", client->current_path, &newpath[5]);
        } else {
            send_msg(client, "451 RETR Failed.\r\n");
            free(newpath);
            return;
        }

    } else {
        snprintf(fullpath, PATH_MAX, "%s/%s", client->current_path, newpath);
    }

    free(newpath);
    struct stat s;
    pid_t pid = fork();
    int n;

    if (pid > 0) {
        // nothing
        close_tcp_connection(client);        
    } else if (pid == 0) {

        if (stat(fullpath, &s) == 0) {
            if (!S_ISDIR(s.st_mode)) {
                fptr = fopen(fullpath, "rb");
                if (fptr) {
                    if (open_tcp_connection(cfg, client)) {
                        send_msg(client, "150 Data connection accepted; transfer starting.\r\n");
                        do {
                            n = fread(buffer, 1, 1024, fptr);
                            send_data(client, buffer, n);
                        } while (n == 1024);
                        fclose(fptr);
                        close_tcp_connection(client);
                        send_msg(client, "226 Transfer OK.\r\n");
                        exit(0);
                    } else {
                        send_msg(client, "425 TCP connection cannot be established.\r\n");
                        fclose(fptr);
                        exit(0);
                    }
                }
            }
        }

        send_msg(client, "451 RETR Failed.\r\n");
        exit(0);
    } else {
        send_msg(client, "451 RETR Failed.\r\n");
    }
}

void handle_LIST(struct ftpserver *cfg, struct ftpclient *client) {
    DIR *dirp;
    struct dirent *dp;
    char newpath[PATH_MAX];
    char linebuffer[PATH_MAX];
    struct stat s;
    struct tm file_tm;
    struct tm now_tm;
    time_t now;
    char *months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    pid_t pid = fork();

    if (pid > 0) {
        // nothing
        close_tcp_connection(client);
    } else if (pid == 0) {
        if (client->current_path == NULL) {
           if (!open_tcp_connection(cfg, client)) {
                send_msg(client, "425 TCP connection cannot be established.\r\n");
                exit(0);
            }
            send_msg(client, "150 Data connection accepted; transfer starting.\r\n");
            now = time(NULL);
            localtime_r(&now, &now_tm);
            if (stat(client->user->indir, &s) == 0) {
                snprintf(linebuffer, PATH_MAX, "dr-x------ 2 0 0 4096 %s %d %02d:%02d in\r\n", months[now_tm.tm_mon], now_tm.tm_mday, now_tm.tm_hour, now_tm.tm_min);
            }
            send_data(client, linebuffer, strlen(linebuffer));
            if (stat(client->user->outdir, &s) == 0) {
                snprintf(linebuffer, PATH_MAX, "drwx------ 2 0 0 4096 %s %d %02d:%02d out\r\n", months[now_tm.tm_mon], now_tm.tm_mday, now_tm.tm_hour, now_tm.tm_min);
            }            
            send_data(client, linebuffer, strlen(linebuffer));
            close_tcp_connection(client);
            send_msg(client, "226 Transfer ok.\r\n");
            exit(0);            
        } else {
            dirp = opendir(client->current_path);

            if (!dirp) {
                send_msg(client, "451 Could not read directory.\r\n");
                exit(0);
            }
            
            if (!open_tcp_connection(cfg, client)) {
                send_msg(client, "425 TCP connection cannot be established.\r\n");
                closedir(dirp);
                exit(0);
            }
            send_msg(client, "150 Data connection accepted; transfer starting.\r\n");
            while ((dp = readdir(dirp)) != NULL) {
                snprintf(newpath, PATH_MAX, "%s/%s", client->current_path, dp->d_name);
                if (stat(newpath, &s) == 0) {
                    localtime_r(&s.st_mtime, &file_tm);
                    now = time(NULL);
                    localtime_r(&now, &now_tm);

                    if (now_tm.tm_year != file_tm.tm_year) {
                        snprintf(linebuffer, PATH_MAX, "%c%c%c%c%c%c%c%c%c%c %ld %d %d %ld %s %d %d %s\r\n", S_ISDIR(s.st_mode) ? 'd' : '-', 
                                                                        S_IRUSR & s.st_mode ? 'r' : '-', S_IWUSR & s.st_mode ? 'w' : '-',S_IXUSR & s.st_mode ? 'x' : '-',
                                                                        S_IRGRP & s.st_mode ? 'r' : '-', S_IWGRP & s.st_mode ? 'w' : '-',S_IXGRP & s.st_mode ? 'x' : '-',
                                                                        S_IROTH & s.st_mode ? 'r' : '-', S_IWOTH & s.st_mode ? 'w' : '-',S_IXOTH & s.st_mode ? 'x' : '-',
                                                                        s.st_nlink, s.st_uid, s.st_gid, s.st_size, months[file_tm.tm_mon], file_tm.tm_mday, file_tm.tm_year + 1900, dp->d_name);
                    } else {
                        snprintf(linebuffer, PATH_MAX, "%c%c%c%c%c%c%c%c%c%c %ld %d %d %ld %s %d %02d:%02d %s\r\n", S_ISDIR(s.st_mode) ? 'd' : '-', 
                                                                        S_IRUSR & s.st_mode ? 'r' : '-', S_IWUSR & s.st_mode ? 'w' : '-',S_IXUSR & s.st_mode ? 'x' : '-',
                                                                        S_IRGRP & s.st_mode ? 'r' : '-', S_IWGRP & s.st_mode ? 'w' : '-',S_IXGRP & s.st_mode ? 'x' : '-',
                                                                        S_IROTH & s.st_mode ? 'r' : '-', S_IWOTH & s.st_mode ? 'w' : '-',S_IXOTH & s.st_mode ? 'x' : '-',
                                                                        s.st_nlink, s.st_uid, s.st_gid, s.st_size, months[file_tm.tm_mon], file_tm.tm_mday, file_tm.tm_hour, file_tm.tm_min, dp->d_name);
                    }
                    send_data(client, linebuffer, strlen(linebuffer));
                }
            }
            closedir(dirp);
            close_tcp_connection(client);
            send_msg(client, "226 Transfer ok.\r\n");
            exit(0);
        }
    } else {
        send_msg(client, "451 Could not read directory.\r\n");
    }
}

void handle_NLST(struct ftpserver *cfg, struct ftpclient *client) {
    DIR *dirp;
    struct dirent *dp;
    char newpath[PATH_MAX];
    char linebuffer[PATH_MAX];
    struct stat s;
    pid_t pid = fork();

    if (pid > 0) {
        // nothing
        close_tcp_connection(client);
    } else if (pid == 0) {
        if (client->current_path == NULL) {
           if (!open_tcp_connection(cfg, client)) {
                send_msg(client, "425 TCP connection cannot be established.\r\n");
                exit(0);
            }
            send_msg(client, "150 Data connection accepted; transfer starting.\r\n");

            if (stat(client->user->indir, &s) == 0) {
                snprintf(linebuffer, PATH_MAX, "in\r\n");
            }
            send_data(client, linebuffer, strlen(linebuffer));
            if (stat(client->user->outdir, &s) == 0) {
                snprintf(linebuffer, PATH_MAX, "out\r\n");
            }            
            send_data(client, linebuffer, strlen(linebuffer));
            close_tcp_connection(client);
            send_msg(client, "226 Transfer ok.\r\n");
            exit(0);            
        } else {
            dirp = opendir(client->current_path);

            if (!dirp) {
                send_msg(client, "451 Could not read directory.\r\n");
                exit(0);
            }
            
            if (!open_tcp_connection(cfg, client)) {
                send_msg(client, "425 TCP connection cannot be established.\r\n");
                closedir(dirp);
                exit(0);
            }
            send_msg(client, "150 Data connection accepted; transfer starting.\r\n");
            while ((dp = readdir(dirp)) != NULL) {
                snprintf(newpath, PATH_MAX, "%s/%s", client->current_path, dp->d_name);
                if (stat(newpath, &s) == 0) {
                    snprintf(linebuffer, PATH_MAX, "%s\r\n", dp->d_name);
                    send_data(client, linebuffer, strlen(linebuffer));
                }
            }
            closedir(dirp);
            close_tcp_connection(client);
            send_msg(client, "226 Transfer ok.\r\n");
            exit(0);
        }
    } else {
        send_msg(client, "451 Could not read directory.\r\n");
    }
}

void handle_PORT(struct ftpserver *cfg, struct ftpclient *client, char *arg) {
    if (client->data_socket > 0) {
        close(client->data_socket);
    }
    int a,b,c,d,e,f;

    sscanf(arg, "%d,%d,%d,%d,%d,%d", &a, &b, &c, &d, &e, &f);
    sprintf(client->data_ip, "%d.%d.%d.%d", a, b, c, d);
    client->data_port = e * 256 + f;
    send_msg(client, "200 PORT command successful.\r\n");
}

void handle_EPRT(struct ftpserver *cfg, struct ftpclient *client, char *arg) {
    if (client->data_socket > 0) {
        close(client->data_socket);
    }
    char delim[2];
    char *ptr;
    int addrtype;

    delim[0] = arg[0];
    delim[1] = '\0';

    ptr = strtok(arg, delim);    
    if (ptr != NULL) {
        addrtype = atoi(ptr);
        if (addrtype == 1) {
            //ipv4
            ptr = strtok(NULL, delim);
            if (ptr != NULL) {
                sprintf(client->data_ip, "%s", ptr);
                ptr = strtok(NULL, delim);
                if (ptr != NULL) {
                    client->data_port = atoi(ptr);
                    send_msg(client, "200 EPRT command successful.\r\n");
                    return;
                }
            }
            
        } else if (addrtype == 2) {
            //ipv6
            ptr = strtok(NULL, delim);
            if (ptr != NULL) {
                sprintf(client->data_ip, "%s", ptr);
                ptr = strtok(NULL, delim);
                if (ptr != NULL) {
                    client->data_port = atoi(ptr);
                    send_msg(client, "200 EPRT command successful.\r\n");
                    return;
                }                
            }
        }
    }
}

void handle_CWD(struct ftpserver *cfg, struct ftpclient *client, char *dir) {
    char *newpath;

    newpath = (char *)malloc(1024);
    parse_path(client, dir, &newpath);

    if (strcasecmp(newpath, "/in") == 0) {
        client->current_path = client->user->indir;
        send_msg(client, "250 Okay.\r\n");
    } else if (strcasecmp(newpath, "/out") == 0) {
        client->current_path = client->user->outdir;
        send_msg(client, "250 Okay.\r\n");
    } else if (strlen(newpath) == 0) {
        client->current_path = NULL;
        send_msg(client, "250 Okay.\r\n");
    } else {
        send_msg(client, "550 No such file or directory.\r\n");    
    }
    free(newpath);
}

void handle_TYPE(struct ftpserver *cfg, struct ftpclient *client) {
    send_msg(client, "200 Type set to I.\r\n");
}

void handle_PWD(struct ftpserver *cfg, struct ftpclient *client) {
    char *buffer = (char *)malloc(strlen(client->current_path) + 9);
    if (!buffer) {
        fprintf(stderr, "Out of memory\n");
        exit(-1);
    }

    if (client->current_path == client->user->indir) {
        sprintf(buffer, "257 \"/in\"\r\n");
    } else if (client->current_path == client->user->outdir) {
        sprintf(buffer, "257 \"/out\"\r\n");
    } else {
        sprintf(buffer, "257 \"/\"\r\n");
    }
    send_msg(client, buffer);
    free(buffer);
}

void handle_SYST(struct ftpserver *cfg, struct ftpclient *client) {
    send_msg(client, "215 UNIX Type: L8\r\n");
}

void handle_PASS(struct ftpserver *cfg, struct ftpclient *client, char *password) {
    if (client->user == NULL) {
        send_msg(client, "503 Need username first\r\n");
        return;
    }

    if (strcmp(client->user->password, password) == 0) {
        send_msg(client, "230 User Logged in, Proceed.\r\n");
        client->authenticated = 1;
    } else {
        send_msg(client, "530 Username or Password unacceptable.\r\n");
    }
}

void handle_USER(struct ftpserver *cfg, struct ftpclient *client, char *username) {
    int i;

    for (i=0;i<user_count;i++) {
        if (strcmp(users[i]->username, username) == 0) {
            client->user = users[i];
            break;
        }
    }

    if (client->user == NULL) {
        send_msg(client, "430 Invalid Username.\r\n");
    } else {
        send_msg(client, "331 User name ok, need password.\r\n");
    }
}

int handle_client(struct ftpserver *cfg, struct ftpclient *client, char *buf, int nbytes) {

    char cmd[1024];
    char argument[1024];
    int i;
    int cmd_len = 0;
    int argument_len = 0;
    int stage = 0;

    memset(cmd, 0, 1024);
    memset(argument, 0, 1024);

    while (buf[nbytes-1] == '\r' || buf[nbytes-1] == '\n') {
        buf[nbytes-1] = '\0';
        nbytes--;
    }

    for (i=0;i<nbytes;i++) {
        if (stage == 0 && buf[i] != ' ') {
            cmd[cmd_len++] = buf[i];
            cmd[cmd_len] = '\0';
        } else if (stage == 0 && buf[i] == ' ') {
            stage = 1;
        } else if (stage == 1) {
            argument[argument_len++] = buf[i];
            argument[argument_len] = '\0';
        }
    }
    
    if (strcmp(cmd, "PASS") == 0) {
        fprintf(stderr, "command: %s, argument: ****\n", cmd);
        dolog("command: %s, argument: ****", cmd);
    } else {
        fprintf(stderr, "command: %s, argument: %s\n", cmd, argument);
        dolog("command: %s, argument: %s", cmd, argument);
    }

    if (strcmp(cmd, "USER") == 0) {
        if (argument_len > 0) {
            handle_USER(cfg, client, argument);
        } else {
            send_msg(client, "530 Missing username.\r\n");
        }
    } else
    if (strcmp(cmd, "PASS") == 0) {
        if (argument_len > 0) {
            handle_PASS(cfg, client, argument);
        } else {
            send_msg(client, "530 Username or Password not accepted.\r\n");
        }
    } else
    if (strcmp(cmd, "SYST") == 0) {
        handle_SYST(cfg, client);
    } else
    if (strcmp(cmd, "PWD") == 0) {
        handle_PWD(cfg, client);
    } else
    if (strcmp(cmd, "TYPE") == 0) {
        handle_TYPE(cfg, client);
    } else 
    if (strcmp(cmd, "CWD") == 0) {
        handle_CWD(cfg, client, argument);
    } else
    if (strcmp(cmd, "PORT") == 0) {
        handle_PORT(cfg, client, argument);
    } else
    if (strcmp(cmd, "NLST") == 0) {
        handle_NLST(cfg, client);
    } else    
    if (strcmp(cmd, "LIST") == 0) {
        handle_LIST(cfg, client);
    } else
    if (strcmp(cmd, "PASV") == 0) {
        handle_PASV(cfg, client);
    } else
    if (strcmp(cmd, "QUIT") == 0) {
        send_msg(client, "221 Goodbye!\r\n");
    } else
    if (strcmp(cmd, "RETR") == 0) {
        handle_RETR(cfg, client, argument);
    } else
    if (strcmp(cmd, "STOR") == 0) {
        handle_STOR(cfg, client, argument);
    } else
    if (strcmp(cmd, "EPRT") == 0) {
        handle_EPRT(cfg, client, argument);
    } else 
    if (strcmp(cmd, "EPSV") == 0) {
        handle_EPSV(cfg, client);
    } else
    if (strcmp(cmd, "DELE") == 0) {
        handle_DELE(cfg, client, argument);
    } else {
        send_msg(client, "500 Command not recognized.\r\n");
    }

    return 0;
}

void init(struct ftpserver *cfg) {
    int ipv6_socket, ipv4_socket;
    struct sockaddr_in6 server, client, host_addr;
    struct sockaddr_in server4, client4, host_addr4;
    fd_set master, read_fds;
    int fdmax = 0;
    socklen_t c;
    int i,j,k;
    char buf[1024];
    int new_fd;
    int nbytes;
	int on = 1;

    FD_ZERO(&master);

    if (cfg->ipv6) {
        ipv6_socket = socket(AF_INET6, SOCK_STREAM, 0);
        if (ipv6_socket == -1) {
            fprintf(stderr, "Couldn't create socket..\n");
            exit(-1);
        }
	    if (setsockopt(ipv6_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on)) < 0) {
		    fprintf(stderr, "setsockopt(SO_REUSEADDR) failed");
		    exit(1);
	    }		
        if (setsockopt(ipv6_socket, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&on, sizeof(on)) < 0) {
			fprintf(stderr, "setsockopt(IPV6_V6ONLY) failed");
		}

        server.sin6_family = AF_INET6;
        server.sin6_addr = in6addr_any;
        server.sin6_port = htons(cfg->port);

        if (bind(ipv6_socket, (struct sockaddr *)&server, sizeof(server)) < 0) {
            perror("Bind Failed, Error\n");
            exit(1);
        }

        listen(ipv6_socket, 3);
        FD_SET(ipv6_socket, &master);
    }

    ipv4_socket = socket(AF_INET, SOCK_STREAM, 0);

    if (ipv4_socket == -1) {
        fprintf(stderr, "Couldn't create socket..\n");
        exit(-1);
    }
	if (setsockopt(ipv4_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on)) < 0) {
	    fprintf(stderr, "setsockopt(SO_REUSEADDR) failed");
	    exit(1);
	}	
    server4.sin_family = AF_INET;
    server4.sin_addr.s_addr = INADDR_ANY;
    server4.sin_port = htons(cfg->port);

    if (bind(ipv4_socket, (struct sockaddr *)&server4, sizeof(server4)) < 0) {
        perror("Bind Failed, Error\n");
        exit(1);
    }

    listen(ipv4_socket, 3);
    FD_SET(ipv4_socket, &master);

    if (cfg->ipv6) {
        if (ipv4_socket > ipv6_socket) {
            fdmax = ipv4_socket;
        } else {
            fdmax = ipv6_socket;
        }
    } else {
        fdmax = ipv4_socket;
    }

//    c = sizeof(struct sockaddr_in6);

    while (1) {
        read_fds = master;
        if (select(fdmax+1, &read_fds, NULL, NULL, NULL) == -1) {
            if (errno == EINTR) {
				continue;
            }
            perror("select");
            exit(-1);
        }

        for(i = 0; i <= fdmax; i++) {
            if (FD_ISSET(i, &read_fds)) {
                if (cfg->ipv6 && i == ipv6_socket) {
                    c = sizeof(struct sockaddr_in6);
                    new_fd = accept(ipv6_socket, (struct sockaddr *)&client, (socklen_t *)&c);
					if (new_fd == -1) {
                        perror("accept");
                    } else {
                        if (client_count == 0) {
                            clients = (struct ftpclient **)malloc(sizeof(struct ftpclient *));
                        } else {
                            clients = (struct ftpclient **)realloc(clients, sizeof(struct ftpclient *) * (client_count + 1));
                        }

                        if (!clients) {
                            fprintf(stderr, "Out of memory!\n");
                            exit(-1);
                        }
                        
                        clients[client_count] = (struct ftpclient *)malloc(sizeof(struct ftpclient));

                        memset(clients[client_count], 0, sizeof(struct ftpclient));

                        if (!clients[client_count]) {
                            fprintf(stderr, "Out of memory!\n");
                            exit(-1);                            
                        }

                        getsockname(new_fd, (struct sockaddr*) &host_addr, &c);
                        inet_ntop(AF_INET6, &(host_addr.sin6_addr), clients[client_count]->hostip, INET6_ADDRSTRLEN);
                        
                        getpeername(new_fd, (struct sockaddr *)&client, &c);
                        inet_ntop(AF_INET6, &(client.sin6_addr), clients[client_count]->ip, INET6_ADDRSTRLEN);

                        clients[client_count]->fd = new_fd;
                        strcpy(clients[client_count]->current_path, "/");
                        clients[client_count]->data_socket = -1;
                        clients[client_count]->data_srv_socket = -1;
                        clients[client_count]->type = 1;
                        clients[client_count]->status = 0;
                        clients[client_count]->data_port = 0;
                        clients[client_count]->user = NULL;
                        clients[client_count]->authenticated = 0;
                        clients[client_count]->ipver = 6;
                        client_count++;

                        FD_SET(new_fd, &master); 
                        if (new_fd > fdmax) {
                            fdmax = new_fd;
                        }

                        send_msg(clients[client_count - 1], "220 mnetftpd Ready\r\n");
                    }
                } else if (i == ipv4_socket) {
                    c = sizeof(struct sockaddr_in);
                    new_fd = accept(ipv4_socket, (struct sockaddr *)&client, (socklen_t *)&c);
					if (new_fd == -1) {
                        perror("accept");
                    } else {
                        if (client_count == 0) {
                            clients = (struct ftpclient **)malloc(sizeof(struct ftpclient *));
                        } else {
                            clients = (struct ftpclient **)realloc(clients, sizeof(struct ftpclient *) * (client_count + 1));
                        }

                        if (!clients) {
                            fprintf(stderr, "Out of memory!\n");
                            exit(-1);
                        }
                        
                        clients[client_count] = (struct ftpclient *)malloc(sizeof(struct ftpclient));

                        memset(clients[client_count], 0, sizeof(struct ftpclient));

                        if (!clients[client_count]) {
                            fprintf(stderr, "Out of memory!\n");
                            exit(-1);                            
                        }

                        getsockname(new_fd, (struct sockaddr*) &host_addr4, &c);
                        inet_ntop(AF_INET, &(host_addr4.sin_addr), clients[client_count]->hostip, INET_ADDRSTRLEN);
                        
                        getpeername(new_fd, (struct sockaddr *)&client4, &c);
                        inet_ntop(AF_INET, &(client4.sin_addr), clients[client_count]->ip, INET_ADDRSTRLEN);

                        clients[client_count]->fd = new_fd;
                        clients[client_count]->current_path = NULL;
                        clients[client_count]->data_socket = -1;
                        clients[client_count]->data_srv_socket = -1;
                        clients[client_count]->type = 1;
                        clients[client_count]->status = 0;
                        clients[client_count]->data_port = 0;
                        clients[client_count]->user = NULL;
                        clients[client_count]->authenticated = 0;
                        clients[client_count]->ipver = 4;
                        client_count++;

                        FD_SET(new_fd, &master); 
                        if (new_fd > fdmax) {
                            fdmax = new_fd;
                        }

                        send_msg(clients[client_count - 1], "220 mnetftpd Ready\r\n");
                    }
                } else {
                    if ((nbytes = recv(i, buf, sizeof buf, 0)) <= 0) {
                        for (k=0;k<client_count;k++) {
                            if (clients[k]->fd == i) {
                                if (clients[k]->data_socket > 0) {
                                    close(clients[k]->data_socket);
                                }

                                if (clients[k]->data_srv_socket > 0) {
                                    close(clients[k]->data_srv_socket);
                                }

                                free(clients[k]);

                                for (j=k;j<client_count-1;j++) {
                                    clients[j] = clients[j+1];
                                }

                                

                                client_count--;

                                if (client_count == 0) {
                                    free(clients);
                                } else {
                                    clients = realloc(clients, sizeof(struct ftpclient) * (client_count));
                                }
                            }
                        }
                        close(i); // bye!
                        FD_CLR(i, &master); // remove from master set
                    } else {
                        for (j=0;j<client_count;j++) {
                            if (clients[j]->fd == i) {
                                if (handle_client(cfg, clients[j], buf, nbytes) != 0) {
                                    close(clients[j]->fd);
                                    FD_CLR(i, &master); // remove from master set
                                    free(clients[j]);

                                    for (k=j;k<client_count-1;k++) {
                                        clients[k] = clients[k+1];
                                    }

                                    client_count--;

                                    if (client_count == 0) {
                                        free(clients);
                                    } else {
                                        clients = realloc(clients, sizeof(struct ftpclient) * (client_count));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

int main(int argc, char **argv) {
    struct sigaction sa;
    struct ftpserver ftpsrv;
    ftpsrv.port = 2121;
    ftpsrv.min_passive_port = 60000;
    ftpsrv.max_passive_port = 65000;
    ftpsrv.ipv6 = 0;

	sa.sa_handler = sigchld_handler; // reap all dead processes
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART | SA_SIGINFO;
	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
			perror("sigaction - sigchld");
			exit(-1);
	}


    if (argc < 2) {
        fprintf(stderr, "Usage: %s [config.ini]\n", argv[0]);
        exit(-1);
    }

    if (ini_parse(argv[1], handler, &ftpsrv) <0) {
		fprintf(stderr, "Unable to load configuration ini (%s)!\n", argv[1]);
		exit(-1);
	}

    ftpsrv.last_passive_port = ftpsrv.min_passive_port;

    init(&ftpsrv);
}
