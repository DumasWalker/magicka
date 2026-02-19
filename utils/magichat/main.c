#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#if defined(__OpenBSD__) || defined(__HAIKU__)
#  include <sys/select.h>
#endif
#include "../../deps/jsmn/jsmn.h"

struct chat_msg {
    char nick[16];
    char bbstag[16];
    char msg[256];
};

struct client {
    char bbstag[16];
    char nick[16];
    int fd;
    char room[16];
    char status[16];
    char *buffer;
    int buffer_size;
};

struct client **clients;
int client_count = 0;

typedef enum { START, KEY, PRINT, SKIP, STOP } parse_state;

static int jsoneq(const char *json, jsmntok_t *tok, const char *s) {
	if (tok->type == JSMN_STRING && (int) strlen(s) == tok->end - tok->start &&
			strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
		return 0;
	}
	return -1;
}

static int contains(const char *str, int len, const char needle) {
    int i;

    for (i=0;i<len;i++) {
        if (str[i]== needle) {
            return 1;
        }
    }

    return 0;
}

int main(int argc, char **argv) {
    int port;
    int server_socket, server_socket6;
    struct sockaddr_in server, client;
    struct sockaddr_in6 server6, client6;
    fd_set master, read_fds;
    int fdmax;
    int c;
    int new_fd;
    struct chat_msg msg;
    int i, j, k, l;
    char buffer[1024];
    char buf[1024];
    char motd[256];
    jsmn_parser parser;
    jsmntok_t tokens[8];
    int r;
    int nbytes;
    FILE *fptr;
    int ipv6 = 0;
	int on = 1;
	int dodisconnect = 0;
	
    if (argc < 2) {
        printf("Usage: magichat [port] [ipv6(true/false)]\n");
        return 0;
    }

    if (argc > 2 && strcasecmp(argv[2], "true") == 0) {
        ipv6 = 1;
    }

    port = atoi(argv[1]);

    if (port <= 1024 && port > 65535) {
        printf("Invalid port number, must be between 1024 - 65535\n");
        return 0;
    }

    FD_ZERO(&master);

    if (ipv6) {
        server_socket6 = socket(AF_INET6, SOCK_STREAM, 0);
        if (server_socket6 == -1) {
            fprintf(stderr, "Couldn't create socket (ipv6)..\n");
            exit(1);
        }

	    if (setsockopt(server_socket6, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on)) < 0) {
		    fprintf(stderr, "setsockopt(SO_REUSEADDR) failed");
		    exit(1);
	    }		
        if (setsockopt(server_socket6, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&on, sizeof(on)) < 0) {
			fprintf(stderr, "setsockopt(IPV6_V6ONLY) failed");
		}

        server6.sin6_family = AF_INET6;
        server6.sin6_addr = in6addr_any;
        server6.sin6_port = htons(port);

        if (bind(server_socket6, (struct sockaddr *)&server6, sizeof(server6)) < 0) {
            perror("Bind Failed, Error\n");
            exit(1);
        }

        listen(server_socket6, 3);
        FD_SET(server_socket6, &master);
    }
	server_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (server_socket == -1) {
		fprintf(stderr, "Couldn't create socket..\n");
		exit(1);
	}
	if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on)) < 0) {
	    fprintf(stderr, "setsockopt(SO_REUSEADDR) failed");
	    exit(1);
	}	
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons(port);

	if (bind(server_socket, (struct sockaddr *)&server, sizeof(server)) < 0) {
		perror("Bind Failed, Error\n");
		exit(1);
	}

	listen(server_socket, 3);
    FD_SET(server_socket, &master);

    if (ipv6) {
        if (server_socket6 > server_socket) {
            fdmax = server_socket6;
        } else {
            fdmax = server_socket;
        }
    } else {
        fdmax = server_socket;
    }

    


    while (1) {
        read_fds = master;
        if (select(fdmax+1, &read_fds, NULL, NULL, NULL) == -1) {
            perror("select");
            exit(-1);
        }

        for(i = 0; i <= fdmax; i++) {
            if (FD_ISSET(i, &read_fds)) {
                if (i == server_socket) {
                    c = sizeof(struct sockaddr_in);
                    new_fd = accept(server_socket, (struct sockaddr *)&client, (socklen_t *)&c);
					if (new_fd == -1) {
                        perror("accept");
                    } else {
                        if (client_count == 0) {
                            clients = (struct client **)malloc(sizeof(struct client *));
                        } else {
                            clients = (struct client **)realloc(clients, sizeof(struct client *) * (client_count + 1));
                        }

                        if (!clients) {
                            fprintf(stderr, "Out of memory!\n");
                            return -1;
                        }
                        
                        clients[client_count] = (struct client *)malloc(sizeof(struct client));

                        if (!clients[client_count]) {
                            fprintf(stderr, "Out of memory!\n");
                            return -1;                            
                        }

                        sprintf(clients[client_count]->bbstag, "UNKNOWN");
                        sprintf(clients[client_count]->nick, "UNKNOWN");
                        sprintf(clients[client_count]->room, "UNKNOWN");
                        clients[client_count]->fd = new_fd;
                        clients[client_count]->buffer = NULL;
                        clients[client_count]->buffer_size = 0;
                        client_count++;

                        FD_SET(new_fd, &master); 
                        if (new_fd > fdmax) {
                            fdmax = new_fd;
                        }
                    }  
                } else if (ipv6 && i == server_socket6) {
                    c = sizeof(struct sockaddr_in6);
                    new_fd = accept(server_socket6, (struct sockaddr *)&client6, (socklen_t *)&c);
					if (new_fd == -1) {
                        perror("accept");
                    } else {
                        if (client_count == 0) {
                            clients = (struct client **)malloc(sizeof(struct client *));
                        } else {
                            clients = (struct client **)realloc(clients, sizeof(struct client *) * (client_count + 1));
                        }

                        if (!clients) {
                            fprintf(stderr, "Out of memory!\n");
                            return -1;
                        }
                        
                        clients[client_count] = (struct client *)malloc(sizeof(struct client));

                        if (!clients[client_count]) {
                            fprintf(stderr, "Out of memory!\n");
                            return -1;                            
                        }

                        sprintf(clients[client_count]->bbstag, "UNKNOWN");
                        sprintf(clients[client_count]->nick, "UNKNOWN");
                        sprintf(clients[client_count]->room, "UNKNOWN");
                        clients[client_count]->fd = new_fd;
                        clients[client_count]->buffer = NULL;
                        clients[client_count]->buffer_size = 0;
                        
                        client_count++;

                        FD_SET(new_fd, &master); 
                        if (new_fd > fdmax) {
                            fdmax = new_fd;
                        }
                    }                                       
                } else {
                    if ((nbytes = recv(i, buf, sizeof buf, 0)) <= 0) {
                        for (k=0;k<client_count;k++) {
                            if (clients[k]->fd == i) {
                                if (strcmp(clients[k]->nick, "UNKNOWN") != 0) {
                                    snprintf(buffer, 1024, "{\"bbs\": \"SYSTEM\", \"nick\": \"SYSTEM\", \"msg\": \"%s (%s) has left the chat\" }\n", clients[k]->nick, clients[k]->bbstag);
                                    for (j=0;j<=fdmax;j++) {
                                        if (FD_ISSET(j, &master)) {
                                            if (ipv6) {
                                                if (j != server_socket && j != server_socket6 && j != clients[k]->fd) {
													for (l =0; l< client_count; l++) {
														if (clients[l]->fd == j) {
															if (strcmp(clients[l]->nick, "UNKNOWN") != 0) {
																if (send(j, buffer, strlen(buffer), 0) == -1) {
																	perror("send");
																}
															}
														}
													}
                                                }
                                            } else {
                                                if (j != server_socket && j != clients[k]->fd) {
													for (l =0; l< client_count; l++) {
														if (clients[l]->fd == j) {
															if (strcmp(clients[l]->nick, "UNKNOWN") != 0) {
																if (send(j, buffer, strlen(buffer), 0) == -1) {
																	perror("send");
																}
															}
														}
													}
                                                }                                                
                                            }
                                        }
                                    }
                                }
                                free(clients[k]->buffer);
                                free(clients[k]);

                                for (j=k;j<client_count-1;j++) {
                                    clients[j] = clients[j+1];
                                }

                                client_count--;

                                if (client_count == 0) {
                                    free(clients);
                                } else {
                                    clients = realloc(clients, sizeof(struct client) * (client_count));
                                }
                            }
                        }
                        close(i); // bye!
                        FD_CLR(i, &master); // remove from master set
                    } else {
                        // we got some data from a client
                        for (j=0;j<client_count;j++) {
                            if (clients[j]->fd == i) {
                                if (clients[j]->buffer == NULL) {
                                    clients[j]->buffer = malloc(nbytes);
                                    clients[j]->buffer_size = nbytes;
                                    memcpy(clients[j]->buffer, buf, nbytes);
                                } else {
                                    clients[j]->buffer = realloc(clients[j]->buffer, clients[j]->buffer_size + nbytes);
                                    memcpy(&clients[j]->buffer[clients[j]->buffer_size], buf, nbytes);
                                    clients[j]->buffer_size += nbytes;
                                }
                                

                                while (contains(clients[j]->buffer, clients[j]->buffer_size, '\n')) {                                
                                    nbytes = 0;
                                    while (clients[j]->buffer[nbytes++] != '\n');

                                    if (nbytes <= sizeof buf) {
                                        memcpy(buf, clients[j]->buffer, nbytes);
                                
                                        jsmn_init(&parser);                        
                                        r = jsmn_parse(&parser, buf, nbytes, tokens, sizeof(tokens)/sizeof(tokens[0]));
                
                                        if (r < 0) {
											free(clients[j]->buffer);
											free(clients[j]);

											for (k=j;k<client_count-1;k++) {
												clients[k] = clients[k+1];
											}

											client_count--;

											if (client_count == 0) {
												free(clients);
											} else {
												clients = realloc(clients, sizeof(struct client) * (client_count));
											}
										
											close(i); // bye!
											FD_CLR(i, &master); // remove from master set
                                            break;
                                        }

                                        if (r < 1 || tokens[0].type != JSMN_OBJECT) {
											free(clients[j]->buffer);
                                            free(clients[j]);

											for (k=j;k<client_count-1;k++) {
												clients[k] = clients[k+1];
											}

											client_count--;

											if (client_count == 0) {
												free(clients);
											} else {
												clients = realloc(clients, sizeof(struct client) * (client_count));
											}
										
											close(i); // bye!
											FD_CLR(i, &master); // remove from master set
                                            break;
                                        }

                                        for (k = 1; k < r; k++) {
                                            if (jsoneq(buf, &tokens[k], "bbs") == 0) {
                                                snprintf(msg.bbstag, 16, "%.*s", tokens[k+1].end-tokens[k+1].start, buf + tokens[k+1].start);
                                                k++;
                                            }
                                            if (jsoneq(buf, &tokens[k], "nick") == 0) {
                                                snprintf(msg.nick, 16, "%.*s", tokens[k+1].end-tokens[k+1].start, buf + tokens[k+1].start);
                                                k++;
                                            }
                                            if (jsoneq(buf, &tokens[k], "msg") == 0) {
                                                snprintf(msg.msg, 256, "%.*s", tokens[k+1].end-tokens[k+1].start, buf + tokens[k+1].start);
                                                k++;
                                            }                     
                                        } 
                                    
                                        if (strcmp(msg.msg, "LOGIN") == 0) {
                                            if (strcmp(clients[j]->nick, "UNKNOWN") == 0) {
                                                if (strcmp(msg.nick, "CLIENT") == 0 || strcmp(msg.nick, "SYSTEM") ==0 || strcmp(msg.nick, "UNKNOWN") ==0 || strcmp(msg.bbstag, "SYSTEM") == 0) {
                                                    // invalid login.
                                                    snprintf(buffer, 1024, "{\"bbs\": \"SYSTEM\", \"nick\": \"SYSTEM\", \"msg\": \"INVALID LOGIN\" }\n");
                                                    if (send(i, buffer, strlen(buffer), 0) == -1) {
                                                        perror("send");
                                                    }
                                                } else {
                                                    strncpy(clients[j]->bbstag, msg.bbstag, 16);
                                                    strncpy(clients[j]->nick, msg.nick, 16);
                                                    strcpy(clients[j]->room, "lobby");
                                                    strcpy(clients[j]->status, "active");
                                                    clients[j]->bbstag[15] = '\0';
                                                    clients[j]->nick[15] = '\0';

                                                    for(k = 0; k < client_count; k++) {
                                                        if (i != clients[k]->fd && strcmp(clients[k]->nick, "UNKNOWN") != 0) {
                                                            snprintf(buffer, 1024, "{\"bbs\": \"SYSTEM\", \"nick\": \"SYSTEM\", \"msg\": \"%s (%s) has joined the chat\" }\n", clients[j]->nick, clients[j]->bbstag);
                                                            if (send(clients[k]->fd, buffer, strlen(buffer), 0) == -1) {
                                                                perror("send");
                                                            }
                                                        }
                                                    }
                                                        
                                                    fptr = fopen("motd.txt", "r");
                                                    if (fptr) {
                                                        fgets(motd, 256, fptr);
                                                        while (!feof(fptr)) {
                                                            if (motd[strlen(motd) - 1] == '\n') {
                                                                motd[strlen(motd) - 1] = '\0';
                                                            }
                                                                
                                                            if (strlen(motd) == 0) {
                                                                sprintf(motd, " ");
                                                            }
                                                                
                                                                
                                                            snprintf(buffer, 1024, "{\"bbs\": \"SYSTEM\", \"nick\": \"SYSTEM\", \"msg\": \"%s\" }\n", motd);
                                                                
                                                            if (send(i, buffer, strlen(buffer), 0) == -1) {
                                                                perror("send");
                                                            }
                                                            fgets(motd, 256, fptr);
                                                        }
                                                        fclose(fptr);
                                                    }
                                                    for (k=0;k<client_count;k++) {
                                                        if (strcmp(clients[k]->nick, "UNKNOWN") != 0) {
                                                            snprintf(buffer, 1024, "{\"bbs\": \"SYSTEM\", \"nick\": \"SYSTEM\", \"msg\": \"(%s)[%s] is online (%s) and in room : %s\" }\n", clients[k]->bbstag, clients[k]->nick, clients[k]->status, clients[k]->room);
                                                                
                                                            if (send(i, buffer, strlen(buffer), 0) == -1) {
                                                                perror("send");
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        } else if (strcmp(msg.msg, "USERS") == 0) {
                                            for (k=0;k<client_count;k++) {
                                                if (strcmp(clients[k]->nick, "UNKNOWN") != 0) {
                                                    snprintf(buffer, 1024, "{\"bbs\": \"SYSTEM\", \"nick\": \"SYSTEM\", \"msg\": \"(%s)[%s] is online (%s) and in room : %s\" }\n", clients[k]->bbstag, clients[k]->nick, clients[k]->status, clients[k]->room);
                                                        
                                                    if (send(i, buffer, strlen(buffer), 0) == -1) {
                                                        perror("send");
                                                    }
                                                }
                                            }
                                        } else if (strcmp(msg.msg, "PING") == 0) {
                                            snprintf(buffer, 1024, "{\"bbs\": \"SYSTEM\", \"nick\": \"SYSTEM\", \"msg\": \"PONG\" }\n");
                                            if (send(i, buffer, strlen(buffer), 0) == -1) {
                                                perror("send");
                                            }	
                                        } else if (strcmp(msg.msg, "ROOM") == 0) {
                                            if (strcmp(clients[j]->nick, "UNKNOWN") != 0) {    
                                                snprintf(buffer, 1024, "{\"bbs\": \"SYSTEM\", \"nick\": \"SYSTEM\", \"msg\": \"You are in the room: %s\" }\n", clients[j]->room);
                                                if (send(i, buffer, strlen(buffer), 0) == -1) {
                                                    perror("send");
                                                }
                                            }
                                        } else if (strncmp(msg.msg, "ROOM ", 5) == 0) {
                                            if (strcmp(clients[j]->nick, "UNKNOWN") != 0) {    
                                                memset(clients[j]->room, 0, 16);
                                                strncpy(clients[j]->room, &msg.msg[5], 15);
                                                snprintf(buffer, 1024, "{\"bbs\": \"SYSTEM\", \"nick\": \"SYSTEM\", \"msg\": \"You are in the room: %s\" }\n", clients[j]->room);
                                                if (send(i, buffer, strlen(buffer), 0) == -1) {
                                                    perror("send");
                                                }
                                            }
                                        } else if (strncmp(msg.msg, "STATUS ", 7) == 0) {
                                            if (strcmp(clients[j]->nick, "UNKNOWN") != 0) {
                                                memset(clients[j]->status, 0, 16);
                                                strncpy(clients[j]->status, &msg.msg[7], 15);
                                                snprintf(buffer, 1024, "{\"bbs\": \"SYSTEM\", \"nick\": \"SYSTEM\", \"msg\": \"Your status is now: %s\" }\n", clients[j]->status);
                                                if (send(i, buffer, strlen(buffer), 0) == -1) {
                                                    perror("send");
                                                }
                                            }
                                        } else if (strcmp(msg.msg, "HELP") == 0) {
                                            fptr = fopen("help.txt", "r");
                                            if (fptr) {
                                                fgets(motd, 256, fptr);
                                                while (!feof(fptr)) {
                                                    if (motd[strlen(motd) - 1] == '\n') {
                                                        motd[strlen(motd) - 1] = '\0';
                                                    }
                                                                
                                                    if (strlen(motd) == 0) {
                                                        sprintf(motd, " ");
                                                    }
                                                                
                                                                
                                                    snprintf(buffer, 1024, "{\"bbs\": \"SYSTEM\", \"nick\": \"SYSTEM\", \"msg\": \"%s\" }\n", motd);
                                                                
                                                    if (send(i, buffer, strlen(buffer), 0) == -1) {
                                                        perror("send");
                                                    }
                                                    fgets(motd, 256, fptr);
                                                }
                                                fclose(fptr);
                                            }
                                        } else if (strcmp(msg.msg, "MOTD") == 0) {
                                            fptr = fopen("motd.txt", "r");
                                            if (fptr) {
                                                fgets(motd, 256, fptr);
                                                while (!feof(fptr)) {
                                                    if (motd[strlen(motd) - 1] == '\n') {
                                                        motd[strlen(motd) - 1] = '\0';
                                                    }
                                                                
                                                    if (strlen(motd) == 0) {
                                                        sprintf(motd, " ");
                                                    }
                                                                
                                                                
                                                    snprintf(buffer, 1024, "{\"bbs\": \"SYSTEM\", \"nick\": \"SYSTEM\", \"msg\": \"%s\" }\n", motd);
                                                                
                                                    if (send(i, buffer, strlen(buffer), 0) == -1) {
                                                        perror("send");
                                                    }
                                                    fgets(motd, 256, fptr);
                                                }
                                                fclose(fptr);
                                            }
                                        } else {
                                            if (strcmp(clients[j]->nick, "UNKNOWN") != 0) {
                                                for(k = 0; k < client_count; k++) {
                                                    if (i != clients[k]->fd && strcmp(clients[k]->nick, "UNKNOWN") != 0 && strcmp(clients[k]->room, clients[j]->room) == 0) {
                                                        if (send(clients[k]->fd, buf, nbytes, 0) == -1) {
                                                            perror("send");
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    l = 0;
                                    for (k = nbytes; k < clients[j]->buffer_size; k++) {
                                        clients[j]->buffer[l++] = clients[j]->buffer[k];
                                    }

                                    clients[j]->buffer = realloc(clients[j]->buffer, l);
                                    clients[j]->buffer_size = l;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
