#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#if defined(__OpenBSD__) || defined(__HAIKU__)
#include <sys/select.h>
#endif
#include "../deps/jsmn/jsmn.h"
#include "bbs.h"

extern struct bbs_config conf;
extern int mynode;
extern int gSocket;
extern int sshBBS;

struct character_t {
	char c;
	int color;
};

static struct character_t ***screenbuffer;
static int chat_socket;
static int line_at;
static int row_at;
static char sbuf[512];
extern struct user_record gUser;
extern int usertimeout;

struct chat_msg {
	char nick[16];
	char bbstag[16];
	char msg[512];
};

static int jsoneq(const char *json, jsmntok_t *tok, const char *s) {
	if (tok->type == JSMN_STRING && (int)strlen(s) == tok->end - tok->start &&
	    strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
		return 0;
	}
	return -1;
}

static char *encapsulate_quote(char *in) {
	char out[512];
	int i = 0;
	int j = 0;
	for (j = 0; j < strlen(in); j++) {
		if (in[j] == '\"' || in[j] == '\\') {
			out[i++] = '\\';
		}
		out[i] = in[j];
		out[i + 1] = '\0';
		i++;
	}
	return strdup(out);
}

void scroll_up() {
	int y;
	int x;
	int color;

	for (y = 1; y < 23; y++) {
		for (x = 0; x < 80; x++) {
			memcpy(screenbuffer[y - 1][x], screenbuffer[y][x], sizeof(struct character_t));
			color = screenbuffer[y][x]->color;
		}
	}
	for (x = 0; x < 80; x++) {
		screenbuffer[22][x]->c = '\0';
		screenbuffer[22][x]->color = color;
	}
	row_at = 0;
}

void raw(char *fmt, ...) {

	va_list ap;
	va_start(ap, fmt);
	vsnprintf(sbuf, 512, fmt, ap);
	va_end(ap);
	write(chat_socket, sbuf, strlen(sbuf));
}

int hostname_to_ip6(char *hostname, char *ip) {
	struct addrinfo hints, *res, *p;
	int status;
	struct sockaddr_in6 *ipv6;

	memset(&hints, 0, sizeof(hints));

	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_STREAM;

	if ((status = getaddrinfo(hostname, NULL, &hints, &res)) != 0) {
		dolog("getaddrinfo: %s\n", gai_strerror(status));
		return 1;
	}

	for (p = res; p != NULL; p = p->ai_next) {
		if (p->ai_family == AF_INET6) {
			ipv6 = (struct sockaddr_in6 *)p->ai_addr;
			inet_ntop(p->ai_family, &(ipv6->sin6_addr), ip, INET6_ADDRSTRLEN);
			freeaddrinfo(res);
			return 0;
		}
	}
	freeaddrinfo(res);
	return 1;
}

int hostname_to_ip(char *hostname, char *ip) {
	struct addrinfo hints, *res, *p;
	int status;
	struct sockaddr_in *ipv4;

	memset(&hints, 0, sizeof(hints));

	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	if ((status = getaddrinfo(hostname, NULL, &hints, &res)) != 0) {
		dolog("getaddrinfo: %s\n", gai_strerror(status));
		return 1;
	}

	for (p = res; p != NULL; p = p->ai_next) {
		if (p->ai_family == AF_INET) {
			ipv4 = (struct sockaddr_in *)p->ai_addr;
			inet_ntop(p->ai_family, &(ipv4->sin_addr), ip, INET_ADDRSTRLEN);
			freeaddrinfo(res);
			return 0;
		}
	}
	freeaddrinfo(res);
	return 1;
}

void append_screenbuffer(char *buffer) {
	int z;
	int i;
	int last_space = 0;
	int last_pos = 0;
	int curr_color = 7;

	for (z = 0; z < strlen(buffer); z++) {
		if (buffer[z] == '\\') {
			z++;
		}
		if (buffer[z] == '|') {
			z++;
			if ((buffer[z] - '0' <= 2 && buffer[z] - '0' >= 0) && (buffer[z + 1] - '0' <= 9 && buffer[z + 1] - '0' >= 0)) {
				curr_color = (buffer[z] - '0') * 10 + (buffer[z + 1] - '0');
				z += 2;
			} else {
				z--;
			}
		}
		if (row_at == 79) {
			if (line_at == 22) {
				if (last_space > 0) {
					for (i = last_space; i <= row_at; i++) {
						screenbuffer[line_at][i]->c = '\0';
						screenbuffer[line_at][i]->color = curr_color;
					}
				} else {
					last_pos = z;
				}
				scroll_up();
				row_at = 0;
				for (i = last_pos + 1; i < z; i++) {
					if (buffer[i] == '|') {
						i++;
						if ((buffer[i] - '0' <= 2 && buffer[i] - '0' >= 0) && (buffer[i + 1] - '0' <= 9 && buffer[i + 1] - '0' >= 0)) {
							curr_color = (buffer[i] - '0') * 10 + (buffer[i + 1] - '0');
							i += 2;
						} else {
							i--;
						}
					}
					if (i < strlen(buffer)) {
						screenbuffer[line_at][row_at]->c = buffer[i];
						screenbuffer[line_at][row_at++]->color = curr_color;
					}
				}
				last_space = 0;
				last_pos = 0;
			} else {
				if (last_space > 0) {
					for (i = last_space; i <= row_at; i++) {
						screenbuffer[line_at][i]->c = '\0';
						screenbuffer[line_at][i]->color = curr_color;
					}
				} else {
					last_pos = z;
				}
				line_at++;
				row_at = 0;
				for (i = last_pos + 1; i < z; i++) {
					if (buffer[i] == '|') {
						i++;
						if ((buffer[i] - '0' <= 2 && buffer[i] - '0' >= 0) && (buffer[i + 1] - '0' <= 9 && buffer[i + 1] - '0' >= 0)) {
							curr_color = (buffer[i] - '0') * 10 + (buffer[i + 1] - '0');
							i += 2;
						} else {
							i--;
						}
					}
					if (i < strlen(buffer)) {
						screenbuffer[line_at][row_at]->c = buffer[i];
						screenbuffer[line_at][row_at++]->color = curr_color;
					}
				}
				last_space = 0;
			}
		}

		if (buffer[z] == ' ') {
			last_space = row_at;
			last_pos = z;
		}

		if (z < strlen(buffer)) {
			screenbuffer[line_at][row_at]->c = buffer[z];
			screenbuffer[line_at][row_at]->color = curr_color;
			row_at++;
			screenbuffer[line_at][row_at]->c = '\0';
			screenbuffer[line_at][row_at]->color = curr_color;
		}
	}
	if (line_at == 22) {
		scroll_up();
	}
	if (line_at < 22) {
		line_at++;
	}

	row_at = 0;
}

int chat_connect_ipv6(int *socketp, char *mserver, int mport) {
	struct sockaddr_in6 servaddr6;
	int chat_socket;
	char buffer[513];

	memset(&servaddr6, 0, sizeof(struct sockaddr_in6));
	if (inet_pton(AF_INET6, mserver, &servaddr6.sin6_addr) != 1) {
		if (hostname_to_ip6(mserver, buffer)) {
			return 0;
		}
		if (!inet_pton(AF_INET6, buffer, &servaddr6.sin6_addr)) {
			return 0;
		}
	}
	servaddr6.sin6_family = AF_INET6;
	servaddr6.sin6_port = htons(mport);
	if ((chat_socket = socket(AF_INET6, SOCK_STREAM, 0)) < 0) {
		return 0;
	}
	if (connect(chat_socket, (struct sockaddr *)&servaddr6, sizeof(servaddr6)) < 0) {
		return 0;
	}

	*socketp = chat_socket;
	return 1;
}

int chat_connect_ipv4(int *socketp, char *mserver, int mport) {
	struct sockaddr_in servaddr;
	int chat_socket;
	char buffer[513];

	memset(&servaddr, 0, sizeof(struct sockaddr_in));
	if (inet_pton(AF_INET, mserver, &servaddr.sin_addr) != 1) {
		if (hostname_to_ip(mserver, buffer)) {
			return 0;
		}
		if (!inet_pton(AF_INET, buffer, &servaddr.sin_addr)) {
			return 0;
		}
	}
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(mport);
	if ((chat_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		return 0;
	}
	if (connect(chat_socket, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
		return 0;
	}

	*socketp = chat_socket;
	return 1;
}

void chat_system(struct user_record *user, char *mserver, int mport) {
	fd_set fds;
	int t;
	int ret;
	char inputbuffer[256];
	int inputbuffer_at = 0;
	int len;
	char c;
	char buffer2[256];
	char outputbuffer[513];
	char readbuffer[1024];
	char message[1024];
	char partmessage[1024];
	int do_update = 1;
	int i;
	int j;
	int chat_in;
	jsmn_parser parser;
	jsmntok_t tokens[8];
	int r;
	struct chat_msg msg;
	char *input_b;
	char *ptr;
	int z;
	int y;
	int last_color = 7;
	int chat_connected = 0;
	time_t msgtime;
	struct tm msgtime_tm;
	if (sshBBS) {
		chat_in = STDIN_FILENO;
	} else {
		chat_in = gSocket;
	}

	memset(inputbuffer, 0, 256);

	row_at = 0;
	line_at = 0;
	s_putstring("\e[2J\e[23;1H");
	s_putstring(get_string(50));
	s_putstring("\e[24;1H");

	if (conf.ipv6) {
		chat_connected = chat_connect_ipv6(&chat_socket, mserver, mport);
	}

	if (!chat_connected) {
		chat_connected = chat_connect_ipv4(&chat_socket, mserver, mport);
	}

	if (!chat_connected) {
		return;
	}

	screenbuffer = (struct character_t ***)malloz(sizeof(struct character_t **) * 23);
	for (i = 0; i < 23; i++) {
		screenbuffer[i] = (struct character_t **)malloz(sizeof(struct character_t *) * 80);
		for (z = 0; z < 80; z++) {
			screenbuffer[i][z] = (struct character_t *)malloz(sizeof(struct character_t));
			screenbuffer[i][z]->c = '\0';
			screenbuffer[i][z]->color = 7;
		}
	}
	memset(partmessage, 0, 1024);

	raw("{ \"bbs\": \"%s\", \"nick\": \"%s\", \"msg\": \"LOGIN\" }\n", conf.mgchat_bbstag, user->loginname);

	while (1) {
		FD_ZERO(&fds);
		FD_SET(chat_in, &fds);
		FD_SET(chat_socket, &fds);

		if (chat_socket > chat_in) {
			t = chat_socket + 1;
		} else {
			t = chat_in + 1;
		}

		ret = select(t, &fds, NULL, NULL, NULL);

		if (ret > 0) {
			if (FD_ISSET(chat_in, &fds)) {
				len = read(chat_in, &c, 1);
				if (len == 0) {
					close(chat_socket);
					disconnect("Socket closed");
				}

				usertimeout = 10;

				if (c == '\r') {
					if (strlen(inputbuffer) > 0) {
						if (inputbuffer[0] == '/') {
							if (strcasecmp(&inputbuffer[1], "quit") == 0 || strcasecmp(&inputbuffer[1], "q") == 0) {
								close(chat_socket);
								for (i = 0; i < 22; i++) {
									free(screenbuffer[i]);
								}
								free(screenbuffer);
								return;
							} else {
								snprintf(buffer2, sizeof buffer2, "|12Invalid client command!");
								append_screenbuffer(buffer2);
								do_update = 1;
								memset(inputbuffer, 0, 256);
								inputbuffer_at = 0;
							}
						} else {
							input_b = encapsulate_quote(inputbuffer);
							raw("{ \"bbs\": \"%s\", \"nick\": \"%s\", \"msg\": \"%s\" }\n", conf.mgchat_bbstag, user->loginname, input_b);
							msgtime = time(NULL);
							localtime_r(&msgtime, &msgtime_tm);
							snprintf(buffer2, sizeof buffer2, "|08%02d:%02d (|13%s|08)[|11%s|08]: |07%s", msgtime_tm.tm_hour, msgtime_tm.tm_min, conf.mgchat_bbstag, user->loginname, input_b);
							free(input_b);
							append_screenbuffer(buffer2);
							do_update = 1;
						}
						memset(inputbuffer, 0, 256);
						inputbuffer_at = 0;
					}
				} else if (c != '\n' && c != '\0') {
					if (c == '\b' || c == 127) {
						if (inputbuffer_at > 0) {
							inputbuffer_at--;
							inputbuffer[inputbuffer_at] = '\0';
							do_update = 2;
						}
					} else if (inputbuffer_at < 255) {
						inputbuffer[inputbuffer_at++] = c;
						do_update = 2;
					}
				}
			}
			if (FD_ISSET(chat_socket, &fds)) {
				len = read(chat_socket, readbuffer, 512);
				if (len == 0) {
					s_putstring("\r\n\r\n\r\nLost connection to chat server!\r\n");
					for (i = 0; i < 22; i++) {
						free(screenbuffer[i]);
					}
					free(screenbuffer);
					return;
				}
				readbuffer[len] = '\0';
				strlcat(partmessage, readbuffer, sizeof(partmessage));

				while (strchr(partmessage, '\n') != NULL) {
					strlcpy(readbuffer, partmessage, sizeof(readbuffer));
					y = 0;
					for (z = 0; z < strlen(readbuffer); z++) {
						if (readbuffer[z] != '\n') {
							message[y] = readbuffer[z];
							message[y + 1] = '\0';
							y++;
						} else {
							break;
						}
					}
					z++;
					y = 0;
					// json parse
					jsmn_init(&parser);
					// we got some data from a client
					r = jsmn_parse(&parser, message, strlen(message), tokens, sizeof(tokens) / sizeof(tokens[0]));

					if ((r < 0) || (r < 1 || tokens[0].type != JSMN_OBJECT)) {
						// invalid json
					} else {
						for (j = 1; j < r; j++) {
							if (jsoneq(message, &tokens[j], "bbs") == 0) {
								snprintf(msg.bbstag, sizeof msg.bbstag, "%.*s",
										tokens[j + 1].end - tokens[j + 1].start,
										message + tokens[j + 1].start);
								j++;
							}
							if (jsoneq(message, &tokens[j], "nick") == 0) {
								snprintf(msg.nick, sizeof msg.nick, "%.*s",
										tokens[j + 1].end - tokens[j + 1].start,
										message + tokens[j + 1].start);
								j++;
							}
							if (jsoneq(message, &tokens[j], "msg") == 0) {
								snprintf(msg.msg, sizeof msg.msg, "%.*s",
										tokens[j + 1].end - tokens[j + 1].start,
										message + tokens[j + 1].start);
								j++;
							}
						}

								// set outputbuffer
						if (strcmp(msg.bbstag, "SYSTEM") == 0 && strcmp(msg.nick, "SYSTEM") == 0) {
							snprintf(outputbuffer, 512, "|03>> %s|07", msg.msg);
						} else {
							msgtime = time(NULL);
							localtime_r(&msgtime, &msgtime_tm);
							if (strcasestr(msg.msg, user->loginname) != NULL) {
								snprintf(outputbuffer, 512, "|08%02d:%02d (|13%s|08)[|11%s|08]: |10%s", msgtime_tm.tm_hour, msgtime_tm.tm_min, msg.bbstag, msg.nick, msg.msg);
							} else {
								snprintf(outputbuffer, 512, "|08%02d:%02d (|13%s|08)[|11%s|08]: |15%s", msgtime_tm.tm_hour, msgtime_tm.tm_min, msg.bbstag, msg.nick, msg.msg);
							}
						}
						// screen_append output buffer
						append_screenbuffer(outputbuffer);
						do_update = 1;

						if (z < strlen(readbuffer)) {
							memset(partmessage, 0, 1024);
							memcpy(partmessage, &readbuffer[z], strlen(readbuffer) - z);
						} else {
							memset(partmessage, 0, 1024);
						}
					}
				}
			}
		}
		if (do_update == 1) {
			s_putstring("\e[2J\e[1;1H");
			for (i = 0; i <= line_at; i++) {
				for (z = 0; z < 80; z++) {
					if (screenbuffer[i][z]->color != last_color) {
						switch (screenbuffer[i][z]->color) {
							case 0:
								s_printf("\e[0;30m");
								break;
							case 1:
								s_printf("\e[0;34m");
								break;
							case 2:
								s_printf("\e[0;32m");
								break;
							case 3:
								s_printf("\e[0;36m");
								break;
							case 4:
								s_printf("\e[0;31m");
								break;
							case 5:
								s_printf("\e[0;35m");
								break;
							case 6:
								s_printf("\e[0;33m");
								break;
							case 7:
								s_printf("\e[0;37m");
								break;
							case 8:
								s_printf("\e[1;30m");
								break;
							case 9:
								s_printf("\e[1;34m");
								break;
							case 10:
								s_printf("\e[1;32m");
								break;
							case 11:
								s_printf("\e[1;36m");
								break;
							case 12:
								s_printf("\e[1;31m");
								break;
							case 13:
								s_printf("\e[1;35m");
								break;
							case 14:
								s_printf("\e[1;33m");
								break;
							case 15:
								s_printf("\e[1;37m");
								break;
						}
						last_color = screenbuffer[i][z]->color;
					}
					if (screenbuffer[i][z]->c == '\0') {
						break;
					} else {
						s_printf("%c", screenbuffer[i][z]->c);
					}
				}
				s_printf("\r\n");
			}
			for (i = line_at + 1; i < 22; i++) {
				s_putstring("\r\n");
			}
			s_putstring("\e[23;1H");
			s_putstring(get_string(50));
			s_putstring("\e[24;1H");
			if (inputbuffer_at > 0) {
				s_putstring(inputbuffer);
			}
			do_update = 0;
		} else if (do_update == 2) {
			if (strlen(inputbuffer) > 79) {
				s_printf("\e[24;1f<%s\e[K", &inputbuffer[strlen(inputbuffer) - 78]);
			} else {
				s_printf("\e[24;1f%s\e[K", inputbuffer);
			}
		}
	}
}
