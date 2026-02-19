#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#ifdef __HAIKU__
#include <posix/fcntl.h>
#else
#include <sys/fcntl.h>
#endif
#include <signal.h>
#include <sys/utsname.h>
#include <sys/time.h>
#include <stdarg.h>
#include <fts.h>
#include <errno.h>
#include <sys/socket.h>
#include <iconv.h>
#ifndef DISABLE_MQTT
#include <mosquitto.h>
#endif
#include "bbs.h"
#include "lua/lua.h"
#include "lua/lualib.h"
#include "lua/lauxlib.h"

int telnet_bin_mode = 0;

int mynode = 0;
struct bbs_config conf;

struct user_record *gUser;
int gSocket;
int sshBBS;
int usertimeout;
int timeoutpaused;
time_t userlaston;
extern struct ptr_vector tagged_files;
#ifndef DISABLE_MQTT
struct mosquitto *mosq = NULL;
#endif

char *ipaddress = NULL;

void sigterm_handler2(int s) {
	if (mynode != 0) {
		disconnect("Terminated.");
	}
	dolog("Terminated...");
	exit(0);
}

void sigint_handler(int s) {
	// do nothing...
}
void broadcast(char *mess, ...) {
#ifndef DISABLE_MQTT
	char buffer[PATH_MAX];
	if (conf.broadcast_enable && conf.broadcast_port != 0 && conf.broadcast_address != NULL) {
		va_list ap;
		va_start(ap, mess);
		vsnprintf(buffer, PATH_MAX, mess, ap);
		va_end(ap);

		mosquitto_publish(mosq, NULL, (conf.broadcast_topic == NULL ? "MagickaBBS" : conf.broadcast_topic), strlen(buffer), buffer, 0, 0);
	}
#endif
}

void dolog_www(char *ipaddr, char *fmt, ...) {
	char buffer[PATH_MAX];
	struct tm time_now;
	time_t timen;
	FILE *logfptr;
	int mypid = getpid();

	if (conf.log_path == NULL) return;

	timen = time(NULL);

	localtime_r(&timen, &time_now);

	snprintf(buffer, PATH_MAX, "%s/%04d%02d%02d.log", conf.log_path, time_now.tm_year + 1900, time_now.tm_mon + 1, time_now.tm_mday);
	logfptr = fopen(buffer, "a");
	if (!logfptr) {
		return;
	}
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buffer, PATH_MAX, fmt, ap);
	va_end(ap);

	fprintf(logfptr, "%02d:%02d:%02d [%d][%s] %s\n", time_now.tm_hour, time_now.tm_min, time_now.tm_sec, mypid, ipaddr, buffer);

	fclose(logfptr);
}

void dolog(const char *fmt, ...) {
	char buffer[PATH_MAX];
	struct tm time_now;
	time_t timen;
	FILE *logfptr;
	int mypid = getpid();

	if (conf.log_path == NULL) return;

	timen = time(NULL);

	localtime_r(&timen, &time_now);

	snprintf(buffer, PATH_MAX, "%s/%04d%02d%02d.log", conf.log_path, time_now.tm_year + 1900, time_now.tm_mon + 1, time_now.tm_mday);
	logfptr = fopen(buffer, "a");
	if (!logfptr) {
		return;
	}
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buffer, PATH_MAX, fmt, ap);
	va_end(ap);

	fprintf(logfptr, "%02d:%02d:%02d [%d][%s] %s\n", time_now.tm_hour, time_now.tm_min, time_now.tm_sec, mypid, ipaddress, buffer);

	fclose(logfptr);
}

struct fido_addr *parse_fido_addr(const char *str) {
	if (str == NULL) {
		return NULL;
	}
	struct fido_addr *ret = (struct fido_addr *)malloz(sizeof(struct fido_addr));
	int c;
	int state = 0;

	ret->zone = 0;
	ret->net = 0;
	ret->node = 0;
	ret->point = 0;

	for (c = 0; c < strlen(str); c++) {
		switch (str[c]) {
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
			case '9': {
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
			} break;
			default:
				free(ret);
				return NULL;
		}
	}
	return ret;
}

void timer_handler(int signum) {
	if (signum == SIGALRM) {
		if (gUser != NULL) {
			gUser->timeleft--;

			if (gUser->timeleft <= 0) {
				s_printf(get_string(0));
				disconnect("Out of Time");
			}
		}
		if (timeoutpaused == 0) {
			usertimeout--;
		}
		if (usertimeout <= 0) {
			s_printf(get_string(1));
			disconnect("Timeout");
		}
	}
}

void s_printf(char *fmt, ...) {
	char buffer[512];
	int i;
	int pos;

	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buffer, 512, fmt, ap);
	va_end(ap);

	if (fmt[0] == '@' && fmt[1] == '@' && fmt[strlen(fmt) - 1] == '@' && fmt[strlen(fmt) - 2] == '@') {
		pos = 0;
		for (i = 2; i < strlen(fmt) - 2; i++) {
			buffer[pos++] = fmt[i];
			buffer[pos] = '\0';
		}
		s_displayansi_pause(buffer, 0);
	} else {
		s_putstring(buffer);
	}
}

int should_convert_utf8() {
	if (gUser != NULL) {
		return gUser->codepage;
	}
	return conf.codepage;
}

int convert_ctrl_codes(unsigned char *in, int in_len, unsigned char *out, int out_len) {
	int j = 0;
	int i;

	for (i=0;i < in_len && j < out_len - 1;i++) {
		if (in[i] < 128) {
			if (in[i] < 0x1F || in[i] == 0x7F) {
				switch(in[i]) {
					case 0x01:
						out[j++] = 0xE2;
						out[j++] = 0x98;
						out[j++] = 0xBA;
						break;
					case 0x02:
						out[j++] = 0xE2;
						out[j++] = 0x98;
						out[j++] = 0xBB;
						break;
					case 0x03:
						out[j++] = 0xE2;
						out[j++] = 0x99;
						out[j++] = 0xA5;
						break;
					case 0x04:
						out[j++] = 0xE2;
						out[j++] = 0x99;
						out[j++] = 0xA6;
						break;
					case 0x05:
						out[j++] = 0xE2;
						out[j++] = 0x99;
						out[j++] = 0xA3;
						break;
					case 0x06:
						out[j++] = 0xE2;
						out[j++] = 0x99;
						out[j++] = 0xA0;
						break;
					case 0x07:
						out[j++] = 0xE2;
						out[j++] = 0x80;
						out[j++] = 0xA2;
						break;
					case 0x08:
						out[j++] = 0xE2;
						out[j++] = 0x97;
						out[j++] = 0x98;
						break;
					case 0x09:
						out[j++] = 0x09; // TAB
						break;
					case 0x0A:
						out[j++] = 0x0A; // Line Feed
						break;
					case 0x0B:
						out[j++] = 0xE2;
						out[j++] = 0x99;
						out[j++] = 0x82;
						break;
					case 0x0C:
						out[j++] = 0xE2;
						out[j++] = 0x99;
						out[j++] = 0x80;
						break;
					case 0x0D:
						out[j++] = 0x0D; // CR
						break;
					case 0x0E:
						out[j++] = 0xE2;
						out[j++] = 0x99;
						out[j++] = 0xAB;
						break;
					case 0x0F:
						out[j++] = 0xE2;
						out[j++] = 0x98;
						out[j++] = 0xBC;
						break;
					case 0x10:
						out[j++] = 0xE2;
						out[j++] = 0x96;
						out[j++] = 0xB6;
						break;
					case 0x11:
						out[j++] = 0xE2;
						out[j++] = 0x97;
						out[j++] = 0x85;
						break;
					case 0x12:
						out[j++] = 0xE2;
						out[j++] = 0x86;
						out[j++] = 0x95;
						break;
					case 0x13:
						out[j++] = 0xE2;
						out[j++] = 0x80;
						out[j++] = 0xBC;
						break;
					case 0x14:
						out[j++] = 0xC2;
						out[j++] = 0xB6;
						break;
					case 0x15:
						out[j++] = 0xC2;
						out[j++] = 0xA7;
						break;
					case 0x16:
						out[j++] = 0xE2;
						out[j++] = 0x96;
						out[j++] = 0xAC;
						break;
					case 0x17:
						out[j++] = 0xE2;
						out[j++] = 0x86;
						out[j++] = 0xA8;
						break;
					case 0x18:
						out[j++] = 0xE2;
						out[j++] = 0x86;
						out[j++] = 0x91;
						break;
					case 0x19:
						out[j++] = 0xE2;
						out[j++] = 0x86;
						out[j++] = 0x93;
						break;
					case 0x1A:
						out[j++] = 0xE2;
						out[j++] = 0x86;
						out[j++] = 0x92;
						break;
					case 0x1B:
						out[j++] = 0x1B; // Escape
						break;
					case 0x1C:
						out[j++] = 0xE2;
						out[j++] = 0x88;
						out[j++] = 0x9F;
						break;
					case 0x1D:
						out[j++] = 0xE2;
						out[j++] = 0x86;
						out[j++] = 0x94;
						break;
					case 0x1E:
						out[j++] = 0xE2;
						out[j++] = 0x96;
						out[j++] = 0xB2;
						break;
					case 0x1F:
						out[j++] = 0xE2;
						out[j++] = 0x96;
						out[j++] = 0xBC;
						break;
					case 0x7F:
						out[j++] = 0xE2;
						out[j++] = 0x8C;
						out[j++] = 0x82;
						break;
					default:
						out[j++] = in[i];
						break;
				}
			} else {
				out[j++] = in[i];
			}
		} else {
			if (in[i] == 0xC2) {
				out[j++] = in[i++];
				out[j++] = in[i];
			} else  if (in[i] == 0xE2) {
				out[j++] = in[i++];
				out[j++] = in[i++];
				out[j++] = in[i];
			}
		}
	}

	return j;
}

void s_putchar(char c) {
	iconv_t ic;
	char *inbuf;
	char *outbuf;
	char *finalbuf;
	char *ptr1;
	char *ptr2;
	size_t inc;
	size_t ouc;
	size_t sz;
	int ret;

	if (!should_convert_utf8()) {
		if (sshBBS) {
			putchar(c);
		} else {
			ret = send(gSocket, &c, 1, 0);
			if (ret == -1) {
				if (errno == ECONNRESET) {
					disconnect("Disconnected");
				}
			}
		}
	} else {
		ic = iconv_open("UTF-8", "CP437");
		inbuf = (char *)malloz(4);
		outbuf = (char *)malloz(4);
		finalbuf = (char *)malloz(4);
		inbuf[0] = c;
		inbuf[1] = '\0';
		inc = 1;
		ouc = 4;
		ptr1 = outbuf;
		ptr2 = inbuf;
		sz = iconv(ic, &inbuf, &inc, &outbuf, &ouc);

		ret = convert_ctrl_codes(ptr1, outbuf - ptr1, finalbuf, 4);

		if (sshBBS) {
			fprintf(stdout, "%s", finalbuf);
		} else {
			ret = send(gSocket, finalbuf, ret, 0);
			if (ret == -1) {
				if (errno == ECONNRESET) {
					iconv_close(ic);
					free(ptr1);
					free(ptr2);
					free(finalbuf);
					disconnect("Disconnected");
				}
			}
		}
		iconv_close(ic);
		free(ptr1);
		free(ptr2);
		free(finalbuf);
	}
}

void s_putstring(char *c) {
	iconv_t ic;
	char *inbuf;
	char *outbuf;
	size_t inc;
	size_t ouc;
	size_t sz;
	char *ptr1;
	char *ptr2;
	char *finalbuf;
	int fbuflen;
	int ret;
	if (!should_convert_utf8()) {
		if (sshBBS) {
			fprintf(stdout, "%s", c);
		} else {
			ret = send(gSocket, c, strlen(c), 0);
			if (ret == -1) {
				if (errno == ECONNRESET) {
					disconnect("Disconnected");
				}
			}
		}
	} else {
		ic = iconv_open("UTF-8", "CP437");
		inc = strlen(c);
		inbuf = strdup(c);
		outbuf = (char *)malloz(inc * 4);
		finalbuf = (char *)malloz(inc * 4);
		fbuflen = inc * 4;
		ptr1 = outbuf;
		ptr2 = inbuf;
		ouc = inc * 4;
		sz = iconv(ic, &inbuf, &inc, &outbuf, &ouc);

		ret = convert_ctrl_codes(ptr1, outbuf - ptr1, finalbuf, fbuflen);
		if (sshBBS) {
			fprintf(stdout, "%s", finalbuf);
		} else {
			ret = send(gSocket, finalbuf, strlen(finalbuf), 0);
			if (ret == -1) {
				if (errno == ECONNRESET) {
					iconv_close(ic);
					free(ptr1);
					free(ptr2);
					free(finalbuf);
					disconnect("Disconnected");
				}
			}
		}
		iconv_close(ic);
		free(ptr1);
		free(ptr2);
		free(finalbuf);
	}
}

void s_displayansi_pause(char *file, int pause) {
	FILE *fptr;
	char c;
	char ch;
	int lines = 0;
	char lastch = 0;
	char buffer[9];
	int len;

	fptr = fopen(file, "r");

	if (!fptr) {
		return;
	}
	c = fgetc(fptr);
	while (!feof(fptr) && c != 0x1a) {
		if (c == '\n' && lastch != '\r') {
			s_putchar('\r');
		} else if (c == '@') {
			memset(buffer, 0, 9);
			len = fread(buffer, 1, 8, fptr);

			if (len != 8 || strcmp(buffer, "@PAUSE@@") != 0) {
				s_putchar('@');
				s_putstring(buffer);
				c = fgetc(fptr);
				continue;
			} else {
				s_printf(get_string(185));
				ch = s_getchar();
				s_printf("\r\n");
				c = fgetc(fptr);
				continue;
			}
		}
		s_putchar(c);

		lastch = c;

		if (pause) {
			if (c == '\n') {
				lines++;
				if (lines == 24) {
					s_printf(get_string(223));
					ch = s_getchar();
					s_printf("\r\n");
					switch (tolower(ch)) {
						case 'c':
							pause = 0;
							break;
						case 'n':
							fclose(fptr);
							return;
						default:
							break;
					}
					lines = 0;
				}
			}
		}
		c = fgetc(fptr);
	}
	fclose(fptr);
}

void s_displayansi_p(char *file) {
	s_displayansi_pause(file, 0);
}

void s_displayansi(char *file) {
	FILE *fptr;
	char c;
	struct stat s;

	char buffer[PATH_MAX];

	if (strchr(file, '/') == NULL) {
		if (gUser != NULL) {
			snprintf(buffer, sizeof buffer, "%s/%s.%d.ans", conf.ansi_path, file, gUser->sec_level);
			if (stat(buffer, &s) != 0) {
				snprintf(buffer, sizeof buffer, "%s/%s.ans", conf.ansi_path, file);
			}
		} else {
			snprintf(buffer, sizeof buffer, "%s/%s.ans", conf.ansi_path, file);
		}
		s_displayansi_pause(buffer, 0);
	} else {
		s_displayansi_pause(file, 0);
	}
}

char s_getchar() {
	unsigned char c;
	unsigned char d;
	int len;
	char iac_binary_will[] = {IAC, IAC_WILL, IAC_TRANSMIT_BINARY, '\0'};
	char iac_binary_do[] = {IAC, IAC_DO, IAC_TRANSMIT_BINARY, '\0'};
	char iac_binary_wont[] = {IAC, IAC_WONT, IAC_TRANSMIT_BINARY, '\0'};
	char iac_binary_dont[] = {IAC, IAC_DONT, IAC_TRANSMIT_BINARY, '\0'};
	int ret;
	do {

		if (sshBBS) {
			c = getchar();
		} else {
			do {
				len = read(gSocket, &c, 1);
			} while (len == -1 && errno == EINTR);
			if (len <= 0) {
				disconnect("Socket Closed");
			}
		}

		if (!sshBBS) {
			while (c == IAC) {
				do {
					len = read(gSocket, &c, 1);
				} while (len == -1 && errno == EINTR);
				if (len == 0) {
					disconnect("Socket Closed");
				} else if (c == IAC) {
					if (gUser != NULL) {
						usertimeout = gUser->sec_info->idle_timeout;
					} else {
						usertimeout = conf.idletimeout;
					}
					return c;
				}
				if (c == IAC_WILL || c == IAC_WONT || c == IAC_DO || c == IAC_DONT) {
					do {
						len = read(gSocket, &d, 1);
					} while (len == -1 && errno == EINTR);
					if (len <= 0) {
						disconnect("Socket Closed");
					}

					switch (c) {
						case IAC_WILL:
							if (d == 0) {
								if (telnet_bin_mode != 1) {
									telnet_bin_mode = 1;
									ret = send(gSocket, iac_binary_do, 3, 0);
									if (ret == -1) {
										if (errno == ECONNRESET) {
											disconnect("Disconnected");
										}
									}
								}
							}
							break;
						case IAC_WONT:
							if (d == 0) {
								if (telnet_bin_mode != 0) {
									telnet_bin_mode = 0;
									ret = send(gSocket, iac_binary_dont, 3, 0);
									if (ret == -1) {
										if (errno == ECONNRESET) {
											disconnect("Disconnected");
										}
									}
								}
							}
							break;
						case IAC_DO:
							if (d == 0) {
								if (telnet_bin_mode != 1) {
									telnet_bin_mode = 1;
									ret = send(gSocket, iac_binary_will, 3, 0);
									if (ret == -1) {
										if (errno == ECONNRESET) {
											disconnect("Disconnected");
										}
									}
								}
							}
							break;
						case IAC_DONT:
							if (d == 0) {
								if (telnet_bin_mode != 0) {
									telnet_bin_mode = 0;
									ret = send(gSocket, iac_binary_wont, 3, 0);
									if (ret == -1) {
										if (errno == ECONNRESET) {
											disconnect("Disconnected");
										}
									}
								}
							}
							break;
					}
				} else if (c == 250) {
					do {
						do {
							len = read(gSocket, &c, 1);
						} while (len == -1 && errno == EINTR);
						if (len <= 0) {
							disconnect("Socket Closed");
						}
					} while (c != 240);
				}

				do {
					len = read(gSocket, &c, 1);
				} while (len == -1 && errno == EINTR);
				if (len <= 0) {
					disconnect("Socket Closed");
				}
			}
		}
	} while (c == '\n' || c == '\0');

	if (gUser != NULL) {
		usertimeout = gUser->sec_info->idle_timeout;
	} else {
		usertimeout = conf.idletimeout;
	}
	return (char)c;
}

char s_getc() {
	char c = s_getchar();

	s_putchar(c);
	return (char)c;
}

void s_readstring_inject(char *buffer, int max, char *inject) {
	int i;
	char c;

	memset(buffer, 0, max);

	if (strlen(inject) > max) {
		return;
	}

	strlcpy(buffer, inject, max);

	s_printf("%s", inject);

	for (i = strlen(buffer); i < max; i++) {
		c = s_getchar();

		if ((c == '\b' || c == 127) && i > 0) {
			buffer[i - 1] = '\0';
			i -= 2;
			s_printf("\e[D \e[D");
			continue;
		} else if (c == '\b' || c == 127) {
			i -= 1;
			continue;
		} else if (c == 27) {
			c = s_getchar();
			if (c == 91) {
				c = s_getchar();
			}
			i -= 1;
			continue;
		}

		if (c == '\n' || c == '\r') {
			return;
		}
		s_putchar(c);
		buffer[i] = c;
		buffer[i + 1] = '\0';
	}
}

void s_readstring(char *buffer, int max) {
	int i;
	char c;

	memset(buffer, 0, max);

	for (i = 0; i < max; i++) {
		c = s_getchar();

		if ((c == '\b' || c == 127) && i > 0) {
			buffer[i - 1] = '\0';
			i -= 2;
			s_printf("\e[D \e[D");
			continue;
		} else if (c == '\b' || c == 127) {
			i -= 1;
			continue;
		} else if (c == 27) {
			c = s_getchar();
			if (c == 91) {
				c = s_getchar();
			}
			i -= 1;
			continue;
		}

		if (c == '\n' || c == '\r') {
			return;
		}
		s_putchar(c);
		buffer[i] = c;
		buffer[i + 1] = '\0';
	}
}

void s_readpass(char *buffer, int max) {
	int i;
	char c;

	for (i = 0; i < max; i++) {
		c = s_getchar();

		if ((c == '\b' || c == 127) && i > 0) {
			buffer[i - 1] = '\0';
			i -= 2;
			s_printf("\e[D \e[D");
			continue;
		} else if (c == '\b' || c == 127) {
			i -= 1;
			continue;
		} else if (c == 27) {
			c = s_getchar();
			if (c == 91) {
				c = s_getchar();
			}
			i -= 1;
			continue;
		}

		if (c == '\n' || c == '\r') {
			return;
		}
		s_putchar('*');
		buffer[i] = c;
		buffer[i + 1] = '\0';
	}
}

void exit_bbs() {
	char buffer[PATH_MAX];

	snprintf(buffer, PATH_MAX, "%s/nodeinuse.%d", conf.bbs_path, mynode);
	remove(buffer);
#ifndef DISABLE_MQTT
	if (mosq != NULL) {
		mosquitto_disconnect(mosq);
		mosquitto_loop_stop(mosq, 0);
		mosquitto_destroy(mosq);
		mosquitto_lib_cleanup();
	}
#endif
}

void disconnect(char *calledby) {
	if (gUser != NULL) {
		do_lua_script("disconnect");
		broadcast("USER: %s; NODE:%d; STATUS: disconnected.", gUser->loginname, mynode);
		save_user(gUser);
	} else {
		broadcast("USER: unknown; NODE:%d; STATUS: disconnected.", mynode);
	}
	dolog("Node %d disconnected (%s)", mynode, calledby);

	if (!sshBBS) {
		close(gSocket);
	}
	exit(0);
}

void record_last10_callers(struct user_record *user) {
	struct last10_callers new_entry;
	struct last10_callers callers[10];

	int i, j;

	char last10_path[PATH_MAX];

	snprintf(last10_path, PATH_MAX, "%s/last10v2.dat", conf.bbs_path);

	FILE *fptr = fopen(last10_path, "rb");

	if (fptr != NULL) {
		for (i = 0; i < 10; i++) {
			if (fread(&callers[i], sizeof(struct last10_callers), 1, fptr) < 1) {
				break;
			}
		}
		fclose(fptr);
	} else {
		i = 0;
	}

	if (strcasecmp(conf.sysop_name, user->loginname) != 0) {
		memset(&new_entry, 0, sizeof(struct last10_callers));
		strlcpy(new_entry.name, user->loginname, sizeof(new_entry.name));
		strlcpy(new_entry.location, user->location, sizeof(new_entry.location));
		new_entry.time = time(NULL);
		new_entry.calls = user->timeson;
		if (i == 10) {
			j = 1;
		} else {
			j = 0;
		}
		fptr = fopen(last10_path, "wb");
		for (; j < i; j++) {
			fwrite(&callers[j], sizeof(struct last10_callers), 1, fptr);
		}
		fwrite(&new_entry, sizeof(struct last10_callers), 1, fptr);
		fclose(fptr);
	}
}

void display_last10_callers(struct user_record *user) {
	struct last10_callers callers[10];

	int i = 0;
	struct tm l10_time;

	FILE *fptr = fopen_bbs_path("last10v2.dat", "rb");

	s_printf("\e[2J\e[1;1H");

	s_printf(get_string(2));
	s_printf(get_string(3));

	if (fptr != NULL) {
		for (i = 0; i < 10; i++) {
			if (fread(&callers[i], sizeof(struct last10_callers), 1, fptr) < 1) {
				break;
			}
		}

		fclose(fptr);
	}

	for (int z = 0; z < i; z++) {
		time_t l10_timet = callers[z].time;
		localtime_r(&l10_timet, &l10_time);
		if (conf.date_style == 1) {
			s_printf(get_string(4), callers[z].name, callers[z].location, l10_time.tm_hour, l10_time.tm_min, l10_time.tm_mon + 1, l10_time.tm_mday, l10_time.tm_year - 100, (callers[z].calls == 1 ? 'N' : ' '));
		} else {
			s_printf(get_string(4), callers[z].name, callers[z].location, l10_time.tm_hour, l10_time.tm_min, l10_time.tm_mday, l10_time.tm_mon + 1, l10_time.tm_year - 100, (callers[z].calls == 1 ? 'N' : ' '));
		}
	}
	s_printf(get_string(5));
	s_printf(get_string(6));
	s_getc();
}

void display_info() {
	struct utsname name;

	uname(&name);
	s_printf("\e[2J\e[1;1H");
	s_printf(get_string(7));
	s_printf(get_string(8));
	s_printf(get_string(9), conf.bbs_name);
	s_printf(get_string(10), conf.sysop_name);
	s_printf(get_string(11), mynode);
	s_printf(get_string(12), VERSION_MAJOR, VERSION_MINOR, VERSION_STR);
	s_printf(get_string(13), name.sysname, name.machine);
	s_printf(get_string(14));

	s_printf(get_string(6));
	s_getc();
}

void automessage_write() {
	FILE *fptr;
	char automsg[450];
	char buffer[76];
	int i;
	struct tm timenow;
	time_t timen;

	memset(automsg, 0, 450);
	memset(buffer, 0, 76);

	if (gUser->sec_level >= conf.automsgwritelvl) {
		timen = time(NULL);
		localtime_r(&timen, &timenow);

		snprintf(automsg, sizeof automsg, get_string(15), gUser->loginname, asctime(&timenow));

		automsg[strlen(automsg) - 1] = '\r';
		automsg[strlen(automsg)] = '\n';
		s_printf(get_string(16));
		for (i = 0; i < 4; i++) {
			s_printf("\r\n%d: ", i);
			s_readstring(buffer, 75);
			strlcat(automsg, buffer, sizeof automsg);
			strlcat(automsg, "\r\n", sizeof automsg);
		}

		fptr = fopen_bbs_path("automessage.txt", "w");
		if (fptr) {
			fwrite(automsg, strlen(automsg), 1, fptr);
			fclose(fptr);
		} else {
			dolog("Unable to open automessage.txt for writing");
		}
	}
}

void automessage_display() {
	char buffer[90];
	int i;
	s_printf("\r\n\r\n");

	FILE *fptr = fopen_bbs_path("automessage.txt", "r");
	if (fptr == NULL) {
		dolog("Error opening automessage.txt");
		s_printf(get_string(17));
	} else {
		for (i = 0; i < 5; i++) {
			memset(buffer, 0, 90);
			fgets(buffer, 88, fptr);
			buffer[strlen(buffer) - 1] = '\r';
			buffer[strlen(buffer)] = '\n';
			s_printf(buffer);
		}
		fclose(fptr);
	}
	s_printf(get_string(6));
	s_getc();
}

void automessage() {
	char c;
	s_printf(get_string(275));
	c = s_getchar();
	s_printf("\r\n");
	switch (tolower(c)) {
		case 'v':
			automessage_display();
			break;
		case 'u':
			automessage_write();
			break;
		default:
			break;
	}
	return;
}

void runbbs_real(int socket, char *ip, int ssh) {
	char buffer[PATH_MAX];
	char password[17];

	struct stat s;
	FILE *nodefile;
	int i;
	char iac_echo[] = {IAC, IAC_WILL, IAC_ECHO, '\0'};
	char iac_sga[] = {IAC, IAC_WILL, IAC_SUPPRESS_GO_AHEAD, '\0'};

	struct user_record *user;
	struct tm thetime;
	struct tm oldtime;
	time_t now;
	struct itimerval itime;
	struct sigaction sa;
	struct sigaction st;
	lua_State *L;
	int do_internal_login = 0;
	int usernotfound;
	int tries;
	int fno;

	atexit(exit_bbs);

	usertimeout = conf.idletimeout;
	timeoutpaused = 0;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = &timer_handler;
	sa.sa_flags = SA_RESTART;
	sigaction(SIGALRM, &sa, 0);

	itime.it_interval.tv_sec = 60;
	itime.it_interval.tv_usec = 0;
	itime.it_value.tv_sec = 60;
	itime.it_value.tv_usec = 0;

	setitimer(ITIMER_REAL, &itime, 0);

	ipaddress = ip;

	st.sa_handler = sigterm_handler2;
	sigemptyset(&st.sa_mask);
	st.sa_flags = SA_SIGINFO;
	if (sigaction((ssh ? SIGHUP : SIGTERM), &st, NULL) == -1) {
		dolog("Failed to setup sigterm handler.");
		exit(1);
	}
	if (sigaction(SIGPIPE, &st, NULL) == -1) {
		dolog("Failed to setup sigpipe handler.");
		exit(1);
	}
	gSocket = socket;

	if (!ssh) {
		gUser = NULL;
		sshBBS = 0;
		if (send(socket, iac_echo, 3, 0) != 3) {
			dolog("Failed to send iac_echo");
			exit(0);
		}
		if (send(socket, iac_sga, 3, 0) != 3) {
			dolog("Failed to send iac_sga");
			exit(0);
		}
	} else {
		sshBBS = 1;
	}

	s_printf("Magicka BBS v%d.%d (%s), Loading...\r\n", VERSION_MAJOR, VERSION_MINOR, VERSION_STR);
	mynode = 0;
	// find out which node we are
	for (i = 1; i <= conf.nodes; i++) {
		snprintf(buffer, sizeof buffer, "%s/nodeinuse.%d", conf.bbs_path, i);

		if (stat(buffer, &s) != 0) {
			fno = open(buffer, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
			if (fno == -1) {
				dolog("Error opening nodefile!");
				continue;
			}
			write(fno, "UNKNOWN", 7);
			close(fno);
			mynode = i;
			break;
		}
	}

	if (mynode == 0) {
		s_printf(get_string(18));
		if (!ssh) {
			close(socket);
		}
		exit(1);
	}

	// initialize mqtt
#ifndef DISABLE_MQTT
	if (conf.broadcast_enable && conf.broadcast_address != NULL && conf.broadcast_port != 0) {
		mosquitto_lib_init();
		mosq = mosquitto_new(NULL, 1, NULL);
		if (conf.broadcast_user != NULL && conf.broadcast_pass != NULL) {
			mosquitto_username_pw_set(mosq, conf.broadcast_user, conf.broadcast_pass);
		}
		if (mosquitto_connect(mosq, conf.broadcast_address, conf.broadcast_port, 60)) {
			dolog("Unable to connect to MQTT server.");
			conf.broadcast_enable = 0;
		} else {
			if (mosquitto_loop_start(mosq) != MOSQ_ERR_SUCCESS) {
				dolog("Unable to start MQTT loop.");
				conf.broadcast_enable = 0;
			}
		}
	}
#endif

	broadcast("USER: unknown; NODE:%d; STATUS: Logging in.", mynode);

	dolog("Incoming %s connection on node %d", (ssh ? "SSH" : "Telnet"), mynode);

	s_displayansi("issue");

	tries = 0;

	if (!ssh) {
	tryagain:
		s_printf(get_string(19));
		s_printf(get_string(20));

		s_readstring(buffer, 25);

		usernotfound = 0;

		if (strcasecmp(buffer, "new") == 0) {
			usernotfound = 1;
		} else if (check_user(buffer)) {
			s_printf(get_string(203));
			goto tryagain;
		}

		if (usernotfound) {
			dolog("New user on node %d", mynode);
			user = new_user();
			gUser = user;
		} else {
			s_printf(get_string(21));
			s_readpass(password, 16);
			user = check_user_pass(buffer, password);
			if (user == NULL) {
				if (tries == 3) {
					s_printf(get_string(22));
					disconnect("Incorrect Login");
				} else {
					tries++;
					s_printf(get_string(22));
					goto tryagain;
				}
			}

			gUser = user;

			for (i = 1; i <= conf.nodes; i++) {
				snprintf(buffer, PATH_MAX, "%s/nodeinuse.%d", conf.bbs_path, i);
				if (stat(buffer, &s) == 0) {
					nodefile = fopen(buffer, "r");
					if (!nodefile) {
						dolog("Error opening nodefile!");
						disconnect("Error opening nodefile!");
					}
					fgets(buffer, 256, nodefile);

					if (strcasecmp(user->loginname, buffer) == 0) {
						fclose(nodefile);
						s_printf(get_string(23));
						disconnect("Already Logged in");
					}
					fclose(nodefile);
				}
			}
		}
	} else {
		if (gUser != NULL) {
			user = gUser;
			s_printf(get_string(24), gUser->loginname);
			s_getc();
			for (i = 1; i <= conf.nodes; i++) {
				snprintf(buffer, PATH_MAX, "%s/nodeinuse.%d", conf.bbs_path, i);
				if (stat(buffer, &s) == 0) {
					nodefile = fopen(buffer, "r");
					if (!nodefile) {
						dolog("Error opening nodefile!");
						disconnect("Error opening nodefile!");
					}
					fgets(buffer, 256, nodefile);

					if (strcasecmp(user->loginname, buffer) == 0) {
						fclose(nodefile);
						s_printf(get_string(23));
						disconnect("Already Logged in");
					}
					fclose(nodefile);
				}
			}
		} else {
			s_printf(get_string(25), conf.bbs_name);
			s_getc();
			gUser = new_user();
			user = gUser;
		}
	}
	if (user == NULL) {
		disconnect("Failed to login");
 	}

	snprintf(buffer, PATH_MAX, "%s/nodeinuse.%d", conf.bbs_path, mynode);
	nodefile = fopen(buffer, "w");
	if (!nodefile) {
		dolog("Error opening nodefile!");
		close(socket);
		exit(1);
	}

	fputs(user->loginname, nodefile);
	fclose(nodefile);

	init_ptr_vector(&tagged_files);

	snprintf(buffer, PATH_MAX, "%s/node%d/nodemsg.txt", conf.bbs_path, mynode);

	if (stat(buffer, &s) == 0) {
		unlink(buffer);
	}

	snprintf(buffer, PATH_MAX, "%s/node%d/lua/", conf.bbs_path, mynode);

	if (stat(buffer, &s) == 0) {
		recursive_delete(buffer);
	}

#if defined(ENABLE_WWW)
	www_expire_old_links();
#endif

	// do post-login
	dolog("%s logged in, on node %d", user->loginname, mynode);
	broadcast("USER: %s; NODE:%d; STATUS: Logged in.", user->loginname, mynode);
	// check time left
	now = time(NULL);
	localtime_r(&now, &thetime);
	localtime_r(&user->laston, &oldtime);

	userlaston = user->laston;

	if (thetime.tm_mday != oldtime.tm_mday || thetime.tm_mon != oldtime.tm_mon || thetime.tm_year != oldtime.tm_year) {
		user->timeleft = user->sec_info->timeperday;
		user->laston = now;
		save_user(user);
	}

	user->timeson++;

	if (conf.script_path != NULL) {
		snprintf(buffer, PATH_MAX, "%s/login_stanza.lua", conf.script_path);
		if (stat(buffer, &s) == 0) {
			L = luaL_newstate();
			luaL_openlibs(L);
			lua_push_cfunctions(L);
			int ret = luaL_dofile(L, buffer);
			if(ret != 0){
  				dolog("Error calling luaL_dofile() Error Code 0x%x",ret);
  				dolog("Error: %s", lua_tostring(L,-1));
			}
			lua_close(L);
			do_internal_login = 0;
		} else {
			do_internal_login = 1;
		}
	} else {
		do_internal_login = 1;
	}

	if (do_internal_login == 1) {
		// bulletins
		display_bulletins();

		blog_display();

		// display info
		display_info();

		display_last10_callers(user);

		// check email
		i = mail_getemailcount(user);
		if (i > 0) {
			s_printf(get_string(26), i);
		} else {
			s_printf(get_string(27));
		}

		mail_scan(user);

		file_scan();

		automessage_display();
	}
	record_last10_callers(user);
	// main menu

	menu_system(conf.root_menu);

	do_logout();

	dolog("%s is logging out, on node %d", user->loginname, mynode);
	broadcast("USER: %s; NODE:%d; STATUS: Logging out.", user->loginname, mynode);
	disconnect("Log out");
}

void do_logout() {
	char buffer[PATH_MAX];
	struct stat s;
	lua_State *L;
	int ret = 0;
	char c;
	int result;
	int do_internal_logout = 1;

	if (conf.script_path != NULL) {
		snprintf(buffer, PATH_MAX, "%s/logout_stanza.lua", conf.script_path);
		if (stat(buffer, &s) == 0) {
			L = luaL_newstate();
			luaL_openlibs(L);
			lua_push_cfunctions(L);
			luaL_loadfile(L, buffer);
			result = lua_pcall(L, 0, 1, 0);
			if (result) {
				dolog("Failed to run script: %s", lua_tostring(L, -1));
				do_internal_logout = 1;
				lua_close(L);
			} else {
				do_internal_logout = 0;
			}
		}
	}

	if (do_internal_logout == 1) {
		s_displayansi("goodbye");
	} else {
		lua_getglobal(L, "logout");
		result = lua_pcall(L, 0, 0, 0);
		if (result) {
			dolog("Failed to run script: %s", lua_tostring(L, -1));
		}
		lua_close(L);
	}
}

void runbbs(int socket, char *ip) {
	runbbs_real(socket, ip, 0);
}

void runbbs_ssh(char *ip) {
	struct sigaction si;
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
	si.sa_handler = sigint_handler;
	sigemptyset(&si.sa_mask);
	if (sigaction(SIGINT, &si, NULL) == -1) {
		dolog("Failed to setup sigint handler.");
		exit(1);
	}
	runbbs_real(-1, ip, 1);
}

int recursive_delete(const char *dir) {
	int ret = 0;
	FTS *ftsp = NULL;
	FTSENT *curr;

	char *files[] = {(char *)dir, NULL};

	ftsp = fts_open(files, FTS_NOCHDIR | FTS_PHYSICAL | FTS_XDEV, NULL);
	if (!ftsp) {
		dolog("%s: fts_open failed: %s", dir, strerror(errno));
		ret = -1;
		goto finish;
	}

	while ((curr = fts_read(ftsp))) {
		switch (curr->fts_info) {
			case FTS_NS:
			case FTS_DNR:
			case FTS_ERR:
				dolog("%s: fts_read error: %s", curr->fts_accpath, strerror(curr->fts_errno));
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
					dolog("%s: Failed to remove: %s", curr->fts_path, strerror(errno));
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

	while (1) {
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

char *str_replace(const char *str, const char *from, const char *to) {
	/* Adjust each of the below values to suit your needs. */

	/* Increment positions cache size initially by this number. */
	size_t cache_sz_inc = 16;
	/* Thereafter, each time capacity needs to be increased,
	 * multiply the increment by this factor. */
	const size_t cache_sz_inc_factor = 3;
	/* But never increment capacity by more than this number. */
	const size_t cache_sz_inc_max = 1048576;

	char *pret, *ret = NULL;
	const char *pstr2, *pstr = str;
	size_t i, count = 0;
	uintptr_t *pos_cache_tmp, *pos_cache = NULL;
	size_t cache_sz = 0;
	size_t cpylen, orglen, retlen, tolen, fromlen = strlen(from);

	/* Find all matches and cache their positions. */
	while ((pstr2 = strstr(pstr, from)) != NULL) {
		count++;

		/* Increase the cache size when necessary. */
		if (cache_sz < count) {
			cache_sz += cache_sz_inc;
			pos_cache_tmp = realloc(pos_cache, sizeof(*pos_cache) * cache_sz);
			if (pos_cache_tmp == NULL) {
				goto end_repl_str;
			} else
				pos_cache = pos_cache_tmp;
			cache_sz_inc *= cache_sz_inc_factor;
			if (cache_sz_inc > cache_sz_inc_max) {
				cache_sz_inc = cache_sz_inc_max;
			}
		}

		pos_cache[count - 1] = pstr2 - str;
		pstr = pstr2 + fromlen;
	}

	orglen = pstr - str + strlen(pstr);

	/* Allocate memory for the post-replacement string. */
	if (count > 0) {
		tolen = strlen(to);
		retlen = orglen + (tolen - fromlen) * count;
	} else
		retlen = orglen;
	ret = malloz(retlen + 1);
	if (ret == NULL) {
		goto end_repl_str;
	}

	if (count == 0) {
		/* If no matches, then just duplicate the string. */
		strlcpy(ret, str, retlen + 1);
	} else {
		/* Otherwise, duplicate the string whilst performing
		 * the replacements using the position cache. */
		pret = ret;
		memcpy(pret, str, pos_cache[0]);
		pret += pos_cache[0];
		for (i = 0; i < count; i++) {
			memcpy(pret, to, tolen);
			pret += tolen;
			pstr = str + pos_cache[i] + fromlen;
			cpylen = (i == count - 1 ? orglen : pos_cache[i + 1]) - pos_cache[i] - fromlen;
			memcpy(pret, pstr, cpylen);
			pret += cpylen;
		}
		ret[retlen] = '\0';
	}

end_repl_str:
	/* Free the cache and return the post-replacement string,
	 * which will be NULL in the event of an error. */
	free(pos_cache);
	return ret;
}
