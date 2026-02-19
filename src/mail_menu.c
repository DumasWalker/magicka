#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/file.h>
#include <fcntl.h>
#include <libgen.h>
#include <iconv.h>

#include "lua/lua.h"
#include "lua/lualib.h"
#include "lua/lauxlib.h"
#include "libuuid/uuid.h"

#include "bbs.h"
#include "mail_utils.h"
#include "msglib/msglib.h"

#ifdef __sun
#include "os/sunos.h"
#endif
extern struct bbs_config conf;
extern struct user_record *gUser;
extern int mynode;

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

unsigned long generate_msgid() {

	char buffer[1024];
	time_t unixtime;

	unsigned long msgid;
	unsigned long lastid;
	FILE *fptr;

	snprintf(buffer, 1024, "%s/msgserial", conf.bbs_path);

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
			dolog("Unable to open message id log");
		}
	}
	snprintf(buffer, sizeof buffer, "%lX", lastid);
	return strtoul(&buffer[strlen(buffer) - 8], NULL, 16);
}

char *external_editor(struct user_record *user, char *to, char *from, char *quote, int qlen, char *qfrom, char *subject, int email, int sig) {
	char c;
	FILE *fptr;
	char *body = NULL;
	char buffer[256];
	int len;
	int totlen;
	char *body2 = NULL;
	char *tagline;
	int i;
	int j;
	struct stat s;
	struct utsname name;
	char *ptr;

	if (conf.external_editor_cmd != NULL && user->exteditor != 0) {
		if (user->exteditor == 2) {
			s_printf(get_string(85));
			c = s_getc();
		} else {
			c = 'y';
		}
		if (tolower(c) == 'y') {
			snprintf(buffer, sizeof buffer, "%s/node%d", conf.bbs_path, mynode);
			if (stat(buffer, &s) != 0) {
				mkdir(buffer, 0755);
			}
			strlcat(buffer, "/MSGTMP", sizeof buffer);
			if (stat(buffer, &s) == 0) {
				remove(buffer);
			}


			// write msgtemp
			if (quote != NULL) {
				stralloc quote_salloc = EMPTY_STRALLOC;

				for (i = 0; i < qlen; i++) {
					if (quote[i] == 0x1) {
						continue;
					} else if (quote[i] == '\e' && quote[i + 1] == '[') {
						while (strchr("ABCDEFGHIGJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", quote[i]) == NULL)
							i++;
					} else if (quote[i] != '\n') {
						stralloc_append1(&quote_salloc, quote[i]);
					}
				}
				stralloc_0(&quote_salloc);
				fptr = fopen(buffer, "w");

				char initial2;

				if (strchr(qfrom, ' ') != NULL) {
					initial2 = *(strchr(qfrom, ' ') + 1);
				} else {
					initial2 = qfrom[1];
				}

				if (initial2 == '\0') {
					initial2 = qfrom[0];
				}

				ptr = wrap_quotes(quote_salloc.s, qfrom[0], initial2);

				for (i=0;i<strlen(ptr);i++) {
					fputc(ptr[i], fptr);
					if (ptr[i] == '\r') {
						fputc('\n', fptr);
					}
				}

				fclose(fptr);
				free(ptr);
			}
			snprintf(buffer, sizeof buffer, "%s/node%d/MSGINF", conf.bbs_path, mynode);
			fptr = fopen(buffer, "w");
			fprintf(fptr, "%s\r\n", user->loginname);
			if (qfrom != NULL) {
				fprintf(fptr, "%s\r\n", qfrom);
			} else {
				fprintf(fptr, "%s\r\n", to);
			}
			fprintf(fptr, "%s\r\n", subject);
			fprintf(fptr, "0\r\n");
			if (email == 1) {
				fprintf(fptr, "E-Mail\r\n");
				fprintf(fptr, "YES\r\n");
			} else {
				if (!sig) {
					struct mail_area *area = get_user_area(user);
					fprintf(fptr, "%s\r\n", area->name);
					if (area->type == TYPE_NETMAIL_AREA) {
						fprintf(fptr, "YES\r\n");
					} else {
						fprintf(fptr, "NO\r\n");
					}
				} else {
					fprintf(fptr, "None\r\n");
					fprintf(fptr, "NO\r\n");
				}
			}
			fclose(fptr);

			rundoor(user, conf.external_editor_cmd, conf.external_editor_stdio, conf.external_editor_codepage);

			// readin msgtmp
			snprintf(buffer, sizeof buffer, "%s/node%d/MSGTMP", conf.bbs_path, mynode);
			body = file2str(buffer);

			if (body == NULL) {
				return NULL;
			}

			totlen = strlen(body);

			if (email == 1) {
				tagline = conf.default_tagline;
			} else {
				tagline = conf.default_tagline;
				struct mail_conference *mc = get_user_conf(user);
				if (mc->tagline != NULL) {
					tagline = mc->tagline;
				}
			}

			if (!sig) {
				uname(&name);

				struct mail_conference *mc = get_user_conf(user);
				if (mc->nettype == NETWORK_FIDO && !email) {
					if (mc->fidoaddr->point == 0) {
						snprintf(buffer, sizeof buffer, "\r--- MagickaBBS v%d.%d%s (%s/%s)\r * Origin: %s (%d:%d/%d)\r",
						         VERSION_MAJOR, VERSION_MINOR, VERSION_STR, name.sysname, name.machine, tagline,
						         mc->fidoaddr->zone, mc->fidoaddr->net, mc->fidoaddr->node);
					} else {
						snprintf(buffer, sizeof buffer, "\r--- MagickaBBS v%d.%d%s (%s/%s)\r * Origin: %s (%d:%d/%d.%d)\r",
						         VERSION_MAJOR, VERSION_MINOR, VERSION_STR, name.sysname, name.machine, tagline,
						         mc->fidoaddr->zone, mc->fidoaddr->net, mc->fidoaddr->node, mc->fidoaddr->point);
					}
				} else if (mc->nettype == NETWORK_MAGI && !email) {
					snprintf(buffer, sizeof buffer, "\r--- MagickaBBS v%d.%d%s (%s/%s)\r * Origin: %s (@%d)\r",
					         VERSION_MAJOR, VERSION_MINOR, VERSION_STR, name.sysname, name.machine, tagline,
					         mc->maginode);
				} else if (mc->nettype == NETWORK_QWK && !email) {
					snprintf(buffer, sizeof buffer, "\r---\r * MagickaBBS * %s\r",
					         tagline);
				} else {
					snprintf(buffer, sizeof buffer, "\r");
				}
				if (user->autosig && user->signature != NULL) {
					body2 = (char *)malloz(totlen + 3 + strlen(buffer) + strlen(user->signature));
					totlen += strlen(buffer) + strlen(user->signature) + 3;
				} else {
					body2 = (char *)malloz(totlen + 2 + strlen(buffer));
					totlen += strlen(buffer) + 2;
				}
			} else {
				body2 = (char *)malloz(totlen + 1);
			}

			j = 0;
			for (i = 0; i < totlen; i++) {
				if (body[i] == '\n') {
					continue;
				} else if (body[i] == '\0') {
					break;
				}
				body2[j++] = body[i];
				body2[j] = '\0';
			}

			if (!sig) {
				if (user->autosig && user->signature != NULL) {
					strlcat(body2, "\r", totlen + 1);
					strlcat(body2, user->signature, totlen + 1);
				}
				strlcat(body2, buffer, totlen + 1);
			}

			free(body);

			return body2;
		}
	}
	return editor(user, quote, qlen, qfrom, email, sig);
}

char *editor(struct user_record *user, char *quote, int quotelen, char *from, int email, int sig) {
	char buffer[256];
	char linebuffer[80];
	int doquit = 0;
	int i;
	char *msg;
	int size = 0;
	int lineat = 0;
	int qfrom, qto;
	int z;
	char *tagline;
	struct utsname name;
	char next_line_buffer[80];
	struct ptr_vector content;
	struct ptr_vector quotecontent;
	int lines;
	char *quotecopy;
	char *wquote;
	memset(next_line_buffer, 0, 80);
	init_ptr_vector(&quotecontent);
	init_ptr_vector(&content);

	if (quote != NULL) {
		char initial2;

		if (strchr(from, ' ') != NULL) {
			initial2 = *(strchr(from, ' ') + 1);
		} else {
			initial2 = from[1];
		}

		if (initial2 == '\0') {
			initial2 = from[0];
		}

		quotecopy = malloz(quotelen + 1);

		for (i=0;i<quotelen;i++) {
			if (quote[i] == 27) {
				while (strchr("ABCDEFGHIGJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", quote[i]) == NULL)
					i++;
				continue;
			}
			quotecopy[lineat++] = quote[i];
			quotecopy[lineat] = '\0';
		}

		wquote = wrap_quotes(quotecopy, from[0], initial2);
		lineat = 0;

		for (i = 0; i < strlen(wquote); i++) {
			if (wquote[i] == '\r' || lineat == 72) {
				ptr_vector_append(&quotecontent, strdup(linebuffer));
				lineat = 0;
				linebuffer[0] = '\0';
				if (wquote[i] != '\r') {
					i--;
				}
			} else {
				linebuffer[lineat++] = wquote[i];
				linebuffer[lineat] = '\0';
			}
		}
		free(wquote);
	}

	s_printf(get_string(86));
	s_printf(get_string(87));

	while (!doquit) {
		s_printf(get_string(88), ptr_vector_len(&content), "");
		strlcpy(linebuffer, next_line_buffer, sizeof(linebuffer));
		s_readstring_inject(linebuffer, 70, next_line_buffer);
		memset(next_line_buffer, 0, 70);

		if (strlen(linebuffer) == 70 && linebuffer[69] != ' ') {
			for (i = strlen(linebuffer) - 1; i > 15; i--) {
				if (linebuffer[i] == ' ') {
					linebuffer[i] = '\0';
					strlcpy(next_line_buffer, &linebuffer[i + 1], sizeof next_line_buffer);
					s_printf("\e[%dD\e[0K", 70 - i);
					break;
				}
			}
		}

		if (linebuffer[0] == '/' && strlen(linebuffer) == 2) {
			if (toupper(linebuffer[1]) == 'S') {
				for (i = 0; i < ptr_vector_len(&content); i++) {
					size += strlen(ptr_vector_get(&content, i)) + 1;
				}
				size++;

				tagline = conf.default_tagline;
				struct mail_conference *mc = get_user_conf(user);
				if (mc->tagline != NULL) {
					tagline = mc->tagline;
				}
				if (!sig) {
					uname(&name);
					if (mc->nettype == NETWORK_FIDO && !email) {
						if (mc->fidoaddr->point == 0) {
							snprintf(buffer, sizeof buffer,
							         "\r--- MagickaBBS v%d.%d%s (%s/%s)\r * Origin: %s (%d:%d/%d)\r",
							         VERSION_MAJOR, VERSION_MINOR, VERSION_STR, name.sysname, name.machine, tagline,
							         mc->fidoaddr->zone, mc->fidoaddr->net, mc->fidoaddr->node);
						} else {
							snprintf(buffer, sizeof buffer,
							         "\r--- MagickaBBS v%d.%d%s (%s/%s)\r * Origin: %s (%d:%d/%d.%d)\r",
							         VERSION_MAJOR, VERSION_MINOR, VERSION_STR, name.sysname, name.machine, tagline,
							         mc->fidoaddr->zone, mc->fidoaddr->net, mc->fidoaddr->node, mc->fidoaddr->point);
						}
					} else if (mc->nettype == NETWORK_MAGI && !email) {
						snprintf(buffer, sizeof buffer,
						         "\r--- MagickaBBS v%d.%d%s (%s/%s)\r * Origin: %s (@%d)\r",
						         VERSION_MAJOR, VERSION_MINOR, VERSION_STR, name.sysname, name.machine, tagline,
						         mc->maginode);
					} else if (mc->nettype == NETWORK_QWK && !email) {
						snprintf(buffer, sizeof buffer, "\r---\r * MagickaBBS * %s\r",
						         tagline);
					} else {
						strlcpy(buffer, "\r", sizeof buffer);
					}
					if (user->autosig && user->signature != NULL) {
						size += 3;
						size += strlen(buffer) + strlen(user->signature);
					} else {
						size += 2;
						size += strlen(buffer);
					}
				} else {
					size += 1;
				}

				msg = (char *)malloz(size);
				for (i = 0; i < ptr_vector_len(&content); i++) {
					strlcat(msg, ptr_vector_get(&content, i), size);
					strlcat(msg, "\r", size);
				}
				ptr_vector_apply(&content, free);
				destroy_ptr_vector(&content);

				if (!sig) {
					if (user->autosig && user->signature != NULL) {
						strlcat(msg, "\r", size);
						strlcat(msg, user->signature, size);
					}
					strlcat(msg, buffer, size);
				}

				if (quote != NULL) {
					ptr_vector_apply(&quotecontent, free);
					destroy_ptr_vector(&quotecontent);
				}
				return msg;
			} else if (toupper(linebuffer[1]) == 'A') {
				ptr_vector_apply(&content, free);
				destroy_ptr_vector(&content);
				if (quote != NULL) {
					ptr_vector_apply(&quotecontent, free);
					destroy_ptr_vector(&quotecontent);
				}
				return NULL;
			} else if (toupper(linebuffer[1]) == 'Q') {
				if (quote == NULL) {
					s_printf(get_string(89));
				} else {

					s_printf("\r\n");
					lines = 0;
					for (i = 0; i < ptr_vector_len(&quotecontent); i++) {
						s_printf(get_string(88), i, ptr_vector_get(&quotecontent, i));
						lines ++;
						if (lines == 22) {
							lines = 0;
							s_printf("\r\n");
							s_printf(get_string(185));
							s_getchar();
							s_printf("\r\n");
						}
					}

					s_printf(get_string(90));
					s_readstring(buffer, 5);
					qfrom = atoi(buffer);
					s_printf(get_string(91));
					s_readstring(buffer, 5);
					qto = atoi(buffer);
					s_printf("\r\n");

					if (qto > ptr_vector_len(&quotecontent)) {
						qto = ptr_vector_len(&quotecontent);
					}
					if (qfrom < 0) {
						qfrom = 0;
					}
					if (qfrom > qto) {
						s_printf(get_string(92));
					}

					for (i = qfrom; i <= qto; i++) {
						char *copy = strdup(ptr_vector_get(&quotecontent, i));
						ptr_vector_append(&content, copy);
					}

					s_printf(get_string(86));
					s_printf(get_string(87));

					for (i = 0; i < ptr_vector_len(&content); i++) {
						s_printf(get_string(88), i, ptr_vector_get(&content, i));
					}
				}
			} else if (toupper(linebuffer[1]) == 'L') {
				s_printf(get_string(86));
				s_printf(get_string(87));

				for (i = 0; i < ptr_vector_len(&content); i++) {
					s_printf(get_string(88), i, ptr_vector_get(&content, i));
				}
			} else if (linebuffer[1] == '?') {
				s_printf(get_string(93));
				s_printf(get_string(94));
				s_printf(get_string(95));
				s_printf(get_string(96));
				s_printf(get_string(97));
				s_printf(get_string(98));
				s_printf(get_string(99));
				s_printf(get_string(100));
			} else if (toupper(linebuffer[1]) == 'D') {
				s_printf(get_string(101));
				s_readstring(buffer, 6);
				if (strlen(buffer) == 0) {
					s_printf(get_string(39));
				} else {
					z = atoi(buffer);
					if (z < 0 || z >= ptr_vector_len(&content)) {
						s_printf(get_string(39));
					} else {
						free(ptr_vector_del(&content, i));
					}
				}
			} else if (toupper(linebuffer[1]) == 'E') {
				s_printf(get_string(102));
				s_readstring(buffer, 6);
				if (strlen(buffer) == 0) {
					s_printf(get_string(39));
				} else {
					z = atoi(buffer);
					if (z < 0 || z >= ptr_vector_len(&content)) {
						s_printf(get_string(39));
					} else {
						s_printf(get_string(88), z, ptr_vector_get(&content, z));
						s_printf(get_string(103), z);
						s_readstring(linebuffer, 70);
						free(ptr_vector_get(&content, z));
						ptr_vector_put(&content, strdup(linebuffer), z);
					}
				}
			} else if (toupper(linebuffer[1]) == 'I') {
				s_printf(get_string(104));
				s_readstring(buffer, 6);
				if (strlen(buffer) == 0) {
					s_printf(get_string(39));
				} else {
					z = atoi(buffer);
					if (z < 0 || z >= ptr_vector_len(&content)) {
						s_printf(get_string(39));
					} else {
						s_printf(get_string(103), z);
						s_readstring(linebuffer, 70);
						ptr_vector_ins(&content, strdup(linebuffer), z);
					}
				}
			}
		} else {
			ptr_vector_append(&content, strdup(linebuffer));
		}
	}
	if (quote != NULL) {
		ptr_vector_apply(&quotecontent, free);
		destroy_ptr_vector(&quotecontent);
	}
	return NULL;
}

struct character_t {
	char c;
	int fg;
	int bg;
};

void unmangle_ansi(char *body, int len, char **body_out, int *body_len, int dopipe) {
	// count lines
	int line_count = 1;
	int line_at = 1;
	int char_at = 1;
	int fg = 0x07;
	int bg = 0x00;
	int state = 0;
	int save_char_at = 0;
	int save_line_at = 0;
	int params[16];
	int param_count = 0;
	int bold = 0;
	stralloc out = EMPTY_STRALLOC;
	char buffer[1024];
	int buf_at;
	int i, j, k, v = 0;  //add v
	struct character_t ***fake_screen;
	int ansi;
	int tab;
	int pipec;
	int quote = 0;
	int last_space = 0;

/*	char quote_buf[6]; */
	char quote_buf[16] = {0};

	line_at = 1;
	char_at = 1;

	for (i = 0; i < len; i++) {

		if (state == 0) {
			if (body[i] == 27) {
				state = 1;
				continue;
/*			} else if (body[i] == '|' && dopipe == 1) { */
                        } else if (body[i] == '|' && dopipe == 1 && (i + 1 < len)) {
				if (body[i + 1] == '|') {
					i++;
					char_at++;
					while (char_at > 80) {
						line_at++;
						char_at -= 80;
					}
					continue;
				} else {
					i += 2;
					continue;
				}
			} else {
				if (body[i] == '\r') {
					char_at = 1;
					last_space = 0;
					line_at++;
					quote = 0;
				} else if (body[i] == '\t') {
					char_at += 8;
					while (char_at > 80) {
						line_at++;
						char_at -= 80;
					}
				} else {
/*					if (body[i] == '>' && char_at < 5) {
						quote = 1;
						int v = 0;
						for (int d = i - (char_at - 1); d <= i;d++) {
							quote_buf[v++] = body[d];
							quote_buf[v] = '\0';
						}
					} */
                                        if (body[i] == '>' && char_at > 0 && char_at < 10) { // Limit to reasonable attribution length
					    quote = 1;
					    v = 0;
    
					    // 1. Calculate safe start point: ensure d is never < 0
					    int start_pos = i - (char_at - 1);
					    if (start_pos < 0) start_pos = 0;

					    // 2. Clear buffer before use (COBOL style: MOVE SPACES/NULLS TO BUFFER)
						    memset(quote_buf, 0, sizeof(quote_buf));

					    // 3. Bound the copy to 15 chars (leaving 1 for the null terminator)
					    for (int d = start_pos; d <= i && v < 15; d++) {
						        quote_buf[v++] = body[d];
					    }
					    quote_buf[v] = '\0'; // Guaranteed null termination
					}

					if ((unsigned char)body[i] == 0x8d || body[i] == ' ') last_space = i;
					char_at++;
					if ((quote < 2 && char_at > 80) || (quote == 2 && char_at > 80 - (strlen(quote_buf) + 2))) {
						if (quote == 1) quote = 2;
						line_at++;
/*						if (last_space != 0) {
							char_at = (i - last_space + (quote * (strlen(quote_buf) + 2))); */
                                                if (last_space != 0 && i >= last_space) {
						        char_at = (i - last_space + (quote * (v + 2))); // Use 'v' instead of strlen()
						} else {
							char_at = 1;
						}
						last_space = 0;
					}
				}

				if (line_at > line_count) {
					line_count = line_at;
				}
			}
		} else if (state == 1) {
			if (body[i] == '[') {
				state = 2;
				continue;
			} else {
				state = 0;
				continue;
			}
		} else if (state == 2) {
			param_count = 0;
			for (j = 0; j < 16; j++) {
				params[j] = 0;
			}
			state = 3;
		}
		if (state == 3) {
			if (body[i] == ';') {
				if (param_count < 15) {
					param_count++;
				}
				continue;
			} else if (body[i] >= '0' && body[i] <= '9') {
				if (!param_count) param_count = 1;
				params[param_count - 1] = params[param_count - 1] * 10 + (body[i] - '0');
				continue;
			} else {
				state = 4;
			}
		}

		if (state == 4) {
			switch (body[i]) {
				case 'H':
				case 'f':
					if (params[0]) params[0]--;
					if (params[1]) params[1]--;
					line_at = params[0] + 1;
					char_at = params[1] + 1;

					if (char_at > 80) {
						char_at = 80;
					}

					if (line_at > line_count) {
						line_count = line_at;
					}

					state = 0;
					break;
				case 'A':
					if (param_count > 0) {
						line_at = line_at - params[0];
					} else {
						line_at--;
					}
					if (line_at < 1) {
						line_at = 1;
					}
					state = 0;
					break;
				case 'B':
					if (param_count > 0) {
						line_at = line_at + params[0];
					} else {
						line_at++;
					}
					if (line_at > line_count) {
						line_count = line_at;
					}
					state = 0;
					break;
				case 'C':
					if (param_count > 0) {
						char_at = char_at + params[0];
					} else {
						char_at++;
					}
					if (char_at > 80) {
						char_at = 80;
					}
					state = 0;
					break;
				case 'D':
					if (param_count > 0) {
						char_at = char_at - params[0];
					} else {
						char_at--;
					}
					if (char_at < 1) {
						char_at = 1;
					}
					state = 0;
					break;
				case 's':
					save_char_at = char_at;
					save_line_at = line_at;
					state = 0;
					break;
				case 'u':
					char_at = save_char_at;
					line_at = save_line_at;
					state = 0;
					break;
				default:
					state = 0;
					break;
			}
		}
	}

	fake_screen = (struct character_t ***)malloz(sizeof(struct character_t **) * line_count);
	for (i = 0; i < line_count; i++) {
		fake_screen[i] = (struct character_t **)malloz(sizeof(struct character_t *) * 80);
		for (j = 0; j < 80; j++) {
			fake_screen[i][j] = (struct character_t *)malloz(sizeof(struct character_t));
			fake_screen[i][j]->c = ' ';
			fake_screen[i][j]->fg = fg;
			fake_screen[i][j]->bg = bg;
		}
	}

	line_at = 1;
	char_at = 1;
	last_space = 0;
	quote = 0;
	for (i = 0; i < len; i++) {

		if (state == 0) {
			if (body[i] == 27) {
				state = 1;
				continue;
			} else if (body[i] == '>' && char_at < 5) {
				quote = 1;
				int v = 0;
				for (int d = i - (char_at - 1); d <= i;d++) {
					quote_buf[v++] = body[d];
					quote_buf[v] = '\0';
				}
				for (int h = 0; h < char_at; h++) {
					fake_screen[line_at - 1][h]->fg = conf.msg_quote_fg;
					fake_screen[line_at - 1][h]->bg = conf.msg_quote_bg;
				}
				fake_screen[line_at - 1][char_at - 1]->c = '>';
				char_at++;
			} else if (body[i] == '|' && dopipe == 1) {
				if (body[i + 1] == '|') {
					i++;
					if (line_at > line_count) line_at = line_count;
					fake_screen[line_at - 1][char_at - 1]->c = body[i];
					if (quote == 0) {
						fake_screen[line_at - 1][char_at - 1]->fg = fg;
						fake_screen[line_at - 1][char_at - 1]->bg = bg;
					} else {
						fake_screen[line_at - 1][char_at - 1]->fg = conf.msg_quote_fg;
						fake_screen[line_at - 1][char_at - 1]->bg = conf.msg_quote_bg;
					}
					char_at++;
					if (char_at > 80) {
						quote = 0;
						line_at++;
						char_at = 1;
						last_space = 0;
					}
				} else {
					if (body[i + 1] >= '0' && body[i + 1] <= '9' && body[i + 2] >= '0' && body[i + 2] <= '9') {
						pipec = ((body[i + 1] - '0') * 10) + (body[i + 2] - '0');
						i += 2;
						switch (pipec) {
							case 0:
								fg = 0x00;
								break;
							case 1:
								fg = 0x01; //D_BLUE;
								break;
							case 2:
								fg = 0x02; //D_GREEN;
								break;
							case 3:
								fg = 0x03; //D_CYAN
								break;
							case 4:
								fg = 0x04; //D_RED
								break;
							case 5:
								fg = 0x05; //D_MAGENTA
								break;
							case 6:
								fg = 0x06; //D_YELLOW
								break;
							case 7:
								fg = 0x07; //D_WHITE
								break;
							case 8:
								fg = 0x08; //B_BLACK
								break;
							case 9:
								fg = 0x09; //B_BLUE
								break;
							case 10:
								fg = 0x0A; //B_GREEN
								break;
							case 11:
								fg = 0x0B; //B_CYAN
								break;
							case 12:
								fg = 0x0C; //B_RED;
								break;
							case 13:
								fg = 0x0D; //B_MAGENTA;
								break;
							case 14:
								fg = 0x0E; //B_YELLOW;
								break;
							case 15:
								fg = 0x0F; //B_WHITE;
								break;
							case 16:
								bg = 0x00; //D_BLACK
								break;
							case 17:
								bg = 0x01; //D_BLUE
								break;
							case 18:
								bg = 0x02; // D_GREEN
								break;
							case 19:
								bg = 0x03; // D_CYAN
								break;
							case 20:
								bg = 0x04; // D_RED
								break;
							case 21:
								bg = 0x05; // D_MAGENTA
								break;
							case 22:
								bg = 0x06; // D_YELLOW
								break;
							case 23:
								bg = 0x07; // D_WHITE
								break;
						}
					} else {
						continue;
					}
				}
			} else {
				if (body[i] == '\r') {
					char_at = 1;
					last_space = 0;
					line_at++;
					quote = 0;
				} else if (body[i] == '\t') {
					for (tab = 0; tab < 8; tab++) {
						if (line_at > line_count) line_at = line_count;
						fake_screen[line_at - 1][char_at - 1]->c = ' ';
						if (quote == 0) {
							fake_screen[line_at - 1][char_at - 1]->fg = fg;
							fake_screen[line_at - 1][char_at - 1]->bg = bg;
						} else {
							fake_screen[line_at - 1][char_at - 1]->fg = conf.msg_quote_fg;
							fake_screen[line_at - 1][char_at - 1]->bg = conf.msg_quote_bg;
						}
						char_at++;
						if (char_at > 80) {
							quote = 0;
							line_at++;
							char_at = 1;
							last_space = 0;
						}
					}
				} else {
					if (body[i] == ' ' || (unsigned char)body[i] == 0x8d) last_space = char_at;
					if (line_at > line_count) line_at = line_count;
					fake_screen[line_at - 1][char_at - 1]->c = body[i];
					if (quote == 0) {
						fake_screen[line_at - 1][char_at - 1]->fg = fg;
						fake_screen[line_at - 1][char_at - 1]->bg = bg;
					} else {
						fake_screen[line_at - 1][char_at - 1]->fg = conf.msg_quote_fg;
						fake_screen[line_at - 1][char_at - 1]->bg = conf.msg_quote_bg;
					}
					char_at++;
					if (char_at > 80) {
						line_at++;
						char_at = 1;
						if (last_space != 0) {
							if (quote == 1) {
								for (int d = 0; d < strlen(quote_buf); d++) {
									fake_screen[line_at - 1][char_at - 1]->c = quote_buf[d];
									fake_screen[line_at - 1][char_at - 1]->fg = conf.msg_quote_fg;
									fake_screen[line_at - 1][char_at - 1]->bg = conf.msg_quote_bg;
									char_at++;
									if (char_at > 80) {
										line_at++;
										char_at = 1;
									}
								}
								fake_screen[line_at - 1][char_at - 1]->c = ' ';
								fake_screen[line_at - 1][char_at - 1]->fg = conf.msg_quote_fg;
								fake_screen[line_at - 1][char_at - 1]->bg = conf.msg_quote_bg;
								char_at++;
								if (char_at > 80) {
									line_at++;
									char_at = 1;
								}
								for (int d = last_space + 1; d <= 80; d++) {
									fake_screen[line_at - 1][char_at - 1]->c = fake_screen[line_at - 2][d - 1]->c;
									fake_screen[line_at - 1][char_at - 1]->fg = conf.msg_quote_fg;
									fake_screen[line_at - 1][char_at - 1]->bg = conf.msg_quote_bg;
									fake_screen[line_at - 2][d - 1]->c = ' ';
									char_at++;
									if (char_at > 80) {
										line_at++;
										char_at = 1;
									}
								}
							} else {
								for (int d = last_space + 1; d <= 80; d++) {
									fake_screen[line_at - 1][char_at - 1]->c = fake_screen[line_at - 2][d - 1]->c;
									fake_screen[line_at - 1][char_at - 1]->fg = fake_screen[line_at - 2][d - 1]->fg;
									fake_screen[line_at - 1][char_at - 1]->bg = fake_screen[line_at - 2][d - 1]->bg;
									fake_screen[line_at - 2][d - 1]->c = ' ';
									char_at++;
									if (char_at > 80) {
										line_at++;
										char_at = 1;
									}
								}
							}
						} else {
							char_at = 1;
						}
						last_space = 0;
					}
				}
			}
		} else if (state == 1) {
			if (body[i] == '[') {
				state = 2;
				continue;
			} else {
				state = 0;
				continue;
			}
		} else if (state == 2) {
			param_count = 0;
			for (j = 0; j < 16; j++) {
				params[j] = 0;
			}
			state = 3;
		}
		if (state == 3) {
			if (body[i] == ';') {
				if (param_count < 15) {
					param_count++;
				}
				continue;
			} else if (body[i] >= '0' && body[i] <= '9') {
				if (!param_count) param_count = 1;
				params[param_count - 1] = params[param_count - 1] * 10 + (body[i] - '0');
				continue;
			} else {
				state = 4;
			}
		}

		if (state == 4) {
			switch (body[i]) {
				case 'H':
				case 'f':
					if (params[0]) params[0]--;
					if (params[1]) params[1]--;
					line_at = params[0] + 1;
					char_at = params[1] + 1;
					state = 0;
					break;
				case 'A':
					if (param_count > 0) {
						line_at = line_at - params[0];
					} else {
						line_at--;
					}
					if (line_at < 1) {
						line_at = 1;
					}
					state = 0;
					break;
				case 'B':
					if (param_count > 0) {
						line_at = line_at + params[0];
					} else {
						line_at++;
					}
					if (line_at > line_count) {
						line_at = line_count;
					}
					state = 0;
					break;
				case 'C':
					if (param_count > 0) {
						char_at = char_at + params[0];
					} else {
						char_at++;
					}
					if (char_at > 80) {
						char_at = 80;
					}
					state = 0;
					break;
				case 'D':
					if (param_count > 0) {
						char_at = char_at - params[0];
					} else {
						char_at--;
					}
					if (char_at < 1) {
						char_at = 1;
					}
					state = 0;
					break;
				case 's':
					save_char_at = char_at;
					save_line_at = line_at;
					state = 0;
					break;
				case 'u':
					char_at = save_char_at;
					line_at = save_line_at;
					state = 0;
					break;
				case 'm':
					for (j = 0; j < param_count; j++) {
						switch (params[j]) {
							case 0:
								fg = 0x07;
								bg = 0x00;
								bold = 0;
								break;
							case 1:
								bold = 1;
								if (fg < 0x08) {
									fg += 0x08;
								}
								break;
							case 2:
								bold = 0;
								if (fg > 0x07) {
									fg -= 0x08;
								}
								break;
							case 30:
								if (bold) {
									fg = 0x08;
								} else {
									fg = 0x00;
								}
								break;
							case 31:
								if (bold) {
									fg = 0x0C;
								} else {
									fg = 0x04;
								}
								break;
							case 32:
								if (bold) {
									fg = 0x0A;
								} else {
									fg = 0x02;
								}
								break;
							case 33:
								if (bold) {
									fg = 0x0E;
								} else {
									fg = 0x06;
								}
								break;
							case 34:
								if (bold) {
									fg = 0x09;
								} else {
									fg = 0x01;
								}
								break;
							case 35:
								if (bold) {
									fg = 0x0D;
								} else {
									fg = 0x05;
								}
								break;
							case 36:
								if (bold) {
									fg = 0x0B;
								} else {
									fg = 0x03;
								}
								break;
							case 37:
								if (bold) {
									fg = 0x0F;
								} else {
									fg = 0x07;
								}
								break;
							case 40:
								bg = 0x00;
								break;
							case 41:
								bg = 0x04;
								break;
							case 42:
								bg = 0x02;
								break;
							case 43:
								bg = 0x06;
								break;
							case 44:
								bg = 0x01;
								break;
							case 45:
								bg = 0x05;
								break;
							case 46:
								bg = 0x03;
								break;
							case 47:
								bg = 0x07;
								break;
						}
					}
					state = 0;
					break;
				case 'K':
					if (params[0] == 0) {
						for (k = char_at - 1; k < 80; k++) {
							fake_screen[line_at - 1][k]->c = ' ';
							fake_screen[line_at - 1][k]->fg = fg;
							fake_screen[line_at - 1][k]->bg = bg;
						}
					} else if (params[0] == 1) {
						for (k = 0; k < char_at; k++) {
							fake_screen[line_at - 1][k]->c = ' ';
							fake_screen[line_at - 1][k]->fg = fg;
							fake_screen[line_at - 1][k]->bg = bg;
						}
					} else if (params[0] == 2) {
						for (k = 0; k < 80; k++) {
							fake_screen[line_at - 1][k]->c = ' ';
							fake_screen[line_at - 1][k]->fg = fg;
							fake_screen[line_at - 1][k]->bg = bg;
						}
					}
					state = 0;
					break;
				case 'J':
					if (params[0] == 0) {
						for (k = char_at - 1; k < 80; k++) {
							fake_screen[line_at - 1][k]->c = ' ';
							fake_screen[line_at - 1][k]->fg = fg;
							fake_screen[line_at - 1][k]->bg = bg;
						}

						for (k = line_at; k < line_count; k++) {
							for (j = 0; j < 80; j++) {
								fake_screen[k][j]->c = ' ';
								fake_screen[k][j]->fg = fg;
								fake_screen[k][j]->bg = bg;
							}
						}
					} else if (params[0] == 1) {
						for (k = 0; k < char_at; k++) {
							fake_screen[line_at - 1][k]->c = ' ';
							fake_screen[line_at - 1][k]->fg = fg;
							fake_screen[line_at - 1][k]->bg = bg;
						}

						for (k = line_at - 2; k >= 0; k--) {
							for (j = 0; j < 80; j++) {
								fake_screen[k][j]->c = ' ';
								fake_screen[k][j]->fg = fg;
								fake_screen[k][j]->bg = bg;
							}
						}
					} else if (params[0] == 2) {
						for (k = 0; k < line_count; k++) {
							for (j = 0; j < 80; j++) {
								fake_screen[k][j]->c = ' ';
								fake_screen[k][j]->fg = fg;
								fake_screen[k][j]->bg = bg;
							}
						}
					}
					state = 0;
					break;
				default:
					// bad ansi
					state = 0;
					break;
			}
		}
	}

	for (i = line_count - 1; i > line_count - 5 && i >= 0; i--) {
		if (fake_screen[i][0]->c == '-' && fake_screen[i][1]->c == '-' && fake_screen[i][2]->c == '-') {
			for (int h = i; h < line_count; h++) {
				for (j = 0; j < 80; j++) {
					fake_screen[h][j]->fg = conf.msg_tag_fg;
					fake_screen[h][j]->bg = conf.msg_tag_bg;
				}
			}

			break;
		}
	}

	fg = 0x07;
	bg = 0x00;
	int z;
	for (i = 0; i < line_count; i++) {
		buf_at = 0;
		z = 0;
		for (j = 0; j < 80; j++) {
			if (fake_screen[i][j]->fg != fg || fake_screen[i][j]->bg != bg) {
				buffer[buf_at++] = 27;
				buffer[buf_at++] = '[';
				fg = fake_screen[i][j]->fg;
				if (fg < 0x08) {
					buffer[buf_at++] = '0';
					buffer[buf_at++] = ';';
					buffer[buf_at++] = '3';
					switch (fg) {
						case 0x00:
							buffer[buf_at++] = '0';
							break;
						case 0x04:
							buffer[buf_at++] = '1';
							break;
						case 0x02:
							buffer[buf_at++] = '2';
							break;
						case 0x06:
							buffer[buf_at++] = '3';
							break;
						case 0x01:
							buffer[buf_at++] = '4';
							break;
						case 0x05:
							buffer[buf_at++] = '5';
							break;
						case 0x03:
							buffer[buf_at++] = '6';
							break;
						case 0x07:
							buffer[buf_at++] = '7';
							break;
					}
				} else {
					buffer[buf_at++] = '1';
					buffer[buf_at++] = ';';
					buffer[buf_at++] = '3';
					switch (fg) {
						case 0x08:
							buffer[buf_at++] = '0';
							break;
						case 0x0C:
							buffer[buf_at++] = '1';
							break;
						case 0x0A:
							buffer[buf_at++] = '2';
							break;
						case 0x0E:
							buffer[buf_at++] = '3';
							break;
						case 0x09:
							buffer[buf_at++] = '4';
							break;
						case 0x0D:
							buffer[buf_at++] = '5';
							break;
						case 0x0B:
							buffer[buf_at++] = '6';
							break;
						case 0x0F:
							buffer[buf_at++] = '7';
							break;
					}
				}

				bg = fake_screen[i][j]->bg;
				buffer[buf_at++] = ';';
				buffer[buf_at++] = '4';
				switch (bg) {
					case 0x00:
						buffer[buf_at++] = '0';
						break;
					case 0x04:
						buffer[buf_at++] = '1';
						break;
					case 0x02:
						buffer[buf_at++] = '2';
						break;
					case 0x06:
						buffer[buf_at++] = '3';
						break;
					case 0x01:
						buffer[buf_at++] = '4';
						break;
					case 0x05:
						buffer[buf_at++] = '5';
						break;
					case 0x03:
						buffer[buf_at++] = '6';
						break;
					case 0x07:
						buffer[buf_at++] = '7';
						break;
				}
				buffer[buf_at++] = 'm';
			}
			if ((unsigned char)fake_screen[i][j]->c == 0x8d) {
				buffer[buf_at++] = ' ';
			} else {
				buffer[buf_at++] = fake_screen[i][j]->c;
			}
			z++;
		}
		while (buf_at > 0 && buffer[buf_at - 1] == ' ') {
			z--;
			buf_at--;
		}

		buffer[buf_at++] = '\r';
		stralloc_catb(&out, buffer, buf_at);
	}

	for (i = 0; i < line_count; i++) {
		for (j = 0; j < 80; j++) {
			free(fake_screen[i][j]);
		}
		free(fake_screen[i]);
	}
	free(fake_screen);

	while (out.s[out.len - 2] == '\r') {
		out.len--;
	}

	*body_out = out.s;
	*body_len = out.len;
}

int read_message(struct user_record *user, struct msg_headers *msghs, int mailno, int newscan) {
	struct msg_base_t *mb;

	char buffer[256];
	int z, z2;
	struct tm msg_date;
	int last_read;
	int high_read;

	char *subject = NULL;
	char *from = NULL;
	char *to = NULL;
	char *body = NULL;
	char *body2 = NULL;
	int lines = 0;
	char c;
	char *replybody;
	struct fido_addr *from_addr = NULL;
	int i, j;
	int doquit = 0;
	int skip_line = 0;
	int chars = 0;
	int ansi;
	int sem_fd;
	int start_line;
	int should_break;
	int position;
	int y;
	int view_seenbys = 0;
	struct ptr_vector msg_lines;
	iconv_t ic;

	init_ptr_vector(&msg_lines);

	struct mail_area *ma = get_user_area(user);
	mb = open_message_base(user->cur_mail_conf, user->cur_mail_area);
	if (!mb) {
		dolog("Error opening message base.. %s", ma->path);
		return 0;
	}

	while (doquit == 0) {
		if (get_message_lastread(mb, user->id) == -1) {
			high_read = get_message_number(msghs, mailno);
		}

		last_read = get_message_number(msghs, mailno);
		high_read = get_message_highread(mb, user->id);
		if (high_read < get_message_number(msghs, mailno)) {
			high_read = get_message_number(msghs, mailno);
		}

		struct mail_conference *mc = get_user_conf(user);
		if (msghs->msgs[mailno]->oaddress != NULL && mc->nettype == NETWORK_FIDO) {
			from_addr = parse_fido_addr(msghs->msgs[mailno]->oaddress);
			char *from_site = nl_get_bbsname(from_addr, mc->domain);
			s_printf(get_string(105), msghs->msgs[mailno]->from, from_addr->zone, from_addr->net, from_addr->node, from_addr->point, from_site);
			free(from_addr);
			free(from_site);
		} else if (msghs->msgs[mailno]->oaddress != NULL && mc->nettype == NETWORK_MAGI) {
			s_printf(get_string(288), msghs->msgs[mailno]->from, atoi(msghs->msgs[mailno]->oaddress));
		} else if (msghs->msgs[mailno]->oaddress != NULL && mc->nettype == NETWORK_QWK) {
			s_printf(get_string(289), msghs->msgs[mailno]->from, msghs->msgs[mailno]->oaddress);
		} else {
			s_printf(get_string(106), msghs->msgs[mailno]->from);
		}
		struct mail_area *ma = get_user_area(user);
		if (msghs->msgs[mailno]->daddress != NULL && mc->nettype == NETWORK_FIDO && ma->type == TYPE_NETMAIL_AREA) {
			from_addr = parse_fido_addr(msghs->msgs[mailno]->daddress);
			char *from_site = nl_get_bbsname(from_addr, mc->domain);
			s_printf(get_string(321), msghs->msgs[mailno]->to, from_addr->zone, from_addr->net, from_addr->node, from_addr->point, from_site);
			free(from_addr);
			free(from_site);
		} else {
			s_printf(get_string(107), msghs->msgs[mailno]->to);
		}
		s_printf(get_string(108), msghs->msgs[mailno]->subject);
		gmtime_r((time_t *)&msghs->msgs[mailno]->msgwritten, &msg_date);
		snprintf(buffer, sizeof buffer, "%s", asctime(&msg_date));
		buffer[strlen(buffer) - 1] = '\0';
		int offhour = msghs->msgs[mailno]->tz_offset / 3600;
		int offmin = (msghs->msgs[mailno]->tz_offset % 3600) / 60;

		s_printf(get_string(109), buffer, (offhour < 0 ? '-' : '+'), abs(offhour), offmin);
		s_printf(get_string(110), (get_message_issent(msghs, mailno) ? "SENT" : ""),
		         (msgbase_is_flagged(user, user->cur_mail_conf, user->cur_mail_area, get_message_number(msghs, mailno)) ? "FLAGGED" : ""), mailno + 1, msghs->msg_count);
		s_printf(get_string(111));

		body = load_message_text(mb, msghs->msgs[mailno]);

		if (msghs->msgs[mailno]->isutf8) {
			// convert body to cp437
			// 1. Measure and Allocate
			size_t body_len = strlen(body);
			body2 = malloz(body_len + 1);
		/*	body2 = malloz(len + 1); */
			// 2. Open the converter
			ic = iconv_open("CP437//TRANSLIT", "UTF-8");
			// 3. Check for valid handle (using the cast to avoid the warning)
                        if (ic != (iconv_t)-1) {
		/*	size_t inc = strlen(body);
			size_t ouc = strlen(body); */
                  	      	size_t inc = body_len;
                  	      	size_t ouc = body_len; 

			      	char *inbuf = body;
			      	char *oubuf = body2;

/*			if (ic != -1) {  */
			if (ic != (iconv_t)-1) {
				if (iconv(ic, &inbuf, &inc, &oubuf, &ouc) == -1) {
					strcpy(oubuf, inbuf);
				}
				free(body);
				body = body2;
				iconv_close(ic); 
                      // Perform the conversion
/*		              	iconv(ic, &in_ptr, &inc, &out_ptr, &ouc);
			        iconv_close(ic);
		     // Use the converted body
				free(body);
			        body = body2;  */
			} else {
				free(body2);
			}
		} }

		if (!newscan) {
			write_lasthighread(mb, user, last_read, high_read);
		}

		if (view_seenbys == 1 && msghs->msgs[mailno]->seenby != NULL) {
			stralloc body_salloc = EMPTY_STRALLOC;
			stralloc_cats(&body_salloc, "\e[1;30m");
			stralloc_cats(&body_salloc, msghs->msgs[mailno]->seenby);
			stralloc_cats(&body_salloc, "\e[0m");
			stralloc_cats(&body_salloc, body);
			stralloc_0(&body_salloc);
			free(body);
			body = body_salloc.s;
		}

		z2 = strlen(body);

		lines = 0;
		chars = 0;

		body2 = body;
		z = z2;

		unmangle_ansi(body2, z, &body, &z2, user->dopipe);
		free(body2);
		start_line = 0;

		// count the number of lines...
		for (z = 0; z < z2; z++) {
			if (body[z] == '\r' || chars == 80) {
				char *msg_line = (char *)malloz(z - start_line + 1);
				ptr_vector_append(&msg_lines, msg_line);
				if (z == start_line) {
					msg_line[0] = '\0';
				} else {
					strlcpy(msg_line, &body[start_line], z - start_line + 1);
					msg_line[z - start_line] = '\0';
				}
				if (body[z] == '\r') {
					start_line = z + 1;
				} else {
					start_line = z;
				}
				chars = 0;
			} else {
				if (body[z] == 27) {
					ansi = z;
					while (strchr("ABCDEFGHIGJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", body[z]) == NULL)
						z++;
					if (body[z] == 'm') {
						// do nothing
					} else {
						y = ansi;
						for (j = z + 1; j < z2; j++) {
							body[y] = body[j];
							y++;
						}
						z2 = z2 - (z2 - y);
						z = ansi - 1;
					}
				} else {
					chars++;
				}
			}
		}

		lines = 0;

		position = 0;
		should_break = 0;

		while (!should_break) {
			s_printf("\e[7;1H");
			for (z = position; z < ptr_vector_len(&msg_lines); z++) {
				s_printf("\e[%d;1H%s\e[K\r\n", z - position + 7, ptr_vector_get(&msg_lines, z));
				if (z - position >= 15) {
					break;
				}
			}

			if (position + 16 >= ptr_vector_len(&msg_lines)) {
				s_printf(get_string(187), 100);
			} else {
				s_printf(get_string(187), (int)((float)(position + 16) / (float)ptr_vector_len(&msg_lines) * 100.));
			}
			if (newscan) {
				int mcle = (strlen(mc->name) > 18 ? 18 : strlen(mc->name));
				int male = (strlen(ma->name) > 18 ? 18 : strlen(ma->name));
				s_printf(get_string(234), mcle, mc->name, male, ma->name);
			} else {
				int mcle = (strlen(mc->name) > 24 ? 24 : strlen(mc->name));
				int male = (strlen(ma->name) > 24 ? 24 : strlen(ma->name));
				s_printf(get_string(186), mcle, mc->name, male, ma->name);
			}
			c = s_getc();

			if (tolower(c) == 'r') {
				should_break = 1;
			} else if (tolower(c) == 'q') {
				should_break = 1;
			} else if (tolower(c) == 'j' && newscan == 1) {
				should_break = 1;
			} else if (tolower(c) == 'f') {
				should_break = 1;
			} else if (tolower(c) == 'v') {
				view_seenbys = !view_seenbys;
				should_break = 1;
			} else if (c == '}' || c == ']') {
				// next reply
				c = '}';
				should_break = 1;
			} else if (c == '{' || c == '[') {
				// prev reply
				c = '{';
				should_break = 1;
			} else if (c == '+') {
				// up reply
				should_break = 1;
			} else if (c == '-') {
				// down reply
				should_break = 1;
			} else if (c == '?') {
				should_break = 1;
			} else if (c == '\e') {
				c = s_getc();
				if (c == 91) {
					c = s_getc();
					if (c == 65) {
						position--;
						if (position < 0) {
							position = 0;
						}
					} else if (c == 66) {
						position++;
						if (position + 15 >= ptr_vector_len(&msg_lines)) {
							position--;
						}
					} else if (c == 67) {
						c = ' ';
						should_break = 1;
					} else if (c == 68) {
						c = 'b';
						should_break = 1;
					} else if (c == 86 || c == '5') {
						if (c == '5') {
							s_getchar();
						}
						// PAGE UP
						position = position - 15;
						if (position < 0) {
							position = 0;
						}
					} else if (c == 85 || c == '6') {
						if (c == '6') {
							s_getchar();
						}
						// PAGE DOWN
						position = position + 15;
						while (position + 15 >= ptr_vector_len(&msg_lines)) {
							position--;
						}
					}
				}
			}
		}

		if (tolower(c) == 'r') {
			close_message_base(mb);
			mb = NULL;
			struct mail_area *ma = get_user_area(user);
			if (!check_security(user, ma->write_sec_level, &ma->wr_req_flags, &ma->wr_not_flags)) {
				s_printf(get_string(113));
				mb = open_message_base(user->cur_mail_area, user->cur_mail_conf);
			} else {
				const char *old_subject = msghs->msgs[mailno]->subject;
				if (old_subject != NULL) {
					*buffer = '\0';
					if (strncasecmp(old_subject, "RE:", 3) != 0)
						strlcpy(buffer, "RE: ", sizeof buffer);
					strlcat(buffer, old_subject, sizeof buffer);
				}
				subject = strdup(buffer);

				s_printf(get_string(114));
				s_readstring_inject(buffer, 32, msghs->msgs[mailno]->from);
				to = strdup(buffer);
				if (ma->type == TYPE_LOCAL_AREA && (strcasecmp(to, "all") != 0 && (check_user(to) || check_fullname_j(to)))) {
					s_printf(get_string(55));
					free(body);
					free(subject);
					free(to);
					ptr_vector_apply(&msg_lines, free);
					destroy_ptr_vector(&msg_lines);
					return 0;
				}
				s_printf(get_string(115));
				s_readstring_inject(buffer, 64, subject);
				free(subject);
				subject = strdup(buffer);

				s_printf("\r\n");

				if (msghs->msgs[mailno]->from != NULL) {
					strlcpy(buffer, msghs->msgs[mailno]->from, sizeof buffer);
				}
				//struct mail_conference *mc = get_user_conf(user);
				if (ma->realnames == 0) {
					from = strdup(user->loginname);
				} else {
					from = str3dup(user->firstname, " ", user->lastname);
				}
				if (ma->type == TYPE_NEWSGROUP_AREA) {
					free(to);
					to = strdup("ALL");
				}
				replybody = external_editor(user, to, from, body, z2, msghs->msgs[mailno]->from, subject, 0, 0);
				if (replybody != NULL) {
					mb = open_message_base(user->cur_mail_conf, user->cur_mail_area);
					if (!mb) {
						dolog("Error opening message base.. %s", ma->path);
						free(replybody);
						free(body);
						free(subject);
						free(to);
						free(from);
						ptr_vector_apply(&msg_lines, free);
						destroy_ptr_vector(&msg_lines);
						return 0;
					}

					if (!write_message(mb, to, from, subject, replybody, msghs->msgs[mailno]->oaddress, msghs->msgs[mailno], NULL, 1)) {
						free(replybody);
						free(body);
						free(subject);
						free(to);
						free(from);
						ptr_vector_apply(&msg_lines, free);
						destroy_ptr_vector(&msg_lines);
						close_message_base(mb);
						return 0;
					}

					// JAM_CloseMB(jb);
					// doquit = 1;
				} else {
					mb = open_message_base(user->cur_mail_conf, user->cur_mail_area);
				}
				free(from);
				free(to);
				free(subject);
			}
			free(body);
		} else if (tolower(c) == 'j' && newscan == 1) {
			free(body);
			doquit = 1;
		} else if (tolower(c) == 'q') {
			free(body);
			doquit = 2;
		} else if (c == ' ') {
			mailno++;
			if (mailno >= msghs->msg_count) {
				s_printf(get_string(118));
				doquit = 1;
			}
			free(body);
		} else if (c == '}') {
			mailno = get_next_reply(msghs, mailno);
			free(body);
		} else if (c == '{') {
			mailno = get_prev_reply(msghs, mailno);
			free(body);
		} else if (c == '+') {
			mailno = get_down_reply(msghs, mailno);
			free(body);
		} else if (c == '-') {
			mailno = get_up_reply(msghs, mailno);
			free(body);
		} else if (c == '?') {
			s_printf("\e[2J\e[1;1H");
			s_displayansi("msghelp");
			s_printf(get_string(185));
			c = s_getchar();
			free(body);
		} else if (tolower(c) == 'b') {
			if (mailno > 0) {
				mailno--;
			}
			free(body);
		} else if (tolower(c) == 'f') {
			msgbase_flag_unflag(user, user->cur_mail_conf, user->cur_mail_area, get_message_number(msghs, mailno));
			free(body);
		} else {
			free(body);
		}
		ptr_vector_apply(&msg_lines, free);
		destroy_ptr_vector(&msg_lines);
	}

	if (mb != NULL)
		close_message_base(mb);

	if (doquit == 2) {
		return 1;
	}

	return 0;
}

int read_new_msgs(struct user_record *user, struct msg_headers *msghs) {
	struct msg_base_t *mb;
	int all_unread;
	int i;
	int k;
	char buffer[7];
	int res;
	int highmsg;

	// list mail in message base
	if (msghs != NULL && msghs->msg_count > 0) {
		struct mail_area *ma = get_user_area(user);
		mb = open_message_base(user->cur_mail_conf, user->cur_mail_area);
		if (!mb) {
			dolog("Error opening JAM base.. %s", ma->path);
			return 0;
		} else {
			all_unread = 0;

			highmsg = get_message_highread(mb, user->id);

			if (highmsg <= 0) {
				highmsg = 0;
				all_unread = 1;
			}
			close_message_base(mb);

			if (all_unread == 0) {
				k = highmsg;
				for (i = msghs->msg_count - 1; i >= 0; i--) {
					if (get_message_number(msghs, i) <= k) {
						i += 2;
						break;
					}
				}

			} else {
				i = 1;
			}

			if (i > 0 && i <= msghs->msg_count) {
				res = read_message(user, msghs, i - 1, 1);
				s_printf("\r\n");
				return res;
			}
		}
	}
	return 0;
}

void read_mail(struct user_record *user) {
	struct msg_headers *msghs;
	struct msg_base_t *mb;
	int all_unread;
	int i;
	int k;
	char buffer[7];
	int high_read;

	s_printf("\r\n");
	// list mail in message base
	msghs = read_message_headers(user->cur_mail_conf, user->cur_mail_area, user, 0);
	if (msghs == NULL)
		return;
	if (msghs->msg_count <= 0) {
		free_message_headers(msghs);
		return;
	}
	struct mail_area *ma = get_user_area(user);
	mb = open_message_base(user->cur_mail_conf, user->cur_mail_area);
	if (!mb) {
		dolog("Error opening message base.. %s", ma->path);
		return;
	}
	all_unread = 0;

	high_read = get_message_highread(mb, user->id);

	if (high_read == -1) {
		high_read = 0;
		all_unread = 1;
	} else if (high_read == 0) {
		all_unread = 1;
	}

	close_message_base(mb);

	s_printf(get_string(120), msghs->msg_count);

	s_readstring(buffer, 6);

	if (tolower(buffer[0]) == 'n') {
		if (all_unread == 0) {
			k = high_read;
			for (i = 0; i < msghs->msg_count; i++) {
				if (get_message_number(msghs, i) == k) {
					break;
				}
			}
			i += 2;
		} else {
			i = 1;
		}
	} else {
		i = atoi(buffer);
	}

	if (i > 0 && i <= msghs->msg_count) {
		read_message(user, msghs, i - 1, 0);
	}
	if (msghs != NULL) {
		free_message_headers(msghs);
	}
}

void post_message(struct user_record *user) {
	char *subject;
	char *from;
	char *to;
	char *msg;
	int closed;
	struct fido_addr *from_addr = NULL;
	char buffer[256];
	char buffer2[256];
	char qwkuuid[38];
	int z;
	int sem_fd;
	char *bbsname;
	uuid_t magi_msgid;
	uuid_t qwk_msgid;
	struct msg_base_t *mb;

	struct mail_area *ma = get_user_area(user);
	if (!check_security(user, ma->write_sec_level, &ma->wr_req_flags, &ma->wr_not_flags)) {
		s_printf(get_string(113));
		return;
	}
	if (ma->type == TYPE_NEWSGROUP_AREA) {
		strlcpy(buffer, "ALL", sizeof buffer);
	} else {
		s_printf(get_string(54));
		s_readstring(buffer, 32);
	}
	if (strlen(buffer) == 0) {
		strlcpy(buffer, "ALL", sizeof(buffer));
	}

	if (ma->type == TYPE_LOCAL_AREA && (strcasecmp(buffer, "all") != 0 && check_user(buffer) && check_fullname_j(buffer))) {
		s_printf(get_string(55));
		return;
	}

	if (ma->type == TYPE_NETMAIL_AREA) {
		s_printf(get_string(121));
		s_readstring(buffer2, 32);
		struct mail_conference *mc = get_user_conf(user);
		if (mc->nettype == NETWORK_FIDO) {
			from_addr = parse_fido_addr(buffer2);
			if (!from_addr) {
				s_printf(get_string(122));
				return;
			} else {
				if (from_addr->zone == 0 && from_addr->net == 0 && from_addr->node == 0 && from_addr->point == 0) {
					free(from_addr);
					s_printf(get_string(122));
					return;
				}

				if (mc->domain != NULL) {
					bbsname = nl_get_bbsname(from_addr, mc->domain);
				} else {
					bbsname = strdup("Unknown");
				}
				s_printf(get_string(123), from_addr->zone, from_addr->net, from_addr->node, from_addr->point, bbsname);

				free(bbsname);
			}
		}
	}
	to = strdup(buffer);
	s_printf(get_string(56));
	s_readstring(buffer, 25);
	if (strlen(buffer) == 0) {
		s_printf(get_string(39));
		free(to);
		if (from_addr != NULL) {
			free(from_addr);
		}
		return;
	}
	subject = strdup(buffer);

	// post a message
	//struct mail_conference *mc = get_user_conf(user);
	if (ma->realnames == 0) {
		from = strdup(user->loginname);
	} else {
		from = str3dup(user->firstname, " ", user->lastname);
	}
	msg = external_editor(user, to, from, NULL, 0, NULL, subject, 0, 0);

	if (msg != NULL) {
		mb = open_message_base(user->cur_mail_conf, user->cur_mail_area);

		if (!mb) {
			dolog("Error opening message base.. %s", ma->path);
			free(msg);
			free(to);
			free(subject);
			free(from);
			return;
		}

		if (from_addr != NULL) {
			snprintf(buffer, sizeof buffer, "%d:%d/%d.%d", from_addr->zone, from_addr->net, from_addr->node, from_addr->point);
		}

		if (!write_message(mb, to, from, subject, msg, (from_addr != NULL ? buffer : NULL), NULL, NULL, 1)) {
			dolog("Failed to write message!");
		}
		close_message_base(mb);
		free(msg);
	}
	free(from_addr);
	free(to);
	free(from);
	free(subject);
}

void list_messages(struct user_record *user) {
	struct msg_headers *msghs;
	struct msg_base_t *mb;
	int all_unread;
	char buffer[256];
	int i;
	int k;
	int j;
	int start;
	int closed;
	int redraw;
	struct tm msg_date;
	char c;
	int offset = 2;
	int height = 22;
	int high_read;
	int msg_jump = 0;

	struct mail_conference *mc = get_user_conf(user);

	if (mc->header != NULL) {
		offset = 8;
		height = 16;
	}

	s_printf("\r\n");
	// list mail in message base
	msghs = read_message_headers(user->cur_mail_conf, user->cur_mail_area, user, 0);
	if (msghs != NULL && msghs->msg_count > 0) {
		struct mail_area *ma = get_user_area(user);
		mb = open_message_base(user->cur_mail_conf, user->cur_mail_area);
		if (!mb) {
			dolog("Error opening JAM base.. %s", ma->path);
			return;
		} else {
			all_unread = 0;
			high_read = get_message_highread(mb, user->id);

			if (high_read == -1) {
				high_read = 0;
				all_unread = 1;
			} else if (high_read == 0) {
				all_unread = 1;
			}
			close_message_base(mb);

			s_printf(get_string(125), msghs->msg_count);

			s_readstring(buffer, 6);
			if (tolower(buffer[0]) == 'n') {
				if (all_unread == 0) {
					k = high_read;
					for (i = 0; i < msghs->msg_count; i++) {
						if (get_message_number(msghs, i) == k) {
							break;
						}
					}
					if (i == msghs->msg_count - 1) {
						i = 1;
					} else {
						i += 2;
					}

				} else {
					i = 1;
				}
			} else {
				i = atoi(buffer);
				if (i <= 0) {
					i = 1;
				}
			}
			closed = 0;

			redraw = 1;
			start = i - 1;
			while (!closed) {
				if (redraw) {
					if (mc->header != NULL) {
						s_printf("\e[2J\e[1;1H");
						s_displayansi(mc->header);
						s_printf("\e[7;1H");
					} else {
						s_printf("\e[2J\e[1;1H");
					}
					s_printf(get_string(126));
					for (j = start; j < start + height && j < msghs->msg_count; j++) {

						gmtime_r((time_t *)&msghs->msgs[j]->msgwritten, &msg_date);
						if (j == i - 1) {
							if (msgbase_is_flagged(user, user->cur_mail_conf, user->cur_mail_area, get_message_number(msghs, j))) {
								if (conf.date_style == 1) {
									s_printf(get_string(286), j + 1, msghs->msgs[j]->subject, msghs->msgs[j]->from, msghs->msgs[j]->to, msg_date.tm_hour, msg_date.tm_min, msg_date.tm_mon + 1, msg_date.tm_mday, msg_date.tm_year - 100);
								} else {
									s_printf(get_string(286), j + 1, msghs->msgs[j]->subject, msghs->msgs[j]->from, msghs->msgs[j]->to, msg_date.tm_hour, msg_date.tm_min, msg_date.tm_mday, msg_date.tm_mon + 1, msg_date.tm_year - 100);
								}
							} else if (get_message_number(msghs, j) > high_read || all_unread) {
								if (conf.date_style == 1) {
									s_printf(get_string(188), j + 1, msghs->msgs[j]->subject, msghs->msgs[j]->from, msghs->msgs[j]->to, msg_date.tm_hour, msg_date.tm_min, msg_date.tm_mon + 1, msg_date.tm_mday, msg_date.tm_year - 100);
								} else {
									s_printf(get_string(188), j + 1, msghs->msgs[j]->subject, msghs->msgs[j]->from, msghs->msgs[j]->to, msg_date.tm_hour, msg_date.tm_min, msg_date.tm_mday, msg_date.tm_mon + 1, msg_date.tm_year - 100);
								}
							} else {
								if (conf.date_style == 1) {
									s_printf(get_string(189), j + 1, msghs->msgs[j]->subject, msghs->msgs[j]->from, msghs->msgs[j]->to, msg_date.tm_hour, msg_date.tm_min, msg_date.tm_mon + 1, msg_date.tm_mday, msg_date.tm_year - 100);
								} else {
									s_printf(get_string(189), j + 1, msghs->msgs[j]->subject, msghs->msgs[j]->from, msghs->msgs[j]->to, msg_date.tm_hour, msg_date.tm_min, msg_date.tm_mday, msg_date.tm_mon + 1, msg_date.tm_year - 100);
								}
							}
						} else {
							if (msgbase_is_flagged(user, user->cur_mail_conf, user->cur_mail_area, get_message_number(msghs, j))) {
								if (conf.date_style == 1) {
									s_printf(get_string(287), j + 1, msghs->msgs[j]->subject, msghs->msgs[j]->from, msghs->msgs[j]->to, msg_date.tm_hour, msg_date.tm_min, msg_date.tm_mon + 1, msg_date.tm_mday, msg_date.tm_year - 100);
								} else {
									s_printf(get_string(287), j + 1, msghs->msgs[j]->subject, msghs->msgs[j]->from, msghs->msgs[j]->to, msg_date.tm_hour, msg_date.tm_min, msg_date.tm_mday, msg_date.tm_mon + 1, msg_date.tm_year - 100);
								}
							} else if (get_message_number(msghs, j) > high_read || all_unread) {
								if (conf.date_style == 1) {
									s_printf(get_string(127), j + 1, msghs->msgs[j]->subject, msghs->msgs[j]->from, msghs->msgs[j]->to, msg_date.tm_hour, msg_date.tm_min, msg_date.tm_mon + 1, msg_date.tm_mday, msg_date.tm_year - 100);
								} else {
									s_printf(get_string(127), j + 1, msghs->msgs[j]->subject, msghs->msgs[j]->from, msghs->msgs[j]->to, msg_date.tm_hour, msg_date.tm_min, msg_date.tm_mday, msg_date.tm_mon + 1, msg_date.tm_year - 100);
								}
							} else {
								if (conf.date_style == 1) {
									s_printf(get_string(128), j + 1, msghs->msgs[j]->subject, msghs->msgs[j]->from, msghs->msgs[j]->to, msg_date.tm_hour, msg_date.tm_min, msg_date.tm_mon + 1, msg_date.tm_mday, msg_date.tm_year - 100);
								} else {
									s_printf(get_string(128), j + 1, msghs->msgs[j]->subject, msghs->msgs[j]->from, msghs->msgs[j]->to, msg_date.tm_hour, msg_date.tm_min, msg_date.tm_mday, msg_date.tm_mon + 1, msg_date.tm_year - 100);
								}
							}
						}
					}
					s_printf(get_string(190));
					s_printf("\e[%d;5H", i - start + offset - 1);
					redraw = 0;
				}
				c = s_getchar();
				if (tolower(c) == 'q') {
					closed = 1;
				} else if (c == 27) {
					c = s_getchar();
					if (c == 91) {
						c = s_getchar();
						if (c == 66) {
							msg_jump = 0;
							// down
							i++;
							if (i > start + height) {
								start += height;
								if (start > msghs->msg_count) {
									start = msghs->msg_count - height;
								}
								redraw = 1;
							}
							if (i - 1 == msghs->msg_count) {
								i--;
								s_printf("\e[%d;5H", i - start + offset - 1);
							} else if (!redraw) {
								s_printf("\e[%d;1H", i - start + offset - 2);
								gmtime_r((time_t *)&msghs->msgs[i - 2]->msgwritten, &msg_date);
								if (msgbase_is_flagged(user, user->cur_mail_conf, user->cur_mail_area, get_message_number(msghs, i - 2))) {
									if (conf.date_style == 1) {
										s_printf(get_string(287), i - 1, msghs->msgs[i - 2]->subject, msghs->msgs[i - 2]->from, msghs->msgs[i - 2]->to, msg_date.tm_hour, msg_date.tm_min, msg_date.tm_mon + 1, msg_date.tm_mday, msg_date.tm_year - 100);
									} else {
										s_printf(get_string(287), i - 1, msghs->msgs[i - 2]->subject, msghs->msgs[i - 2]->from, msghs->msgs[i - 2]->to, msg_date.tm_hour, msg_date.tm_min, msg_date.tm_mday, msg_date.tm_mon + 1, msg_date.tm_year - 100);
									}
								} else if (get_message_number(msghs, i - 2) > high_read || all_unread) {
									if (conf.date_style == 1) {
										s_printf(get_string(127), i - 1, msghs->msgs[i - 2]->subject, msghs->msgs[i - 2]->from, msghs->msgs[i - 2]->to, msg_date.tm_hour, msg_date.tm_min, msg_date.tm_mon + 1, msg_date.tm_mday, msg_date.tm_year - 100);
									} else {
										s_printf(get_string(127), i - 1, msghs->msgs[i - 2]->subject, msghs->msgs[i - 2]->from, msghs->msgs[i - 2]->to, msg_date.tm_hour, msg_date.tm_min, msg_date.tm_mday, msg_date.tm_mon + 1, msg_date.tm_year - 100);
									}
								} else {
									if (conf.date_style == 1) {
										s_printf(get_string(128), i - 1, msghs->msgs[i - 2]->subject, msghs->msgs[i - 2]->from, msghs->msgs[i - 2]->to, msg_date.tm_hour, msg_date.tm_min, msg_date.tm_mon + 1, msg_date.tm_mday, msg_date.tm_year - 100);
									} else {
										s_printf(get_string(128), i - 1, msghs->msgs[i - 2]->subject, msghs->msgs[i - 2]->from, msghs->msgs[i - 2]->to, msg_date.tm_hour, msg_date.tm_min, msg_date.tm_mday, msg_date.tm_mon + 1, msg_date.tm_year - 100);
									}
								}
								s_printf("\e[%d;1H", i - start + offset - 1);
								gmtime_r((time_t *)&msghs->msgs[i - 1]->msgwritten, &msg_date);
								if (msgbase_is_flagged(user, user->cur_mail_conf, user->cur_mail_area, get_message_number(msghs, i - 1))) {
									if (conf.date_style == 1) {
										s_printf(get_string(286), i, msghs->msgs[i - 1]->subject, msghs->msgs[i - 1]->from, msghs->msgs[i - 1]->to, msg_date.tm_hour, msg_date.tm_min, msg_date.tm_mon + 1, msg_date.tm_mday, msg_date.tm_year - 100);
									} else {
										s_printf(get_string(286), i, msghs->msgs[i - 1]->subject, msghs->msgs[i - 1]->from, msghs->msgs[i - 1]->to, msg_date.tm_hour, msg_date.tm_min, msg_date.tm_mday, msg_date.tm_mon + 1, msg_date.tm_year - 100);
									}
								} else if (get_message_number(msghs, i - 1) > high_read || all_unread) {
									if (conf.date_style == 1) {
										s_printf(get_string(188), i, msghs->msgs[i - 1]->subject, msghs->msgs[i - 1]->from, msghs->msgs[i - 1]->to, msg_date.tm_hour, msg_date.tm_min, msg_date.tm_mon + 1, msg_date.tm_mday, msg_date.tm_year - 100);
									} else {
										s_printf(get_string(188), i, msghs->msgs[i - 1]->subject, msghs->msgs[i - 1]->from, msghs->msgs[i - 1]->to, msg_date.tm_hour, msg_date.tm_min, msg_date.tm_mday, msg_date.tm_mon + 1, msg_date.tm_year - 100);
									}
								} else {
									if (conf.date_style == 1) {
										s_printf(get_string(189), i, msghs->msgs[i - 1]->subject, msghs->msgs[i - 1]->from, msghs->msgs[i - 1]->to, msg_date.tm_hour, msg_date.tm_min, msg_date.tm_mon + 1, msg_date.tm_mday, msg_date.tm_year - 100);
									} else {
										s_printf(get_string(189), i, msghs->msgs[i - 1]->subject, msghs->msgs[i - 1]->from, msghs->msgs[i - 1]->to, msg_date.tm_hour, msg_date.tm_min, msg_date.tm_mday, msg_date.tm_mon + 1, msg_date.tm_year - 100);
									}
								}
								s_printf("\e[%d;5H", i - start + offset - 1);
							}
						} else if (c == 65) {
							// up
							msg_jump = 0;
							i--;
							if (i - 1 < start) {
								start -= height;
								if (start < 0) {
									start = 0;
								}
								redraw = 1;
							}
							if (i <= 1) {
								start = 0;
								i = 1;
								redraw = 1;
							} else if (!redraw) {
								s_printf("\e[%d;1H", i - start + offset);
								gmtime_r((time_t *)&msghs->msgs[i]->msgwritten, &msg_date);
								if (msgbase_is_flagged(user, user->cur_mail_conf, user->cur_mail_area, get_message_number(msghs, i))) {
									if (conf.date_style == 1) {
										s_printf(get_string(287), i + 1, msghs->msgs[i]->subject, msghs->msgs[i]->from, msghs->msgs[i]->to, msg_date.tm_hour, msg_date.tm_min, msg_date.tm_mon + 1, msg_date.tm_mday, msg_date.tm_year - 100);
									} else {
										s_printf(get_string(287), i + 1, msghs->msgs[i]->subject, msghs->msgs[i]->from, msghs->msgs[i]->to, msg_date.tm_hour, msg_date.tm_min, msg_date.tm_mday, msg_date.tm_mon + 1, msg_date.tm_year - 100);
									}
								} else if (get_message_number(msghs, i) > high_read || all_unread) {
									if (conf.date_style == 1) {
										s_printf(get_string(127), i + 1, msghs->msgs[i]->subject, msghs->msgs[i]->from, msghs->msgs[i]->to, msg_date.tm_hour, msg_date.tm_min, msg_date.tm_mon + 1, msg_date.tm_mday, msg_date.tm_year - 100);
									} else {
										s_printf(get_string(127), i + 1, msghs->msgs[i]->subject, msghs->msgs[i]->from, msghs->msgs[i]->to, msg_date.tm_hour, msg_date.tm_min, msg_date.tm_mday, msg_date.tm_mon + 1, msg_date.tm_year - 100);
									}
								} else {
									if (conf.date_style == 1) {
										s_printf(get_string(128), i + 1, msghs->msgs[i]->subject, msghs->msgs[i]->from, msghs->msgs[i]->to, msg_date.tm_hour, msg_date.tm_min, msg_date.tm_mon + 1, msg_date.tm_mday, msg_date.tm_year - 100);
									} else {
										s_printf(get_string(128), i + 1, msghs->msgs[i]->subject, msghs->msgs[i]->from, msghs->msgs[i]->to, msg_date.tm_hour, msg_date.tm_min, msg_date.tm_mday, msg_date.tm_mon + 1, msg_date.tm_year - 100);
									}
								}
								s_printf("\e[%d;1H", i - start + offset - 1);
								gmtime_r((time_t *)&msghs->msgs[i - 1]->msgwritten, &msg_date);
								if (msgbase_is_flagged(user, user->cur_mail_conf, user->cur_mail_area, get_message_number(msghs, i - 1))) {
									if (conf.date_style == 1) {
										s_printf(get_string(286), i, msghs->msgs[i - 1]->subject, msghs->msgs[i - 1]->from, msghs->msgs[i - 1]->to, msg_date.tm_hour, msg_date.tm_min, msg_date.tm_mon + 1, msg_date.tm_mday, msg_date.tm_year - 100);
									} else {
										s_printf(get_string(286), i, msghs->msgs[i - 1]->subject, msghs->msgs[i - 1]->from, msghs->msgs[i - 1]->to, msg_date.tm_hour, msg_date.tm_min, msg_date.tm_mday, msg_date.tm_mon + 1, msg_date.tm_year - 100);
									}
								} else if (get_message_number(msghs, i - 1) > high_read || all_unread) {
									if (conf.date_style == 1) {
										s_printf(get_string(188), i, msghs->msgs[i - 1]->subject, msghs->msgs[i - 1]->from, msghs->msgs[i - 1]->to, msg_date.tm_hour, msg_date.tm_min, msg_date.tm_mon + 1, msg_date.tm_mday, msg_date.tm_year - 100);
									} else {
										s_printf(get_string(188), i, msghs->msgs[i - 1]->subject, msghs->msgs[i - 1]->from, msghs->msgs[i - 1]->to, msg_date.tm_hour, msg_date.tm_min, msg_date.tm_mday, msg_date.tm_mon + 1, msg_date.tm_year - 100);
									}
								} else {
									if (conf.date_style == 1) {
										s_printf(get_string(189), i, msghs->msgs[i - 1]->subject, msghs->msgs[i - 1]->from, msghs->msgs[i - 1]->to, msg_date.tm_hour, msg_date.tm_min, msg_date.tm_mon + 1, msg_date.tm_mday, msg_date.tm_year - 100);
									} else {
										s_printf(get_string(189), i, msghs->msgs[i - 1]->subject, msghs->msgs[i - 1]->from, msghs->msgs[i - 1]->to, msg_date.tm_hour, msg_date.tm_min, msg_date.tm_mday, msg_date.tm_mon + 1, msg_date.tm_year - 100);
									}
								}
								s_printf("\e[%d;5H", i - start + offset - 1);
							}
						} else if (c == 75) {
							// END KEY
							msg_jump = 0;
							i = msghs->msg_count;
							start = i - height;
							if (start < 0) {
								start = 0;
							}
							redraw = 1;
						} else if (c == 72) {
							// HOME KEY
							msg_jump = 0;
							i = 1;
							start = 0;
							redraw = 1;
						} else if (c == 86 || c == '5') {
							if (c == '5') {
								s_getchar();
							}
							// PAGE UP
							msg_jump = 0;
							i = i - height;
							if (i <= 0) {
								i = 1;
							}
							start = i - 1;
							redraw = 1;
						} else if (c == 85 || c == '6') {
							if (c == '6') {
								s_getchar();
							}
							// PAGE DOWN
							msg_jump = 0;
							i = i + height;
							if (i > msghs->msg_count) {
								i = msghs->msg_count;
							}
							start = i - 1;
							redraw = 1;
						}
					}
				} else if (c == 13) {
					msg_jump = 0;
					redraw = 1;
					read_message(user, msghs, i - 1, 0);
					free_message_headers(msghs);
					msghs = read_message_headers(user->cur_mail_conf, user->cur_mail_area, user, 0);
					struct mail_area *ma = get_user_area(user);
					mb = open_message_base(user->cur_mail_conf, user->cur_mail_area);
					if (!mb) {
						dolog("Error opening message base.. %s", ma->path);
						if (msghs != NULL) {
							free_message_headers(msghs);
						}
						return;
					} else {
						all_unread = 0;
						high_read = get_message_highread(mb, user->id);

						if (high_read == -1) {
							high_read = 0;
							all_unread = 1;
						}
						close_message_base(mb);
					}
				} else if (tolower(c) == 'f') {
					msg_jump = 0;
					redraw = 1;
					msgbase_flag_unflag(user, user->cur_mail_conf, user->cur_mail_area, get_message_number(msghs, i - 1));
				} else if (c >= '0' || c <= '9') {
					msg_jump = msg_jump * 10 + (c - '0');
					i = msg_jump;
					if (i > msghs->msg_count) {
						i = msghs->msg_count;
					}
					if (i < 1) {
						i = 1;
					}
					start = i - 1;
					redraw = 1;
				}
			}
		}

		if (msghs != NULL) {
			free_message_headers(msghs);
		}
	} else {
		s_printf(get_string(130));
	}
}

struct conf_tmp_t {
	struct mail_conference *conference;
	int index;
};

int choose_conference() {
	int i;
	int list_tmp = 0;
	struct conf_tmp_t **conf_tmp;
	int redraw = 1;
	int start = 0;
	int selected = 0;
	char c;
	struct ptr_vector vec;
	int conf_jump = 0;
	int ret = gUser->cur_mail_conf;

	init_ptr_vector(&vec);
	for (i = 0; i < ptr_vector_len(&conf.mail_conferences); ++i) {
		struct mail_conference *mc = ptr_vector_get(&conf.mail_conferences, i);
		if (check_security(gUser, mc->sec_level, &mc->vis_req_flags, &mc->vis_not_flags)) {
			struct conf_tmp_t *c = (struct conf_tmp_t *)malloz(sizeof(struct conf_tmp_t));
			c->conference = mc;
			c->index = i;
			ptr_vector_append(&vec, c);
		}
	}
	list_tmp = ptr_vector_len(&vec);
	conf_tmp = (struct conf_tmp_t **)consume_ptr_vector(&vec);

	while (1) {
		if (redraw) {
			s_printf("\e[2J\e[1;1H");
			s_printf(get_string(247));
			s_printf(get_string(248));
			for (i = start; i < start + 22 && i < list_tmp; i++) {
				if (i == selected) {
					s_printf(get_string(249), i - start + 2, conf_tmp[i]->index, conf_tmp[i]->conference->name);
				} else {
					s_printf(get_string(250), i - start + 2, conf_tmp[i]->index, conf_tmp[i]->conference->name);
				}
			}
			s_printf("\e[%d;5H", selected - start + 2);
			redraw = 0;
		}
		c = s_getchar();
		if (tolower(c) == 'q') {
			break;
		} else if (c == 27) {
			c = s_getchar();
			if (c == 91) {
				c = s_getchar();
				if (c == 66) {
					// down
					conf_jump = 0;
					if (selected + 1 >= start + 22) {
						start += 22;
						if (start >= list_tmp) {
							start = list_tmp - 22;
						}
						redraw = 1;
					}
					selected++;
					if (selected >= list_tmp) {
						selected = list_tmp - 1;
					} else {
						if (!redraw) {
							s_printf(get_string(250), selected - start + 1, conf_tmp[selected - 1]->index, conf_tmp[selected - 1]->conference->name);
							s_printf(get_string(249), selected - start + 2, conf_tmp[selected]->index, conf_tmp[selected]->conference->name);
							s_printf("\e[%d;5H", selected - start + 2);
						}
					}
				} else if (c == 65) {
					// up
					conf_jump = 0;
					if (selected - 1 < start) {
						start -= 22;
						if (start < 0) {
							start = 0;
						}
						redraw = 1;
					}
					selected--;
					if (selected < 0) {
						selected = 0;
					} else {
						if (!redraw) {
							s_printf(get_string(249), selected - start + 2, conf_tmp[selected]->index, conf_tmp[selected]->conference->name);
							s_printf(get_string(250), selected - start + 3, conf_tmp[selected + 1]->index, conf_tmp[selected + 1]->conference->name);
							s_printf("\e[%d;5H", selected - start + 2);
						}
					}
				} else if (c == 75) {
					// END KEY
					conf_jump = 0;
					selected = list_tmp - 1;
					start = list_tmp - 22;
					if (start < 0) {
						start = 0;
					}
					redraw = 1;
				} else if (c == 72) {
					// HOME KEY
					conf_jump = 0;
					selected = 0;
					start = 0;
					redraw = 1;
				} else if (c == 86 || c == '5') {
					if (c == '5') {
						s_getchar();
					}
					// PAGE UP
					conf_jump = 0;
					selected = selected - 22;
					if (selected < 0) {
						selected = 0;
					}
					start = selected;
					redraw = 1;
				} else if (c == 85 || c == '6') {
					if (c == '6') {
						s_getchar();
					}
					// PAGE DOWN
					conf_jump = 0;
					selected = selected + 22;
					if (selected >= list_tmp) {
						selected = list_tmp - 1;
					}
					start = selected;
					redraw = 1;
				}
			}
		} else if (c == 13) {
			ret = conf_tmp[selected]->index;
			break;
		} else if (c >= '0' || c <= '9') {
			conf_jump = conf_jump * 10 + (c - '0');
			selected = conf_jump;
			if (selected >= list_tmp) {
				selected = list_tmp - 1;
			}
			start = selected;
			redraw = 1;
		}
	}

	for (i = 0; i < list_tmp; i++) {
		free(conf_tmp[i]);
	}
	free(conf_tmp);
	return ret;
}

struct area_tmp_t {
	struct mail_area *area;
	int index;
};

int choose_area(int confr) {
	int i;
	int list_tmp = 0;
	struct area_tmp_t **area_tmp;
	int redraw = 1;
	int start = 0;
	int selected = 0;
	char c;
	int offset = 2;
	int height = 22;
	struct ptr_vector vec;
	int area_jump = 0;
	int ret = gUser->cur_mail_area;

	struct mail_conference *gmc = get_conf(confr);
	if (gmc->header != NULL) {
		offset = 8;
		height = 16;
	}

	init_ptr_vector(&vec);
	for (i = 0; i < ptr_vector_len(&gmc->mail_areas); ++i) {
		struct mail_area *ma = ptr_vector_get(&gmc->mail_areas, i);
		if (check_security(gUser, ma->read_sec_level, &ma->rd_req_flags, &ma->wr_req_flags)) {
			struct area_tmp_t *area = (struct area_tmp_t *)malloz(sizeof(struct area_tmp_t));
			area->area = ma;
			area->index = i;
			ptr_vector_append(&vec, area);
		}
	}
	list_tmp = ptr_vector_len(&vec);
	area_tmp = (struct area_tmp_t **)consume_ptr_vector(&vec);

	while (1) {
		if (redraw) {
			if (gmc->header != NULL) {
				s_printf("\e[2J\e[1;1H");
				s_displayansi(gmc->header);
				s_printf("\e[7;1H");
			} else {
				s_printf("\e[2J\e[1;1H");
			}
			s_printf(get_string(251), gmc->name);
			s_printf(get_string(248));
			for (i = start; i < start + height && i < list_tmp; i++) {
				if (i == selected) {
					if (new_messages(gUser, gUser->cur_mail_conf, area_tmp[i]->index)) {
						s_printf(get_string(259), i - start + offset, area_tmp[i]->index, area_tmp[i]->area->name);
					} else {
						s_printf(get_string(249), i - start + offset, area_tmp[i]->index, area_tmp[i]->area->name);
					}
				} else {
					if (new_messages(gUser, gUser->cur_mail_conf, area_tmp[i]->index)) {
						s_printf(get_string(260), i - start + offset, area_tmp[i]->index, area_tmp[i]->area->name);
					} else {
						s_printf(get_string(250), i - start + offset, area_tmp[i]->index, area_tmp[i]->area->name);
					}
				}
			}
			s_printf("\e[%d;5H", selected - start + offset);
			redraw = 0;
		}
		c = s_getchar();
		if (tolower(c) == 'q') {
			break;
		} else if (c == 27) {
			c = s_getchar();
			if (c == 91) {
				c = s_getchar();
				if (c == 66) {
					area_jump = 0;
					// down
					if (selected + 1 >= start + height) {
						start += height;
						if (start >= list_tmp) {
							start = list_tmp - height;
						}
						redraw = 1;
					}
					selected++;
					if (selected >= list_tmp) {
						selected = list_tmp - 1;
					} else {
						if (!redraw) {
							if (new_messages(gUser, gUser->cur_mail_conf, area_tmp[selected - 1]->index)) {
								s_printf(get_string(260), selected - start + (offset - 1), area_tmp[selected - 1]->index, area_tmp[selected - 1]->area->name);
							} else {
								s_printf(get_string(250), selected - start + (offset - 1), area_tmp[selected - 1]->index, area_tmp[selected - 1]->area->name);
							}
							if (new_messages(gUser, gUser->cur_mail_conf, area_tmp[selected]->index)) {
								s_printf(get_string(259), selected - start + offset, area_tmp[selected]->index, area_tmp[selected]->area->name);
							} else {
								s_printf(get_string(249), selected - start + offset, area_tmp[selected]->index, area_tmp[selected]->area->name);
							}
							s_printf("\e[%d;5H", selected - start + offset);
						}
					}
				} else if (c == 65) {
					area_jump = 0;
					// up
					if (selected - 1 < start) {
						start -= height;
						if (start < 0) {
							start = 0;
						}
						redraw = 1;
					}
					selected--;
					if (selected < 0) {
						selected = 0;
					} else {
						if (!redraw) {
							if (new_messages(gUser, gUser->cur_mail_conf, area_tmp[selected]->index)) {
								s_printf(get_string(259), selected - start + offset, area_tmp[selected]->index, area_tmp[selected]->area->name);
							} else {
								s_printf(get_string(249), selected - start + offset, area_tmp[selected]->index, area_tmp[selected]->area->name);
							}
							if (new_messages(gUser, gUser->cur_mail_conf, area_tmp[selected + 1]->index)) {
								s_printf(get_string(260), selected - start + (offset + 1), area_tmp[selected + 1]->index, area_tmp[selected + 1]->area->name);
							} else {
								s_printf(get_string(250), selected - start + (offset + 1), area_tmp[selected + 1]->index, area_tmp[selected + 1]->area->name);
							}
							s_printf("\e[%d;5H", selected - start + offset);
						}
					}
				} else if (c == 75) {
					area_jump = 0;
					// END KEY
					selected = list_tmp - 1;
					start = list_tmp - height;
					if (start < 0) {
						start = 0;
					}
					redraw = 1;
				} else if (c == 72) {
					area_jump = 0;
					// HOME KEY
					selected = 0;
					start = 0;
					redraw = 1;
				} else if (c == 86 || c == '5') {
					if (c == '5') {
						s_getchar();
					}
					area_jump = 0;
					// PAGE UP
					selected = selected - height;
					if (selected < 0) {
						selected = 0;
					}
					start = selected;
					redraw = 1;
				} else if (c == 85 || c == '6') {
					if (c == '6') {
						s_getchar();
					}
					area_jump = 0;
					// PAGE DOWN
					selected = selected + height;
					if (selected >= list_tmp) {
						selected = list_tmp - 1;
					}
					start = selected;
					redraw = 1;
				}
			}
		} else if (c == 13) {
			ret = area_tmp[selected]->index;
			break;
		} else if (c >= '0' || c <= '9') {
			area_jump = area_jump * 10 + (c - '0');
			selected = area_jump;
			if (selected >= list_tmp) {
				selected = list_tmp - 1;
			}
			start = selected;
			redraw = 1;
		}
	}

	for (i = 0; i < list_tmp; i++) {
		free(area_tmp[i]);
	}
	free(area_tmp);

	return ret;
}

void next_mail_conf(struct user_record *user) {
	size_t n = ptr_vector_len(&conf.mail_conferences);
	size_t start = user->cur_mail_conf;
	size_t i;
	for (i = (start + 1) % n; i != start; i = (i + 1) % n) {
		struct mail_conference *mc = get_conf(i);
		if (check_security(user, mc->sec_level, &mc->vis_req_flags, &mc->vis_not_flags)) {
			break;
		}
	}
	user->cur_mail_conf = i;
	user->cur_mail_area = 0;
}

void prev_mail_conf(struct user_record *user) {
	size_t n = ptr_vector_len(&conf.mail_conferences);
	size_t start = user->cur_mail_conf;
	size_t i;
	for (i = (start + n - 1) % n; i != start; i = (i + n - 1) % n) {
		struct mail_conference *mc = get_conf(i);
		if (check_security(user, mc->sec_level, &mc->vis_req_flags, &mc->vis_not_flags)) {
			break;
		}
	}
	user->cur_mail_conf = i;
	user->cur_mail_area = 0;
}

void next_mail_area(struct user_record *user) {
	struct mail_conference *mc = get_user_conf(user);
	size_t n = ptr_vector_len(&mc->mail_areas);
	size_t start = user->cur_mail_area;
	for (size_t i = (start + 1) % n; i != start; i = (i + 1) % n) {
		struct mail_area *ma = get_area(user->cur_mail_conf, i);
		if (check_security(user, ma->read_sec_level, &ma->rd_req_flags, &ma->rd_not_flags)) {
			user->cur_mail_area = i;
			break;
		}
	}
}

void prev_mail_area(struct user_record *user) {
	struct mail_conference *mc = get_user_conf(user);
	size_t n = ptr_vector_len(&mc->mail_areas);
	size_t start = user->cur_mail_area;
	for (size_t i = (start + n - 1) % n; i != start; i = (i + n - 1) % n) {
		struct mail_area *ma = get_area(user->cur_mail_conf, i);
		if (check_security(user, ma->read_sec_level, &ma->rd_req_flags, &ma->rd_not_flags)) {
			user->cur_mail_area = i;
			break;
		}
	}
}

int count_msgs_above_msgno(struct msg_headers *msghs, int highmsgno) {
	int i;
	int highmsg = 0;

	if (highmsgno == -1) {
		// all unread
		return msghs->msg_count;
	}

	for (i = msghs->msg_count - 1; i >= 0; i--) {
		if (msghs->msgs[i]->msg_no <= highmsgno) break;
		highmsg++;
	}
	return highmsg;
}

void do_mail_scan(struct user_record *user, int oldscan, int personal) {
	struct msg_base_t *mb;
	struct msg_headers *msghs;
	char c;
	int i;
	int j;
	int lines = 0;
	int orig_conf;
	int orig_area;
	int res = 0;
	char ch;
	int unread_count;
	int k;
	int high_read;

	if (personal) {
		s_printf(get_string(276));
	} else {
		s_printf(get_string(139));
	}
	c = s_getc();

	s_printf("\r\n");


	if (tolower(c) == 'y' || tolower(c) == 's') {
		for (i = 0; i < ptr_vector_len(&conf.mail_conferences); i++) {
			struct mail_conference *mc = get_conf(i);
			if (!check_security(user, mc->sec_level, &mc->vis_req_flags, &mc->vis_not_flags)) {
				continue;
			}
			if (oldscan) {

				s_printf(get_string(324));
				lines++;
				if (lines == 22) {
					s_printf(get_string(6));
					s_getc();
					lines = 0;
				}
				s_printf(get_string(326), mc->name);
				lines++;
				if (lines == 22) {
					s_printf(get_string(6));
					s_getc();
					lines = 0;
				}
				s_printf(get_string(324));
				lines++;
				if (lines == 22) {
					s_printf(get_string(6));
					s_getc();
					lines = 0;
				}				
			}
			for (j = 0; j < ptr_vector_len(&mc->mail_areas); j++) {
				struct mail_area *ma = get_area(i, j);
				if (!check_security(user, ma->read_sec_level, &ma->rd_req_flags, &ma->rd_not_flags)) {
					continue;
				}

				if (tolower(c) == 's' && !msgbase_is_subscribed(i, j)) {
					continue;
				}

				msghs = read_message_headers(i, j, user, personal);
				if (!msghs) {
					continue;
				}

				if (msghs->msg_count == 0) {
					free_message_headers(msghs);
					continue;
				}

				mb = open_message_base(i, j);
				if (!mb) {
					free_message_headers(msghs);
					dolog("Unable to open message base");
					continue;
				}

				high_read = get_message_highread(mb, user->id);

				close_message_base(mb);

				if (high_read < get_message_number(msghs, msghs->msg_count - 1)) {
					if (ma->type == TYPE_NETMAIL_AREA) {
						unread_count = count_msgs_above_msgno(msghs, high_read);
						if (unread_count > 0) {
							if (oldscan) {
								s_printf(get_string(327), ma->name, msghs->msg_count, unread_count);
								lines++;
								if (lines == 22) {
									s_printf(get_string(6));
									s_getc();
									lines = 0;
								}
							} else {
								s_printf("\e[2J\e[1;1H");
								s_printf(get_string(277), i, mc->name);
								s_printf(get_string(278), j, ma->name, unread_count);
								s_printf(get_string(279));

								ch = s_getchar();
								s_printf("\r\n");
								if (tolower(ch) == 'y') {
									orig_conf = user->cur_mail_conf;
									orig_area = user->cur_mail_area;

									user->cur_mail_conf = i;
									user->cur_mail_area = j;

									res = read_new_msgs(user, msghs);

									user->cur_mail_conf = orig_conf;
									user->cur_mail_area = orig_area;
								}
							}
						} 
					} else {
						unread_count = count_msgs_above_msgno(msghs, high_read);
						if (unread_count > 0) {
							if (oldscan) {
								s_printf(get_string(327), ma->name, msghs->msg_count, unread_count);
								lines++;
								if (lines == 22) {
									s_printf(get_string(6));
									s_getc();
									lines = 0;
								}
							} else {
								s_printf("\e[2J\e[1;1H");
								s_printf(get_string(277), i, mc->name);
								s_printf(get_string(278), j, ma->name, unread_count);
								s_printf(get_string(279));

								ch = s_getchar();
								s_printf("\r\n");
								if (tolower(ch) == 'y') {
									orig_conf = user->cur_mail_conf;
									orig_area = user->cur_mail_area;
									user->cur_mail_conf = i;
									user->cur_mail_area = j;

									res = read_new_msgs(user, msghs);

									user->cur_mail_conf = orig_conf;
									user->cur_mail_area = orig_area;
								}
							}
						}
					}
				} else {
					if (oldscan) {
						s_printf(get_string(325), ma->name, msghs->msg_count);
						lines++;
						if (lines == 22) {
							s_printf(get_string(6));
							s_getc();
							lines = 0;
						}
					}
				}

				free_message_headers(msghs);
				if (res) {
					break;
				}
			}
			if (res) {
				break;
			}
		}

		s_printf(get_string(6));
		s_getc();
	}
}

void full_mail_scan_personal(struct user_record *user) {
	do_mail_scan(user, 0, 1);
}

void full_mail_scan(struct user_record *user) {
	do_mail_scan(user, 0, 0);
}

void mail_scan(struct user_record *user) {
	do_mail_scan(user, 1, 0);
}

void msg_conf_sub_bases() {
	int i;
	int lines = 0;
	char buffer[10];
	int toggle_area;
	int done = 0;
	int j;
	int k;
	s_printf("\e[1;1H\e[2J");
	struct mail_conference *smc = NULL;
	int smci;

	smci = choose_conference();
	smc = ptr_vector_get(&conf.mail_conferences, smci);

	if (smc == NULL) {
		return;
	}

	s_printf("\e[1;1H\e[2J");

	lines = 0;
	do {
		for (i = 0; i < ptr_vector_len(&smc->mail_areas); i++) {
			struct mail_area *ma = ptr_vector_get(&smc->mail_areas, i);
			if (check_security(gUser, ma->read_sec_level, &ma->rd_req_flags, &ma->rd_not_flags)) {
				s_printf(get_string(226), i, (msgbase_is_subscribed(smci, i) ? get_string(227) : get_string(228)), ma->name);
				lines++;
			}

			if (lines == 23) {
				s_printf(get_string(225));
				s_readstring(buffer, 9);
				s_printf("\r\n");
				if (strlen(buffer) > 0) {
					if (buffer[0] >= '0' && buffer[0] <= '9') {
						toggle_area = atoi(buffer);
						struct mail_area *ma = ptr_vector_get(&smc->mail_areas, toggle_area);
						if (ma != NULL) {
							if (check_security(gUser, ma->read_sec_level, &ma->rd_req_flags, &ma->rd_not_flags)) {
								msgbase_sub_unsub(smci, toggle_area);
							}
						}
						lines = 0;
						break;
					}
					if (buffer[0] == 'a' || buffer[0] == 'A') {
						for (j = 0; j < ptr_vector_len(&smc->mail_areas); j++) {
							struct mail_area *ma = ptr_vector_get(&smc->mail_areas, j);
							if (check_security(gUser, ma->read_sec_level, &ma->rd_req_flags, &ma->rd_not_flags)) {
								if (!msgbase_is_subscribed(smci, j)) {
									msgbase_sub_unsub(smci, j);
								}
							}
						}
						lines = 0;
						break;
					}
					if (buffer[0] == 'n' || buffer[0] == 'N') {
						for (j = 0; j < ptr_vector_len(&smc->mail_areas); j++) {
							struct mail_area *ma = ptr_vector_get(&smc->mail_areas, j);
							if (check_security(gUser, ma->read_sec_level, &ma->rd_req_flags, &ma->rd_not_flags)) {
								if (msgbase_is_subscribed(smci, j)) {
									msgbase_sub_unsub(smci, j);
								}
							}
						}
						lines = 0;
						break;
					}
					if (buffer[0] == 'q' || buffer[0] == 'Q') {
						done = 1;
						lines = 0;
						break;
					}
				}
			}
		}

		if (lines > 0) {
			s_printf(get_string(225));
			s_readstring(buffer, 9);
			s_printf("\r\n");
			if (strlen(buffer) > 0) {
				if (buffer[0] >= '0' && buffer[0] <= '9') {
					toggle_area = atoi(buffer);
					struct mail_area *ma = ptr_vector_get(&smc->mail_areas, toggle_area);
					if (ma != NULL) {
						if (check_security(gUser, ma->read_sec_level, &ma->rd_req_flags, &ma->rd_not_flags)) {
							msgbase_sub_unsub(smci, toggle_area);
						}
						lines = 0;
					}
				} else if (buffer[0] == 'a' || buffer[0] == 'A') {
					for (j = 0; j < ptr_vector_len(&smc->mail_areas); j++) {
						struct mail_area *ma = ptr_vector_get(&smc->mail_areas, j);
						if (check_security(gUser, ma->read_sec_level, &ma->rd_req_flags, &ma->rd_not_flags)) {
							if (!msgbase_is_subscribed(smci, j)) {
								msgbase_sub_unsub(smci, j);
							}
						}
					}
				} else if (buffer[0] == 'n' || buffer[0] == 'N') {
					for (j = 0; j < ptr_vector_len(&smc->mail_areas); j++) {
						struct mail_area *ma = ptr_vector_get(&smc->mail_areas, j);
						if (check_security(gUser, ma->read_sec_level, &ma->rd_req_flags, &ma->rd_not_flags)) {
							if (msgbase_is_subscribed(smci, j)) {
								msgbase_sub_unsub(smci, j);
							}
						}
					}
				} else if (buffer[0] == 'q' || buffer[0] == 'Q') {
					done = 1;
				}
			}
		} else {
			lines = 0;
		}
	} while (!done);
}

void msgbase_reset_pointers(int conference, int msgarea, int readm, int msgno) {
	int max_msg;
	int active_msgs;
	int j, k;
	struct msg_base_t *mb;
	struct msg_headers *msghs;
	struct mail_area *ma = get_area(conference, msgarea);

	mb = open_message_base(conference, msgarea);
	if (!mb) {
		dolog("Unable to open message base");
		return;
	}

	msghs = read_message_headers(conference, msgarea, gUser, 0);

	if (msghs != NULL && msghs->msg_count > 0) {

		j = 0;

		if (msgno == -1 && readm) {
			k = get_message_number(msghs, msghs->msg_count - 1);
		} else if (msgno == -1 && !readm) {
			k = 0;
		} else {
			if (msgno > get_message_number(msghs, msghs->msg_count - 1)) {
				k = get_message_number(msghs, msghs->msg_count - 1);
			} else {
				k = msgno;
			}
		}

		write_lasthighread(mb, gUser, k, k);
	}
	close_message_base(mb);
}

void msgbase_reset_all_pointers(int readm) {
	for (size_t i = 0; i < ptr_vector_len(&conf.mail_conferences); ++i) {
		struct mail_conference *mc = ptr_vector_get(&conf.mail_conferences, i);
		for (size_t j = 0; j < ptr_vector_len(&mc->mail_areas); ++j)
			msgbase_reset_pointers(i, j, readm, -1);
	}
}

int new_messages(struct user_record *user, int conference, int area) {
	int count = 0;
	struct msg_base_t *mb;

	mb = open_message_base(conference, area);
	count = new_message_count(mb, user);
	close_message_base(mb);

	return count;
}

char *find_quote_ptr(char *str, int len) {
	char *lastptr = NULL;
	for (int i = 0; i < strlen(str) && i < len; i++) {
		if (str[i] == '>') lastptr = &str[i];
	}

	return lastptr;
}

char *wrap_quotes(char *body, char initial1, char initial2) {

	struct ptr_vector q_lines, q_lines2;
	stralloc line = EMPTY_STRALLOC;
	stralloc eline = EMPTY_STRALLOC;
	int i, j;
	char *ptr1, *ptr2, *ptr3, *ptr4;
	stralloc newbody = EMPTY_STRALLOC;
	char *isquote;
	char *extra;
	int wraplen = 67;

	// Step 1. Break the quote into lines.
	init_ptr_vector(&q_lines);
	for (i=0;i<strlen(body);i++) {
		if (body[i] != '\r') {
			stralloc_append1(&line, body[i]);
		} else {
			stralloc_0(&line);
			ptr_vector_append(&q_lines, line.s);
			line = EMPTY_STRALLOC;
		}

	}

	extra = NULL;
	init_ptr_vector(&q_lines2);
	for (i=0;i<ptr_vector_len(&q_lines);i++) {
		line = EMPTY_STRALLOC;
		if (extra != NULL) {

			ptr1 = ptr_vector_get(&q_lines, i);
			ptr2 = find_quote_ptr(ptr1, 8);
			ptr4 = find_quote_ptr(extra, 8);

			if (ptr2 != NULL && ptr4 != NULL && ptr2 - ptr1 < 8 && ptr4 - extra < 8) {
				// extra is quote, next line is quote
				if (strncmp(ptr1, extra, ptr2 - ptr1) == 0 && strlen(ptr2) > 1) {

					// same quote
					stralloc_cats(&line, extra);
					stralloc_append1(&line, ' ');
					stralloc_cats(&line, ptr2 + 2);
					stralloc_0(&line);

					if (strlen(line.s) > wraplen) {
						ptr3 = &line.s[wraplen];
						while (ptr3 != line.s + (ptr4 - extra + 1)) {
							if (*ptr3 == ' ') break;
							ptr3--;
						}

						if (ptr3 != line.s + (ptr4 - extra + 1)) {
							free(extra);
							extra = NULL;
							eline = EMPTY_STRALLOC;
							stralloc_catb(&eline, ptr1, ptr2 - ptr1 + 1);
							stralloc_append1(&eline, ' ');
							stralloc_cats(&eline, ptr3 + 1);
							stralloc_0(&eline);
							extra = eline.s;
							*ptr3 = '\r';
							ptr3++;
							*ptr3 = '\0';
						} else {
							free(extra);
							extra = NULL;
							eline = EMPTY_STRALLOC;
							stralloc_catb(&eline, ptr1, ptr2 - ptr1 + 1);
							stralloc_append1(&eline, ' ');
							stralloc_cats(&eline, &line.s[wraplen]);
							stralloc_0(&eline);
							extra = eline.s;
							line.s[wraplen] = '\r';
							line.s[wraplen + 1] = '\0';
						}
						ptr_vector_append(&q_lines2, strdup(line.s));
						free(line.s);
						free(ptr1);
						continue;
					} else {
						free(extra);
						extra = NULL;
						eline = EMPTY_STRALLOC;
						stralloc_cats(&eline, line.s);
						stralloc_append1(&eline, '\r');
						stralloc_0(&eline);

						ptr_vector_append(&q_lines2, strdup(eline.s));
						free(eline.s);
						free(line.s);
						free(ptr1);
						continue;
					}
				}
			} else if (ptr2 == NULL && ptr4 == NULL && strlen(ptr1) > 0) {
				stralloc_cats(&line, extra);
				free(extra);
				extra = NULL;
				stralloc_append1(&line, ' ');
				stralloc_cats(&line, ptr1);
				stralloc_0(&line);
				if (strlen(line.s) > wraplen) {
					free(extra);
					ptr3 = &line.s[wraplen];
					while (ptr3 != line.s) {
						if (*ptr3 == ' ') break;
						ptr3--;
					}
					if (ptr3 != line.s) {
						extra = strdup(ptr3 + 1);
						*ptr3 = '\r';
						ptr3++;
						*ptr3 = '\0';
					} else {
						extra = strdup(&line.s[wraplen]);
						line.s[wraplen] ='\r';
						line.s[wraplen + 1] ='\0';
					}
					ptr_vector_append(&q_lines2, strdup(line.s));
					free(line.s);
					free(ptr1);
					continue;
				} else {
					free(extra);
					extra = NULL;
					eline = EMPTY_STRALLOC;
					stralloc_cats(&eline, line.s);
					stralloc_append1(&eline, '\r');
					stralloc_0(&eline);

					ptr_vector_append(&q_lines2, strdup(eline.s));
					free(eline.s);
					free(line.s);
					free(ptr1);
					continue;
				}
			} else {
				// extra is quote, next line is different quote
				eline = EMPTY_STRALLOC;
				stralloc_cats(&eline, extra);
				stralloc_append1(&eline, '\r');
				stralloc_0(&eline);

				ptr_vector_append(&q_lines2, strdup(eline.s));
				free(eline.s);
				free(extra);
				extra = NULL;
			}
		} else {
			ptr1 = ptr_vector_get(&q_lines, i);
			ptr2 = find_quote_ptr(ptr1, 8);
		}

		if (ptr2 != NULL && ptr2 - ptr1 < 8) {
			// line is a quote
			if (strlen(ptr1) > wraplen) {
				ptr3 = &ptr1[wraplen];
				while (ptr3 != ptr2 + 1) {
					if (*ptr3 == ' ') break;
					ptr3--;
				}
				if (ptr3 != ptr2 + 1) {
					eline = EMPTY_STRALLOC;
					stralloc_catb(&eline, ptr1, ptr2 - ptr1 + 1);
					stralloc_append1(&eline, ' ');
					stralloc_cats(&eline, ptr3 + 1);
					stralloc_0(&eline);
					extra = eline.s;
					*ptr3 = '\r';
					ptr3++;
					*ptr3 = '\0';
				} else {
					eline = EMPTY_STRALLOC;
					stralloc_catb(&eline, ptr1, ptr2 - ptr1 + 1);
					stralloc_append1(&eline, ' ');
					stralloc_cats(&eline, &ptr1[wraplen]);
					stralloc_0(&eline);
					extra = eline.s;
					ptr1[wraplen] ='\r';
					ptr1[wraplen + 1] ='\0';
				}
				ptr_vector_append(&q_lines2, strdup(ptr1));
				free(ptr1);
			} else {
				line = EMPTY_STRALLOC;
				stralloc_cats(&line, ptr1);
				stralloc_append1(&line, '\r');
				stralloc_0(&line);
				ptr_vector_append(&q_lines2, line.s);
				free(ptr1);
			}
		} else {
			if (strlen(ptr1) > wraplen) {
				ptr3 = &ptr1[wraplen];
				while (ptr3 != ptr1) {
					if (*ptr3 == ' ') break;
					ptr3--;
				}
				if (ptr3 != ptr1) {
					extra = strdup(ptr3 + 1);
					*ptr3 = '\r';
					ptr3++;
					*ptr3 = '\0';
				} else {
					extra = strdup(&ptr1[wraplen]);
					ptr1[wraplen] ='\r';
					ptr1[wraplen + 1] ='\0';
				}
				ptr_vector_append(&q_lines2, strdup(ptr1));
				free(ptr1);
			} else {
				line = EMPTY_STRALLOC;
				stralloc_cats(&line, ptr1);
				stralloc_append1(&line, '\r');
				stralloc_0(&line);
				ptr_vector_append(&q_lines2, line.s);
				free(ptr1);
			}
		}
	}

	if (extra != NULL) {
		eline = EMPTY_STRALLOC;
		stralloc_cats(&eline, extra);
		stralloc_append1(&eline, '\r');
		stralloc_0(&eline);

		ptr_vector_append(&q_lines2, strdup(eline.s));
		free(eline.s);
		free(extra);
	}

	destroy_ptr_vector(&q_lines);

	for (i=0;i<ptr_vector_len(&q_lines2);i++) {
		ptr1 = ptr_vector_get(&q_lines2, i);
		ptr2 = strchr(ptr1, '>');
		if (ptr2 != NULL && ptr2 - ptr1 < 5 || ptr1[0] == '\r') {
			// already quoted
			stralloc_cats(&newbody, ptr1);
		} else {
			line = EMPTY_STRALLOC;
			stralloc_append1(&line, ' ');
			stralloc_append1(&line, initial1);
			stralloc_append1(&line, initial2);
			stralloc_append1(&line, '>');
			stralloc_append1(&line, ' ');
			stralloc_cats(&line, ptr1);
			stralloc_0(&line);
			stralloc_cats(&newbody, line.s);
			free(line.s);
		}
		free(ptr1);
	}
	free(body);
	destroy_ptr_vector(&q_lines2);
	stralloc_0(&newbody);
	return newbody.s;
}
