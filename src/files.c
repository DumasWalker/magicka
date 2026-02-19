#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <unistd.h>
#include <sys/stat.h>
#include <libgen.h>
#include <ctype.h>
#include <errno.h>
#include <termios.h>
#include <dirent.h>
#include <fcntl.h>
#include <time.h>
#include <sys/wait.h>
#include "Xmodem/zmodem.h"
#include "bbs.h"
#include "lua/lua.h"
#include "lua/lualib.h"
#include "lua/lauxlib.h"
#ifdef __HAIKU__
#include <sys/select.h>
#endif

extern struct bbs_config conf;
extern int gSocket;
extern int sshBBS;
extern int mynode;
extern int bbs_stdin;
extern int bbs_stdout;
extern int bbs_stderr;
extern time_t userlaston;
extern struct user_record *gUser;
extern int telnet_bin_mode;
extern int timeoutpaused;

struct file_entry {
	int fid;
	int dir;
	int sub;
	char *filename;
	char *description;
	int size;
	int dlcount;
	time_t uploaddate;
};

struct tagged_file {
	char *filename;
	int dir;
	int sub;
	int fid;
};

static struct file_directory *get_dir(size_t d) {
	struct file_directory *dir = ptr_vector_get(&conf.file_directories, d);
	assert(dir != NULL);
	return dir;
}

static struct file_directory *user_dir(struct user_record *user) {
	assert(user != NULL);
	return get_dir(user->cur_file_dir);
}

static struct file_sub *get_sub(size_t d, size_t s) {
	struct file_directory *dir = get_dir(d);
	struct file_sub *sub = ptr_vector_get(&dir->file_subs, s);
	assert(sub != NULL);
	return sub;
}

static struct file_sub *user_sub(struct user_record *user) {
	assert(user != NULL);
	return get_sub(user->cur_file_dir, user->cur_file_sub);
}

static void open_sub_db_or_die(sqlite3 **db, char *sub) {
	char buffer[PATH_MAX];
	snprintf(buffer, PATH_MAX, "%s/%s.sq3", conf.bbs_path, sub);
	if (sqlite3_open(buffer, db) != SQLITE_OK) {
		dolog("Cannot open database: %s", sqlite3_errmsg(*db));
		sqlite3_close(*db);
		exit(1);
	}
	assert(db != NULL);
	sqlite3_busy_timeout(*db, 5000);
}

struct ptr_vector tagged_files;

int ttySetRaw(int fd, struct termios *prevTermios) {
	struct termios t;

	if (tcgetattr(fd, &t) == -1)
		return -1;

	if (prevTermios != NULL)
		*prevTermios = t;

	t.c_lflag &= ~(ICANON | ISIG | IEXTEN | ECHO);
	t.c_iflag &= ~(BRKINT | ICRNL | IGNBRK | IGNCR | INLCR | INPCK | ISTRIP | IXON | PARMRK);
	t.c_oflag &= ~OPOST;
	t.c_cc[VMIN] = 1;
	t.c_cc[VTIME] = 0;

	if (tcsetattr(fd, TCSAFLUSH, &t) == -1)
		return -1;

	return 0;
}

int ZXmitStr(u_char *str, int len, ZModem *info) {
	int i;

	for (i = 0; i < len; i++) {
		if (str[i] == 255 && !sshBBS) {
			if (write(info->ofd, &str[i], 1) == 0) {
				return ZmErrSys;
			}
		}
		if (write(info->ofd, &str[i], 1) == 0) {
			return ZmErrSys;
		}
	}

	return 0;
}

void ZIFlush(ZModem *info) {
}

void ZOFlush(ZModem *info) {
}

int ZAttn(ZModem *info) {
	char *ptr;

	if (info->attn == NULL)
		return 0;

	for (ptr = info->attn; *ptr != '\0'; ++ptr) {
		if (*ptr == ATTNBRK) {

		} else if (*ptr == ATTNPSE) {
			sleep(1);
		} else {
			write(info->ifd, ptr, 1);
		}
	}
	return 0;
}

void ZFlowControl(int onoff, ZModem *info) {
}

void ZStatus(int type, int value, char *status) {
}

char *upload_path;
char upload_filename[PATH_MAX];

FILE *ZOpenFile(char *name, u_long crc, ZModem *info) {
	FILE *fptr;

	snprintf(upload_filename, sizeof upload_filename, "%s/%s", upload_path, basename(name));
	if (access(upload_filename, F_OK) == 0) {
		return NULL;
	}

	fptr = fopen(upload_filename, "wb");

	return fptr;
}

int ZWriteFile(u_char *buffer, int len, FILE *file, ZModem *info) {
	return fwrite(buffer, 1, len, file) == len ? 0 : ZmErrSys;
}

int ZCloseFile(ZModem *info) {
	fclose(info->file);
	return 0;
}

void ZIdleStr(u_char *buffer, int len, ZModem *info) {
}

int doIO(ZModem *zm) {
	fd_set readfds;
	struct timeval timeout;
	u_char buffer[2048];
	u_char buffer2[2048];
	int len;
	int pos;
	int done = 0;
	int i;
	int j;
	char iac_binary_will[] = {IAC, IAC_WILL, IAC_TRANSMIT_BINARY, '\0'};
	char iac_binary_do[] = {IAC, IAC_DO, IAC_TRANSMIT_BINARY, '\0'};
	char iac_binary_wont[] = {IAC, IAC_WONT, IAC_TRANSMIT_BINARY, '\0'};
	char iac_binary_dont[] = {IAC, IAC_DONT, IAC_TRANSMIT_BINARY, '\0'};

	while (!done) {
		FD_ZERO(&readfds);
		FD_SET(zm->ifd, &readfds);
		timeout.tv_sec = zm->timeout;
		timeout.tv_usec = 0;
		i = select(zm->ifd + 1, &readfds, NULL, NULL, &timeout);

		if (i == 0) {
			done = ZmodemTimeout(zm);
		} else if (i > 0) {
			len = read(zm->ifd, buffer, 2048);
			if (len == 0) {
				disconnect("Socket closed");
			}

			pos = 0;
			for (j = 0; j < len; j++) {
				if (buffer[j] == 255 && !sshBBS) {
					if (buffer[j + 1] == 255) {
						buffer2[pos] = 255;
						pos++;
						j++;
					} else {
						// IAC command
						if (buffer[j + 1] == IAC_WILL || buffer[j + 1] == IAC_WONT || buffer[j + 1] == IAC_DO || buffer[j + 1] == IAC_DONT) {
							switch (buffer[j + 1]) {
								case IAC_WILL:
									if (buffer[j + 2] == 0) {
										if (telnet_bin_mode != 1) {
											telnet_bin_mode = 1;
											write(gSocket, iac_binary_do, 3);
										}
									}
									break;
								case IAC_WONT:
									if (buffer[j + 2] == 0) {
										if (telnet_bin_mode != 0) {
											telnet_bin_mode = 0;
											write(gSocket, iac_binary_dont, 3);
										}
									}
									break;
								case IAC_DO:
									if (buffer[j + 2] == 0) {
										if (telnet_bin_mode != 1) {
											telnet_bin_mode = 1;
											write(gSocket, iac_binary_will, 3);
										}
									}
									break;
								case IAC_DONT:
									if (buffer[j + 2] == 0) {
										if (telnet_bin_mode != 0) {
											telnet_bin_mode = 0;
											write(gSocket, iac_binary_wont, 3);
										}
									}
									break;
							}
							j += 2;
						} else if (buffer[j + 1] == 250) {
							j++;
							do {
								j++;
							} while (buffer[j] != 240);
						}
					}
				} else {
					buffer2[pos] = buffer[j];
					pos++;
				}
			}
			if (pos > 0) {
				done = ZmodemRcv(buffer2, pos, zm);
			}
		} else {
			// SIG INT catch
			if (errno != EINTR) {
				dolog("SELECT ERROR %s", strerror(errno));
			}
		}
	}
	return done;
}

void upload_zmodem(struct user_record *user, char *upload_p) {
	ZModem zm;
	struct termios oldit;
	struct termios oldot;
	if (sshBBS) {
		ttySetRaw(STDIN_FILENO, &oldit);
		ttySetRaw(STDOUT_FILENO, &oldot);
	}

	upload_path = upload_p;

	zm.attn = NULL;
	zm.windowsize = 0;
	zm.bufsize = 0;

	if (!sshBBS) {
		zm.ifd = gSocket;
		zm.ofd = gSocket;
	} else {
		zm.ifd = STDIN_FILENO;
		zm.ofd = STDOUT_FILENO;
	}
	zm.zrinitflags = 0;
	zm.zsinitflags = 0;

	zm.packetsize = 1024;

	ZmodemRInit(&zm);

	doIO(&zm);

	free(zm.buffer);

	if (sshBBS) {
		tcsetattr(STDIN_FILENO, TCSANOW, &oldit);
		tcsetattr(STDOUT_FILENO, TCSANOW, &oldot);
	}
}

char *get_file_id_diz(char *filename) {
	char *description;
	char buffer[1024];
	int bpos;
	int i;
	FILE *fptr;
	int len;
	int ext;
	int arch;
	int stout;
	int stin;
	int sterr;
	int ret;
	pid_t pid;
	char **args;
	char *cmd;
	ext = 0;
	arch = -1;

	for (i = strlen(filename) - 1; i >= 0; i--) {
		if (filename[i] == '.') {
			ext = i + 1;
			break;
		}
	}

	if (ext == 0) {
		return NULL;
	}

	struct archiver *arc = NULL;
	for (i = 0; i < ptr_vector_len(&conf.archivers); ++i) {
		arc = ptr_vector_get(&conf.archivers, i);
		if (strcasecmp(&filename[ext], arc->extension) == 0) {
			arch = i;
			break;
		}
	}

	if (arch == -1) {
		return NULL;
	}
	assert(arc != NULL);

	snprintf(buffer, sizeof buffer, "%s/node%d", conf.bbs_path, mynode);
	if (access(buffer, X_OK) != 0) {
		mkdir(buffer, 0755);
	}

	snprintf(buffer, sizeof buffer, "%s/node%d/temp", conf.bbs_path, mynode);
	if (access(buffer, F_OK | W_OK) == 0) {
		if (recursive_delete(buffer) != 0) {
			return NULL;
		}
	}
	mkdir(buffer, 0755);

	char *s = buffer;
	size_t blen = sizeof buffer;
	for (const char *p = arc->unpack; *p != '\0' && blen > 1; ++p) {
		if (*p != '*') {
			*s++ = *p;
			--blen;
			continue;
		}
		p++;
		size_t slen = 0;
		if (*p == 'a') {
			strlcpy(s, filename, blen);
			slen = strlen(s);
		} else if (*p == 'd') {
			snprintf(s, blen, "%s/node%d/temp/", conf.bbs_path, mynode);
			slen = strlen(s);
		} else if (*p == '*') {
			*s++ = '*';
			slen = 1;
		}
		s += slen;
		blen -= slen;
	}
	*s = '\0';

	if (sshBBS) {
		stout = dup(STDOUT_FILENO);
		stin = dup(STDIN_FILENO);
		sterr = dup(STDERR_FILENO);

		dup2(bbs_stdout, STDOUT_FILENO);
		dup2(bbs_stderr, STDERR_FILENO);
		dup2(bbs_stdin, STDIN_FILENO);
	}
	args = split_args(buffer, NULL);
	cmd = args[0];
	pid = fork();
	if (pid == 0) {
		execvp(cmd, args);
		exit(0);
	} else if (pid > 0) {
		waitpid(pid, &ret, 0);
	} else {
		ret = -1;
	}
	free(args);

	if (sshBBS) {
		dup2(stout, STDOUT_FILENO);
		dup2(sterr, STDERR_FILENO);
		dup2(stin, STDIN_FILENO);

		close(stin);
		close(stout);
		close(sterr);
	}

	snprintf(buffer, sizeof buffer, "%s/node%d/temp/FILE_ID.DIZ", conf.bbs_path, mynode);
	description = file2str(buffer);
	if (description == NULL) {
		snprintf(buffer, sizeof buffer, "%s/node%d/temp/file_id.diz", conf.bbs_path, mynode);
		description = file2str(buffer);
		if (description == NULL) {
			snprintf(buffer, sizeof buffer, "%s/node%d/temp", conf.bbs_path, mynode);
			recursive_delete(buffer);
			return NULL;
		}
	}

	char *b = description;
	for (char *p = description; *p != '\0'; ++p)
		if (*p != '\r')
			*b++ = *p;
	*b = '\0';

	snprintf(buffer, sizeof buffer, "%s/node%d/temp", conf.bbs_path, mynode);
	recursive_delete(buffer);

	return description;
}

int do_download(struct user_record *user, char *file) {
	struct termios oldit;
	struct termios oldot;
	char download_command[PATH_MAX];
	char **dc;
	int i;
	int argc;
	int last_char_space;
	char **arguments;
	int bpos;
	int len;
	char iac_binary_will[] = {IAC, IAC_WILL, IAC_TRANSMIT_BINARY, '\0'};
	char iac_binary_do[] = {IAC, IAC_DO, IAC_TRANSMIT_BINARY, '\0'};

	struct protocol *defproto = ptr_vector_get(&conf.protocols, user->defprotocol - 1);
	assert(defproto != NULL);
	if (defproto->internal_zmodem) {
		if (sshBBS) {
			ttySetRaw(STDIN_FILENO, &oldit);
			ttySetRaw(STDOUT_FILENO, &oldot);
		} else {
			if (telnet_bin_mode == 0) {
				write(gSocket, iac_binary_will, 3);
				write(gSocket, iac_binary_do, 3);
			}
		}
		timeoutpaused = 1;
		download_zmodem(user, file);
		timeoutpaused = 0;
		if (sshBBS) {
			tcsetattr(STDIN_FILENO, TCSANOW, &oldit);
			tcsetattr(STDOUT_FILENO, TCSANOW, &oldot);
		}
		return 1;
	} else {
		char *b = download_command;
		size_t blen = sizeof download_command;
		for (const char *p = defproto->download; *p != '\0' && blen > 1; ++p) {
			if (*p == '*') {
				p++;
				if (*p == '*') {
					*b++ = '*';
					--blen;
					continue;
				}

				size_t alen = 0;
				if (*p == 'f') {
					strlcpy(b, file, blen);
					alen = strlen(b);
				} else if (*p == 's') {
					if (sshBBS) {
						s_printf(get_string(209), defproto->name);
						return 0;
					}
					snprintf(b, blen, "%d", gSocket);
					alen = strlen(b);
				}
				b += alen;
				blen -= alen;
			} else {
				*b++ = *p;
				--blen;
			}
		}
		*b = '\0';
		argc = 1;
		last_char_space = 0;
		for (i = 0; i < strlen(download_command); i++) {
			if (download_command[i] == ' ') {
				if (!last_char_space) {
					argc++;
					last_char_space = 1;
				}
			} else {
				last_char_space = 0;
			}
		}
		bpos = 1;
		arguments = (char **)malloz(sizeof(char *) * (argc + 1));
		len = strlen(download_command);
		for (i = 0; i < len;) {
			if (download_command[i] != ' ') {
				i++;
				continue;
			}

			download_command[i] = '\0';
			i++;

			while (download_command[i] == ' ')
				i++;

			arguments[bpos++] = &download_command[i];
		}
		arguments[bpos] = NULL;

		arguments[0] = download_command;
		if (!sshBBS) {
			if (telnet_bin_mode == 0) {
				write(gSocket, iac_binary_will, 3);
				write(gSocket, iac_binary_do, 3);
			}
		}

		runexternal(user, download_command, defproto->stdio, arguments, conf.bbs_path, 1, NULL);

		free(arguments);
	}
	return 1;
}

int do_upload(struct user_record *user, char *final_path) {
	char upload_path[PATH_MAX];
	char upload_command[PATH_MAX];
	char buffer3[256];
	int bpos;
	int i;
	int argc;
	int last_char_space;
	char **arguments;
	DIR *inb;
	struct dirent *dent;
	int len;
	char iac_binary_will[] = {IAC, IAC_WILL, IAC_TRANSMIT_BINARY, '\0'};
	char iac_binary_do[] = {IAC, IAC_DO, IAC_TRANSMIT_BINARY, '\0'};
	int gotfile;
	char *argv[3];
	struct protocol *defproto = ptr_vector_get(&conf.protocols, user->defprotocol - 1);

	snprintf(upload_path, sizeof upload_path, "%s/node%d/upload/", conf.bbs_path, mynode);

	if (defproto->internal_zmodem) {
		if (!sshBBS) {
			if (telnet_bin_mode == 0) {
				write(gSocket, iac_binary_will, 3);
				write(gSocket, iac_binary_do, 3);
			}
		}
		timeoutpaused = 1;
		if (access(upload_path, F_OK) == 0) {
			recursive_delete(upload_path);
		}

		mkdir(upload_path, 0755);

		upload_zmodem(user, upload_path);
	} else {
		if (defproto->upload_prompt) {
			s_printf(get_string(210));
			s_readstring(buffer3, 256);
			s_printf("\r\n");
		}
		bpos = 0;
		for (i = 0; i < strlen(defproto->upload); i++) {
			if (defproto->upload[i] == '*') {
				i++;
				if (defproto->upload[i] == '*') {
					upload_command[bpos++] = defproto->upload[i];
					upload_command[bpos] = '\0';
					continue;
				} else if (defproto->upload[i] == 'f') {
					if (defproto->upload_prompt) {
						size_t blen = sizeof(upload_command) - bpos;
						strlcpy(upload_command + bpos, buffer3, blen);
						bpos = strlen(upload_command);
					}
					continue;
				} else if (defproto->upload[i] == 's') {
					if (!sshBBS) {
						size_t blen = sizeof(upload_command) - bpos;
						snprintf(upload_command + bpos, blen, "%d", gSocket);
						bpos = strlen(upload_command);
					} else {
						s_printf(get_string(209), defproto->name);
						return 0;
					}
				}

			} else {
				upload_command[bpos++] = defproto->upload[i];
				upload_command[bpos] = '\0';
			}
		}
		argc = 1;
		last_char_space = 0;
		for (i = 0; i < strlen(upload_command); i++) {
			if (upload_command[i] == ' ') {
				if (!last_char_space) {
					argc++;
					last_char_space = 1;
				}
			} else {
				last_char_space = 0;
			}
		}
		bpos = 1;
		arguments = (char **)malloz(sizeof(char *) * (argc + 1));
		len = strlen(upload_command);
		for (i = 0; i < len;) {
			if (upload_command[i] != ' ') {
				i++;
				continue;
			}

			upload_command[i] = '\0';
			i++;

			while (upload_command[i] == ' ')
				i++;

			arguments[bpos++] = &upload_command[i];
		}
		arguments[bpos] = NULL;

		arguments[0] = upload_command;

		if (access(upload_path, F_OK) == 0) {
			recursive_delete(upload_path);
		}

		mkdir(upload_path, 0755);

		if (!sshBBS) {
			if (telnet_bin_mode == 0) {
				write(gSocket, iac_binary_will, 3);
				write(gSocket, iac_binary_do, 3);
			}
		}
		timeoutpaused = 1;
		runexternal(user, upload_command, defproto->stdio, arguments, upload_path, 1, NULL);
		free(arguments);
	}

	if (!defproto->internal_zmodem && defproto->upload_prompt) {
		snprintf(upload_command, sizeof upload_command, "%s%s", upload_path, buffer3);
		if (access(upload_command, W_OK | X_OK) != 0) {
			recursive_delete(upload_path);
			timeoutpaused = 0;
			return 0;
		}

		snprintf(upload_filename, sizeof upload_filename, "%s/%s", final_path, buffer3);
	} else {
		inb = opendir(upload_path);
		if (!inb) {
			timeoutpaused = 0;
			return 0;
		}
		gotfile = 0;
		while ((dent = readdir(inb)) != NULL) {
#if defined(__sun) || defined(__HAIKU__)
			snprintf(upload_command, sizeof upload_command, "%s%s", upload_path, dent->d_name);
			struct stat s;
			stat(upload_command, &s);
			if (S_ISREG(s.st_mode)) {
#else
			if (dent->d_type == DT_REG) {
#endif
				snprintf(upload_command, sizeof upload_command, "%s%s", upload_path, dent->d_name);
				snprintf(upload_filename, sizeof upload_filename, "%s/%s", final_path, dent->d_name);

				closedir(inb);
				gotfile = 1;
				break;
			}
		}
		if (!gotfile) {
			closedir(inb);
			timeoutpaused = 0;
			return 0;
		}
	}
	if (conf.upload_checker != NULL) {
		argv[0] = strdup(basename(conf.upload_checker));
		argv[1] = strdup(upload_command);
		argv[2] = NULL;
		if (runexternal(gUser, conf.upload_checker, 1, argv, NULL, 0, (conf.upload_checker_codepage == NULL ? "CP437" : conf.upload_checker_codepage)) != 0) {
			s_printf(get_string(211));
			free(argv[0]);
			free(argv[1]);
			timeoutpaused = 0;
			return 0;
		}
		free(argv[0]);
		free(argv[1]);
	}

	if (access(upload_filename, F_OK) == 0) {
		recursive_delete(upload_path);
		s_printf(get_string(214));
		timeoutpaused = 0;
		return 0;
	}

	if (copy_file(upload_command, upload_filename) != 0) {
		recursive_delete(upload_path);
		timeoutpaused = 0;
		return 0;
	}

	recursive_delete(upload_path);
	timeoutpaused = 0;
	return 1;
}

void upload(struct user_record *user) {
	stralloc buffer = EMPTY_STRALLOC;
	char pathname[PATH_MAX];

	int i;
	char *create_sql = "CREATE TABLE IF NOT EXISTS files ("
	                   "Id INTEGER PRIMARY KEY,"
	                   "filename TEXT,"
	                   "description TEXT,"
	                   "size INTEGER,"
	                   "dlcount INTEGER,"
	                   "uploaddate INTEGER,"
	                   "approved INTEGER);";
	char *sql = "INSERT INTO files (filename, description, size, dlcount, approved, uploaddate) VALUES(?, ?, ?, 0, 0, ?)";
	sqlite3 *db;
	sqlite3_stmt *res;
	int rc;
	char *err_msg = NULL;
	char *description;
	time_t curtime;

	struct file_sub *sub = user_sub(user);

	if (!check_security(user, sub->upload_sec_level, &sub->up_req_flags, &sub->up_not_flags)) {
		s_printf(get_string(84));
		return;
	}

	if (!do_upload(user, sub->upload_path)) {
		s_printf(get_string(211));
		return;
	}

	description = NULL;

	s_printf(get_string(198));
	description = get_file_id_diz(upload_filename);

	if (description == NULL) {
		char descbuf[66];

		s_printf(get_string(199));
		s_printf(get_string(200));
		for (i = 0; i < 5; i++) {
			s_printf("\r\n%d: ", i);
			s_readstring(descbuf, sizeof(descbuf) - 1);
			if (*descbuf == '\0') {
				break;
			}
			stralloc_cats(&buffer, descbuf);
			stralloc_append1(&buffer, '\n');
		}
		stralloc_0(&buffer);
	} else {
		s_printf(get_string(201));
	}
	open_sub_db_or_die(&db, sub->database);
	rc = sqlite3_exec(db, create_sql, 0, 0, &err_msg);
	if (rc != SQLITE_OK) {
		dolog("SQL error: %s", err_msg);
		sqlite3_free(err_msg);
		sqlite3_close(db);
		free(description);
		free(buffer.s);
		return;
	}
	rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);

	if (rc == SQLITE_OK) {
		struct stat s;
		stat(upload_filename, &s);

		sqlite3_bind_text(res, 1, upload_filename, -1, 0);
		if (description == NULL) {
			sqlite3_bind_text(res, 2, buffer.s, -1, 0);
		} else {
			sqlite3_bind_text(res, 2, description, -1, 0);
		}
		sqlite3_bind_int(res, 3, s.st_size);
		curtime = time(NULL);
		sqlite3_bind_int(res, 4, curtime);
	} else {
		dolog("Failed to execute statement: %s", sqlite3_errmsg(db));
		sqlite3_finalize(res);
		sqlite3_close(db);
		free(description);
		free(buffer.s);
		return;
	}

	rc = sqlite3_step(res);

	if (rc != SQLITE_DONE) {
		dolog("execution failed: %s", sqlite3_errmsg(db));
		sqlite3_finalize(res);
		sqlite3_close(db);
		free(description);
		free(buffer.s);
		return;
	}
	sqlite3_finalize(res);
	sqlite3_close(db);
	free(description);
	free(buffer.s);

	s_printf(get_string(202));
	s_printf(get_string(6));
	s_getc();
}

void download_zmodem(struct user_record *user, char *filename) {
	ZModem zm;
	int done;

	dolog("Attempting to upload %s", filename);

	zm.attn = NULL;
	zm.windowsize = 0;
	zm.bufsize = 0;

	if (!sshBBS) {
		zm.ifd = gSocket;
		zm.ofd = gSocket;
	} else {
		zm.ifd = STDIN_FILENO;
		zm.ofd = STDOUT_FILENO;
	}
	zm.zrinitflags = 0;
	zm.zsinitflags = 0;

	zm.packetsize = 1024;

	ZmodemTInit(&zm);

	done = ZmodemTFile(filename, basename(filename), ZCBIN, 0, 0, 0, 1, 0, &zm);

	switch (done) {
		case 0:
			break;

		case ZmErrCantOpen:
			dolog("cannot open file \"%s\": %s", filename, strerror(errno));
			return;

		case ZmFileTooLong:
			dolog("filename \"%s\" too long, skipping...", filename);
			return;

		case ZmDone:
			return;

		default:
			return;
	}

	if (!done) {
		done = doIO(&zm);
	}

	if (done != ZmDone) {
		return;
	}

	done = ZmodemTFinish(&zm);

	if (!done) {
		done = doIO(&zm);
	}
}

void genurls() {
#if defined(ENABLE_WWW)
	int i;
	char *url;
	struct tagged_file *tf;
	if (conf.www_server) {
		for (i = 0; i < ptr_vector_len(&tagged_files); i++) {
			if (i % 6 == 0 && i != 0) {
				// pause
				s_printf(get_string(6));
				s_getc();
			}


			tf = ptr_vector_get(&tagged_files, i);
			url = www_create_link(tf->dir, tf->sub, tf->fid);

			if (url != NULL) {
				s_printf(get_string(255), basename(tf->filename));
				s_printf(get_string(256), url);
				free(url);
			} else {
				s_printf(get_string(257));
			}
		}
		for (i = 0; i < ptr_vector_len(&tagged_files); i++) {
			tf = ptr_vector_get(&tagged_files, i);
			free(tf->filename);
			free(tf);
		}
		destroy_ptr_vector(&tagged_files);
		init_ptr_vector(&tagged_files);
		s_printf(get_string(6));
		s_getc();
	} else {
		s_printf(get_string(258));
		s_printf(get_string(6));
		s_getc();
	}
#else
	s_printf(get_string(258));
	s_printf(get_string(6));
	s_getc();
#endif
}

void download(struct user_record *user) {
	int i;
	char *ssql = "select dlcount from files where filename like ?";
	char *usql = "update files set dlcount=? where filename like ?";
	char buffer[256];
	int dloads;
	sqlite3 *db;
	sqlite3_stmt *res;
	int rc;
	struct tagged_file *tf;

	for (i = 0; i < ptr_vector_len(&tagged_files); i++) {
		tf = ptr_vector_get(&tagged_files, i);
		s_printf(get_string(254), basename(tf->filename));

		do_download(user, tf->filename);

		struct file_sub *sub = get_sub(tf->dir, tf->sub);
		open_sub_db_or_die(&db, sub->database);
		rc = sqlite3_prepare_v2(db, ssql, -1, &res, 0);

		if (rc == SQLITE_OK) {
			sqlite3_bind_text(res, 1, tf->filename, -1, 0);
		} else {
			dolog("Failed to execute statement: %s", sqlite3_errmsg(db));
		}

		rc = sqlite3_step(res);

		if (rc != SQLITE_ROW) {
			dolog("Downloaded a file not in database!!!!!");
			sqlite3_finalize(res);
			sqlite3_close(db);
			exit(1);
		}

		dloads = sqlite3_column_int(res, 0);
		dloads++;
		sqlite3_finalize(res);

		rc = sqlite3_prepare_v2(db, usql, -1, &res, 0);

		if (rc == SQLITE_OK) {
			sqlite3_bind_int(res, 1, dloads);
			sqlite3_bind_text(res, 2, tf->filename, -1, 0);
		} else {
			dolog("Failed to execute statement: %s", sqlite3_errmsg(db));
		}

		rc = sqlite3_step(res);

		sqlite3_finalize(res);
		sqlite3_close(db);
	}

	for (i = 0; i < ptr_vector_len(&tagged_files); i++) {
		tf = ptr_vector_get(&tagged_files, i);
		free(tf->filename);
		free(tf);
	}
	destroy_ptr_vector(&tagged_files);
	init_ptr_vector(&tagged_files);
}

void do_list_files(struct file_entry **files_e, int files_c) {
	int file_size;
	char file_unit;
	int lines = 0;
	int i;
	int j;
	int z;
	int k;
	int match;
	struct tagged_file *tf;

	char buffer[6];
	struct stat s;
	struct tm file_tm;
	s_printf("\r\n");

	for (i = 0; i < files_c; i++) {
		file_size = files_e[i]->size;
		if (file_size > 1024 * 1024 * 1024) {
			file_size = file_size / 1024 / 1024 / 1024;
			file_unit = 'G';
		} else if (file_size > 1024 * 1024) {
			file_size = file_size / 1024 / 1024;
			file_unit = 'M';
		} else if (file_size > 1024) {
			file_size = file_size / 1024;
			file_unit = 'K';
		} else {
			file_unit = 'b';
		}

		if (stat(files_e[i]->filename, &s) != 0) {
			s_printf(get_string(315), i, files_e[i]->dlcount, file_size, file_unit, basename(files_e[i]->filename));
		} else {
			localtime_r(&s.st_mtime, &file_tm);
			if (files_e[i]->uploaddate > userlaston) {
				if (conf.date_style == 0) {
					s_printf(get_string(231), i, files_e[i]->dlcount, file_size, file_unit, file_tm.tm_mday, file_tm.tm_mon + 1, file_tm.tm_year + 1900, basename(files_e[i]->filename));
				} else {
					s_printf(get_string(231), i, files_e[i]->dlcount, file_size, file_unit, file_tm.tm_mon + 1, file_tm.tm_mday, file_tm.tm_year + 1900, basename(files_e[i]->filename));
				}
			} else {
				if (conf.date_style == 0) {
					s_printf(get_string(69), i, files_e[i]->dlcount, file_size, file_unit, file_tm.tm_mday, file_tm.tm_mon + 1, file_tm.tm_year + 1900, basename(files_e[i]->filename));
				} else {
					s_printf(get_string(69), i, files_e[i]->dlcount, file_size, file_unit, file_tm.tm_mon + 1, file_tm.tm_mday, file_tm.tm_year + 1900, basename(files_e[i]->filename));
				}
			}
		}
		lines += 3;
		for (j = 0; j < strlen(files_e[i]->description); j++) {
			if (files_e[i]->description[j] == '\n') {
				s_printf("\r\n");
				lines++;
				if (lines >= 18) {
					lines = 0;
					while (1) {
						s_printf(get_string(70));
						s_readstring(buffer, 5);
						if (strlen(buffer) == 0) {
							s_printf("\r\n");
							break;
						} else if (tolower(buffer[0]) == 'q') {
							for (z = 0; z < files_c; z++) {
								free(files_e[z]->filename);
								free(files_e[z]->description);
								free(files_e[z]);
							}
							free(files_e);
							s_printf("\r\n");
							return;
						} else {
							z = atoi(buffer);
							if (z >= 0 && z < files_c) {
								if (check_security(gUser, get_sub(files_e[z]->dir, files_e[z]->sub)->download_sec_level, &get_sub(files_e[z]->dir, files_e[z]->sub)->down_req_flags, &get_sub(files_e[z]->dir, files_e[z]->sub)->down_not_flags)) {
									match = 0;
									for (k = 0; k < ptr_vector_len(&tagged_files); k++) {
										tf = ptr_vector_get(&tagged_files, k);
										if (strcmp(tf->filename, files_e[z]->filename) == 0) {
											match = 1;
											break;
										}
									}
									if (match == 0) {
										struct tagged_file *file = (struct tagged_file *)malloz(sizeof(struct tagged_file));
										file->filename = strdup(files_e[z]->filename);
										file->dir = files_e[z]->dir;
										file->sub = files_e[z]->sub;
										file->fid = files_e[z]->fid;
										ptr_vector_append(&tagged_files, file);
										s_printf(get_string(71), basename(files_e[z]->filename));
									} else {
										s_printf(get_string(72));
									}
								} else {
									s_printf(get_string(73));
								}
							}
						}
					}
				}
				if (strlen(&(files_e[i]->description[j])) > 1) {
					s_printf(get_string(74));
				}
			} else {
				s_putchar(files_e[i]->description[j]);
			}
		}
		if (lines >= 18) {
			lines = 0;
			while (1) {
				s_printf(get_string(70));
				s_readstring(buffer, 5);
				if (strlen(buffer) == 0) {
					s_printf("\r\n");
					break;
				} else if (tolower(buffer[0]) == 'q') {
					for (z = 0; z < files_c; z++) {
						free(files_e[z]->filename);
						free(files_e[z]->description);
						free(files_e[z]);
					}
					free(files_e);
					s_printf("\r\n");
					return;
				} else {
					z = atoi(buffer);
					if (z >= 0 && z < files_c) {
						if (check_security(gUser, get_sub(files_e[z]->dir, files_e[z]->sub)->download_sec_level, &get_sub(files_e[z]->dir, files_e[z]->sub)->down_req_flags, &get_sub(files_e[z]->dir, files_e[z]->sub)->down_not_flags)) {
							match = 0;
							for (k = 0; k < ptr_vector_len(&tagged_files); k++) {
								tf = ptr_vector_get(&tagged_files, k);
								if (strcmp(tf->filename, files_e[z]->filename) == 0) {
									match = 1;
									break;
								}
							}
							if (match == 0) {
								struct tagged_file *file = (struct tagged_file *)malloz(sizeof(struct tagged_file));
								file->filename = strdup(files_e[z]->filename);
								file->dir = files_e[z]->dir;
								file->sub = files_e[z]->sub;
								file->fid = files_e[z]->fid;
								ptr_vector_append(&tagged_files, file);
								s_printf(get_string(71), basename(files_e[z]->filename));
							} else {
								s_printf(get_string(72));
							}
						} else {
							s_printf(get_string(73));
						}
					}
				}
			}
		}
	}
	while (1) {
		s_printf(get_string(75));
		s_readstring(buffer, 5);
		if (strlen(buffer) == 0) {
			for (z = 0; z < files_c; z++) {
				free(files_e[z]->filename);
				free(files_e[z]->description);
				free(files_e[z]);
			}
			free(files_e);
			s_printf("\r\n");
			return;
		} else {
			z = atoi(buffer);
			if (z >= 0 && z < files_c) {
				if (check_security(gUser, get_sub(files_e[z]->dir, files_e[z]->sub)->download_sec_level, &get_sub(files_e[z]->dir, files_e[z]->sub)->down_req_flags, &get_sub(files_e[z]->dir, files_e[z]->sub)->down_not_flags)) {
					match = 0;
					for (k = 0; k < ptr_vector_len(&tagged_files); k++) {
						tf = ptr_vector_get(&tagged_files, k);
						if (strcmp(tf->filename, files_e[z]->filename) == 0) {
							match = 1;
							break;
						}
					}
					if (match == 0) {
						struct tagged_file *file = (struct tagged_file *)malloz(sizeof(struct tagged_file));
						file->filename = strdup(files_e[z]->filename);
						file->dir = files_e[z]->dir;
						file->sub = files_e[z]->sub;
						file->fid = files_e[z]->fid;
						ptr_vector_append(&tagged_files, file);
						s_printf(get_string(71), basename(files_e[z]->filename));
					} else {
						s_printf(get_string(72));
					}
				} else {
					s_printf(get_string(73));
				}
			}
		}
	}
}

void file_search() {
	char ch;
	int all = 0;
	int stype = 0;
	char buffer[PATH_MAX];
	char sqlbuffer[1024];
	char **searchterms;
	size_t searchterm_count = 0;
	char *ptr;
	int i;
	int j;
	int search_dir;
	int search_sub;
	sqlite3 *db;
	sqlite3_stmt *res;
	int rc;
	int files_c;
	struct file_entry **files_e;
	struct ptr_vector files;

	s_printf(get_string(236));
	ch = s_getc();

	switch (tolower(ch)) {
		case 'd':
			stype = 1;
			break;
		case 'b':
			stype = 2;
			break;
	}

	s_printf(get_string(237));

	ch = s_getc();
	if (tolower(ch) == 'a') {
		all = 1;
	}

	s_printf(get_string(239));

	s_readstring(buffer, 128);

	if (strlen(buffer) == 0) {
		s_printf(get_string(238));
		return;
	}
	searchterms = split_on_space(buffer, &searchterm_count);

	for (i=0;i<searchterm_count;i++) {
		searchterms[i] = strdup(searchterms[i]);
	}

	if (stype == 0) {
		snprintf(sqlbuffer, sizeof sqlbuffer, "select id, filename, description, size, dlcount, uploaddate from files where approved=1 AND (filename LIKE '%' || ?");
		for (i = 1; i < searchterm_count; i++) {
			strlcat(sqlbuffer, " OR filename LIKE '%' || ?", sizeof sqlbuffer);
		}
		strlcat(sqlbuffer, ")", sizeof sqlbuffer);
	}
	if (stype == 1) {
		snprintf(sqlbuffer, sizeof sqlbuffer, "select id, filename, description, size, dlcount, uploaddate from files where approved=1 AND (description LIKE '%' || ? || '%'");
		for (i = 1; i < searchterm_count; i++) {
			strlcat(sqlbuffer, " OR description LIKE '%' || ? || '%'", sizeof sqlbuffer);
		}
		strlcat(sqlbuffer, ")", sizeof sqlbuffer);
	}
	if (stype == 2) {
		snprintf(sqlbuffer, sizeof sqlbuffer, "select id, filename, description, size, dlcount, uploaddate from files where approved=1 AND (filename LIKE '%' || ?");
		for (i = 1; i < searchterm_count; i++) {
			strlcat(sqlbuffer, " OR filename LIKE '%' || ?", sizeof sqlbuffer);
		}
		strlcat(sqlbuffer, " OR description LIKE '%' || ? || '%'", sizeof sqlbuffer);
		for (i = 1; i < searchterm_count; i++) {
			strlcat(sqlbuffer, " OR description LIKE '%' || ? || '%'", sizeof sqlbuffer);
		}
		strlcat(sqlbuffer, ")", sizeof sqlbuffer);
	}

	if (!all) {
		files_c = 0;
		struct file_sub *sub = user_sub(gUser);
		open_sub_db_or_die(&db, sub->database);

		rc = sqlite3_prepare_v2(db, sqlbuffer, -1, &res, 0);

		if (rc != SQLITE_OK) {
			sqlite3_finalize(res);
			sqlite3_close(db);
			for (i = 0; i < searchterm_count; i++) {
				free(searchterms[i]);
			}
			free(searchterms);
			return;
		}
		if (stype == 2) {
			for (j = 0; j < 2; j++) {
				for (i = 0; i < searchterm_count; i++) {
					sqlite3_bind_text(res, j * searchterm_count + i + 1, searchterms[i], -1, 0);
				}
			}
		} else {
			for (i = 0; i < searchterm_count; i++) {
				sqlite3_bind_text(res, i + 1, searchterms[i], -1, 0);
			}
		}

		init_ptr_vector(&files);
		while (sqlite3_step(res) == SQLITE_ROW) {
			struct file_entry *file = (struct file_entry *)malloz(sizeof(struct file_entry));
			file->fid = sqlite3_column_int(res, 0);
			file->filename = strdup((char *)sqlite3_column_text(res, 1));
			file->description = strdup((char *)sqlite3_column_text(res, 2));
			file->size = sqlite3_column_int(res, 3);
			file->dlcount = sqlite3_column_int(res, 4);
			file->uploaddate = sqlite3_column_int(res, 5);
			file->dir = gUser->cur_file_dir;
			file->sub = gUser->cur_file_sub;
			ptr_vector_append(&files, file);
		}
		files_c = ptr_vector_len(&files);
		files_e = (struct file_entry **)consume_ptr_vector(&files);

		sqlite3_finalize(res);
		sqlite3_close(db);

		if (files_c != 0) {
			do_list_files(files_e, files_c);
		}
	} else {
		files_c = 0;
		init_ptr_vector(&files);
		for (search_dir = 0; search_dir < ptr_vector_len(&conf.file_directories); search_dir++) {
			struct file_directory *dir = ptr_vector_get(&conf.file_directories, search_dir);
			if (!check_security(gUser, dir->sec_level, &dir->vis_req_flags, &dir->vis_not_flags)) {
				continue;
			}

			for (search_sub = 0; search_sub < ptr_vector_len(&dir->file_subs); search_sub++) {
				struct file_sub *sub = ptr_vector_get(&dir->file_subs, search_sub);
				if (!check_security(gUser, sub->download_sec_level, &sub->down_req_flags, &sub->down_not_flags)) {
					continue;
				}
				open_sub_db_or_die(&db, sub->database);

				rc = sqlite3_prepare_v2(db, sqlbuffer, -1, &res, 0);

				if (rc != SQLITE_OK) {
					sqlite3_finalize(res);
					sqlite3_close(db);
					continue;
				}
				if (stype == 2) {
					for (j = 0; j < 2; j++) {
						for (i = 0; i < searchterm_count; i++) {
							sqlite3_bind_text(res, j * searchterm_count + i + 1, searchterms[i], -1, 0);
						}
					}
				} else {
					for (i = 0; i < searchterm_count; i++) {
						sqlite3_bind_text(res, i + 1, searchterms[i], -1, 0);
					}
				}


				while (sqlite3_step(res) == SQLITE_ROW) {
					struct file_entry *file = (struct file_entry *)malloz(sizeof(struct file_entry));
					file->fid = sqlite3_column_int(res, 0);
					file->filename = strdup((char *)sqlite3_column_text(res, 1));
					file->description = strdup((char *)sqlite3_column_text(res, 2));
					file->size = sqlite3_column_int(res, 3);
					file->dlcount = sqlite3_column_int(res, 4);
					file->uploaddate = sqlite3_column_int(res, 5);
					file->dir = search_dir;
					file->sub = search_sub;
					ptr_vector_append(&files, file);
				}


				sqlite3_finalize(res);
				sqlite3_close(db);

			}
		}

		files_c = ptr_vector_len(&files);
		files_e = (struct file_entry **)consume_ptr_vector(&files);

		if (files_c != 0) {
			do_list_files(files_e, files_c);
		}
	}
	for (i = 0; i < searchterm_count; i++) {
		free(searchterms[i]);
	}
	free(searchterms);
}

void list_files(struct user_record *user) {
	char *dsql = "select id, filename, description, size, dlcount, uploaddate from files where approved=1 ORDER BY uploaddate DESC";
	char *fsql = "select id, filename, description, size, dlcount, uploaddate from files where approved=1 ORDER BY filename";
	char *psql = "select id, filename, description, size, dlcount, uploaddate from files where approved=1 ORDER BY dlcount DESC";
	char *nsql = "select id, filename, description, size, dlcount, uploaddate from files where approved=1 ORDER BY uploaddate DESC WHERE uploaddate > ?";
	char *sql;
	char buffer[PATH_MAX];
	sqlite3 *db;
	sqlite3_stmt *res;
	int rc;
	int files_c;

	char ch;
	struct file_entry **files_e;
	struct ptr_vector files;

	s_printf(get_string(233));
	ch = s_getc();

	switch (tolower(ch)) {
		case 'u':
			sql = dsql;
			break;
		case 'p':
			sql = psql;
			break;
		case 'n':
			sql = nsql;
			break;
		default:
			sql = fsql;
			break;
	}
	s_printf("\r\n");
	struct file_sub *sub = user_sub(user);
	open_sub_db_or_die(&db, sub->database);
	rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
	if (rc != SQLITE_OK) {
		sqlite3_close(db);
		s_printf(get_string(68));
		return;
	}
	if (sql == nsql) {
		sqlite3_bind_int(res, 1, userlaston);
	}

	init_ptr_vector(&files);
	while (sqlite3_step(res) == SQLITE_ROW) {
		struct file_entry *file = (struct file_entry *)malloz(sizeof(struct file_entry));
		file->fid = sqlite3_column_int(res, 0);
		file->filename = strdup((char *)sqlite3_column_text(res, 1));
		file->description = strdup((char *)sqlite3_column_text(res, 2));
		file->size = sqlite3_column_int(res, 3);
		file->dlcount = sqlite3_column_int(res, 4);
		file->uploaddate = sqlite3_column_int(res, 5);
		file->dir = user->cur_file_dir;
		file->sub = user->cur_file_sub;
		ptr_vector_append(&files, file);
	}
	files_c = ptr_vector_len(&files);
	files_e = (struct file_entry **)consume_ptr_vector(&files);

	sqlite3_finalize(res);
	sqlite3_close(db);

	if (files_c == 0) {
		s_printf(get_string(68));
		return;
	}

	do_list_files(files_e, files_c);
}

struct subdir_tmp_t {
	struct file_sub *sub;
	int index;
};

void choose_subdir() {
	int i;
	int list_tmp = 0;
	struct subdir_tmp_t **sub_tmp;
	int redraw = 1;
	int start = 0;
	int selected = 0;
	char c;
	struct ptr_vector subs;
	int area_jump = 0;

	init_ptr_vector(&subs);
	struct file_directory *dir = user_dir(gUser);
	for (i = 0; i < ptr_vector_len(&dir->file_subs); i++) {
		struct file_sub *fsub = ptr_vector_get(&dir->file_subs, i);
		if (check_security(gUser, fsub->download_sec_level, &fsub->down_req_flags, &fsub->down_not_flags)) {
			struct subdir_tmp_t *sub = (struct subdir_tmp_t *)malloz(sizeof(struct subdir_tmp_t));
			sub->sub = fsub;
			sub->index = i;
			ptr_vector_append(&subs, sub);
		}
	}
	list_tmp = ptr_vector_len(&subs);
	sub_tmp = (struct subdir_tmp_t **)consume_ptr_vector(&subs);

	while (1) {
		if (redraw) {
			s_printf("\e[2J\e[1;1H");
			s_printf(get_string(252), user_dir(gUser)->name);
			s_printf(get_string(248));
			for (i = start; i < start + 22 && i < list_tmp; i++) {
				if (i == selected) {
					s_printf(get_string(249), i - start + 2, sub_tmp[i]->index, sub_tmp[i]->sub->name);
				} else {
					s_printf(get_string(250), i - start + 2, sub_tmp[i]->index, sub_tmp[i]->sub->name);
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
					area_jump = 0;
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
							s_printf(get_string(250), selected - start + 1, sub_tmp[selected - 1]->index, sub_tmp[selected - 1]->sub->name);
							s_printf(get_string(249), selected - start + 2, sub_tmp[selected]->index, sub_tmp[selected]->sub->name);
							s_printf("\e[%d;5H", selected - start + 2);
						}
					}
				} else if (c == 65) {
					// up
					area_jump = 0;
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
							s_printf(get_string(249), selected - start + 2, sub_tmp[selected]->index, sub_tmp[selected]->sub->name);
							s_printf(get_string(250), selected - start + 3, sub_tmp[selected + 1]->index, sub_tmp[selected + 1]->sub->name);
							s_printf("\e[%d;5H", selected - start + 2);
						}
					}
				} else if (c == 75) {
					// END KEY
					area_jump = 0;
					selected = list_tmp - 1;
					start = list_tmp - 22;
					if (start < 0) {
						start = 0;
					}
					redraw = 1;
				} else if (c == 72) {
					// HOME KEY
					area_jump = 0;
					selected = 0;
					start = 0;
					redraw = 1;
				} else if (c == 86 || c == '5') {
					if (c == '5') {
						s_getchar();
					}
					// PAGE UP
					area_jump = 0;
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
					area_jump = 0;
					selected = selected + 22;
					if (selected >= list_tmp) {
						selected = list_tmp - 1;
					}
					start = selected;
					redraw = 1;
				}
			}
		} else if (c == 13) {
			gUser->cur_file_sub = sub_tmp[selected]->index;
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
		free(sub_tmp[i]);
	}
	free(sub_tmp);
}

struct dir_tmp_t {
	struct file_directory *dir;
	int index;
};

void choose_directory() {
	int i;
	int list_tmp = 0;
	struct dir_tmp_t **dir_tmp;
	int redraw = 1;
	int start = 0;
	int selected = 0;
	char c;
	struct ptr_vector dirs;
	int area_jump = 0;

	init_ptr_vector(&dirs);
	for (i = 0; i < ptr_vector_len(&conf.file_directories); i++) {
		struct file_directory *fdir = ptr_vector_get(&conf.file_directories, i);
		if (check_security(gUser, fdir->sec_level, &fdir->vis_req_flags, &fdir->vis_not_flags)) {
			struct dir_tmp_t *dir = (struct dir_tmp_t *)malloz(sizeof(struct dir_tmp_t));
			dir->dir = fdir;
			dir->index = i;
			ptr_vector_append(&dirs, dir);
		}
	}
	list_tmp = ptr_vector_len(&dirs);
	dir_tmp = (struct dir_tmp_t **)consume_ptr_vector(&dirs);

	while (1) {
		if (redraw) {
			s_printf("\e[2J\e[1;1H");
			s_printf(get_string(253));
			s_printf(get_string(248));
			for (i = start; i < start + 22 && i < list_tmp; i++) {
				if (i == selected) {
					s_printf(get_string(249), i - start + 2, dir_tmp[i]->index, dir_tmp[i]->dir->name);
				} else {
					s_printf(get_string(250), i - start + 2, dir_tmp[i]->index, dir_tmp[i]->dir->name);
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
					area_jump = 0;
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
							s_printf(get_string(250), selected - start + 1, dir_tmp[selected - 1]->index, dir_tmp[selected - 1]->dir->name);
							s_printf(get_string(249), selected - start + 2, dir_tmp[selected]->index, dir_tmp[selected]->dir->name);
							s_printf("\e[%d;5H", selected - start + 2);
						}
					}
				} else if (c == 65) {
					// up
					area_jump = 0;
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
							s_printf(get_string(249), selected - start + 2, dir_tmp[selected]->index, dir_tmp[selected]->dir->name);
							s_printf(get_string(250), selected - start + 3, dir_tmp[selected + 1]->index, dir_tmp[selected + 1]->dir->name);
							s_printf("\e[%d;5H", selected - start + 2);
						}
					}
				} else if (c == 75) {
					// END KEY
					area_jump = 0;
					selected = list_tmp - 1;
					start = list_tmp - 22;
					if (start < 0) {
						start = 0;
					}
					redraw = 1;
				} else if (c == 72) {
					// HOME KEY
					area_jump = 0;
					selected = 0;
					start = 0;
					redraw = 1;
				} else if (c == 86 || c == '5') {
					if (c == '5') {
						s_getchar();
					}
					// PAGE UP
					area_jump = 0;
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
					area_jump = 0;
					selected = selected + 22;
					if (selected >= list_tmp) {
						selected = list_tmp - 1;
					}
					start = selected;
					redraw = 1;
				}
			}
		} else if (c == 13) {
			gUser->cur_file_dir = dir_tmp[selected]->index;
			gUser->cur_file_sub = 0;
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
		free(dir_tmp[i]);
	}
	free(dir_tmp);
}

void clear_tagged_files() {
	int i;
	struct tagged_file *tf;
	// Clear tagged files
	if (ptr_vector_len(&tagged_files) > 0) {
		for (i = 0; i < ptr_vector_len(&tagged_files); i++) {
			tf = ptr_vector_get(&tagged_files, i);
			free(tf->filename);
			free(tf);
		}
		destroy_ptr_vector(&tagged_files);
		init_ptr_vector(&tagged_files);
	}
}

void next_file_dir(struct user_record *user) {
	size_t n = ptr_vector_len(&conf.file_directories);
	size_t start = user->cur_file_dir;
	size_t i;
	for (i = (start + 1) % n; i != start; i = (i + 1) % n) {
		struct file_directory *dir = get_dir(i);
		if (check_security(user, dir->sec_level, &dir->vis_req_flags, &dir->vis_not_flags))
			break;
	}
	user->cur_file_dir = i;
	user->cur_file_sub = 0;
}

void prev_file_dir(struct user_record *user) {
	size_t n = ptr_vector_len(&conf.file_directories);
	size_t start = user->cur_file_dir;
	size_t i;
	for (i = (start + n - 1) % n; i != start; i = (i + n - 1) % n) {
		struct file_directory *dir = get_dir(i);
		if (check_security(user, dir->sec_level, &dir->vis_req_flags, &dir->vis_not_flags))
			break;
	}
	user->cur_file_dir = i;
	user->cur_file_sub = 0;
}

void next_file_sub(struct user_record *user) {

	size_t n = ptr_vector_len(&get_dir(user->cur_file_dir)->file_subs);
	user->cur_file_sub = (user->cur_file_sub + 1) % n;
}

void prev_file_sub(struct user_record *user) {
	size_t n = ptr_vector_len(&get_dir(user->cur_file_dir)->file_subs);
	user->cur_file_sub = (user->cur_file_sub + n - 1) % n;
}

void file_scan() {
	char c;
	int i;
	int j;
	char buffer[PATH_MAX];
	char sql[] = "SELECT COUNT(*) FROM files WHERE uploaddate > ? AND approved=1";
	int rc;
	sqlite3 *db;
	sqlite3_stmt *res;
	int new_files;
	int lines = 0;

	s_printf(get_string(232));
	c = s_getc();

	if (tolower(c) == 'y') {
		for (i = 0; i < ptr_vector_len(&conf.file_directories); i++) {
			struct file_directory *dir = ptr_vector_get(&conf.file_directories, i);
			if (!check_security(gUser, dir->sec_level, &dir->vis_req_flags, &dir->vis_not_flags)) {
				continue;
			}
			s_printf(get_string(140), i, dir->name);
			lines += 2;
			if (lines == 22) {
				s_printf(get_string(6));
				s_getc();
				lines = 0;
			}
			for (j = 0; j < ptr_vector_len(&dir->file_subs); j++) {
				struct file_sub *sub = ptr_vector_get(&dir->file_subs, j);
				if (!check_security(gUser, sub->download_sec_level, &sub->down_req_flags, &sub->down_not_flags)) {
					continue;
				}
				open_sub_db_or_die(&db, sub->database);
				rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);

				if (rc != SQLITE_OK) {
					sqlite3_finalize(res);
					sqlite3_close(db);
					continue;
				}
				sqlite3_bind_int(res, 1, userlaston);

				if (sqlite3_step(res) != SQLITE_ERROR) {
					new_files = sqlite3_column_int(res, 0);
					if (new_files > 0) {
						s_printf(get_string(141), j, sub->name, new_files);
						lines++;
					}
				}
				sqlite3_finalize(res);
				sqlite3_close(db);

				if (lines == 22) {
					s_printf(get_string(6));
					s_getc();
					lines = 0;
				}
			}
		}
		s_printf(get_string(6));
		s_getc();
	}
}
