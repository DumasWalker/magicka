#include <stdio.h>
#include <sys/stat.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <iconv.h>
#if defined(linux)
#include <pty.h>
#elif defined(__OpenBSD__) || defined(__NetBSD__) || defined(__APPLE__)
#include <util.h>
#elif defined(__FreeBSD__)
#include <libutil.h>
#elif defined(__sun)
#include "os/sunos.h"
#endif
#ifdef __HAIKU__
#include <sys/select.h>
#endif
#include "bbs.h"
#include "lua/lua.h"
#include "lua/lualib.h"
#include "lua/lauxlib.h"

extern struct bbs_config conf;
extern int mynode;
extern int gSocket;
extern int sshBBS;
extern int bbs_stderr;

int running_door_pid = 0;
int running_door = 0;

extern int telnet_bin_mode;
extern int timeoutpaused;

int doorret = 0;

void doorchld_handler(int s) {
	// waitpid() might overwrite errno, so we save and restore it:
	while (waitpid(-1, &doorret, WNOHANG) > 0)
		;

	running_door = 0;
}

int write_door32sys(struct user_record *user) {
	struct stat s;
	char buffer[1024];
	FILE *fptr;
	char *ptr;
	int i;

	snprintf(buffer, sizeof buffer, "%s/node%d", conf.bbs_path, mynode);

	if (stat(buffer, &s) != 0) {
		mkdir(buffer, 0755);
	}

	snprintf(buffer, 1024, "%s/node%d/door32.sys", conf.bbs_path, mynode);

	fptr = fopen(buffer, "w");

	if (!fptr) {
		dolog("Unable to open %s for writing!", buffer);
		return 1;
	}

	fprintf(fptr, "2\r\n");           // telnet type
	fprintf(fptr, "%d\r\n", gSocket); // socket
	fprintf(fptr, "38400\r\n");       // baudrate
	fprintf(fptr, "Magicka %d.%d\r\n", VERSION_MAJOR, VERSION_MINOR);
	fprintf(fptr, "%d\r\n", user->id);
	fprintf(fptr, "%s %s\r\n", user->firstname, user->lastname);
	fprintf(fptr, "%s\r\n", user->loginname);
	fprintf(fptr, "%d\r\n", user->sec_level);
	fprintf(fptr, "%d\r\n", user->timeleft);
	fprintf(fptr, "1\r\n"); // ansi emulation = 1
	fprintf(fptr, "%d\r\n", mynode);

	fclose(fptr);

	// create dorinfo1.def

	snprintf(buffer, sizeof buffer, "%s/node%d/dorinfo1.def", conf.bbs_path, mynode);

	fptr = fopen(buffer, "w");

	if (!fptr) {
		dolog("Unable to open %s for writing!", buffer);
		return 1;
	}

	strlcpy(buffer, conf.sysop_name, sizeof(buffer));

	ptr = NULL;

	for (i = 0; i < strlen(buffer); i++) {
		if (buffer[i] == ' ') {
			ptr = &buffer[i + 1];
			buffer[i] = '\0';
			break;
		}
	}

	fprintf(fptr, "%s\r\n", conf.bbs_name); // telnet type
	fprintf(fptr, "%s\r\n", buffer);
	if (ptr != NULL) {
		fprintf(fptr, "%s\r\n", ptr);
	} else {
		fprintf(fptr, "\r\n");
	}
	fprintf(fptr, "COM1\r\n"); // com port
	fprintf(fptr, "38400 BAUD,N,8,1\r\n");
	fprintf(fptr, "0\r\n");
	fprintf(fptr, "%s\r\n", user->firstname);
	fprintf(fptr, "%s\r\n", user->lastname);
	fprintf(fptr, "%s\r\n", user->location);
	fprintf(fptr, "1\r\n");
	fprintf(fptr, "%d\r\n", user->sec_level);
	fprintf(fptr, "%d\r\n", user->timeleft);
	fprintf(fptr, "-1\r\n");

	fclose(fptr);

	// create door.sys

	snprintf(buffer, sizeof buffer, "%s/node%d/door.sys", conf.bbs_path, mynode);

	fptr = fopen(buffer, "w");

	if (!fptr) {
		dolog("Unable to open %s for writing!", buffer);
		return 1;
	}

	fprintf(fptr, "COM1:\r\n");
	fprintf(fptr, "38400\r\n");
	fprintf(fptr, "8\r\n");
	fprintf(fptr, "%d\r\n", mynode);
	fprintf(fptr, "38400\r\n");
	fprintf(fptr, "Y\r\n");
	fprintf(fptr, "N\r\n");
	fprintf(fptr, "Y\r\n");
	fprintf(fptr, "Y\r\n");
	fprintf(fptr, "%s %s\r\n", user->firstname, user->lastname);
	fprintf(fptr, "%s\r\n", user->location);
	fprintf(fptr, "00-0000-0000\r\n");
	fprintf(fptr, "00-0000-0000\r\n");
	fprintf(fptr, "SECRET\r\n");
	fprintf(fptr, "%d\r\n", user->sec_level);
	fprintf(fptr, "%d\r\n", user->timeson);
	fprintf(fptr, "01-01-1971\r\n");
	fprintf(fptr, "%d\r\n", user->timeleft * 60);
	fprintf(fptr, "%d\r\n", user->timeleft);
	fprintf(fptr, "GR\r\n");
	fprintf(fptr, "25\r\n");
	fprintf(fptr, "N\r\n");
	fprintf(fptr, "\r\n");
	fprintf(fptr, "\r\n");
	fprintf(fptr, "\r\n");
	fprintf(fptr, "%d\r\n", user->id);
	fprintf(fptr, "\r\n");
	fprintf(fptr, "0\r\n");
	fprintf(fptr, "0\r\n");
	fprintf(fptr, "0\r\n");
	fprintf(fptr, "99999\r\n");
	fprintf(fptr, "01-01-1971\r\n");
	fprintf(fptr, "\r\n");
	fprintf(fptr, "\r\n");
	fprintf(fptr, "%s\r\n", conf.sysop_name);
	fprintf(fptr, "%s\r\n", user->loginname);
	fprintf(fptr, "none\r\n");
	fprintf(fptr, "Y\r\n");
	fprintf(fptr, "N\r\n");
	fprintf(fptr, "Y\r\n");
	fprintf(fptr, "7\r\n");
	fprintf(fptr, "0\r\n");
	fprintf(fptr, "01-01-1971\r\n");
	fprintf(fptr, "00:00\r\n");
	fprintf(fptr, "00:00\r\n");
	fprintf(fptr, "32768\r\n");
	fprintf(fptr, "0\r\n");
	fprintf(fptr, "0\r\n");
	fprintf(fptr, "0\r\n");
	fprintf(fptr, "None.\r\n");
	fprintf(fptr, "0\r\n");
	fprintf(fptr, "0\r\n");

	fclose(fptr);

	return 0;
}

void rundoor(struct user_record *user, char *cmd, int stdio, char *codepage) {
	char *arguments[4];
	int door_out;
	char buffer[10];

	if (sshBBS) {
		door_out = STDOUT_FILENO;
	} else {
		door_out = gSocket;
	}
	arguments[0] = strdup(cmd);
	snprintf(buffer, sizeof buffer, "%d", mynode);
	arguments[1] = strdup(buffer);
	snprintf(buffer, sizeof buffer, "%d", door_out);
	arguments[2] = strdup(buffer);
	arguments[3] = NULL;

	runexternal(user, cmd, stdio, arguments, NULL, 0, codepage);

	free(arguments[0]);
	free(arguments[1]);
	free(arguments[2]);
}

int runexternal(struct user_record *user, char *cmd, int stdio, char *argv[], char *cwd, int raw, char *codepage) {

	char buffer[1024];
	int ret = 0;
	unsigned char c;
	int len;
	int master;
	int slave;
	fd_set fdset;
	int t;
	struct winsize ws;
	struct sigaction sa;
	int door_in;
	int door_out;
	int i;
	int gotiac;
	int flush;
	iconv_t ic;

	struct timeval thetimeout;
	struct termios oldit;
	struct termios oldot;
	struct termios oldit2;

	char inbuf[256];
	char outbuf[512];
	int h;
	int g;
	char *ptr1;
	char *ptr2;
	char *ptr2p;
	size_t ouc;
	size_t inc;
	size_t sz;
	char **args, *arg;
	struct ptr_vector args_vec;
	pid_t pid;
	int iac;
	char iac_binary_will[] = {IAC, IAC_WILL, IAC_TRANSMIT_BINARY, '\0'};
	char iac_binary_do[] = {IAC, IAC_DO, IAC_TRANSMIT_BINARY, '\0'};
	char iac_binary_wont[] = {IAC, IAC_WONT, IAC_TRANSMIT_BINARY, '\0'};
	char iac_binary_dont[] = {IAC, IAC_DONT, IAC_TRANSMIT_BINARY, '\0'};

	timeoutpaused = 1;

	if (write_door32sys(user) != 0) {
		return -1;
	}

	doorret = 0;

	if (stdio) {

		if (sshBBS) {
			door_in = STDIN_FILENO;
			door_out = STDOUT_FILENO;
		} else {
			door_in = gSocket;
			door_out = gSocket;
		}

		ws.ws_row = 24;
		ws.ws_col = 80;

		running_door = 1;

		if (openpty(&master, &slave, NULL, NULL, &ws) == 0) {
			sa.sa_handler = doorchld_handler;
			sigemptyset(&sa.sa_mask);
			sa.sa_flags = SA_RESTART | SA_SIGINFO;
			if (sigaction(SIGCHLD, &sa, NULL) == -1) {
				perror("sigaction");
				exit(1);
			}

			if (sshBBS) {
				ttySetRaw(STDIN_FILENO, &oldit);
				ttySetRaw(STDOUT_FILENO, &oldot);
			}

			if (raw) {
				ttySetRaw(master, &oldit2);
				ttySetRaw(slave, &oldit2);
			}
			pid = fork();
			if (pid < 0) {
				return -1;
			} else if (pid == 0) {
				if (cwd != NULL) {
					chdir(cwd);
				}
				close(master);
				dup2(slave, 0);
				dup2(slave, 1);
				dup2(bbs_stderr, 2);

				close(slave);

				setsid();

				ioctl(0, TIOCSCTTY, 1);

				execvp(cmd, argv);
				exit(-1);
			} else {
				running_door_pid = pid;
				gotiac = 0;
				flush = 0;

				while (running_door || !flush) {
					FD_ZERO(&fdset);
					FD_SET(master, &fdset);
					FD_SET(door_in, &fdset);
					if (master > door_in) {
						t = master + 1;
					} else {
						t = door_in + 1;
					}

					thetimeout.tv_sec = 5;
					thetimeout.tv_usec = 0;

					ret = select(t, &fdset, NULL, NULL, &thetimeout);
					if (ret > 0) {
						if (FD_ISSET(door_in, &fdset)) {
							len = read(door_in, inbuf, 256);
							if (len == 0) {
								close(master);
								disconnect("Socket Closed");
								return -1;
							}
							g = 0;
							for (h = 0; h < len; h++) {
								c = inbuf[h];
								if (!raw) {
									if (c == '\n' || c == '\0') {
										continue;
									}
								}
								if (!running_door) {
									continue;
								}

								if (!sshBBS) {
									if (c == 255) {
										if (gotiac == 1) {
											outbuf[g++] = c;
											gotiac = 0;
										} else {
											gotiac = 1;
										}
									} else {
										if (gotiac == 1) {
											if (c == 254 || c == 253 || c == 252 || c == 251) {
												gotiac = 2;
												iac = c;
											} else if (c == 250) {
												gotiac = 3;
											} else {
												gotiac = 0;
											}
										} else if (gotiac == 2) {
											switch (iac) {
												case IAC_WILL:
													if (c == 0) {
														if (telnet_bin_mode != 1) {
															telnet_bin_mode = 1;
															write(master, iac_binary_do, 3);
														}
													}
													break;
												case IAC_WONT:
													if (c == 0) {
														if (telnet_bin_mode != 0) {
															telnet_bin_mode = 0;
															write(master, iac_binary_dont, 3);
														}
													}
													break;
												case IAC_DO:
													if (c == 0) {
														if (telnet_bin_mode != 1) {
															telnet_bin_mode = 1;
															write(master, iac_binary_will, 3);
														}
													}
													break;
												case IAC_DONT:
													if (c == 0) {
														if (telnet_bin_mode != 0) {
															telnet_bin_mode = 0;
															write(master, iac_binary_wont, 3);
														}
													}
													break;
											}
											gotiac = 0;
										} else if (gotiac == 3) {
											if (c == 240) {
												gotiac = 0;
											}
										} else {
											outbuf[g++] = c;
										}
									}
								} else {
									outbuf[g++] = c;
								}
							}
							if (codepage == NULL || (strcmp(codepage, "CP437") == 0 && user->codepage == 0) || (strcmp(codepage, "UTF-8") == 0 && user->codepage == 1) || raw) {
								write(master, outbuf, g);
							} else {
								if (user->codepage == 0) {
									ic = iconv_open(codepage, "CP437");
								} else {
									ic = iconv_open(codepage, "UTF-8");
								}
								ptr1 = outbuf;
								ptr2 = (char *)malloz((g + 1) * 4);
								ptr2p = ptr2;
								inc = g;
								ouc = (g + 1) * 4;

								iconv(ic, &ptr1, &inc, &ptr2, &ouc);
								write(master, ptr2p, ptr2 - ptr2p);

								free(ptr2p);
								iconv_close(ic);
							}
						} else if (FD_ISSET(master, &fdset)) {
							len = read(master, inbuf, 256);
							if (len == 0) {
								close(master);
								break;
							}
							g = 0;

							for (h = 0; h < len; h++) {
								c = inbuf[h];
								if (c == 255 && !sshBBS) {
									outbuf[g++] = c;
								}
								outbuf[g++] = c;
							}
							if (codepage == NULL || (strcmp(codepage, "CP437") == 0 && user->codepage == 0) || (strcmp(codepage, "UTF-8") == 0 && user->codepage == 1) || raw) {
								write(door_out, outbuf, g);
							} else {
								if (user->codepage == 0) {
									ic = iconv_open("CP437", codepage);
								} else {
									ic = iconv_open("UTF-8", codepage);
								}
								ptr1 = outbuf;
								ptr2 = (char *)malloz((g + 1) * 4);
								ptr2p = ptr2;
								inc = g;
								ouc = (g + 1) * 4;

								sz = iconv(ic, &ptr1, &inc, &ptr2, &ouc);
								if (sz == -1) {
									perror("Iconv");
								}
								write(door_out, ptr2p, ptr2 - ptr2p);

								free(ptr2p);
								iconv_close(ic);
							}
						}
					} else {
						if (!running_door) {
							flush = 1;
						}
					}
				}

				if (WIFEXITED(doorret)) {
					ret = WEXITSTATUS(doorret);
				} else {
					ret = -1;
				}
			}
			if (sshBBS) {
				tcsetattr(STDIN_FILENO, TCSANOW, &oldit);
				tcsetattr(STDOUT_FILENO, TCSANOW, &oldot);
			}
		}

	/*	} else {

			if (raw) {
				ttySetRaw(STDIN_FILENO, &oldit);
				ttySetRaw(STDOUT_FILENO, &oldot);
			}

			sa.sa_handler = doorchld_handler;
			sigemptyset(&sa.sa_mask);
			sa.sa_flags = SA_RESTART | SA_SIGINFO;
			if (sigaction(SIGCHLD, &sa, NULL) == -1) {
				perror("sigaction");
				exit(1);
			}
			pid = fork();
			if (pid < 0) {
				return -1;
			} else if (pid == 0) {
				if (cwd != NULL) {
					chdir(cwd);
				}

				dup2(bbs_stderr, 2);
				execvp(cmd, argv);
			} else {
				while (running_door) {
					sleep(1);
				}
				if (WIFEXITED(doorret)) {
					ret = WEXITSTATUS(doorret);
				} else {
					ret = -1;
				}
			}


		}
		* */
	} else {
		if (!sshBBS) {
			snprintf(buffer, 1024, "%s", cmd);
			for (i = 1; argv[i] != NULL; i++) {
				snprintf(&buffer[strlen(buffer)], 1024 - strlen(buffer), " %s", argv[i]);
			}

			args = split_args(buffer, NULL);
			cmd = args[0];
			pid = fork();
			if (pid == 0) {
				if (cwd != NULL) {
					chdir(cwd);
				}
				execvp(cmd, args);
				exit(0);
			} else if (pid > 0) {
				waitpid(pid, &ret, 0);
				if (WIFEXITED(ret)) {
					ret = WEXITSTATUS(ret);
				}
			} else {
				ret = -1;
			}
			free(args);
			if (cwd != NULL) {
				chdir(conf.bbs_path);
			}
		} else {
			s_printf(get_string(51));
		}
	}
	timeoutpaused = 0;

	return ret;
}
