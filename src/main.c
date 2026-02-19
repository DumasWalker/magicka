#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <pwd.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#ifndef DISABLE_SSH
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>
#endif
#include <string.h>
#include <poll.h>
#if defined(linux)
#include <pty.h>
#elif defined(__OpenBSD__) || defined(__NetBSD__) || defined(__APPLE__)
#include <util.h>
#elif defined(__FreeBSD__)
#include <libutil.h>
#elif defined(__sun)
#include "os/sunos.h"
#endif
#if defined(ENABLE_WWW)
#include <microhttpd.h>
#endif
#include <termios.h>
#include "bbs.h"
#include "inih/ini.h"
#include "hashmap/hashmap.h"
#include "msglib/msglib.h"

map_t ip_guard_map;

extern struct bbs_config conf;
extern struct user_record *gUser;

int ssh_pid = -1;
int bbs_pid = 0;
int server_socket = -1;
int ipv6_pid = -1;

int bbs_stdin;
int bbs_stdout;
int bbs_stderr;

#if defined(ENABLE_WWW)
struct MHD_Daemon *www_daemon;
struct MHD_Daemon *ssl_daemon;
#endif

void sigterm_handler(int s) {
	if (ssh_pid != -1) {
		kill(ssh_pid, SIGTERM);
	}
	if (server_socket != -1) {
		close(server_socket);
	}
#if defined(ENABLE_WWW)
	if (www_daemon != NULL) {
		MHD_stop_daemon(www_daemon);
	}
	if (ssl_daemon != NULL) {
		MHD_stop_daemon(ssl_daemon);
	}
#endif
	if (ipv6_pid != -1) {
		kill(ipv6_pid, SIGTERM);
	}
	remove(conf.pid_file);
	exit(0);
}

void sigchld_handler(int s) {
	// waitpid() might overwrite errno, so we save and restore it:
	int saved_errno = errno;

	while (waitpid(-1, NULL, WNOHANG) > 0)
		;

	errno = saved_errno;
}

static int protocol_config_handler(void *user, const char *section, const char *name,
                                   const char *value) {
	struct bbs_config *conf = (struct bbs_config *)user;

	struct protocol *proto = NULL;
	for (size_t i = 0; i < ptr_vector_len(&conf->protocols); ++i) {
		struct protocol *aproto = ptr_vector_get(&conf->protocols, i);
		assert(aproto != NULL);
		if (strcasecmp(aproto->name, section) == 0) {
			proto = aproto;
			break;
		}
	}
	if (proto == NULL) {
		proto = (struct protocol *)malloz(sizeof(struct protocol));
		ptr_vector_append(&conf->protocols, proto);
		proto->name = strdup(section);
		proto->internal_zmodem = 0;
		proto->upload_prompt = 0;
		proto->stdio = 0;
	}
	if (strcasecmp(name, "upload command") == 0) {
		free(proto->upload);
		proto->upload = strdup(value);
	} else if (strcasecmp(name, "download command") == 0) {
		free(proto->download);
		proto->download = strdup(value);
	} else if (strcasecmp(name, "internal zmodem") == 0) {
		proto->internal_zmodem = (strcasecmp(value, "true") == 0);
	} else if (strcasecmp(name, "stdio") == 0) {
		proto->stdio = (strcasecmp(value, "true") == 0);
	} else if (strcasecmp(name, "upload prompt") == 0) {
		proto->upload_prompt = (strcasecmp(value, "true") == 0);
	}

	return 1;
}

static int archiver_config_handler(void *user, const char *section, const char *name,
                                   const char *value) {
	struct bbs_config *conf = (struct bbs_config *)user;

	struct archiver *arc = NULL;
	for (size_t i = 0; i < ptr_vector_len(&conf->archivers); ++i) {
		struct archiver *anarc = ptr_vector_get(&conf->archivers, i);
		if (strcasecmp(anarc->name, section) == 0) {
			arc = anarc; // hy in the UK.
			break;
		}
	}
	if (arc == NULL) {
		arc = malloz(sizeof(struct archiver));
		ptr_vector_append(&conf->archivers, arc);

		arc->name = strdup(section);
	}
	if (strcasecmp(name, "extension") == 0) {
		free(arc->extension);
		arc->extension = strdup(value);
	} else if (strcasecmp(name, "unpack") == 0) {
		free(arc->unpack);
		arc->unpack = strdup(value);
	} else if (strcasecmp(name, "pack") == 0) {
		free(arc->pack);
		arc->pack = strdup(value);
	}

	return 1;
}

static int door_config_handler(void *user, const char *section, const char *name,
                               const char *value) {
	struct bbs_config *conf = (struct bbs_config *)user;

	struct door_config *door = NULL;
	for (size_t i = 0; i < ptr_vector_len(&conf->doors); ++i) {
		struct door_config *adoor = ptr_vector_get(&conf->doors, i);
		assert(adoor != NULL);
		if (strcasecmp(adoor->name, section) == 0) {
			door = adoor;
			break;
		}
	}
	if (door == NULL) {
		door = malloz(sizeof(struct door_config));
		ptr_vector_append(&conf->doors, door);
		door->name = strdup(section);
		door->codepage = NULL;
	}
	if (strcasecmp(name, "command") == 0) {
		free(door->command);
		door->command = strdup(value);
	} else if (strcasecmp(name, "stdio") == 0) {
		door->stdio = (strcasecmp(value, "true") == 0);
	} else if (strcasecmp(name, "codepage") == 0) {
		free(door->codepage);
		door->codepage = strdup(value);
	}

	return 1;
}

static int file_sub_handler(void *user, const char *section, const char *name,
                            const char *value) {
	struct file_directory *fd = (struct file_directory *)user;

	if (strcasecmp(section, "main") == 0) {
		if (strcasecmp(name, "visible sec level") == 0) {
			fd->sec_level = atoi(value);
		} else if (strcasecmp(name, "visible req flags") == 0) {
			split_to_ptr_vector(value, &fd->vis_req_flags);
		} else if (strcasecmp(name, "visible not flags") == 0) {
			split_to_ptr_vector(value, &fd->vis_not_flags);
		} else if (strcasecmp(name, "visible on web") == 0) {
			if (strcasecmp(value, "true") == 0) {
				fd->display_on_web = 1;
			} else if (strcasecmp(value, "authenticated") == 0) {
				fd->display_on_web = 2;
			} else {
				fd->display_on_web = 0;
			}
		}
		return 1;
	}
	// check if it's partially filled in
	struct file_sub *sub = NULL;
	for (size_t i = 0; i < ptr_vector_len(&fd->file_subs); ++i) {
		struct file_sub *asub = ptr_vector_get(&fd->file_subs, i);
		assert(asub != NULL);
		if (strcasecmp(asub->name, section) == 0) {
			sub = asub;
			break;
		}
	}
	if (sub == NULL) {
		sub = (struct file_sub *)malloz(sizeof(struct file_sub));
		ptr_vector_append(&fd->file_subs, sub);
		sub->name = strdup(section);
		init_ptr_vector(&sub->up_req_flags);
		init_ptr_vector(&sub->up_not_flags);
		init_ptr_vector(&sub->down_req_flags);
		init_ptr_vector(&sub->down_not_flags);
		sub->display_on_web = fd->display_on_web;
	}
	if (strcasecmp(name, "upload sec level") == 0) {
		sub->upload_sec_level = atoi(value);
	} else if (strcasecmp(name, "download sec level") == 0) {
		sub->download_sec_level = atoi(value);
	} else if (strcasecmp(name, "database") == 0) {
		free(sub->database);
		sub->database = strdup(value);
	} else if (strcasecmp(name, "upload path") == 0) {
		free(sub->upload_path);
		sub->upload_path = strdup(value);
	} else if (strcasecmp(name, "upload req flags") == 0) {
		split_to_ptr_vector(value, &sub->up_req_flags);
	} else if (strcasecmp(name, "upload not flags") == 0) {
		split_to_ptr_vector(value, &sub->up_not_flags);
	} else if (strcasecmp(name, "download req flags") == 0) {
		split_to_ptr_vector(value, &sub->down_req_flags);
	} else if (strcasecmp(name, "download not flags") == 0) {
		split_to_ptr_vector(value, &sub->down_not_flags);
	} else if (strcasecmp(name, "visible on web") == 0) {
		if (strcasecmp(value, "true") == 0) {
			sub->display_on_web = 1;
		} else if (strcasecmp(value, "authenticated") == 0) {
			sub->display_on_web = 2;
		} else {
			sub->display_on_web = 0;
		}
	}
	return 1;
}

static int mail_area_handler(void *user, const char *section, const char *name,
                             const char *value) {
	struct mail_conference *mc = (struct mail_conference *)user;

	if (strcasecmp(section, "main") == 0) {
		if (strcasecmp(name, "visible sec level") == 0) {
			mc->sec_level = atoi(value);
		} else if (strcasecmp(name, "networked") == 0) {
			mc->networked = (strcasecmp(value, "true") == 0);
		} else if (strcasecmp(name, "real names") == 0) {
			mc->realnames = (strcasecmp(value, "true") == 0);
		} else if (strcasecmp(name, "tagline") == 0) {
			free(mc->tagline);
			mc->tagline = strdup(value);
		} else if (strcasecmp(name, "header") == 0) {
			free(mc->header);
			mc->header = strdup(value);
		} else if (strcasecmp(name, "semaphore") == 0) {
			free(mc->semaphore);
			mc->semaphore = strdup(value);
		} else if (strcasecmp(name, "visible req flags") == 0) {
			split_to_ptr_vector(value, &mc->vis_req_flags);
		} else if (strcasecmp(name, "visible_not_flags") == 0) {
			split_to_ptr_vector(value, &mc->vis_not_flags);
		}
	} else if (strcasecmp(section, "network") == 0) {
		if (strcasecmp(name, "type") == 0) {
			if (strcasecmp(value, "fido") == 0) {
				mc->nettype = NETWORK_FIDO;
			} else if (strcasecmp(value, "magi") == 0) {
				mc->nettype = NETWORK_MAGI;
			} else if (strcasecmp(value, "qwk") == 0) {
				mc->nettype = NETWORK_QWK;
			}
		} else if (strcasecmp(name, "fido node") == 0) {
			mc->fidoaddr = parse_fido_addr(value);
		} else if (strcasecmp(name, "domain") == 0) {
			free(mc->domain);
			mc->domain = strdup(value);
		} else if (strcasecmp(name, "magi node") == 0) {
			mc->maginode = atoi(value);
		}
	} else {
		// check if it's partially filled in
		struct mail_area *area = NULL;
		for (size_t i = 0; i < ptr_vector_len(&mc->mail_areas); ++i) {
			struct mail_area *anarea = ptr_vector_get(&mc->mail_areas, i);
			if (strcasecmp(anarea->name, section) == 0) {
				area = anarea;
				break;
			}
		}
		if (area == NULL) {
			area = (struct mail_area *)malloz(sizeof(struct mail_area));
			ptr_vector_append(&mc->mail_areas, area);
			area->qwkname = NULL;
			area->qwkconfno = -1;
			area->name = strdup(section);
			area->realnames = mc->realnames;
			area->base_type = BASE_TYPE_JAM;
		}
		if (strcasecmp(name, "read sec level") == 0) {
			area->read_sec_level = atoi(value);
		} else if (strcasecmp(name, "write sec level") == 0) {
			area->write_sec_level = atoi(value);
		} else if (strcasecmp(name, "path") == 0) {
			area->path = strdup(value);
		} else if (strcasecmp(name, "type") == 0) {
			if (strcasecmp(value, "local") == 0) {
				area->type = TYPE_LOCAL_AREA;
			} else if (strcasecmp(value, "echo") == 0) {
				area->type = TYPE_ECHOMAIL_AREA;
			} else if (strcasecmp(value, "netmail") == 0) {
				area->type = TYPE_NETMAIL_AREA;
			} else if (strcasecmp(value, "newsgroup") == 0) {
				area->type = TYPE_NEWSGROUP_AREA;
			}
		} else if (strcasecmp(name, "qwk name") == 0) {
			area->qwkname = strndup(value, 8);
		} else if (strcasecmp(name, "qwk conference") == 0) {
			area->qwkconfno = atoi(value);
			if (area->qwkconfno < 1 || area->qwkconfno > 9999) {
				area->qwkconfno = -1;
				fprintf(stderr, "Invalid QWK conference for area %s\n", area->name);
			}
		} else if (strcasecmp(name, "format") == 0) {
			if (strcasecmp(value, "jam") == 0) {
				area->base_type = BASE_TYPE_JAM;
			} else if (strcasecmp(value, "sq3") == 0) {
				area->base_type = BASE_TYPE_SQ3;
			}
		} else if (strcasecmp(name, "real names") == 0) {
			area->realnames = (strcasecmp(value, "true") == 0);
		} else if (strcasecmp(name, "read req flags") == 0) {
			split_to_ptr_vector(value, &area->rd_req_flags);
		} else if (strcasecmp(name, "read not flags") == 0) {
			split_to_ptr_vector(value, &area->rd_not_flags);
		} else if (strcasecmp(name, "write req flags") == 0) {
			split_to_ptr_vector(value, &area->wr_req_flags);
		} else if (strcasecmp(name, "write not flags") == 0) {
			split_to_ptr_vector(value, &area->wr_not_flags);
		}
	}

	return 1;
}

static int handler(void *user, const char *section, const char *name,
                   const char *value) {
	struct bbs_config *conf = (struct bbs_config *)user;
	struct passwd *pwd;

	if (strcasecmp(section, "main") == 0) {
		if (strcasecmp(name, "bbs name") == 0) {
			conf->bbs_name = strdup(value);
		} else if (strcasecmp(name, "new user password") == 0) {
			conf->new_user_pass = strdup(value);
		} else if (strcasecmp(name, "idle timeout") == 0) {
			conf->idletimeout = atoi(value);
		} else if (strcasecmp(name, "bbs location") == 0) {
			conf->bbs_location = strdup(value);
		} else if (strcasecmp(name, "external address") == 0) {
			conf->external_address = strdup(value);
		} else if (strcasecmp(name, "telnet port") == 0) {
			conf->telnet_port = atoi(value);
		} else if (strcasecmp(name, "enable ssh") == 0) {
			if (strcasecmp(value, "true") == 0) {
				conf->ssh_server = 1;
			} else {
				conf->ssh_server = 0;
			}
		} else if (strcasecmp(name, "enable ipv6") == 0) {
			if (strcasecmp(value, "true") == 0) {
				conf->ipv6 = 1;
			} else {
				conf->ipv6 = 0;
			}
		} else if (strcasecmp(name, "enable www") == 0) {
			if (strcasecmp(value, "true") == 0) {
				conf->www_server = 1;
			} else {
				conf->www_server = 0;
			}
		} else if (strcasecmp(name, "www port") == 0) {
			conf->www_port = atoi(value);
		} else if (strcasecmp(name, "www url") == 0) {
			if (value[strlen(value) - 1] == '/') {
				conf->www_url = strdup(value);
			} else {
				conf->www_url = str2dup(value, "/");
			}
		} else if (strcasecmp(name, "ssh port") == 0) {
			conf->ssh_port = atoi(value);
		} else if (strcasecmp(name, "ssh dsa key") == 0) {
			conf->ssh_dsa_key = strdup(value);
		} else if (strcasecmp(name, "ssh rsa key") == 0) {
			conf->ssh_rsa_key = strdup(value);
		} else if (strcasecmp(name, "ssh ecdsa key") == 0) {
			conf->ssh_ecdsa_key = strdup(value);
		} else if (strcasecmp(name, "ssh ed25519 key") == 0) {
			conf->ssh_ed25519_key = strdup(value);
		} else if (strcasecmp(name, "www ssl cert") == 0) {
			conf->ssl_cert = file2str(value);
		} else if (strcasecmp(name, "www ssl key") == 0) {
			conf->ssl_key = file2str(value);
		} else if (strcasecmp(name, "www ssl only") == 0) {
			conf->ssl_only = (strcasecmp(value, "true") == 0);
		} else if (strcasecmp(name, "www ssl port") == 0) {
			conf->ssl_port = atoi(value);
		} else if (strcasecmp(name, "www ssl url") == 0) {
			conf->ssl_url = strdup(value);
		} else if (strcasecmp(name, "www ssl redirect") == 0) {
			conf->www_redirect_ssl = (strcasecmp(value, "true") == 0);
 		} else if (strcasecmp(name, "sysop name") == 0) {
			conf->sysop_name = strdup(value);
		} else if (strcasecmp(name, "nodes") == 0) {
			conf->nodes = atoi(value);
		} else if (strcasecmp(name, "new user level") == 0) {
			conf->newuserlvl = atoi(value);
		} else if (strcasecmp(name, "magichat server") == 0) {
			conf->mgchat_server = strdup(value);
		} else if (strcasecmp(name, "magichat port") == 0) {
			conf->mgchat_port = atoi(value);
		} else if (strcasecmp(name, "magichat bbstag") == 0) {
			conf->mgchat_bbstag = strdup(value);
		} else if (strcasecmp(name, "default tagline") == 0) {
			conf->default_tagline = strdup(value);
		} else if (strcasecmp(name, "upload checker") == 0) {
			conf->upload_checker = strdup(value);
		}	else if (strcasecmp(name, "upload checker codepage") == 0) {
			conf->external_editor_codepage = strdup(value);
		} else if (strcasecmp(name, "external editor cmd") == 0) {
			conf->external_editor_cmd = strdup(value);
		} else if (strcasecmp(name, "external editor codepage") == 0) {
			conf->external_editor_codepage = strdup(value);
		} else if (strcasecmp(name, "external editor stdio") == 0) {
			if (strcasecmp(value, "true") == 0) {
				conf->external_editor_stdio = 1;
			} else {
				conf->external_editor_stdio = 0;
			}
		} else if (strcasecmp(name, "automessage write level") == 0) {
			conf->automsgwritelvl = atoi(value);
		} else if (strcasecmp(name, "fork") == 0) {
			if (strcasecmp(value, "true") == 0) {
				conf->fork = 1;
			} else {
				conf->fork = 0;
			}
		} else if (strcasecmp(name, "qwk name") == 0) {
			conf->bwave_name = strdup(value);
			if (strlen(conf->bwave_name) > 8) {
				conf->bwave_name[8] = '\0';
			}
		} else if (strcasecmp(name, "main aka") == 0) {
			conf->main_aka = parse_fido_addr(value);
		} else if (strcasecmp(name, "qwk max messages") == 0) {
			conf->bwave_max_msgs = atoi(value);
		} else if (strcasecmp(name, "mqtt enable") == 0) {
			if (strcasecmp(value, "true") == 0) {
				conf->broadcast_enable = 1;
			} else {
				conf->broadcast_enable = 0;
			}
		} else if (strcasecmp(name, "mqtt port") == 0) {
			conf->broadcast_port = atoi(value);
		} else if (strcasecmp(name, "mqtt address") == 0) {
			conf->broadcast_address = strdup(value);
		} else if (strcasecmp(name, "mqtt topic") == 0) {
			conf->broadcast_topic = strdup(value);
		} else if (strcasecmp(name, "mqtt user") == 0) {
			conf->broadcast_user = strdup(value);
		} else if (strcasecmp(name, "mqtt pass") == 0) {
			conf->broadcast_pass = strdup(value);
		} else if (strcasecmp(name, "ip guard enable") == 0) {
			if (strcasecmp(value, "true") == 0) {
				conf->ipguard_enable = 1;
			} else {
				conf->ipguard_enable = 0;
			}
		} else if (strcasecmp(name, "ip guard timeout") == 0) {
			conf->ipguard_timeout = atoi(value);
		} else if (strcasecmp(name, "ip guard tries") == 0) {
			conf->ipguard_tries = atoi(value);
		} else if (strcasecmp(name, "root menu") == 0) {
			conf->root_menu = strdup(value);
		} else if (strcasecmp(name, "codepage") == 0) {
			if (strcasecmp(value, "cp437") == 0) {
				conf->codepage = 0;
			} else if (strcasecmp(value, "utf-8") == 0) {
				conf->codepage = 1;
			}
		} else if (strcasecmp(name, "date style") == 0) {
			if (strcasecmp(value, "us") == 0) {
				conf->date_style = 1;
			} else {
				conf->date_style = 0;
			}
		} else if (strcasecmp(name, "run as user") == 0) {
			pwd = getpwnam(value);
			if (pwd != NULL) {
				conf->uid = pwd->pw_uid;
				conf->gid = pwd->pw_gid;
			}
		}
	} else if (strcasecmp(section, "colors") == 0 || strcasecmp(section, "colours") == 0) {
		int fg;
		int bg;

		if (strcasecmp(value, "black") == 0) {
			fg = 0x00;
			bg = 0x00;
		} else if (strcasecmp(value, "blue") == 0) {
			fg = 0x01;
			bg = 0x01;
		} else if (strcasecmp(value, "red") == 0) {
			fg = 0x04;
			bg = 0x04;
		} else if (strcasecmp(value, "green") == 0) {
			fg = 0x02;
			bg = 0x02;
		} else if (strcasecmp(value, "cyan") == 0) {
			fg = 0x03;
			bg = 0x03;
		} else if (strcasecmp(value, "white") == 0) {
			fg = 0x07;
			bg = 0x07;
		} else if (strcasecmp(value, "magenta") == 0) {
			fg = 0x05;
			bg = 0x05;
		} else if (strcasecmp(value, "brown") == 0) {
			fg = 0x06;
			bg = 0x06;
		} else if (strcasecmp(value, "bright black") == 0) {
			fg = 0x08;
			bg = 0x00;
		} else if (strcasecmp(value, "bright blue") == 0) {
			fg = 0x09;
			bg = 0x00;
		} else if (strcasecmp(value, "bright red") == 0) {
			fg = 0x0C;
			bg = 0x00;
		} else if (strcasecmp(value, "bright green") == 0) {
			fg = 0x0A;
			bg = 0x00;
		} else if (strcasecmp(value, "bright cyan") == 0) {
			fg = 0x0B;
			bg = 0x00;
		} else if (strcasecmp(value, "bright white") == 0) {
			fg = 0x0F;
			bg = 0x00;
		} else if (strcasecmp(value, "bright magenta") == 0) {
			fg = 0x0D;
			bg = 0x00;
		} else if (strcasecmp(value, "bright brown") == 0 || strcasecmp(value, "yellow") == 0) {
			fg = 0x0E;
			bg = 0x00;
		}

		if (strcasecmp(name, "message quote foreground") == 0) {
			conf->msg_quote_fg = fg;
		} else if (strcasecmp(name, "message quote background") == 0) {
			conf->msg_quote_bg = bg;
		} else if (strcasecmp(name, "message origin forground") == 0) {
			conf->msg_tag_fg = fg;
		} else if (strcasecmp(name, "message origin background") == 0) {
			conf->msg_tag_bg = bg;
		}
	} else if (strcasecmp(section, "paths") == 0) {
		if (strcasecmp(name, "ansi path") == 0) {
			conf->ansi_path = strdup(value);
		} else if (strcasecmp(name, "bbs path") == 0) {
			conf->bbs_path = strdup(value);
		} else if (strcasecmp(name, "log path") == 0) {
			conf->log_path = strdup(value);
		} else if (strcasecmp(name, "script path") == 0) {
			conf->script_path = strdup(value);
		} else if (strcasecmp(name, "echomail semaphore") == 0) {
			conf->echomail_sem = strdup(value);
		} else if (strcasecmp(name, "netmail semaphore") == 0) {
			conf->netmail_sem = strdup(value);
		} else if (strcasecmp(name, "pid file") == 0) {
			conf->pid_file = strdup(value);
		} else if (strcasecmp(name, "string file") == 0) {
			conf->string_file = strdup(value);
		} else if (strcasecmp(name, "www path") == 0) {
			conf->www_path = strdup(value);
		} else if (strcasecmp(name, "config path") == 0) {
			conf->config_path = strdup(value);
		} else if (strcasecmp(name, "menu path") == 0) {
			conf->menu_path = strdup(value);
		} else if (strcasecmp(name, "ipdata database") == 0) {
			conf->ipdata_location = strdup(value);
		}
	} else if (strcasecmp(section, "mail conferences") == 0) {
		struct mail_conference *conference = malloz(sizeof(struct mail_conference));
		conference->name = strdup(name);
		conference->path = strdup(value);
		conference->tagline = NULL;
		init_ptr_vector(&conference->vis_req_flags);
		init_ptr_vector(&conference->vis_not_flags);
		init_ptr_vector(&conference->mail_areas);
		conference->nettype = 0;
		conference->domain = NULL;
		conference->header = NULL;
		conference->semaphore = NULL;
		ptr_vector_append(&conf->mail_conferences, conference);
	} else if (strcasecmp(section, "file directories") == 0) {
		struct file_directory *dir = malloz(sizeof(struct file_directory));
		dir->name = strdup(name);
		dir->path = strdup(value);
		init_ptr_vector(&dir->vis_req_flags);
		init_ptr_vector(&dir->vis_not_flags);
		init_ptr_vector(&dir->file_subs);
		dir->display_on_web = 0;
		ptr_vector_append(&conf->file_directories, dir);
	} else if (strcasecmp(section, "text files") == 0) {
		struct text_file *file = malloz(sizeof(struct text_file));
		file->name = strdup(name);
		file->path = strdup(value);
		ptr_vector_append(&conf->text_files, file);
	}

	return 1;
}

#ifndef DISABLE_SSH

int ssh_authenticate(ssh_session p_ssh_session) {
	ssh_message message;
	char *username;
	char *password;

	do {
		message = ssh_message_get(p_ssh_session);

		if (message == NULL) {
			gUser = NULL;
			return 0;
		}

		switch (ssh_message_type(message)) {
			case SSH_REQUEST_AUTH:
				switch (ssh_message_subtype(message)) {
					case SSH_AUTH_METHOD_PASSWORD:
						username = ssh_message_auth_user(message);
						password = ssh_message_auth_password(message);

						if (strcasecmp(username, "new") == 0 && strcasecmp(password, "new") == 0) {
							ssh_message_auth_reply_success(message, 0);
							ssh_message_free(message);
							gUser = NULL;
							return 1;
						}
						gUser = check_user_pass(username, password);
						if (gUser != NULL) {
							ssh_message_auth_reply_success(message, 0);
							ssh_message_free(message);
							return 1;
						}
						ssh_message_free(message);
						return 0;
					case SSH_AUTH_METHOD_NONE:
					default:
						ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_PASSWORD | SSH_AUTH_METHOD_INTERACTIVE);
						ssh_message_reply_default(message);
						break;
				}
				break;
			default:
				ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_PASSWORD | SSH_AUTH_METHOD_INTERACTIVE);
				ssh_message_reply_default(message);
				break;
		}

		ssh_message_free(message);
	} while (1);
}
/*
char *ssh_getip(ssh_session session) {
  struct sockaddr_storage tmp;
  struct sockaddr_in *sock;
  unsigned int len = 100;
  char ip[100] = "\0";

  getpeername(ssh_get_fd(session), (struct sockaddr*)&tmp, &len);
  sock = (struct sockaddr_in *)&tmp;
  inet_ntop(AF_INET, &sock->sin_addr, ip, len);

	return strdup(ip);
}
*/
static int ssh_copy_fd_to_chan(socket_t fd, int revents, void *userdata) {
	ssh_channel chan = (ssh_channel)userdata;
	char buf[2048];
	int sz = 0;

	if (!chan) {
		close(fd);
		return -1;
	}
	if (revents & POLLIN) {
		sz = read(fd, buf, 2048);
		if (sz > 0) {
			ssh_channel_write(chan, buf, sz);
		}
	}
	if (revents & POLLHUP) {
		ssh_channel_close(chan);
		sz = -1;
	}
	return sz;
}

static int ssh_copy_chan_to_fd(ssh_session session,
                               ssh_channel channel,
                               void *data,
                               uint32_t len,
                               int is_stderr,
                               void *userdata) {
	int fd = *(int *)userdata;
	int sz;
	(void)session;
	(void)channel;
	(void)is_stderr;

	sz = write(fd, data, len);
	return sz;
}

static void ssh_chan_close(ssh_session session, ssh_channel channel, void *userdata) {
	int fd = *(int *)userdata;
	int status;
	(void)session;
	(void)channel;
	close(fd);
}

struct ssh_channel_callbacks_struct ssh_cb = {
    .channel_data_function = ssh_copy_chan_to_fd,
    .channel_eof_function = ssh_chan_close,
    .channel_close_function = ssh_chan_close,
    .userdata = NULL};

void serverssh(int port, int ipv6) {
	ssh_session p_ssh_session;
	ssh_bind p_ssh_bind;
	int err;
	int pid;
	int shell = 0;
	int fd;
	ssh_channel chan = 0;
	char *ip;
	ssh_event event;
	short events;
	ssh_message message;
	struct termios tios;
	struct ip_address_guard *ip_guard;
	int i;
	char buffer[1024];
	FILE *fptr;
	struct sockaddr_in6 server, client;
	struct sockaddr_in server4, client4;
	void *server_p, *client_p;
	int ssh_sock, csock, c;
	int on = 1;
	char str[INET6_ADDRSTRLEN];

	bbs_stdin = dup(STDIN_FILENO);
	bbs_stdout = dup(STDOUT_FILENO);
	bbs_stderr = dup(STDERR_FILENO);

	err = ssh_init();
	if (err == -1) {
		fprintf(stderr, "Error starting SSH server.\n");
		exit(-1);
	}

	p_ssh_bind = ssh_bind_new();
	if (p_ssh_bind == NULL) {
		fprintf(stderr, "Error starting SSH server.\n");
		exit(-1);
	}

#if LIBSSH_VERSION_INT < SSH_VERSION_INT(0, 7, 0)
	ssh_bind_options_set(p_ssh_bind, SSH_BIND_OPTIONS_DSAKEY, conf.ssh_dsa_key);
	ssh_bind_options_set(p_ssh_bind, SSH_BIND_OPTIONS_RSAKEY, conf.ssh_rsa_key);
#if defined(SSH_BIND_OPTIONS_ECDSAKEY)
	if (conf.ssh_ecdsa_key != NULL) {
		ssh_bind_options_set(p_ssh_bind, SSH_BIND_OPTIONS_ECDSAKEY, conf.ssh_ecdsa_key);
	}
#endif
#else
	ssh_bind_options_set(p_ssh_bind, SSH_BIND_OPTIONS_HOSTKEY, conf.ssh_dsa_key);
	ssh_bind_options_set(p_ssh_bind, SSH_BIND_OPTIONS_HOSTKEY, conf.ssh_rsa_key);

	if (conf.ssh_ecdsa_key != NULL) {
		ssh_bind_options_set(p_ssh_bind, SSH_BIND_OPTIONS_HOSTKEY, conf.ssh_ecdsa_key);
	}
	if (conf.ssh_ed25519_key != NULL) {
		ssh_bind_options_set(p_ssh_bind, SSH_BIND_OPTIONS_HOSTKEY, conf.ssh_ed25519_key);
	}
#endif
	//ssh_bind_listen(p_ssh_bind);
	if (ipv6) {
		ssh_sock = socket(AF_INET6, SOCK_STREAM, 0);
	} else {
		ssh_sock = socket(AF_INET, SOCK_STREAM, 0);
	}
	if (ssh_sock == -1) {
		fprintf(stderr, "Error starting SSH server.\n");
		exit(-1);
	}

	if (setsockopt(ssh_sock, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on)) < 0) {
		fprintf(stderr, "setsockopt(SO_REUSEADDR) failed");
		exit(-1);
	}

	if (ipv6) {
		if (setsockopt(ssh_sock, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&on, sizeof(on)) < 0) {
			fprintf(stderr, "setsockopt(IPV6_V6ONLY) failed");
		}

		memset(&server, 0, sizeof(server));
		server.sin6_family = AF_INET6;
		server.sin6_addr = in6addr_any;
		server.sin6_port = htons(port);

		server_p = &server;
		client_p = &client;

		if (bind(ssh_sock, (struct sockaddr *)server_p, sizeof(struct sockaddr_in6)) < 0) {
			perror("Bind Failed, Error\n");
			exit(1);
		}
		c = sizeof(struct sockaddr_in6);
	} else {
		memset(&server4, 0, sizeof(server4));
		server4.sin_family = AF_INET;
		server4.sin_addr.s_addr = INADDR_ANY;
		server4.sin_port = htons(port);

		server_p = &server4;
		client_p = &client4;

		if (bind(ssh_sock, (struct sockaddr *)server_p, sizeof(struct sockaddr_in)) < 0) {
			perror("Bind Failed, Error\n");
			exit(1);
		}
		c = sizeof(struct sockaddr_in);
	}

	if (conf.uid != getuid()) {
		if (setgid(conf.gid) != 0 || setuid(conf.uid) != 0) {
			perror("SetUID Failed: ");
			remove(conf.pid_file);
			exit(1);
		}
	}

	listen(ssh_sock, 3);

	while ((csock = accept(ssh_sock, (struct sockaddr *)client_p, (socklen_t *)&c))) {
		p_ssh_session = ssh_new();
		if (p_ssh_session == NULL) {
			fprintf(stderr, "Error starting SSH session.\n");
			close(csock);
			continue;
		}
		if (ssh_bind_accept_fd(p_ssh_bind, p_ssh_session, csock) == SSH_OK) {
			if (ipv6) {
				ip = strdup(inet_ntop(AF_INET6, &((struct sockaddr_in6 *)client_p)->sin6_addr, str, sizeof(str)));
			} else {
				ip = strdup(inet_ntop(AF_INET, &((struct sockaddr_in *)client_p)->sin_addr, str, sizeof(str)));
			}
			if (conf.ipguard_enable) {
				i = hashmap_get(ip_guard_map, ip, (void **)(&ip_guard));

				if (i == MAP_MISSING) {
					ip_guard = (struct ip_address_guard *)malloz(sizeof(struct ip_address_guard));
					ip_guard->status = IP_STATUS_UNKNOWN;
					ip_guard->last_connection = time(NULL);
					ip_guard->connection_count = 1;
					hashmap_put(ip_guard_map, strdup(ip), ip_guard);
				} else if (i == MAP_OK) {

					if (ip_guard->status == IP_STATUS_BLACKLISTED) {
						free(ip);
						ssh_disconnect(p_ssh_session);
						continue;
					} else if (ip_guard->status == IP_STATUS_UNKNOWN) {
						if (ip_guard->last_connection + conf.ipguard_timeout > time(NULL)) {
							ip_guard->connection_count++;
							if (ip_guard->connection_count == conf.ipguard_tries) {
								ip_guard->status = IP_STATUS_BLACKLISTED;
								snprintf(buffer, 1024, "%s/blacklist.ip%d", conf.bbs_path, (ipv6 ? 6 : 4));
								fptr = fopen(buffer, "a");
								fprintf(fptr, "%s\n", ip);
								fclose(fptr);
								free(ip);
								ssh_disconnect(p_ssh_session);
								continue;
							}
						} else {
							ip_guard->connection_count = 0;
							ip_guard->last_connection = time(NULL);
						}
					}
				}
			}

			pid = fork();
			if (pid == 0) {
				close(ssh_sock);
				if (ssh_handle_key_exchange(p_ssh_session)) {
					fprintf(stderr, "Key exchange failed.\n");
					exit(-1);
				}
				if (ssh_authenticate(p_ssh_session) == 1) {
					do {
						message = ssh_message_get(p_ssh_session);
						if (message) {

							if (ssh_message_type(message) == SSH_REQUEST_CHANNEL_OPEN && ssh_message_subtype(message) == SSH_CHANNEL_SESSION) {
								chan = ssh_message_channel_request_open_reply_accept(message);
								ssh_message_free(message);
								break;
							} else {
								ssh_message_reply_default(message);
								ssh_message_free(message);
							}
						} else {
							break;
						}
					} while (!chan);
					if (!chan) {
						fprintf(stderr, "Failed to get channel\n");
						ssh_finalize();
						exit(-1);
					}

					do {
						message = ssh_message_get(p_ssh_session);
						if (message) {
							if (ssh_message_type(message) == SSH_REQUEST_CHANNEL) {
								if (ssh_message_subtype(message) == SSH_CHANNEL_REQUEST_SHELL) {
									shell = 1;
									ssh_message_channel_request_reply_success(message);
									ssh_message_free(message);
									break;
								} else if (ssh_message_subtype(message) == SSH_CHANNEL_REQUEST_PTY) {
									ssh_message_channel_request_reply_success(message);
									ssh_message_free(message);
									continue;
								}
							}
						} else {
							break;
						}
					} while (!shell);

					if (!shell) {
						fprintf(stderr, "Failed to get shell\n");
						ssh_finalize();
						exit(-1);
					}

					bbs_pid = forkpty(&fd, NULL, NULL, NULL);
					if (bbs_pid == 0) {
						tcgetattr(STDIN_FILENO, &tios);
						tios.c_lflag &= ~(ICANON | ECHO | ECHONL);
						tios.c_iflag &= INLCR;
						tcsetattr(STDIN_FILENO, TCSAFLUSH, &tios);
						runbbs_ssh(ip);
						exit(0);
					}
					free(ip);
					ssh_cb.userdata = &fd;
					ssh_callbacks_init(&ssh_cb);
					ssh_set_channel_callbacks(chan, &ssh_cb);

					events = POLLIN | POLLPRI | POLLERR | POLLHUP | POLLNVAL;

					event = ssh_event_new();
					if (event == NULL) {
						ssh_finalize();
						exit(0);
					}
					if (ssh_event_add_fd(event, fd, events, ssh_copy_fd_to_chan, chan) != SSH_OK) {
						ssh_finalize();
						exit(0);
					}
					if (ssh_event_add_session(event, p_ssh_session) != SSH_OK) {
						ssh_finalize();
						exit(0);
					}

					do {
						ssh_event_dopoll(event, 1000);
					} while (!ssh_channel_is_closed(chan));

					ssh_event_remove_fd(event, fd);

					ssh_event_remove_session(event, p_ssh_session);

					ssh_event_free(event);
				}
				ssh_disconnect(p_ssh_session);
				ssh_finalize();
				close(csock);
				exit(0);
			} else if (pid > 0) {
				ssh_free(p_ssh_session);
				close(csock);
				free(ip);
			} else {
			}
		}
	}
}
#endif
void server(int port, int ipv6) {
	struct sigaction sa;
	struct sigaction st;
	struct sigaction sq;
	int client_sock, c;
	int pid;
	char *ip;
	struct sockaddr_in6 server, client;
	struct sockaddr_in server4, client4;
	void *client_p, *server_p;
	FILE *fptr;
	char buffer[1024];
	struct ip_address_guard *ip_guard;
	int i;
	int on = 1;
	char str[INET6_ADDRSTRLEN];
	struct stat s;
#if defined(ENABLE_WWW)
	www_daemon = NULL;
	ssl_daemon = NULL;
#endif

	if (conf.ipguard_enable) {

		ip_guard_map = hashmap_new();

		snprintf(buffer, 1024, "%s/whitelist.ip%d", conf.bbs_path, (ipv6 ? 6 : 4));

		fptr = fopen(buffer, "r");
		if (fptr) {
			fgets(buffer, 1024, fptr);
			while (!feof(fptr)) {
				for (i = strlen(buffer) - 1; i > 0; i--) {
					if (buffer[i] == '\r' || buffer[i] == '\n') {
						buffer[i] = '\0';
					} else {
						break;
					}
				}

				if (hashmap_get(ip_guard_map, buffer, (void*)&ip_guard) == MAP_MISSING) {

					ip_guard = (struct ip_address_guard *)malloz(sizeof(struct ip_address_guard));
					ip_guard->status = IP_STATUS_WHITELISTED;
				}
				hashmap_put(ip_guard_map, strdup(buffer), ip_guard);

				fgets(buffer, 1024, fptr);
			}
			fclose(fptr);
		}
		snprintf(buffer, 1024, "%s/blacklist.ip%d", conf.bbs_path, (ipv6 ? 6 : 4));

		fptr = fopen(buffer, "r");
		if (fptr) {
			fgets(buffer, 1024, fptr);
			while (!feof(fptr)) {
				for (i = strlen(buffer) - 1; i > 0; i--) {
					if (buffer[i] == '\r' || buffer[i] == '\n') {
						buffer[i] = '\0';
					} else {
						break;
					}
				}
				if (hashmap_get(ip_guard_map, buffer, (void*)&ip_guard) == MAP_MISSING) {
					ip_guard = (struct ip_address_guard *)malloz(sizeof(struct ip_address_guard));
					ip_guard->status = IP_STATUS_BLACKLISTED;
				}
				hashmap_put(ip_guard_map, strdup(buffer), ip_guard);

				fgets(buffer, 1024, fptr);
			}
			fclose(fptr);
		}
	}
	sa.sa_handler = sigchld_handler; // reap all dead processes
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART | SA_SIGINFO;
	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		perror("sigaction - sigchld");
		remove(conf.pid_file);
		exit(1);
	}

	st.sa_handler = sigterm_handler;
	sigemptyset(&st.sa_mask);
	st.sa_flags = SA_SIGINFO;
	if (sigaction(SIGTERM, &st, NULL) == -1) {
		perror("sigaction - sigterm");
		remove(conf.pid_file);
		exit(1);
	}

	sq.sa_handler = sigterm_handler;
	sigemptyset(&sq.sa_mask);
	sq.sa_flags = SA_SIGINFO;
	if (sigaction(SIGQUIT, &sq, NULL) == -1) {
		perror("sigaction - sigquit");
		remove(conf.pid_file);
		exit(1);
	}
#ifndef DISABLE_SSH
	if (conf.ssh_server) {
		if (!conf.fork) {
			printf(" - SSH Starting on Port %d (IPv%d)\n", conf.ssh_port, (ipv6 ? 6 : 4));
		}

		// fork ssh server
		ssh_pid = fork();

		if (ssh_pid == 0) {
			ipv6_pid = -1;
			ssh_pid = -1;
			serverssh(conf.ssh_port, ipv6);
			exit(0);
		}
		if (ssh_pid < 0) {
			fprintf(stderr, "Error forking ssh server.");
		}
	}
#endif
	if (ipv6) {
		server_socket = socket(AF_INET6, SOCK_STREAM, 0);
	} else {
		server_socket = socket(AF_INET, SOCK_STREAM, 0);
	}

	if (server_socket == -1) {
		remove(conf.pid_file);
		fprintf(stderr, "Couldn't create socket..\n");
		exit(1);
	}

	if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on)) < 0) {
		remove(conf.pid_file);
		fprintf(stderr, "setsockopt(SO_REUSEADDR) failed");
		exit(1);
	}

	if (!conf.fork) {
		printf(" - Telnet Starting on Port %d (IPv%d)\n", port, (ipv6 ? 6 : 4));
	}

	if (ipv6) {
		if (setsockopt(server_socket, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&on, sizeof(on)) < 0) {
			fprintf(stderr, "setsockopt(IPV6_V6ONLY) failed");
		}
		memset(&server, 0, sizeof(server));

		server.sin6_family = AF_INET6;
		server.sin6_addr = in6addr_any;
		server.sin6_port = htons(port);

		if (bind(server_socket, (struct sockaddr *)&server, sizeof(server)) < 0) {
			perror("Bind Failed, Error\n");
			remove(conf.pid_file);
			exit(1);
		}
		c = sizeof(struct sockaddr_in6);
		server_p = &server;
		client_p = &client;
	} else {
		memset(&server4, 0, sizeof(server4));

		server4.sin_family = AF_INET;
		server4.sin_addr.s_addr = INADDR_ANY;
		server4.sin_port = htons(port);

		if (bind(server_socket, (struct sockaddr *)&server4, sizeof(server4)) < 0) {
			perror("Bind Failed, Error\n");
			remove(conf.pid_file);
			exit(1);
		}
		c = sizeof(struct sockaddr_in);
		server_p = &server4;
		client_p = &client4;
	}

	if (conf.uid != getuid()) {
		if (setgid(conf.gid) != 0 || setuid(conf.uid) != 0) {
			perror("SetUID Failed: ");
			remove(conf.pid_file);
			exit(1);
		}
	}

#if defined(ENABLE_WWW)
/* force ipv6 OFF - MLP */
        ipv6 = 0;

	if (conf.www_server && conf.www_path != NULL && conf.www_url != NULL) {
		if (!conf.fork) {
			printf(" - HTTP Starting on Port %d (IPv%d)\n", conf.www_port, (ipv6 ? 6 : 4));
		}
		www_init();
		if (!conf.ssl_only) {
			if (ipv6) {
/*				www_daemon = MHD_start_daemon(MHD_USE_THREAD_PER_CONNECTION | MHD_USE_IPv6, conf.www_port, NULL, NULL, &www_handler, NULL, MHD_OPTION_NOTIFY_COMPLETED, &www_request_completed, NULL, MHD_OPTION_URI_LOG_CALLBACK, &www_logger, NULL, MHD_OPTION_END);*/
                                www_daemon = MHD_start_daemon(MHD_USE_THREAD_PER_CONNECTION | MHD_USE_IPv6, conf.www_port, NULL, NULL,
                                                 (MHD_AccessHandlerCallback) &www_handler, NULL,
                                                 MHD_OPTION_NOTIFY_COMPLETED, &www_request_completed, NULL,
                                                 MHD_OPTION_URI_LOG_CALLBACK, &www_logger, NULL, MHD_OPTION_END);
			} else {
/*				www_daemon = MHD_start_daemon(MHD_USE_THREAD_PER_CONNECTION, conf.www_port, NULL, NULL, &www_handler, NULL, MHD_OPTION_NOTIFY_COMPLETED, &www_request_completed, NULL, MHD_OPTION_URI_LOG_CALLBACK, &www_logger, NULL, MHD_OPTION_END); */
                                www_daemon = MHD_start_daemon(MHD_USE_THREAD_PER_CONNECTION, conf.www_port, NULL, NULL,
                                                 (MHD_AccessHandlerCallback) &www_handler, NULL,
                                                 MHD_OPTION_NOTIFY_COMPLETED, &www_request_completed, NULL,
                                                 MHD_OPTION_URI_LOG_CALLBACK, &www_logger, NULL, MHD_OPTION_END);
			}
		}

                if (www_daemon == NULL) {
                       printf(" !!! ERROR: MHD_start_daemon failed to initialize on port %d\n", conf.www_port);
                } else {
                       printf(" --- HTTP Daemon is now LIVE on port %d\n", conf.www_port);
                }

		if (conf.ssl_port != 0 && conf.ssl_key != NULL && conf.ssl_cert != NULL) {
			if (!conf.fork) {
				printf(" - HTTPS Starting on Port %d (IPv%d)\n", conf.ssl_port, (ipv6 ? 6 : 4));
			}
			if (ipv6) {
/*				ssl_daemon = MHD_start_daemon(MHD_USE_THREAD_PER_CONNECTION | MHD_USE_IPv6 | MHD_USE_SSL, conf.ssl_port, NULL, NULL, &www_handler, NULL, MHD_OPTION_NOTIFY_COMPLETED, &www_request_completed, NULL, MHD_OPTION_URI_LOG_CALLBACK, &www_logger, NULL,
					MHD_OPTION_HTTPS_MEM_KEY, conf.ssl_key, MHD_OPTION_HTTPS_MEM_CERT, conf.ssl_cert, MHD_OPTION_END); */
                                ssl_daemon = MHD_start_daemon(MHD_USE_THREAD_PER_CONNECTION | MHD_USE_IPv6 | MHD_USE_SSL, conf.ssl_port, NULL, NULL,
                                                 (MHD_AccessHandlerCallback) &www_handler, NULL,
                                                 MHD_OPTION_NOTIFY_COMPLETED, &www_request_completed, NULL,
                                                 MHD_OPTION_URI_LOG_CALLBACK, &www_logger, NULL, 
                                                 MHD_OPTION_HTTPS_MEM_KEY, conf.ssl_key, MHD_OPTION_HTTPS_MEM_CERT, conf.ssl_cert, MHD_OPTION_END);
		        } else {
/*				ssl_daemon = MHD_start_daemon(MHD_USE_THREAD_PER_CONNECTION | MHD_USE_SSL, conf.ssl_port, NULL, NULL, &www_handler, NULL, MHD_OPTION_NOTIFY_COMPLETED, &www_request_completed, NULL, MHD_OPTION_URI_LOG_CALLBACK, &www_logger, NULL,
					MHD_OPTION_HTTPS_MEM_KEY, conf.ssl_key, MHD_OPTION_HTTPS_MEM_CERT, conf.ssl_cert, MHD_OPTION_END); */
                                ssl_daemon = MHD_start_daemon(MHD_USE_THREAD_PER_CONNECTION | MHD_USE_SSL, conf.ssl_port, NULL, NULL,
                                                 (MHD_AccessHandlerCallback) &www_handler, NULL,
                                                 MHD_OPTION_NOTIFY_COMPLETED, &www_request_completed, NULL,
                                                 MHD_OPTION_URI_LOG_CALLBACK, &www_logger, NULL, 
                                                 MHD_OPTION_HTTPS_MEM_KEY, conf.ssl_key, MHD_OPTION_HTTPS_MEM_CERT, conf.ssl_cert, MHD_OPTION_END);
			}
		}
	}
#endif

	listen(server_socket, 3);

	while ((client_sock = accept(server_socket, (struct sockaddr *)client_p, (socklen_t *)&c))) {
		if (ipv6) {
			ip = strdup(inet_ntop(AF_INET6, &((struct sockaddr_in6 *)client_p)->sin6_addr, str, sizeof(str)));
		} else {
			ip = strdup(inet_ntop(AF_INET, &((struct sockaddr_in *)client_p)->sin_addr, str, sizeof(str)));
		}
		if (client_sock == -1) {
			if (errno == EINTR) {
				continue;
			} else {
				exit(-1);
			}
		}

		if (conf.ipguard_enable) {
			i = hashmap_get(ip_guard_map, ip, (void **)(&ip_guard));

			if (i == MAP_MISSING) {
				ip_guard = (struct ip_address_guard *)malloz(sizeof(struct ip_address_guard));
				ip_guard->status = IP_STATUS_UNKNOWN;
				ip_guard->last_connection = time(NULL);
				ip_guard->connection_count = 1;
				hashmap_put(ip_guard_map, strdup(ip), ip_guard);
			} else if (i == MAP_OK) {

				if (ip_guard->status == IP_STATUS_BLACKLISTED) {
					write(client_sock, "BLOCKED\r\n", 9);
					free(ip);
					close(client_sock);
					continue;
				} else if (ip_guard->status == IP_STATUS_UNKNOWN) {
					if (ip_guard->last_connection + conf.ipguard_timeout > time(NULL)) {
						ip_guard->connection_count++;
						if (ip_guard->connection_count == conf.ipguard_tries) {
							ip_guard->status = IP_STATUS_BLACKLISTED;
							snprintf(buffer, 1024, "%s/blacklist.ip%d", conf.bbs_path, (ipv6 ? 6 : 4));
							fptr = fopen(buffer, "a");
							fprintf(fptr, "%s\n", ip);
							fclose(fptr);
							write(client_sock, "BLOCKED\r\n", 9);
							free(ip);
							close(client_sock);
							continue;
						}
					} else {
						ip_guard->connection_count = 0;
						ip_guard->last_connection = time(NULL);
					}
				}
			}
		}
		pid = fork();

		if (pid < 0) {
			perror("Error on fork\n");
			exit(1);
		}

		if (pid == 0) {
			close(server_socket);
			server_socket = -1;
			runbbs(client_sock, ip);

			exit(0);
		} else {
			free(ip);
			close(client_sock);
		}
	}
}

int main(int argc, char **argv) {
	int i;
	int main_pid;
	FILE *fptr;
	struct stat s;
	char buffer[1024];

	if (argc < 2) {
		fprintf(stderr, "Usage ./magicka config/bbs.ini\n");
		exit(1);
	}

	init_ptr_vector(&conf.mail_conferences);
	init_ptr_vector(&conf.doors);
	init_ptr_vector(&conf.file_directories);
	conf.mgchat_server = NULL;
	conf.mgchat_port = 2025;
	conf.mgchat_bbstag = NULL;
	init_ptr_vector(&conf.text_files);
	conf.external_editor_cmd = NULL;
	conf.external_editor_codepage = NULL;
	conf.log_path = NULL;
	conf.script_path = NULL;
	conf.automsgwritelvl = 10;
	conf.echomail_sem = NULL;
	conf.netmail_sem = NULL;
	conf.telnet_port = 0;
	conf.string_file = NULL;
	conf.www_path = NULL;
	conf.www_url = NULL;
	conf.ssl_only = 0;
	conf.ssl_key = NULL;
	conf.ssl_cert = NULL;
	conf.ssl_port = 0;
	init_ptr_vector(&conf.archivers);
	conf.broadcast_enable = 0;
	conf.broadcast_port = 0;
	conf.broadcast_address = NULL;
	conf.broadcast_topic = NULL;
	conf.broadcast_user = NULL;
	conf.broadcast_pass = NULL;
	conf.config_path = NULL;
	conf.ipguard_enable = 0;
	conf.ipguard_tries = 4;
	conf.ipguard_timeout = 120;
	init_ptr_vector(&conf.protocols);
	conf.codepage = 0;
	conf.date_style = 0;
	conf.ipv6 = 0;
	conf.uid = getuid();
	conf.gid = getgid();
	conf.external_address = NULL;
	conf.bbs_location = NULL;
	conf.idletimeout = 10;
	conf.new_user_pass = NULL;
	conf.msg_quote_bg = 0x00;
	conf.msg_quote_fg = 0x0B;

	conf.msg_tag_bg = 0x00;
	conf.msg_tag_fg = 0x09;

	conf.ipdata_location = NULL;
	conf.ssh_ecdsa_key = NULL;
	conf.ssh_ed25519_key = NULL;

	conf.upload_checker = NULL;
	conf.upload_checker_codepage = NULL;

	// Load BBS data
	if (ini_parse(argv[1], handler, &conf) < 0) {
		fprintf(stderr, "Unable to load configuration ini (%s)!\n", argv[1]);
		exit(-1);
	}

	if (conf.config_path == NULL) {
		fprintf(stderr, "Config Path must be set in your bbs ini!\n");
		exit(-1);
	}

	if (conf.root_menu == NULL) {
		fprintf(stderr, "Root Menu must be set in your bbs ini!\n");
		exit(-1);
	}

	// Load mail Areas
	for (i = 0; i < ptr_vector_len(&conf.mail_conferences); i++) {
		struct mail_conference *conference = ptr_vector_get(&conf.mail_conferences, i);
		if (ini_parse(conference->path, mail_area_handler, conference) < 0) {
			fprintf(stderr, "Unable to load configuration ini (%s)!\n", conference->path);
			exit(-1);
		}
	}

	// Load file Subs
	for (i = 0; i < ptr_vector_len(&conf.file_directories); i++) {
		struct file_directory *dir = ptr_vector_get(&conf.file_directories, i);
		if (ini_parse(dir->path, file_sub_handler, dir) < 0) {
			fprintf(stderr, "Unable to load configuration ini (%s)!\n", dir->path);
			exit(-1);
		}
	}

	snprintf(buffer, 1024, "%s/doors.ini", conf.config_path);
	if (ini_parse(buffer, door_config_handler, &conf) < 0) {
		fprintf(stderr, "Unable to load configuration ini (doors.ini)!\n");
		exit(-1);
	}

	snprintf(buffer, 1024, "%s/archivers.ini", conf.config_path);
	if (ini_parse(buffer, archiver_config_handler, &conf) < 0) {
		fprintf(stderr, "Unable to load configuration ini %s\n", buffer);
		exit(-1);
	}

	snprintf(buffer, 1024, "%s/protocols.ini", conf.config_path);
	if (ini_parse(buffer, protocol_config_handler, &conf) < 0) {
		fprintf(stderr, "Unable to load configuration ini %s\n", buffer);
		exit(-1);
	}

	load_strings();

	if (conf.fork) {
		if (stat(conf.pid_file, &s) == 0) {
			fprintf(stderr, "Magicka already running or stale pid file at: %s\n", conf.pid_file);
			exit(-1);
		}

		main_pid = fork();

		if (main_pid < 0) {
			fprintf(stderr, "Error forking.\n");
			exit(-1);
		} else if (main_pid > 0) {
			if (conf.uid != getuid()) {
				if (setgid(conf.gid) != 0 || setuid(conf.uid) != 0) {
					perror("Setuid Error: ");
					exit(1);
				}
			}
			fptr = fopen(conf.pid_file, "w");
			if (!fptr) {
				fprintf(stderr, "Unable to open pid file for writing.\n");
			} else {
				fprintf(fptr, "%d", main_pid);
				fclose(fptr);
			}
		} else {
			for (i = 1; i <= conf.nodes; i++) {
				snprintf(buffer, 1024, "%s/nodeinuse.%d", conf.bbs_path, i);
				if (stat(buffer, &s) == 0) {
					unlink(buffer);
				}
			}
			if (conf.ipv6) {
				ipv6_pid = fork();
				if (ipv6_pid < 0) {
					fprintf(stderr, "Error forking.\n");
					exit(-1);
				} else if (ipv6_pid > 0) {
					server(conf.telnet_port, 0);
				} else {
					ipv6_pid = -1;
					server(conf.telnet_port, 1);
				}
			} else {
				server(conf.telnet_port, 0);
			}
		}
	} else {
		printf("Magicka BBS Server Starting....\n");

		for (i = 1; i <= conf.nodes; i++) {
			snprintf(buffer, 1024, "%s/nodeinuse.%d", conf.bbs_path, i);
			if (stat(buffer, &s) == 0) {
				printf(" - Removing stale file: nodeinuse.%d\n", i);
				unlink(buffer);
			}
		}
		if (conf.ipv6) {
			ipv6_pid = fork();
			if (ipv6_pid < 0) {
				fprintf(stderr, "Error forking.\n");
				exit(-1);
			} else if (ipv6_pid > 0) {
				server(conf.telnet_port, 0);
			} else {
				ipv6_pid = -1;
				server(conf.telnet_port, 1);
			}
		} else {
			server(conf.telnet_port, 0);
		}
	}
}
