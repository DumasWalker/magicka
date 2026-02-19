#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <limits.h>
#include <dirent.h>
#include "ccenter.h"
#include "../../inih/ini.h"

struct bbs_config conf;

int get_valid_seclevels(int **levels, int *count) {
    DIR *dp;
    struct dirent *dirp;
    int c = 0;
    int *lvls;

    dp = opendir(conf.config_path);
    if (!dp) {
        return 0;
    }
    while ((dirp = readdir(dp)) != NULL) {
        if (dirp->d_name[0] == 's' && atoi(&dirp->d_name[1]) > 0) {
            if (c == 0) {
                lvls = (int *)malloc(sizeof(int) * (c + 1));
            } else {
                lvls = (int *)realloc(lvls, sizeof(int) * (c + 1));
            }
            lvls[c] = atoi(&dirp->d_name[1]);
            c++;
        }
    }
    closedir(dp);

    *levels = lvls;
    *count = c;
    return 1;
}

struct fido_addr *parse_fido_addr(const char *str) {
	if (str == NULL) {
		return NULL;
	}
	struct fido_addr *ret = (struct fido_addr *)malloc(sizeof(struct fido_addr));
	int c;
	int state = 0;

	ret->zone = 0;
	ret->net = 0;
	ret->node = 0;
	ret->point = 0;

	for (c=0;c<strlen(str);c++) {
		switch(str[c]) {
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
			case '9':
				{
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
				}
				break;
			default:
				free(ret);
				return NULL;
		}
	}
	return ret;
}

static int protocol_config_handler(void* user, const char* section, const char* name,
                   const char* value)
{
	struct bbs_config *conf = (struct bbs_config *)user;
	int i;

	for (i=0;i<conf->protocol_count;i++) {
		if (strcasecmp(conf->protocols[i]->name, section) == 0) {
			// found it
			if (strcasecmp(name, "upload command") == 0) {
				conf->protocols[i]->upload = strdup(value);
			} else if (strcasecmp(name, "download command") == 0) {
				conf->protocols[i]->download = strdup(value);
			} else if (strcasecmp(name, "internal zmodem") == 0) {
				if (strcasecmp(value, "true") == 0) {
					conf->protocols[i]->internal_zmodem = 1;
				} else {
					conf->protocols[i]->internal_zmodem = 0;
				}
			} else if (strcasecmp(name, "stdio") == 0) {
				if (strcasecmp(value, "true") == 0) {
					conf->protocols[i]->stdio = 1;
				} else {
					conf->protocols[i]->stdio = 0;
				}
			} else if (strcasecmp(name, "upload prompt") == 0) {
				if (strcasecmp(value, "true") == 0) {
					conf->protocols[i]->upload_prompt = 1;
				} else {
					conf->protocols[i]->upload_prompt = 0;
				}
			}
			return 1;
		}
	}

	if (conf->protocol_count == 0) {
		conf->protocols = (struct protocol **)malloc(sizeof(struct protocol *));
	} else {
		conf->protocols = (struct protocol **)realloc(conf->protocols, sizeof(struct protocol *) * (conf->protocol_count + 1));
	}

	conf->protocols[conf->protocol_count] = (struct protocol *)malloc(sizeof(struct protocol));

	conf->protocols[conf->protocol_count]->name = strdup(section);
	conf->protocols[conf->protocol_count]->internal_zmodem = 0;
	conf->protocols[conf->protocol_count]->upload_prompt = 0;
	conf->protocols[conf->protocol_count]->stdio = 0;
	
	if (strcasecmp(name, "upload command") == 0) {
		conf->protocols[conf->protocol_count]->upload = strdup(value);
	} else if (strcasecmp(name, "download command") == 0) {
		conf->protocols[conf->protocol_count]->download = strdup(value);
	} else if (strcasecmp(name, "internal zmodem") == 0) {
		if (strcasecmp(value, "true") == 0) {
			conf->protocols[conf->protocol_count]->internal_zmodem = 1;
		} else {
			conf->protocols[conf->protocol_count]->internal_zmodem = 0;
		}
	} else if (strcasecmp(name, "stdio") == 0) {
		if (strcasecmp(value, "true") == 0) {
			conf->protocols[conf->protocol_count]->stdio = 1;
		} else {
			conf->protocols[conf->protocol_count]->stdio = 0;
		}
	} else if (strcasecmp(name, "upload prompt") == 0) {
		if (strcasecmp(value, "true") == 0) {
			conf->protocols[conf->protocol_count]->upload_prompt = 1;
		} else {
			conf->protocols[conf->protocol_count]->upload_prompt = 0;
		}
	}
	conf->protocol_count++;

	return 1;
}

static int archiver_config_handler(void* user, const char* section, const char* name,
                   const char* value)
{
	struct bbs_config *conf = (struct bbs_config *)user;
	int i;

	for (i=0;i<conf->archiver_count;i++) {
		if (strcasecmp(conf->archivers[i]->name, section) == 0) {
			// found it
			if (strcasecmp(name, "extension") == 0) {
				conf->archivers[i]->extension = strdup(value);
			} else if (strcasecmp(name, "unpack") == 0) {
				conf->archivers[i]->unpack = strdup(value);
			} else if (strcasecmp(name, "pack") == 0) {
				conf->archivers[i]->pack = strdup(value);
			}
			return 1;
		}
	}

	if (conf->archiver_count == 0) {
		conf->archivers = (struct archiver **)malloc(sizeof(struct archiver *));
	} else {
		conf->archivers = (struct archiver **)realloc(conf->archivers, sizeof(struct archiver *) * (conf->archiver_count + 1));
	}

	conf->archivers[conf->archiver_count] = (struct archiver *)malloc(sizeof(struct archiver));

	conf->archivers[conf->archiver_count]->name = strdup(section);

	if (strcasecmp(name, "extension") == 0) {
		conf->archivers[conf->archiver_count]->extension = strdup(value);
	} else if (strcasecmp(name, "unpack") == 0) {
		conf->archivers[conf->archiver_count]->unpack = strdup(value);
	} else if (strcasecmp(name, "pack") == 0) {
		conf->archivers[conf->archiver_count]->pack = strdup(value);
	}
	conf->archiver_count++;

	return 1;
}

static int door_config_handler(void* user, const char* section, const char* name,
                   const char* value)
{
	struct bbs_config *conf = (struct bbs_config *)user;
	int i;

	for (i=0;i<conf->door_count;i++) {
		if (strcasecmp(conf->doors[i]->name, section) == 0) {
			// found it
			if (strcasecmp(name, "key") == 0) {
				conf->doors[i]->key = value[0];
			} else if (strcasecmp(name, "command") == 0) {
				conf->doors[i]->command = strdup(value);
			} else if (strcasecmp(name, "stdio") == 0) {
				if (strcasecmp(value, "true") == 0) {
					conf->doors[i]->stdio = 1;
				} else {
					conf->doors[i]->stdio = 0;
				}
			}
			return 1;
		}
	}

	if (conf->door_count == 0) {
		conf->doors = (struct door_config **)malloc(sizeof(struct door_config *));
	} else {
		conf->doors = (struct door_config **)realloc(conf->doors, sizeof(struct door_config *) * (conf->door_count + 1));
	}

	conf->doors[conf->door_count] = (struct door_config *)malloc(sizeof(struct door_config));

	conf->doors[conf->door_count]->name = strdup(section);

	if (strcasecmp(name, "key") == 0) {
		conf->doors[conf->door_count]->key = value[0];
	} else if (strcasecmp(name, "command") == 0) {
		conf->doors[conf->door_count]->command = strdup(value);
	} else if (strcasecmp(name, "stdio") == 0) {
		if (strcasecmp(value, "true") == 0) {
			conf->doors[conf->door_count]->stdio = 1;
		} else {
			conf->doors[conf->door_count]->stdio = 0;
		}
	}
	conf->door_count++;

	return 1;
}

static int file_sub_handler(void* user, const char* section, const char* name,
                   const char* value)
{
	struct file_directory *fd = (struct file_directory *)user;
	int i;

	if (strcasecmp(section, "main") == 0) {
		if (strcasecmp(name, "visible sec level") == 0) {
			fd->sec_level = atoi(value);
		}
	} else {
		// check if it's partially filled in
		for (i=0;i<fd->file_sub_count;i++) {
			if (strcasecmp(fd->file_subs[i]->name, section) == 0) {
				if (strcasecmp(name, "upload sec level") == 0) {
					fd->file_subs[i]->upload_sec_level = atoi(value);
				} else if (strcasecmp(name, "download sec level") == 0) {
					fd->file_subs[i]->download_sec_level = atoi(value);
				} else if (strcasecmp(name, "database") == 0) {
					fd->file_subs[i]->database = strdup(value);
				} else if (strcasecmp(name, "upload path") == 0) {
					fd->file_subs[i]->upload_path = strdup(value);
				}
				return 1;
			}
		}
		if (fd->file_sub_count == 0) {
			fd->file_subs = (struct file_sub **)malloc(sizeof(struct file_sub *));
		} else {
			fd->file_subs = (struct file_sub **)realloc(fd->file_subs, sizeof(struct file_sub *) * (fd->file_sub_count + 1));
		}

		fd->file_subs[fd->file_sub_count] = (struct file_sub *)malloc(sizeof(struct file_sub));

		fd->file_subs[fd->file_sub_count]->name = strdup(section);
		if (strcasecmp(name, "upload sec level") == 0) {
			fd->file_subs[fd->file_sub_count]->upload_sec_level = atoi(value);
		} else if (strcasecmp(name, "download sec level") == 0) {
			fd->file_subs[fd->file_sub_count]->download_sec_level = atoi(value);
		} else if (strcasecmp(name, "database") == 0) {
			fd->file_subs[fd->file_sub_count]->database = strdup(value);
		} else if (strcasecmp(name, "upload path") == 0) {
			fd->file_subs[fd->file_sub_count]->upload_path = strdup(value);
		}
		fd->file_sub_count++;
	}
	return 1;
}


static int mail_area_handler(void* user, const char* section, const char* name,
                   const char* value)
{
	struct mail_conference *mc = (struct mail_conference *)user;
	int i;

	if (strcasecmp(section, "main") == 0) {
		if (strcasecmp(name, "visible sec level") == 0) {
			mc->sec_level = atoi(value);
		} else if (strcasecmp(name, "networked") == 0) {
			if (strcasecmp(value, "true") == 0) {
				mc->networked = 1;
			} else {
				mc->networked = 0;
			}
		} else if (strcasecmp(name, "real names") == 0) {
			if (strcasecmp(value, "true") == 0) {
				mc->realnames = 1;
			} else {
				mc->realnames = 0;
			}
		} else if (strcasecmp(name, "tagline") == 0) {
			mc->tagline = strdup(value);
		}
	} else if (strcasecmp(section, "network") == 0) {
		if (strcasecmp(name, "type") == 0) {
			if (strcasecmp(value, "fido") == 0) {
				mc->nettype = NETWORK_FIDO;
			} 
		} else if (strcasecmp(name, "fido node") == 0) {
			mc->fidoaddr = parse_fido_addr(value);
		} 
	} else {
		// check if it's partially filled in
		for (i=0;i<mc->mail_area_count;i++) {
			if (strcasecmp(mc->mail_areas[i]->name, section) == 0) {
				if (strcasecmp(name, "read sec level") == 0) {
					mc->mail_areas[i]->read_sec_level = atoi(value);
				} else if (strcasecmp(name, "write sec level") == 0) {
					mc->mail_areas[i]->write_sec_level = atoi(value);
				} else if (strcasecmp(name, "path") == 0) {
					mc->mail_areas[i]->path = strdup(value);
				} else if (strcasecmp(name, "type") == 0) {
					if (strcasecmp(value, "local") == 0) {
						mc->mail_areas[i]->type = TYPE_LOCAL_AREA;
					} else if (strcasecmp(value, "echo") == 0) {
						mc->mail_areas[i]->type = TYPE_ECHOMAIL_AREA;
					} else if (strcasecmp(value, "netmail") == 0) {
						mc->mail_areas[i]->type = TYPE_NETMAIL_AREA;
					} else if (strcasecmp(value, "newsgroup") == 0) {
						mc->mail_areas[i]->type = TYPE_NEWSGROUP_AREA;
					}
				} else if (strcasecmp(name, "qwk name") == 0) {
					mc->mail_areas[i]->qwkname = strdup(value);
					if (strlen(mc->mail_areas[i]->qwkname) > 8) {
						mc->mail_areas[i]->qwkname[8] = '\0';
					}
				}
				return 1;
			}
		}
		if (mc->mail_area_count == 0) {
			mc->mail_areas = (struct mail_area **)malloc(sizeof(struct mail_area *));
		} else {
			mc->mail_areas = (struct mail_area **)realloc(mc->mail_areas, sizeof(struct mail_area *) * (mc->mail_area_count + 1));
		}

		mc->mail_areas[mc->mail_area_count] = (struct mail_area *)malloc(sizeof(struct mail_area));
		
		mc->mail_areas[mc->mail_area_count]->qwkname = NULL;
		
		mc->mail_areas[mc->mail_area_count]->name = strdup(section);
		if (strcasecmp(name, "read sec level") == 0) {
			mc->mail_areas[mc->mail_area_count]->read_sec_level = atoi(value);
		} else if (strcasecmp(name, "write sec level") == 0) {
			mc->mail_areas[mc->mail_area_count]->write_sec_level = atoi(value);
		} else if (strcasecmp(name, "path") == 0) {
			mc->mail_areas[mc->mail_area_count]->path = strdup(value);
		} else if (strcasecmp(name, "type") == 0) {
			if (strcasecmp(value, "local") == 0) {
				mc->mail_areas[mc->mail_area_count]->type = TYPE_LOCAL_AREA;
			} else if (strcasecmp(value, "echo") == 0) {
				mc->mail_areas[mc->mail_area_count]->type = TYPE_ECHOMAIL_AREA;
			} else if (strcasecmp(value, "netmail") == 0) {
				mc->mail_areas[mc->mail_area_count]->type = TYPE_NETMAIL_AREA;
			} else if (strcasecmp(value, "newsgroup") == 0) {
				mc->mail_areas[mc->mail_area_count]->type = TYPE_NEWSGROUP_AREA;
			}
		} else if (strcasecmp(name, "qwk name") == 0) {
			mc->mail_areas[mc->mail_area_count]->qwkname = strdup(value);
			if (strlen(mc->mail_areas[mc->mail_area_count]->qwkname) > 8) {
				mc->mail_areas[mc->mail_area_count]->qwkname[8] = '\0';
			}
		}
		mc->mail_area_count++;
	}
	return 1;
}

static int handler(void* user, const char* section, const char* name,
                   const char* value)
{
	struct bbs_config *conf = (struct bbs_config *)user;

	if (strcasecmp(section, "main") == 0) {
		if (strcasecmp(name, "bbs name") == 0) {
			conf->bbs_name = strdup(value);
		} else if (strcasecmp(name, "telnet port") == 0) {
			conf->telnet_port = atoi(value);
		} else if (strcasecmp(name, "enable ssh") == 0) {
			if (strcasecmp(value, "true") == 0) {
				conf->ssh_server = 1;
			} else {
				conf->ssh_server = 0;
			}
		} else if (strcasecmp(name, "enable www") == 0) {
			if (strcasecmp(value, "true") == 0) {
				conf->www_server = 1;
			} else {
				conf->www_server = 0;
			}
		} else if (strcasecmp(name, "www port") == 0) {
			conf->www_port = atoi(value);
		} else if (strcasecmp(name, "ssh port") == 0) {
			conf->ssh_port = atoi(value);
		} else if (strcasecmp(name, "ssh dsa key") == 0) {
			conf->ssh_dsa_key = strdup(value);
		} else if (strcasecmp(name, "ssh rsa key") == 0) {
			conf->ssh_rsa_key = strdup(value);
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
		} else if (strcasecmp(name, "external editor cmd") == 0) {
			conf->external_editor_cmd = strdup(value);
		} else if (strcasecmp(name, "external editor stdio") == 0) {
			if (strcasecmp(value, "true") == 0) {
				conf->external_editor_stdio = 1;
			} else {
				conf->external_editor_stdio = 0;
			}
		} else if (strcasecmp(name, "automessage write level") == 0) {
			conf->automsgwritelvl = atoi(value);
		} else if (strcasecmp(name, "fork") == 0)  {
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
		} else if (strcasecmp(name, "broadcast enable") == 0) {
			if (strcasecmp(value, "true") == 0) {
				conf->broadcast_enable = 1;
			} else {
				conf->broadcast_enable = 0;
			}
		} else if (strcasecmp(name, "broadcast port") == 0) {
			conf->broadcast_port = atoi(value);
		} else if (strcasecmp(name, "broadcast address") == 0) {
			conf->broadcast_address = strdup(value);
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
		}
	} else if (strcasecmp(section, "paths") == 0){
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
		}
	} else if (strcasecmp(section, "mail conferences") == 0) {
		if (conf->mail_conference_count == 0) {
			conf->mail_conferences = (struct mail_conference **)malloc(sizeof(struct mail_conference *));
		} else {
			conf->mail_conferences = (struct mail_conference **)realloc(conf->mail_conferences, sizeof(struct mail_conference *) * (conf->mail_conference_count + 1));
		}

		conf->mail_conferences[conf->mail_conference_count] = (struct mail_conference *)malloc(sizeof(struct mail_conference));
		conf->mail_conferences[conf->mail_conference_count]->name = strdup(name);
		conf->mail_conferences[conf->mail_conference_count]->path = strdup(value);
		conf->mail_conferences[conf->mail_conference_count]->tagline = NULL;
		conf->mail_conferences[conf->mail_conference_count]->mail_area_count = 0;
		conf->mail_conferences[conf->mail_conference_count]->nettype = 0;
		conf->mail_conference_count++;
	} else if (strcasecmp(section, "file directories") == 0) {
		if (conf->file_directory_count == 0) {
			conf->file_directories = (struct file_directory **)malloc(sizeof(struct file_directory *));
		} else {
			conf->file_directories = (struct file_directory **)realloc(conf->file_directories, sizeof(struct file_directory *) * (conf->file_directory_count + 1));
		}

		conf->file_directories[conf->file_directory_count] = (struct file_directory *)malloc(sizeof(struct file_directory));
		conf->file_directories[conf->file_directory_count]->name = strdup(name);
		conf->file_directories[conf->file_directory_count]->path = strdup(value);
		conf->file_directories[conf->file_directory_count]->file_sub_count = 0;
		conf->file_directory_count++;
	} else if (strcasecmp(section, "text files") == 0) {
		if (conf->text_file_count == 0) {
			conf->text_files = (struct text_file **)malloc(sizeof(struct text_file *));
		} else {
			conf->text_files = (struct text_file **)realloc(conf->text_files, sizeof(struct text_file *) * (conf->text_file_count + 1));
		}

		conf->text_files[conf->text_file_count] = (struct text_file *)malloc(sizeof(struct text_file));
		conf->text_files[conf->text_file_count]->name = strdup(name);
		conf->text_files[conf->text_file_count]->path = strdup(value);
		conf->text_file_count++;

	}

	return 1;
}

int load_ini_file(char *ini_file) {
	int i;
	char buffer[PATH_MAX];

    conf.mail_conference_count = 0;
	conf.door_count = 0;
	conf.file_directory_count = 0;
	conf.mgchat_server = NULL;
	conf.mgchat_port = 2025;
	conf.mgchat_bbstag = NULL;
	conf.text_file_count = 0;
	conf.external_editor_cmd = NULL;
	conf.log_path = NULL;
	conf.script_path = NULL;
	conf.automsgwritelvl = 10;
	conf.echomail_sem = NULL;
	conf.netmail_sem = NULL;
	conf.telnet_port = 0;
	conf.string_file = NULL;
	conf.www_path = NULL;
	conf.archiver_count = 0;
	conf.broadcast_enable = 0;
	conf.broadcast_port = 0;
	conf.broadcast_address = NULL;
	conf.config_path = NULL;
	conf.ipguard_enable = 0;
	conf.ipguard_tries = 4;
	conf.ipguard_timeout = 120;
	conf.protocol_count = 0;	
	
	// Load BBS data
	if (ini_parse(ini_file, handler, &conf) <0) {
        fprintf(stderr, "Failed reading ini: %s\n", ini_file);
		return 0;
	}
	
	if (conf.config_path == NULL) {
		return 0;
	}
	
	// Load mail Areas
	for (i=0;i<conf.mail_conference_count;i++) {
        if (conf.mail_conferences[i]->path[0] != '/') {
            snprintf(buffer, PATH_MAX, "%s/%s", conf.bbs_path, conf.mail_conferences[i]->path);
        } else {
            snprintf(buffer, PATH_MAX, "%s", conf.mail_conferences[i]->path);
        }

		if (ini_parse(buffer, mail_area_handler, conf.mail_conferences[i]) <0) {
            fprintf(stderr, "Failed reading ini: %s\n", buffer);
            return 0;
		}
	}
	// Load file Subs
	for (i=0;i<conf.file_directory_count;i++) {
        if (conf.file_directories[i]->path[0] != '/') {
            snprintf(buffer, PATH_MAX, "%s/%s", conf.bbs_path, conf.file_directories[i]->path);
        } else {
            snprintf(buffer, PATH_MAX, "%s", conf.file_directories[i]->path);
        }        
		if (ini_parse(buffer, file_sub_handler, conf.file_directories[i]) <0) {
            fprintf(stderr, "Failed reading ini: %s\n", buffer);
            return 0;
		}
	}

	snprintf(buffer, PATH_MAX, "%s/doors.ini", conf.config_path);

	if (ini_parse(buffer, door_config_handler, &conf) <0) {
        fprintf(stderr, "Failed reading ini: %s\n", buffer);
        return 0;
	}

	snprintf(buffer, PATH_MAX, "%s/archivers.ini", conf.config_path);
	if (ini_parse(buffer, archiver_config_handler, &conf) <0) {
        fprintf(stderr, "Failed reading ini: %s\n", buffer);
        return 0;
	}

	snprintf(buffer, PATH_MAX, "%s/protocols.ini", conf.config_path);
	if (ini_parse(buffer, protocol_config_handler, &conf) <0) {
        fprintf(stderr, "Failed reading ini: %s\n", buffer);
        return 0;
	}

    return 1;
}