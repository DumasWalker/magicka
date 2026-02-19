static int handler(void* user, const char* section, const char* name,
                   const char* value)
{
	if (strcasecmp(section, "main") == 0) {
		if (strcasecmp(name, "inbound directory") == 0) {
			conf.inbound = strdup(value);
		} else if (strcasecmp(name, "bad files directory") == 0) {
			conf.bad = strdup(value);
		} else if (strcasecmp(name, "ignore case") == 0) {
			if (strcasecmp(value, "true") == 0) {
				conf.case_insensitve = 1;
			} else {
				conf.case_insensitve = 0;
			}
		}
	} else if (strcasecmp(section, "networks") == 0) {
		if (conf.network_count == 0) {
			conf.networks = (struct network_t **)malloc(sizeof(struct network_t *));
		} else {
			conf.networks = (struct network_t **)realloc(conf.networks, sizeof(struct network_t *) * (conf.network_count + 1));
		}
		conf.networks[conf.network_count] = (struct network_t *)malloc(sizeof(struct network_t));
		conf.networks[conf.network_count]->name = strdup(name);
		conf.networks[conf.network_count]->config = strdup(value);
		conf.network_count++;
	}
	return 1;
}

static int network_handler(void* user, const char* section, const char* name,
                   const char* value)
{
	struct network_t *net = (struct network_t *)user;
	int i;
	
	if (strcasecmp(section, "main") == 0) {
		if (strcasecmp(name, "uplink password") == 0) {
			net->uplink_password = strdup(value);
		} else if (strcasecmp(name, "netmail base") == 0) {
			net->netmail_base = strdup(value);
			net->netmail_type = 0;
		} else if (strcasecmp(name, "netmail type") == 0) {
			if (strcasecmp(value, "JAM") == 0) {
				net->netmail_type = 0;
			} else if (strcasecmp(value, "SQ3") == 0) {
				net->netmail_type = 1;
			}
		} else if (strcasecmp(name, "all downlinks") == 0) {
			net->downlink_config = strdup(value);
		} else if (strcasecmp(name, "uplink") == 0) {
			net->uplink = strdup(value);
		}
	} else {
		for (i=0;i<net->filearea_count;i++) {
			if (strcasecmp(section, net->file_areas[i]->name) == 0) {
				if (strcasecmp(name, "database") == 0) {
					net->file_areas[i]->database = strdup(value);
				} else if (strcasecmp(name, "file path") == 0) {
					net->file_areas[i]->path = strdup(value) {
				} else if (strcasecmp(name, "connected downlinks") == 0) {
					net->file_areas[i]->downlink_file = strdup(value);
				} else if (strcasecmp(name, "passthrough") == 0) {
					if (strcasecmp(value, "true") == 0) {
						net->file_areas[i]->passthrough = 1;
					} else {
						net->file_areas[i]->passthrough = 0;
					}
				}
				return 1;
			}
		}

		if (net->filearea_count == 0) {
			net->file_areas = (struct filearea_t **)malloc(sizeof(struct filearea_t *));
		} else {
			net->file_areas = (struct filearea_t **)realloc(net->file_areas, sizeof(struct filearea_t *) * (net->filearea_count + 1));
		}
		net->file_areas[net->filearea_count] = (struct filearea_t *)malloc(sizeof(struct filearea_t));
		net->file_areas[net->filearea_count]->name = strdup(section);
		net->file_areas[net->filearea_count]->passthrough = 0;
		
		if (strcasecmp(name, "password") == 0) {
			net->file_areas[net->filearea_count]->password = strdup(value);
		} else if (strcasecmp(name, "database") == 0) {
			net->file_areas[net->filearea_count]->database = strdup(value);
		} else if (strcasecmp(name, "file path") == 0) {
			net->file_areas[net->filearea_count]->path = strdup(value);
		} else if (strcasecmp(name, "passthrough") == 0) {
			if (strcasecmp(value, "true") == 0) {
				net->file_areas[net->filearea_count]->passthrough = 1;
			} else {
				net->file_areas[net->filearea_count]->passthrough = 0;
			}
		}
		net->filearea_count++;	
	}
	
	return 1;
}

static int network_handler(void* user, const char* section, const char* name,
                   const char* value)
{
	struct network_t *net = (struct network_t *)user;
	
	int i;
	for (i=0;i<net->downlink_count;i++) {
		if (strcasecmp(section, net->downlinks[i]->address) == 0) {
			if (strcasecmp(name, "password") == 0) {
				net->downlinks[i]->password = strdup(value);
			} else if (strcasecmp(name, "outbox") == 0) {
				net->downlinks[i]->outbox = strdup(value);
			}
			return 1;
		}
	}
	
	if (net->downlink_count == 0) {
		net->downlinks = (struct downlink_t **)malloc(sizeof(struct downlink_t *));
	} else {
		net->downlinks = (struct downlink_t **)realloc(net->downlinks, sizeof(struct downlink_t *) * (net->downlink_count + 1));
	}
	net->downlinks[net->downlink_count] = (struct downlink_t *)malloc(sizeof(struct downlink_t));
	net->downlinks[net->downlink_count]->address = strdup(section);
	
	net->downlinks[net->downlink_count]->password = NULL;
	net->downlinks[net->downlink_count]->outbox = NULL;
	
	if (strcasecmp(name, "password") == 0) {
		net->downlinks[net->downlink_count]->password = strdup(value);
	} else if (strcasecmp(name, "outbox") == 0) {
		net->downlinks[net->downlink_count]->outbox = strdup(value);
	}
	
	net->downlink_count++;
}

void chomp(char *string) {
	while ((string[strlen(string)-1] == '\r' || string[strlen(string)-1] == '\n') && strlen(string)) {
		string[strlen(string)-1] = '\0';
	}
}

int process_tic_file(char *ticfilen) {
	FILE *fptr;
	char ticfilename[PATH_MAX];
	char buffer[1024];
	struct ticfile_t ticfile;
	int i;
	int ret;
	int network;
	
	ticfile.area = NULL;
	ticfile.password = NULL;
	ticfile.file = NULL;
	ticfile.lname = NULL;
	ticfile.ldesc_lines = 0;
	ticfile.ldesc = NULL;
	ticfile.desc = NULL;
	ticfile.replaces = NULL;
	ticfile.crc = NULL;
	ticfile.from_addr = NULL;
	ticfile.to_addr = NULL;
	ticfile.origin = NULL;
	ticfile.size = NULL;
	ticfile.date = NULL;
	ticfile.magic = NULL;
	ticfile.path_lines = 0;
	ticfile.seenby_lines = 0;
	
	sprintf(ticfilename, "%s/%s", conf.inbound, ticfilen);
	fptr = fopen(ticfilename, "r");
	if (!fptr) {
		fprintf(stderr, "Error opening %s\n", ticfilename);
		return -1;
	}
	fgets(buffer, 1024, fptr);
	while (!feof(fptr)) {
		chomp(buffer);
		if (strncasecmp(buffer, "area ", 5) == 0) {
			ticfile.area = strdup(&buffer[5]);
		} else if (strncasecmp(buffer, "areadesc", 8) == 0) {
			// nothing currently
		} else if (strncasecmp(buffer, "origin", 6) == 0) {
			ticfile.origin = strdup(&buffer, 7);
		} else if (strncasecmp(buffer, "from", 4) == 0) {
			ticfile.from_addr = strdup(&buffer[5]);
		} else if (strncasecmp(buffer, "to", 2) == 0) {
			ticfile.to_addr = strdup(&buffer[3]);
		} else if (strncasecmp(buffer, "file", 4) == 0) {
			ticfile.file = strdup(&buffer[5]);
		} else if (strncasecmp(buffer, "lfile", 5) == 0) {
			ticfile.lname = strdup(&buffer[6]);
		} else if (strncasecmp(buffer, "fullname", 8) == 0) {
			ticfile.lname = strdup(&buffer[9]);
		} else if (strncasecmp(buffer, "size", 4) == 0) {
			ticfile.size = strdup(&buffer[5]);
		} else if (strncasecmp(buffer, "date", 4) == 0) {
			ticfile.date = strdup(&buffer[5]);
		} else if (strncasecmp(buffer, "desc", 4) == 0) {
			if (ticfile.desc != NULL) {
				free(ticfile.desc);
			}
			ticfile.desc = strdup(&buffer[5]);
		} else if (strncasecmp(buffer, "ldesc", 5) == 0) {
			if (ticfile.ldesc_lines == 0) {
				ticfile.ldesc = (char **)malloc(sizeof(char*));
			} else {
				ticfile.ldesc = (char **)realloc(ticfile.ldesc, sizeof(char*) * (ticfile.ldesc_lines + 1));
			}
			ticfile.ldesc[ticfile.ldesc_lines] = strdup(&buffer[6]);
			ticfile.ldesc_lines++;
		} else if (strncasecmp(buffer, "magic", 5) == 0) {
			ticfile.magic = strdup(&buffer[6]);
		} else if (strncasecmp(buffer, "replaces", 8) == 0) {
			ticfile.replaces = strdup(&buffer[9]);
		} else if (strncasecmp(buffer, "crc", 3) == 0) {
			ticfile.crc = strdup(&buffer[4]);
		} else if (strncasecmp(buffer, "path", 4) == 0) {
			if (ticfile.path_lines == 0) {
				ticfile.path = (char **)malloc(sizeof(char*));
			} else {
				ticfile.path = (char **)realloc(ticfile.path, sizeof(char*) * (ticfile.path_lines + 1));
			}
			ticfile.path[ticfile.path_lines] = strdup(&buffer[5]);
			ticfile.path_lines++;
		} else if (strncasecmp(buffer, "seenby", 6) == 0) {
			if (ticfile.seenby_lines == 0) {
				ticfile.seenby = (char **)malloc(sizeof(char*));
			} else {
				ticfile.seenby = (char **)realloc(ticfile.seenby, sizeof(char*) * (ticfile.seenby_lines + 1));
			}
			ticfile.seenby[ticfile.seenby_lines] = strdup(&buffer[7]);
			ticfile.seenby_lines++;
		} else if (strncasecmp(buffer, "pw", 2) == 0) {
			ticfile.password = strdup(&buffer[3]);
		}

		fgets(buffer, 1024, fptr);
	}
	fclose(fptr);
	
	// work out which network it's from
	network = -1;
	for (i=0;i<conf.network_count;i++) {
		if (strcasecmp(conf.networks[i]->uplink, ticfile.from_addr) == 0) {
			network = i;
			break;
		}
	}
	
	if (network == -1) {
		fprintf(stderr, "TIC file from unknown network!\n");
		// TODO: move to bad..
		free_ticfile(&ticfile);
		return 0;
	}
	
	// add the file to our base if not passthrough
	ret = add_file(&ticfile);
	
	// send the file to downlinks if there are any
	
	
	if (ticfile.area != NULL) {
		free(ticfile.area);
	}

	if (ticfile.password != NULL) {
		free(ticfile.password);
	}

	if (ticfile.file != NULL) {
		free(ticfile.file);
	}
	
	if (ticfile.lname != NULL) {
		free(ticfile.lname);
	}
	
	if (ticfile.desc_lines > 0) {
		for (i=0;i<ticfile.desc_lines;i++) {
			free(ticfile.desc[i]);
		}
		free(ticfile.desc);
	}
	
	if (ticfile.replaces != NULL) {
		free(ticfile.replaces);
	}
	if (ticfile.crc != NULL) {
		free(ticfile.crc);
	}
	if (ret == 0) {
		remove(ticfilename);
	}
	return ret;
}


int main(int argc, char **argv) {
	DIR *inb;
	struct dirent *dent;

	int i;
	int j;
	char buffer[256];
	conf.case_insensitve = 0;
	conf.network_count = 0;
	
	if (argc < 3) {
		fprintf(stderr, "Usage: \n    ./ticproc config.ini [scan|proc]\n");
		return -1;
	}

	if (ini_parse(argv[1], handler, NULL) <0) {
		fprintf(stderr, "Unable to load configuration ini (%s)!\n", argv[1]);
		exit(-1);
	}

	for (i=0;i<conf.network_count;i++) {
		conf.networks[i]->filearea_count = 0;
		conf.networks[i]->downlink_config = NULL;
		conf.networks[i]->uplink_password = NULL;
		if (ini_parse(conf.networks[i]->config, network_handler, conf.networks[i]) <0) {
			fprintf(stderr, "Unable to load network configuration ini (%s)\n", conf.networks[i]->config);
			exit(-1);
		}
		
		if (conf.networks[i]->downlink_config != NULL) {
			if (ini_parse(conf.networks[i]->downlink_config, downlink_handler, conf.networks[i]) < 0) {
				fprintf(stderr, "Unable to load downlink configuration ini (%s)\n", conf.networks[i]->downlink_config);
				exit(-1);
			}
			
			for (j=0;j<conf.networks[i]->filearea_count;j++) {
				// load connected downlinks
				conf.networks[i]->file_areas[j]->downlink_count = 0;
				FILE *fptr = fopen(conf.networks[i]->file_areas[j]->downlink_file, "r");
				if (fptr) {
					fgets(buffer, 256, fptr);
					while (!feof(fptr)) {
						chomp(buffer);
						
						if (conf.networks[i]->file_areas[j]->downlink_count == 0) {
							conf.networks[i]->file_areas[j]->downlinks = (char **)malloc(sizeof(char *));
						} else {
							conf.networks[i]->file_areas[j]->downlinks = (char **)realloc(conf.networks[i]->file_areas[j]->downlinks, sizeof(char *) * (conf.networks[i]->file_areas[j]->downlink_count + 1));
						}
						
						conf.networks[i]->file_areas[j]->downlinks[conf.networks[i]->file_areas[j]->downlink_count] = strdup(buffer);
						
						conf.networks[i]->file_areas[j]->downlink_count++;
						
						fgets(buffer, 256, fptr);
					}
					fclose(fptr);
				}
			}
		}
	}
	
	if (strcasecmp(argv[2], "proc") == 0) {
		// get inbound tic files
		inb = opendir(conf.inbound);
		if (!inb) {
			fprintf(stderr, "Error opening inbound directory\n");
			return -1;
		}
		while ((dent = readdir(inb)) != NULL) {
			if (dent->d_name[strlen(dent->d_name) - 4] == '.' &&
					tolower(dent->d_name[strlen(dent->d_name) - 3]) == 't' &&
					tolower(dent->d_name[strlen(dent->d_name) - 2]) == 'i' &&
					tolower(dent->d_name[strlen(dent->d_name) - 1]) == 'c'
				) {
					// process tic file
					fprintf(stderr, "Processing tic file %s\n", dent->d_name);
					if (process_tic_file(dent->d_name) != -1) {
						rewinddir(inb);
					}
				}
		}
		closedir(inb);
	} else if (strcasecmp(argv[2], "scan") == 0) {
		// scan netmail for filefix requests.
	}
}
