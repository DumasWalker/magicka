#include <fnmatch.h>
#include <sqlite3.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <dirent.h>
#include <libgen.h>
#include <ctype.h>
#include <time.h>
#include "../../src/inih/ini.h"
#include "ticproc.h"
#include "crc32.h"

struct ticproc_t conf;

char *find_file_nocase(char *filename) {
	DIR *inb;
	struct dirent *dent;
	char *ncasefname;
	
	inb = opendir(conf.inbound);
	if (!inb) {
		fprintf(stderr, "Error opening inbound directory\n");
		return NULL;
	}
	while ((dent = readdir(inb)) != NULL) {
		if (strcasecmp(dent->d_name, filename) == 0) {
			ncasefname = strdup(dent->d_name);
			closedir(inb);
			return ncasefname;
		}
	}
	closedir(inb);
	return NULL;
}

static int handler(void* user, const char* section, const char* name,
                   const char* value)
{
	int i;

	if (strcasecmp(section, "main") == 0) {
		if (strcasecmp(name, "ignore password") == 0) {
			if (strcasecmp(value, "true") == 0) {
				conf.ignore_pass = 1;
			} else {
				conf.ignore_pass = 0;
			}
		} else if (strcasecmp(name, "inbound directory") == 0) {
			conf.inbound = strdup(value);
		} else if (strcasecmp(name, "bad files directory") == 0) {
			conf.bad = strdup(value);
		} else if (strcasecmp(name, "ignore case") == 0) {
			if (strcasecmp(value, "true") == 0) {
				conf.case_insensitve = 1;
			} else {
				conf.case_insensitve = 0;
			}
		} else if (strcasecmp(name, "do not delete") == 0) {
			if (strcasecmp(value, "true") == 0) {
				conf.do_not_delete = 1;
			} else {
				conf.do_not_delete = 0;
			}
		}
	} else {
		for (i=0;i<conf.filearea_count;i++) {
			if (strcasecmp(section, conf.file_areas[i]->name) == 0) {
				if (strcasecmp(name, "password") == 0) {
					conf.file_areas[i]->password = strdup(value);
				} else if (strcasecmp(name, "database") == 0) {
					conf.file_areas[i]->database = strdup(value);
				} else if (strcasecmp(name, "file path") == 0) {
					conf.file_areas[i]->path = strdup(value);
				}
				return 1;
			}
		}

		if (conf.filearea_count == 0) {
			conf.file_areas = (struct filearea_t **)malloc(sizeof(struct filearea_t *));
		} else {
			conf.file_areas = (struct filearea_t **)realloc(conf.file_areas, sizeof(struct filearea_t *) * (conf.filearea_count + 1));
		}
		conf.file_areas[conf.filearea_count] = (struct filearea_t *)malloc(sizeof(struct filearea_t));
		conf.file_areas[conf.filearea_count]->name = strdup(section);
		if (strcasecmp(name, "password") == 0) {
			conf.file_areas[conf.filearea_count]->password = strdup(value);
		} else if (strcasecmp(name, "database") == 0) {
			conf.file_areas[conf.filearea_count]->database = strdup(value);
		} else if (strcasecmp(name, "file path") == 0) {
			conf.file_areas[conf.filearea_count]->path = strdup(value);
		}
		conf.filearea_count++;
		return 1;
	}
	return 1;
}

void chomp(char *string) {
	while ((string[strlen(string)-1] == '\r' || string[strlen(string)-1] == '\n') && strlen(string)) {
		string[strlen(string)-1] = '\0';
	}
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

	while(1) {
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

int add_file(struct ticfile_t *ticfile) {
	FILE *fptr;
	struct stat s;
	char src_filename[4096];
	char dest_filename[4096];
	char *description;
	int desc_len;
	char create_sql[] = "CREATE TABLE IF NOT EXISTS files ("
						"Id INTEGER PRIMARY KEY,"
						"filename TEXT,"
						"description TEXT,"
						"size INTEGER,"
						"dlcount INTEGER,"
						"approved INTEGER,"
						"uploaddate INTEGER);";
	char fetch_sql[] = "SELECT Id, filename FROM files";
	char delete_sql[] = "DELETE FROM files WHERE Id=?";
	char insert_sql[] = "INSERT INTO files (filename, description, size, dlcount, approved, uploaddate) VALUES(?, ?, ?, 0, 1, ?)";
	int i;
	int j;
	char *fname;
	int rc;
	sqlite3 *db;
	sqlite3_stmt *res;
	sqlite3_stmt *res2;
	char *err_msg = 0;
	int len;
	unsigned long crc;
	time_t curtime;
	char *casename;
	char *nocasename;
	
	if (ticfile->area == NULL) {
		return -1;
	}

	for (i=0;i<conf.filearea_count;i++) {
		if (strcasecmp(conf.file_areas[i]->name, ticfile->area) == 0) {
			break;
		}
	}

	if (i == conf.filearea_count) {
		fprintf(stderr, "Couldn't find area %s\n", ticfile->area);
		return -1;
	}

	if (ticfile->password == NULL) {
		if (!conf.ignore_pass) {
			fprintf(stderr, "No Password in Tic file\n");
			return -1;
		}
	} else {
		if (!conf.ignore_pass) {
			if (strcasecmp(conf.file_areas[i]->password, ticfile->password) != 0) {
				fprintf(stderr, "Password mismatch\n");
				return -1;
			}
		}
	}

	rc = sqlite3_open(conf.file_areas[i]->database, &db);
	
	if (rc != SQLITE_OK) {
		fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
		return -1;
	}
	sqlite3_busy_timeout(db, 5000);
	rc = sqlite3_exec(db, create_sql, 0, 0, &err_msg);

	if (rc != SQLITE_OK) {
		printf("SQL error: %s", err_msg);
		sqlite3_free(err_msg);
		sqlite3_close(db);
		return -1;
	}
	// figure out source and dest filenames
	if (ticfile->lname != NULL) {
		snprintf(src_filename, 4096, "%s/%s", conf.inbound, ticfile->lname);
		snprintf(dest_filename, 4096, "%s/%s", conf.file_areas[i]->path, ticfile->lname);
		
		
		if (stat(src_filename, &s) != 0) {
			snprintf(src_filename, 4096, "%s/%s", conf.inbound, ticfile->file);
			snprintf(dest_filename, 4096, "%s/%s", conf.file_areas[i]->path, ticfile->file);		
			casename = ticfile->file;
		} else {
			casename = ticfile->lname;
		}
	} else {
		snprintf(src_filename, 4096, "%s/%s", conf.inbound, ticfile->file);
		snprintf(dest_filename, 4096, "%s/%s", conf.file_areas[i]->path, ticfile->file);
		casename = ticfile->file;
	}
	// check crc
	fptr = fopen(src_filename, "rb");
	if (!fptr) {
		
		if (conf.case_insensitve) {
			nocasename = find_file_nocase(casename);
			if (nocasename == NULL) {
				if (casename == ticfile->lname) {
					nocasename = find_file_nocase(ticfile->file);
					if (nocasename == NULL) {
						fprintf(stderr, "Error Opening %s\n", src_filename);
						sqlite3_free(err_msg);
						sqlite3_close(db);
						return -1;
						
					}
				} else {
					fprintf(stderr, "Error Opening %s\n", src_filename);
					sqlite3_free(err_msg);
					sqlite3_close(db);
					return -1;
				}
			}
			snprintf(src_filename, 4096, "%s/%s", conf.inbound, nocasename);
			free(nocasename);
			fptr = fopen(src_filename, "rb");
			if (!fptr) {
				fprintf(stderr, "Error Opening %s\n", src_filename);
				sqlite3_free(err_msg);
				sqlite3_close(db);
				return -1;					
			}
		} else {
			fprintf(stderr, "Error Opening %s\n", src_filename);
			sqlite3_free(err_msg);
			sqlite3_close(db);
			return -1;
		}
	}

	if (ticfile->crc != NULL) {
		if (Crc32_ComputeFile(fptr, &crc) == -1) {
			fprintf(stderr, "Error computing CRC\n");
			sqlite3_close(db);
			return -1;
		}
		fclose(fptr);

		if (crc != strtoul(ticfile->crc, NULL, 16)) {
			fprintf(stderr, "CRC Mismatch, bailing 0x%x != 0x%x\n", crc, strtoul(ticfile->crc, NULL, 16));
			sqlite3_close(db);
			return -1;
		}
	}

	// password is good, or not needed, check replaces
	if (ticfile->replaces != NULL) {
		rc = sqlite3_prepare_v2(db, fetch_sql, -1, &res, 0);
		if (rc != SQLITE_OK) {
			fprintf(stderr, "Error preparing statement: %s\n", sqlite3_errmsg(db));
			sqlite3_close(db);
			return -1;
		}

		while (sqlite3_step(res) == SQLITE_ROW) {
			fname = strdup(sqlite3_column_text(res, 1));
			if (fnmatch(ticfile->replaces, basename(fname), FNM_CASEFOLD) == 0) {
				// remove file
				rc = sqlite3_prepare_v2(db, delete_sql, -1, &res2, 0);

				if (rc != SQLITE_OK) {
					fprintf(stderr, "Error preparing statement: %s\n", sqlite3_errmsg(db));
					sqlite3_finalize(res);
					sqlite3_close(db);
					free(fname);
					return -1;
				}
				sqlite3_bind_int(res2, 1, sqlite3_column_int(res, 0));

				sqlite3_step(res2);
				sqlite3_finalize(res2);
				remove(fname);
				free(fname);
			}
		}
		sqlite3_finalize(res);
	}
	// add the file
	if (stat(dest_filename, &s) == 0) {
		// uh oh, filename collision.
		fprintf(stderr, "Filename collision! %s\n", dest_filename);
		snprintf(dest_filename, 4096, "%s/%s", conf.bad, ticfile->file);
		j = 1;
		while (stat(dest_filename, &s) == 0) {
			snprintf(dest_filename, 4096, "%s/%s.%d", conf.bad, ticfile->file, j);
			j++;
		}
		if (copy_file(src_filename, dest_filename) != 0) {
			fprintf(stderr, "Error copying file %s\n", src_filename);
			sqlite3_close(db);
			return -1;
		} else {
			if (!conf.do_not_delete)
				remove(src_filename);
		}
		sqlite3_close(db);
		return 0;
	}

	if (stat(src_filename, &s) != 0) {
		fprintf(stderr, "Error accessing file %s\n", src_filename);
		sqlite3_close(db);
		return -1;
	}

	if (copy_file(src_filename, dest_filename) != 0) {
		fprintf(stderr, "Error copying file %s\n", src_filename);
		sqlite3_close(db);
		return -1;
	}

	if (!conf.do_not_delete)
		remove(src_filename);

	desc_len = 0;
	for (j=0;j<ticfile->desc_lines;j++) {
		desc_len += strlen(ticfile->desc[j]) + 1;
	}

	description = (char *)malloc(desc_len + 1);

	memset(description, 0, desc_len + 1);

	for (j=0;j<ticfile->desc_lines;j++) {
		strcat(description, ticfile->desc[j]);
		strcat(description, "\n");
	}

	rc = sqlite3_prepare_v2(db, insert_sql, -1, &res, 0);

	if (rc != SQLITE_OK) {
		fprintf(stderr, "Error preparing statement: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		free(fname);
		return -1;
	}
	curtime = time(NULL);
	sqlite3_bind_text(res, 1, dest_filename, -1, 0);
	sqlite3_bind_text(res, 2, description, -1, 0);
	sqlite3_bind_int(res, 3, s.st_size);
	sqlite3_bind_int(res, 4, curtime);
	sqlite3_step(res);
	sqlite3_finalize(res);
	sqlite3_close(db);

	free(description);
	return 0;
}

int process_tic_file(char *ticfilen) {
	FILE *fptr;
	char ticfilename[4096];
	char buffer[1024];
	struct ticfile_t ticfile;
	int i;
	int ret;

	ticfile.area = NULL;
	ticfile.password = NULL;
	ticfile.file = NULL;
	ticfile.lname = NULL;
	ticfile.desc_lines = 0;
	ticfile.desc = NULL;
	ticfile.replaces = NULL;
	ticfile.crc = NULL;
	
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
			// nothing currently
		} else if (strncasecmp(buffer, "from", 4) == 0) {
			// nothing currently
		} else if (strncasecmp(buffer, "to", 2) == 0) {
			// nothing currently
		} else if (strncasecmp(buffer, "file", 4) == 0) {
			ticfile.file = strdup(&buffer[5]);
		} else if (strncasecmp(buffer, "lfile", 5) == 0) {
			ticfile.lname = strdup(&buffer[6]);
		} else if (strncasecmp(buffer, "fullname", 8) == 0) {
			ticfile.lname = strdup(&buffer[9]);
		} else if (strncasecmp(buffer, "size", 4) == 0) {
		} else if (strncasecmp(buffer, "date", 4) == 0) {
		} else if (strncasecmp(buffer, "desc", 4) == 0 || strncasecmp(buffer, "ldesc", 5) == 0) {
			if (ticfile.desc_lines == 0) {
				ticfile.desc = (char **)malloc(sizeof(char*));
			} else {
				ticfile.desc = (char **)realloc(ticfile.desc, sizeof(char*) * (ticfile.desc_lines + 1));
			}
			if (strncasecmp(buffer, "desc", 4) == 0) {
				ticfile.desc[ticfile.desc_lines] = strdup(&buffer[5]);
			} else {
				ticfile.desc[ticfile.desc_lines] = strdup(&buffer[6]);
			}
			ticfile.desc_lines++;
		} else if (strncasecmp(buffer, "magic", 5) == 0) {
			// nothing currently
		} else if (strncasecmp(buffer, "replaces", 8) == 0) {
			ticfile.replaces = strdup(&buffer[9]);
		} else if (strncasecmp(buffer, "crc", 3) == 0) {
			ticfile.crc = strdup(&buffer[4]);
		} else if (strncasecmp(buffer, "path", 4) == 0) {
			// nothing currently
		} else if (strncasecmp(buffer, "seenby", 6) == 0) {
			// nothing currently
		} else if (strncasecmp(buffer, "pw", 2) == 0) {
			ticfile.password = strdup(&buffer[3]);
		}

		fgets(buffer, 1024, fptr);
	}
	fclose(fptr);
	ret = add_file(&ticfile);
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
		if (!conf.do_not_delete)
			remove(ticfilename);
	}
	return ret;
}

int main(int argc, char **argv) {
	DIR *inb;
	struct dirent *dent;

	conf.filearea_count = 0;
	conf.case_insensitve = 0;
	conf.do_not_delete = 0;

	if (argc < 2) {
		fprintf(stderr, "Usage: \n    ./ticproc config.ini\n");
		return -1;
	}

	if (ini_parse(argv[1], handler, NULL) <0) {
		fprintf(stderr, "Unable to load configuration ini (%s)!\n", argv[1]);
		exit(-1);
	}

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
				if (process_tic_file(dent->d_name) != -1 && !conf.do_not_delete) {
					rewinddir(inb);
				}
			}
	}
	closedir(inb);
}
