#include <curses.h>
#include <cdk.h>
#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <fts.h>
#include <sys/stat.h>
#include <libgen.h>
#include "../../src/inih/ini.h"
#include "filecenter.h"

struct files {
	char *name;
	char *description;
	int approved;
	int dlcount;
	time_t uploadtime;
};

struct file_directory **file_directories;
int file_directory_count = 0;
CDKSCREEN *cdkscreen = 0;
//CDKMENTRY *desc_entry = 0;
WINDOW *desc_win = 0;
WINDOW *instruction_win = 0;

char instructions[] = "t - toggle approval\na - approve all\nu - unapprove all\nd - delete file\nm - move file\ns - scan for files\ne - edit description";
char *bbspath;
char *configpath;

int current_dir;
int current_sub;

struct files **f;
int fcount = 0;
char **filenames;

struct archiver **archivers;
int archiver_count = 0;

static int archiver_config_handler(void* user, const char* section, const char* name,
                   const char* value)
{
	int i;

	for (i=0;i<archiver_count;i++) {
		if (strcasecmp(archivers[i]->name, section) == 0) {
			// found it
			if (strcasecmp(name, "extension") == 0) {
				archivers[i]->extension = strdup(value);
			} else if (strcasecmp(name, "unpack") == 0) {
				archivers[i]->unpack = strdup(value);
			} else if (strcasecmp(name, "pack") == 0) {
				archivers[i]->pack = strdup(value);
			}
			return 1;
		}
	}

	if (archiver_count == 0) {
		archivers = (struct archiver **)malloc(sizeof(struct archiver *));
	} else {
		archivers = (struct archiver **)realloc(archivers, sizeof(struct archiver *) * (archiver_count + 1));
	}

	archivers[archiver_count] = (struct archiver *)malloc(sizeof(struct archiver));

	archivers[archiver_count]->name = strdup(section);

	if (strcasecmp(name, "extension") == 0) {
		archivers[archiver_count]->extension = strdup(value);
	} else if (strcasecmp(name, "unpack") == 0) {
		archivers[archiver_count]->unpack = strdup(value);
	} else if (strcasecmp(name, "pack") == 0) {
		archivers[archiver_count]->pack = strdup(value);
	}
	archiver_count++;

	return 1;
}

static int bbs_cfg_handler(void *user, const char* section, const char* name, const char *value)
{
    if (strcasecmp(section, "paths") == 0) {
        if (strcasecmp(name, "bbs path") == 0) {
            bbspath = strdup(value);
        }
		if (strcasecmp(name, "config path") == 0) {
			configpath = strdup(value);
		}
    }
    if (strcasecmp(section, "file directories") == 0) {
		if (file_directory_count == 0) {
			file_directories = (struct file_directory **)malloc(sizeof(struct file_directory *));
		} else {
			file_directories = (struct file_directory **)realloc(file_directories, sizeof(struct file_directory *) * (file_directory_count + 1));
		}

		file_directories[file_directory_count] = (struct file_directory *)malloc(sizeof(struct file_directory));
		file_directories[file_directory_count]->name = strdup(name);
		file_directories[file_directory_count]->path = strdup(value);
		file_directories[file_directory_count]->file_sub_count = 0;
		file_directories[file_directory_count]->display_on_web = 0;
		file_directory_count++;
	} 
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
		} else if (strcasecmp(name, "visible on web") == 0) {
			if (strcasecmp(value, "true") == 0) {
				fd->display_on_web = 1;
			} else {
				fd->display_on_web = 0;
			}
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

static void doApprove(int index) {
	char sql_approve[] = "UPDATE files SET approved=1 WHERE filename LIKE ?";
	sqlite3_stmt *res;
	int rc;
	struct stat st;
    sqlite3 *db;
    char database[PATH_MAX];


	if (file_directories[current_dir]->file_subs[current_sub]->database[0] == '/') {
		snprintf(database, PATH_MAX, "%s.sq3", file_directories[current_dir]->file_subs[current_sub]->database);
	} else {
	    snprintf(database, PATH_MAX, "%s/%s.sq3", bbspath, file_directories[current_dir]->file_subs[current_sub]->database);
	}
    // populate scroll list
  	rc = sqlite3_open(database, &db);

    if (rc != SQLITE_OK) {
         return;
    }
    sqlite3_busy_timeout(db, 5000);


	if (stat(f[index]->name, &st) == 0) {
		f[index]->approved = 1;
		sprintf(filenames[index], "</24>%s (approved)<!24>", basename(f[index]->name));
		rc = sqlite3_prepare_v2(db, sql_approve, -1, &res, 0);
		if (rc != SQLITE_OK) {
            sqlite3_close(db);
			return;
		}
		sqlite3_bind_text(res, 1, f[index]->name, -1, 0);

		sqlite3_step(res);

		sqlite3_finalize(res);
	}
    sqlite3_close(db);
}

static void doDisapprove(int index) {
	char sql_approve[] = "UPDATE files SET approved=0 WHERE filename LIKE ?";
	sqlite3 *db;
    sqlite3_stmt *res;
	int rc;
	struct stat s;
    char database[PATH_MAX];

	if (file_directories[current_dir]->file_subs[current_sub]->database[0] == '/') {
		snprintf(database, PATH_MAX, "%s.sq3", file_directories[current_dir]->file_subs[current_sub]->database);
	} else {
	    snprintf(database, PATH_MAX, "%s/%s.sq3", bbspath, file_directories[current_dir]->file_subs[current_sub]->database);
	}
  
	// populate scroll list
	rc = sqlite3_open(database, &db);

	if (rc != SQLITE_OK) {
        return;
	}
	sqlite3_busy_timeout(db, 5000);

	f[index]->approved = 0;
	if (stat(f[index]->name, &s) != 0) {
		sprintf(filenames[index], "</16>%s (missing)<!16>", basename(f[index]->name));
	} else {
		sprintf(filenames[index], "</32>%s (unapproved)<!32>", basename(f[index]->name));
	}
	rc = sqlite3_prepare_v2(db, sql_approve, -1, &res, 0);
	if (rc != SQLITE_OK) {
        sqlite3_close(db);
		return;
	}
	sqlite3_bind_text(res, 1, f[index]->name, -1, 0);

	sqlite3_step(res);

	sqlite3_finalize(res);
    sqlite3_close(db);
}

static int deleteFile(EObjectType cdktype, void *object, void *clientData, chtype input) {
	CDKSCROLL *s = (CDKSCROLL *)object;

	int index = getCDKScrollCurrent(s);
	sqlite3 *db;
    sqlite3_stmt *res;
	int rc;
	struct stat st;
    char database[PATH_MAX];
	int i;

	char sql_delete[] = "DELETE FROM files WHERE filename LIKE ?";

	if (index >= fcount) {
		return FALSE;
	}

	if (file_directories[current_dir]->file_subs[current_sub]->database[0] == '/') {
		snprintf(database, PATH_MAX, "%s.sq3", file_directories[current_dir]->file_subs[current_sub]->database);
	} else {
	    snprintf(database, PATH_MAX, "%s/%s.sq3", bbspath, file_directories[current_dir]->file_subs[current_sub]->database);
	}
 		
	rc = sqlite3_open(database, &db);

	if (rc != SQLITE_OK) {
        return FALSE;
	}
	sqlite3_busy_timeout(db, 5000);
		
	rc = sqlite3_prepare_v2(db, sql_delete, -1, &res, 0);
	if (rc != SQLITE_OK) {
        sqlite3_close(db);
		return FALSE;
	}
	sqlite3_bind_text(res, 1, f[index]->name, -1, 0);

	sqlite3_step(res);

	sqlite3_finalize(res);
    sqlite3_close(db);


	if (stat(f[index]->name, &st) == 0) {
		remove(f[index]->name);
	}	

	free(f[index]->name);
	free(f[index]->description);
	free(f[index]);
	free(filenames[index]);


	for (i=index; i < fcount - 1; i++) {
		filenames[i] = filenames[i+1];
		f[i] = f[i+1];
	}

	fcount--;

	if (fcount == 0) {
		free(filenames);
		free(f);
		filenames = NULL;
		setCDKScrollItems(s, filenames, fcount, FALSE);
		eraseCDKScroll(s);
		drawCDKScroll(s, TRUE);
//		refreshCDKScreen(cdkscreen);
		return FALSE;
	}

	filenames = (char **)realloc(filenames, sizeof(char *) * (fcount));
	f = (struct files **)realloc(f, sizeof(struct files *) * (fcount));


	setCDKScrollItems(s, filenames, fcount, FALSE);
	eraseCDKScroll(s);
	drawCDKScroll(s, TRUE);
//	refreshCDKScreen(cdkscreen);
	return FALSE;
}

static int approveFile(EObjectType cdktype, void *object, void *clientData, chtype input) {
	CDKSCROLL *s = (CDKSCROLL *)object;


	int index = getCDKScrollCurrent(s);
	if (index >= fcount) {
		return FALSE;
	}
	if (f[index]->approved == 1) {
		doDisapprove(index);
	} else {
		doApprove(index);
	}
	setCDKScrollItems(s, filenames, fcount, FALSE);
//	refreshCDKScreen(cdkscreen);
	return FALSE;
}

static int approveAll(EObjectType cdktype, void *object, void *clientData, chtype input) {
	CDKSCROLL *s = (CDKSCROLL *)object;
	int i;

	for (i=0;i<fcount;i++) {
		if (f[i]->approved == 0) {
			doApprove(i);
		}
	}
	setCDKScrollItems(s, filenames, fcount, FALSE);
//	refreshCDKScreen(cdkscreen);
	return FALSE;

}

static int disapproveAll(EObjectType cdktype, void *object, void *clientData, chtype input) {
	CDKSCROLL *s = (CDKSCROLL *)object;
	int i;

	for (i=0;i<fcount;i++) {
		if (f[i]->approved == 1) {
			doDisapprove(i);
		}
	}
	setCDKScrollItems(s, filenames, fcount, FALSE);
//	refreshCDKScreen(cdkscreen);
	return FALSE;

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

int recursive_delete(const char *dir) {
    int ret = 0;
    FTS *ftsp = NULL;
    FTSENT *curr;

    char *files[] = { (char *) dir, NULL };

    ftsp = fts_open(files, FTS_NOCHDIR | FTS_PHYSICAL | FTS_XDEV, NULL);
    if (!ftsp) {
        ret = -1;
        goto finish;
    }

    while ((curr = fts_read(ftsp))) {
        switch (curr->fts_info) {
        case FTS_NS:
        case FTS_DNR:
        case FTS_ERR:
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

static int moveFile(EObjectType cdktype, void *object, void *clientData, chtype input) {
	CDKSCROLL *s = (CDKSCROLL *)object;
	CDKSCROLL *dirScrollList;
	CDKSCROLL *subScrollList;

	int dir_sel;
	int sub_sel;

	char **filedirs;
	char **filesubs;

	char dest_file[PATH_MAX];

	int index = getCDKScrollCurrent(s);

	char title[42];
	sqlite3 *db;
    sqlite3_stmt *res;
	int rc;
	struct stat st;
    char database[PATH_MAX];
	int i;
    char create_sql[] = "CREATE TABLE IF NOT EXISTS files ("
						"Id INTEGER PRIMARY KEY,"
						"filename TEXT,"
						"description TEXT,"
						"size INTEGER,"
						"dlcount INTEGER,"
						"uploaddate INTEGER,"
						"approved INTEGER);";

	char sql_delete[] = "DELETE FROM files WHERE filename LIKE ?";
	char sql_insert[] = "INSERT INTO files (filename, description, size, dlcount, uploaddate, approved) VALUES(?, ?, ?, ?, ?, ?)";

	char *err_msg = 0;

	if (index >= fcount) {
		return FALSE;
	}

    dirScrollList  = newCDKScroll(cdkscreen, 9, 1, 1, 12, 36, "</48>File Directories<!48>", NULL, 0, FALSE, A_REVERSE, TRUE, TRUE);

    filedirs = (char **)malloc(sizeof(char *) * file_directory_count);

    for (i=0;i<file_directory_count;i++) {
        filedirs[i] = strdup(file_directories[i]->name);
    }
    
    setCDKScrollItems(dirScrollList, filedirs, file_directory_count, FALSE);

    while(1) {
		dir_sel = activateCDKScroll(dirScrollList, 0);
		if (dirScrollList->exitType == vESCAPE_HIT) {
			break;
		} else if (dirScrollList->exitType == vNORMAL) {
		    snprintf(title, 42, "</48>%s<!48>", file_directories[dir_sel]->name);

			subScrollList  = newCDKScroll(cdkscreen, 12, 1, 1, 12, 36, title, NULL, 0, FALSE, A_REVERSE, TRUE, TRUE);

			filesubs = (char **)malloc(sizeof(char *) * file_directory_count);

			for (i=0;i<file_directories[dir_sel]->file_sub_count;i++) {
				filesubs[i] = strdup(file_directories[dir_sel]->file_subs[i]->name);
			}
			
			setCDKScrollItems(subScrollList, filesubs, file_directories[dir_sel]->file_sub_count, FALSE);
            
			while (1) {
				sub_sel = activateCDKScroll(subScrollList, 0);
				if (subScrollList->exitType == vESCAPE_HIT) {
					for (i=0;i<file_directories[dir_sel]->file_sub_count;i++) {
						free(filesubs[i]);
					}
					free(filesubs);
					destroyCDKScroll(subScrollList);
					break;
				} else if (subScrollList->exitType == vNORMAL) {
					snprintf(dest_file, PATH_MAX, "%s/%s", file_directories[dir_sel]->file_subs[sub_sel]->upload_path, basename(f[index]->name));

					if (stat(dest_file, &st) != 0) {
						// move file
						if (copy_file(f[index]->name, dest_file) == 0) {
							// success
							unlink(f[index]->name);
							// remove from database
							if (file_directories[current_dir]->file_subs[current_sub]->database[0] == '/') {
								snprintf(database, PATH_MAX, "%s.sq3", file_directories[current_dir]->file_subs[current_sub]->database);
							} else {
	    						snprintf(database, PATH_MAX, "%s/%s.sq3", bbspath, file_directories[current_dir]->file_subs[current_sub]->database);
							}							
							rc = sqlite3_open(database, &db);

							if (rc != SQLITE_OK) {
								break;
							}
							sqlite3_busy_timeout(db, 5000);
			
							rc = sqlite3_prepare_v2(db, sql_delete, -1, &res, 0);
							if (rc != SQLITE_OK) {
								sqlite3_close(db);
								break;
							}
							sqlite3_bind_text(res, 1, f[index]->name, -1, 0);

							sqlite3_step(res);

							sqlite3_finalize(res);
							sqlite3_close(db);
							
							// add to dest database
							if (file_directories[dir_sel]->file_subs[sub_sel]->database[0] == '/') {
								snprintf(database, PATH_MAX, "%s.sq3", file_directories[dir_sel]->file_subs[sub_sel]->database);
							} else {
	    						snprintf(database, PATH_MAX, "%s/%s.sq3", bbspath, file_directories[dir_sel]->file_subs[sub_sel]->database);
							}
							rc = sqlite3_open(database, &db);
	
							if (rc != SQLITE_OK) {
								break;
							}
							sqlite3_busy_timeout(db, 5000);
			
							rc = sqlite3_exec(db, create_sql, 0, 0, &err_msg);
							if (rc != SQLITE_OK ) {
								sqlite3_free(err_msg);
								sqlite3_close(db);
								return FALSE;
							}

							rc = sqlite3_prepare_v2(db, sql_insert, -1, &res, 0);
							if (rc != SQLITE_OK) {
								sqlite3_close(db);
								return FALSE;
							}

							stat(dest_file, &st);
							sqlite3_bind_text(res, 1, dest_file, -1, 0);
							sqlite3_bind_text(res, 2, f[index]->description, -1, 0);
							sqlite3_bind_int(res, 3, st.st_size);
							sqlite3_bind_int(res, 4, f[index]->dlcount);
							sqlite3_bind_int(res, 5, f[index]->uploadtime);
							sqlite3_bind_int(res, 6, f[index]->approved);
							sqlite3_step(res);

							sqlite3_finalize(res);
							sqlite3_close(db);
							// remove from current memory

							free(filenames[index]);
							free(f[index]->name);
							free(f[index]->description);
							free(f[index]);

							for (i=index;i<fcount-1;i++) {
								f[i] = f[i+1];
								filenames[i] = filenames[i+1];
							}

							fcount--;

							f = (struct files **)realloc(f, sizeof(struct files *) * fcount);
							filenames = (char **)realloc(filenames, sizeof(char *) * fcount);


						}
					}
					break;
				}
				for (i=0;i<file_directories[dir_sel]->file_sub_count;i++) {
					free(filesubs[i]);
				}
				free(filesubs);
				eraseCDKScroll(subScrollList);
				destroyCDKScroll(subScrollList);
			}
			for (i=0;i<file_directory_count;i++) {
				free(filedirs[i]);
			}
			free(filedirs);
			eraseCDKScroll(dirScrollList);
			destroyCDKScroll(dirScrollList);

			break;
        }
	}
	setCDKScrollItems(s, filenames, fcount, FALSE);
	eraseCDKScroll(s);
	drawCDKScroll(s, TRUE);
//	refreshCDKScreen(cdkscreen);
}

static int editFileID(EObjectType cdktyp, void *object, void *clientData, chtype input) {
	FILE *fptr;
	CDKSCROLL *s = (CDKSCROLL *)object;
	int index = getCDKScrollCurrent(s);
	struct stat st;
	char buffer[PATH_MAX];
	sqlite3 *db;
    sqlite3_stmt *res;
	int rc;
	char sql_update[] = "UPDATE files SET description=? WHERE filename LIKE ?";
	snprintf(buffer, PATH_MAX, "/tmp/filecenter_id.txt");

	fptr = fopen(buffer, "w");

	if (!fptr) {
		return FALSE;
	}

	fputs(f[index]->description, fptr);

	fclose(fptr);

	snprintf(buffer, PATH_MAX, "./editor.sh");
	if (stat(buffer, &st) != 0) {
		snprintf(buffer, PATH_MAX, "/usr/bin/nano");
		if (stat(buffer, &st) != 0) {
			snprintf(buffer, PATH_MAX, "/usr/bin/vi");
			if (stat(buffer, &st) != 0) {
				return FALSE;
			}
		}
	}
	strncat(buffer, " /tmp/filecenter_id.txt", (PATH_MAX - strlen(buffer)));
	def_prog_mode();
	savetty();
	system(buffer);
	resetty();
	reset_prog_mode();
	snprintf(buffer, PATH_MAX, "/tmp/filecenter_id.txt");

	if (stat(buffer, &st) != 0) {
		return FALSE;
	}
	fptr = fopen(buffer, "r");
	if (!fptr) {
		return FALSE;
	}
	free(f[index]->description);

	f[index]->description = (char *)malloc(sizeof(char) * (st.st_size + 1));
	memset(f[index]->description, 0, st.st_size + 1);


	fread(f[index]->description, 1, st.st_size, fptr);

	fclose(fptr);
	unlink(buffer);

	// update file descripiton
	if (file_directories[current_dir]->file_subs[current_sub]->database[0] == '/') {
		snprintf(buffer, PATH_MAX, "%s.sq3", file_directories[current_dir]->file_subs[current_sub]->database);
	} else {
	    snprintf(buffer, PATH_MAX, "%s/%s.sq3", bbspath, file_directories[current_dir]->file_subs[current_sub]->database);
	}			
	rc = sqlite3_open(buffer, &db);

	if (rc != SQLITE_OK) {
        return FALSE;
	}
	sqlite3_busy_timeout(db, 5000);
		
	rc = sqlite3_prepare_v2(db, sql_update, -1, &res, 0);
	
	sqlite3_bind_text(res, 1, f[index]->description, -1, 0);
	sqlite3_bind_text(res, 2, f[index]->name, -1, 0);

	sqlite3_step(res);

	sqlite3_finalize(res);
	sqlite3_close(db);

	// update display
	refreshCDKScreen(cdkscreen);
	werase(desc_win);
	waddstr(desc_win, f[index]->description);
	wrefresh(desc_win);
	werase(instruction_win);
	waddstr(instruction_win, instructions);
	wrefresh(instruction_win);
}

static int scanFiles(EObjectType cdktype, void *object, void *clientData, chtype input) {
	DIR *ind = opendir(file_directories[current_dir]->file_subs[current_sub]->upload_path);
	FILE *fptr;
	struct dirent *dent;
	int i;
	int j;
	int bpos;
	int gotdesc = 0;
	char buffer[PATH_MAX];
	int found;
	char *description;
	char addfilesql[] = "INSERT INTO files (filename, description, size, dlcount, uploaddate, approved) VALUES(?, ?, ?, 0, ?, 0)";
	char database[PATH_MAX];
	sqlite3 *db;
	int rc;
	sqlite3_stmt *res;
	struct stat st;
	int fdate;
	int len;
	CDKSCROLL *s = (CDKSCROLL *)object;

	if (!ind) {
		return FALSE;
	}

	while ((dent = readdir(ind)) != NULL) {
		if (strcmp(dent->d_name, ".") == 0 || strcmp(dent->d_name, "..") == 0) {
			continue;
		}

		if (file_directories[current_dir]->file_subs[current_sub]->database[0] == '/') {
			snprintf(buffer, PATH_MAX, "%s.sq3", file_directories[current_dir]->file_subs[current_sub]->database);
		} else {
	    	snprintf(buffer, PATH_MAX, "%s/%s.sq3", bbspath, file_directories[current_dir]->file_subs[current_sub]->database);
		}	
		stat(buffer, &st);

		if (!S_ISREG(st.st_mode)) {
			continue;
		}

		found = 0;
		for (j=0;j<fcount;j++) {
			if (strcmp(basename(f[j]->name), dent->d_name) == 0) {
				found = 1;
				break;
			}
		}

		if (found == 1) {
			continue;
		}

		gotdesc = 0;
		description = NULL;

		for (i=0;i<archiver_count;i++) {
			if (strlen(dent->d_name) >= strlen(archivers[i]->extension) + 1) {
				if (strcasecmp(&dent->d_name[strlen(dent->d_name) - strlen(archivers[i]->extension)], archivers[i]->extension) == 0) {
					// match
					bpos = 0;
					for (j=0;j<strlen(archivers[i]->unpack);j++) {
						if (archivers[i]->unpack[j] == '*') {
							j++;
							if (archivers[i]->unpack[j] == 'a') {
								sprintf(&buffer[bpos], "%s/%s", file_directories[current_dir]->file_subs[current_sub]->upload_path, dent->d_name);
								bpos = strlen(buffer);
							} else if (archivers[i]->unpack[j] == 'd') {
								sprintf(&buffer[bpos], "/tmp/filecenter_temp");
								bpos = strlen(buffer);				
							} else if (archivers[i]->unpack[j] == '*') {
								buffer[bpos++] = '*';
								buffer[bpos] = '\0';
							}
						} else {
							buffer[bpos++] = archivers[i]->unpack[j];
							buffer[bpos] = '\0';
						}
					}

					system(buffer);

					snprintf(buffer, PATH_MAX, "/tmp/filecenter_temp/FILE_ID.DIZ");
					if (stat(buffer, &st) != 0) {
						snprintf(buffer, PATH_MAX, "/tmp/filecenter_temp/file_id.diz");
						if (stat(buffer, &st) != 0) {
							gotdesc = 0;
							snprintf(buffer, PATH_MAX, "/tmp/filecenter_temp");
							recursive_delete(buffer);
							break;
						}
					}

					description = (char *)malloc(st.st_size + 1);
					
					fptr = fopen(buffer, "rb");
					
					fread(description, 1, st.st_size, fptr);
					description[st.st_size] = '\0';
					fclose(fptr);
					
					bpos = 0;
					len = strlen(description);
					for (j=0;j<len;j++) {
						if (description[j] == '\r') {
							continue;
						} else {
							description[bpos++] = description[j];							
						}
					}
					description[bpos] = '\0';

					gotdesc = 1;
					snprintf(buffer, PATH_MAX, "/tmp/filecenter_temp");
					recursive_delete(buffer);
					break;
				}
			}
		}

		if (!gotdesc) {
			description = strdup("No Description.");
		}

		if (fcount == 0) {
			filenames = (char **)malloc(sizeof(char *));
		} else {
			filenames = (char **)realloc(filenames, sizeof(char *) * (fcount + 1));
		}
		filenames[fcount] = (char *)malloc(strlen(dent->d_name) + 30);
		sprintf(filenames[fcount], "</32>%s (unapproved)<!32>", dent->d_name);

		if (fcount == 0) {
			f = (struct files **)malloc(sizeof(struct files *));
		} else {
			f = (struct files **)realloc(f, sizeof(struct files *) * (fcount + 1));
		}
		f[fcount] = (struct files *)malloc(sizeof(struct files));
		f[fcount]->name = (char *)malloc(strlen(file_directories[current_dir]->file_subs[current_sub]->upload_path) + strlen(dent->d_name) + 2);
		sprintf(f[fcount]->name, "%s/%s", file_directories[current_dir]->file_subs[current_sub]->upload_path, dent->d_name);
		f[fcount]->description = description;
		f[fcount]->approved = 0;

		// add to database
		if (file_directories[current_dir]->file_subs[current_sub]->database[0] == '/') {
			snprintf(database, PATH_MAX, "%s.sq3", file_directories[current_dir]->file_subs[current_sub]->database);
		} else {
		    snprintf(database, PATH_MAX, "%s/%s.sq3", bbspath, file_directories[current_dir]->file_subs[current_sub]->database);
		}	
		rc = sqlite3_open(database, &db);
		if (rc != SQLITE_OK) {
			free(f[fcount]->name);
			free(f[fcount]->description);
			free(filenames[fcount]);
			free(f[fcount]);
			if (fcount == 0) {
				free(f);
				free(filenames);
			} else {
				f = (struct files **)realloc(f, sizeof(struct files *) * fcount);
				filenames = (char **)realloc(filenames, sizeof(char *) * fcount);
			}
			setCDKScrollItems(s, filenames, fcount, FALSE);
			eraseCDKScroll(s);
			drawCDKScroll(s, TRUE);
//			refreshCDKScreen(cdkscreen);
			closedir(ind);
        	return FALSE;
		}

		sqlite3_busy_timeout(db, 5000);
		rc = sqlite3_prepare_v2(db, addfilesql, -1, &res, 0);
		if (rc != SQLITE_OK) {
			sqlite3_close(db);
			free(f[fcount]->name);
			free(f[fcount]->description);
			free(filenames[fcount]);
			free(f[fcount]);
			if (fcount == 0) {
				free(f);
				free(filenames);
			} else {
				f = (struct files **)realloc(f, sizeof(struct files *) * fcount);
				filenames = (char **)realloc(filenames, sizeof(char *) * fcount);
			}
		
			setCDKScrollItems(s, filenames, fcount, FALSE);
			eraseCDKScroll(s);
			drawCDKScroll(s, TRUE);
//			refreshCDKScreen(cdkscreen);
			closedir(ind);
        	return FALSE;
		}
		stat(f[fcount]->name, &st);

		sqlite3_bind_text(res, 1, f[fcount]->name, -1, 0);
		sqlite3_bind_text(res, 2, f[fcount]->description, -1, 0);
		sqlite3_bind_int(res, 3, st.st_size);
		fdate = time(NULL);
		sqlite3_bind_int(res, 4, fdate);

		sqlite3_step(res);

		sqlite3_finalize(res);
		sqlite3_close(db);
		fcount++;

	}	
	setCDKScrollItems(s, filenames, fcount, FALSE);
	eraseCDKScroll(s);
	drawCDKScroll(s, TRUE);
//	refreshCDKScreen(cdkscreen);
	closedir(ind);
	return FALSE;
}

int desc_function(EObjectType objtype, void *obj, void *clientData, chtype input) {
	CDKSCROLL *s = (CDKSCROLL *)obj;

	if (fcount == 0) return FALSE;
	int index = getCDKScrollCurrent(s);

	werase(desc_win);
	waddstr(desc_win, f[index]->description);
	wrefresh(desc_win);
//	setCDKMentryValue(desc_entry, f[index]->description);
	return FALSE;
}

void list_files(int dir, int sub) {
    CDKSCROLL *scrollList = 0;
    int selection;
    int i;
    char title[42];
    sqlite3 *db;
    sqlite3_stmt *res;
    int rc;
    struct stat s;
	char sql_read[] = "SELECT filename, description, approved, dlcount, uploaddate FROM files";
    char create_sql[] = "CREATE TABLE IF NOT EXISTS files ("
						"Id INTEGER PRIMARY KEY,"
						"filename TEXT,"
						"description TEXT,"
						"size INTEGER,"
						"dlcount INTEGER,"
						"uploaddate INTEGER,"
						"approved INTEGER);";
    char database[PATH_MAX];
    char *err_msg;


    current_dir = dir;
    current_sub = sub;


    snprintf(title, 42, "</48>%s<!48>", file_directories[dir]->file_subs[sub]->name);
	if (file_directories[dir]->file_subs[sub]->database[0] == '/') {
		snprintf(database, PATH_MAX, "%s.sq3", file_directories[dir]->file_subs[sub]->database);
	} else {
	    snprintf(database, PATH_MAX, "%s/%s.sq3", bbspath, file_directories[dir]->file_subs[sub]->database);
	}	

	// populate scroll list
	rc = sqlite3_open(database, &db);
	

	if (rc != SQLITE_OK) {
        return;
	}
	sqlite3_busy_timeout(db, 5000);
    rc = sqlite3_exec(db, create_sql, 0, 0, &err_msg);
    if (rc != SQLITE_OK ) {
        sqlite3_free(err_msg);
        sqlite3_close(db);
        return;
    }
	rc = sqlite3_prepare_v2(db, sql_read, -1, &res, 0);

	f = NULL;
	filenames = NULL;

	while(sqlite3_step(res) == SQLITE_ROW) {
		if (fcount == 0) {
			f = (struct files **)malloc(sizeof(struct files *));
			filenames = (char **)malloc(sizeof(char *));
 		} else {
			f = (struct files **)realloc(f, sizeof(struct files *) * (fcount + 1));
			filenames = (char **)realloc(filenames, sizeof(char *) * (fcount + 1));
		}
	
    	f[fcount] = (struct files *)malloc(sizeof(struct files));
		f[fcount]->name = strdup((char *)sqlite3_column_text(res, 0));
		f[fcount]->description = strdup((char *)sqlite3_column_text(res, 1));
		f[fcount]->approved = sqlite3_column_int(res, 2);
		f[fcount]->dlcount = sqlite3_column_int(res, 3);
		f[fcount]->uploadtime = sqlite3_column_int(res, 4);
		filenames[fcount] = (char *)malloc(strlen(basename(f[fcount]->name)) + 30);
		if (stat(f[fcount]->name, &s) != 0) {
			sprintf(filenames[fcount], "</16>%s (missing)<!16>", basename(f[fcount]->name));
			if (f[fcount]->approved == 1) {
				// unapprove missing file
				doDisapprove(fcount);
			}
		} else if (f[fcount]->approved) {
			sprintf(filenames[fcount], "</24>%s (approved)<!24>", basename(f[fcount]->name));
		} else {
			sprintf(filenames[fcount], "</32>%s (unapproved)<!32>", basename(f[fcount]->name));
		}
		fcount++;
	}

	sqlite3_finalize(res);
    sqlite3_close(db);

    scrollList  = newCDKScroll(cdkscreen, 6, 1, 1, 12, 36, title, NULL, 0, FALSE, A_REVERSE, TRUE, TRUE);
    if (!scrollList) {
        for (i=0;i<fcount;i++) {
            free(f[i]->name);
            free(f[i]->description);
            free(f[i]);
            free(filenames[i]);
        }

        free(f);
        free(filenames);
        fcount = 0;
        return;
    }
	if (fcount > 0) {
		werase(desc_win);
		waddstr(desc_win, f[0]->description);
//		setCDKMentryValue(desc_entry, f[0]->description);
	} else {
//		setCDKMentryValue(desc_entry, "");
		werase(desc_win);
	}
	wrefresh(desc_win);
	setCDKScrollPostProcess(scrollList, desc_function, NULL);
	setCDKScrollItems(scrollList, filenames, fcount, FALSE);

	bindCDKObject (vSCROLL, scrollList, 'm', moveFile, NULL);
	bindCDKObject (vSCROLL, scrollList, 'u', disapproveAll, NULL);
	bindCDKObject (vSCROLL, scrollList, 'a', approveAll, NULL);
	bindCDKObject (vSCROLL, scrollList, 't', approveFile, NULL);
	bindCDKObject (vSCROLL, scrollList, 'd', deleteFile, NULL);
	bindCDKObject (vSCROLL, scrollList, 's', scanFiles, NULL);
	bindCDKObject (vSCROLL, scrollList, 'e', editFileID, NULL);

	while(1) {
		selection = activateCDKScroll(scrollList, 0);
		if (scrollList->exitType == vESCAPE_HIT) {
			break;
		}
	}
	for (i=0;i<fcount;i++) {
		free(f[i]->name);
		free(f[i]->description);
		free(f[i]);
		free(filenames[i]);
	}
	if (fcount != 0) {
		free(f);
		free(filenames);
	}
	fcount = 0;
	destroyCDKScroll(scrollList);
}

void list_subdirs(int selected) {
    CDKSCROLL *scrollList = 0;
    int selection;
    int i;
    char title[42];

    char **filesubs = (char **)malloc(sizeof(char *) * file_directories[selected]->file_sub_count);

    snprintf(title, 42, "</48>%s<!48>", file_directories[selected]->name);

    for (i=0;i<file_directories[selected]->file_sub_count;i++) {
        filesubs[i] = strdup(file_directories[selected]->file_subs[i]->name);
    }

    scrollList  = newCDKScroll(cdkscreen, 4, 1, 1, 12, 36, title, NULL, 0, FALSE, A_REVERSE, TRUE, TRUE);
    if (!scrollList) {
        fprintf(stderr, "Unable to make scrolllist!");
		destroyCDKScreen(cdkscreen);
		endCDK();
		exit(-1);
    }
    setCDKScrollItems(scrollList, filesubs, file_directories[selected]->file_sub_count, FALSE);
    while(1) {
		selection = activateCDKScroll(scrollList, 0);
		if (scrollList->exitType == vESCAPE_HIT) {
			break;
		} else if (scrollList->exitType == vNORMAL) {
            list_files(selected, selection);
        }
	}

	destroyCDKScroll(scrollList);
    for (i=0;i<file_directories[selected]->file_sub_count;i++) {
        free(filesubs[i]);
    }

    free(filesubs);
}

int main(int argc, char **argv) {
    int i;
    CDK_PARAMS params;
    WINDOW *cursesWin = 0;
    CDKSCROLL *scrollList = 0;
    int selection;
    char **filedirs;
    char buffer[PATH_MAX];

    CDKparseParams(argc, argv, &params, "c:" CDK_CLI_PARAMS);

    if (ini_parse(CDKparamString (&params, 'c'), bbs_cfg_handler, NULL) <0) {
		fprintf(stderr, "Unable to load configuration ini (%s)!\n", argv[1]);
		exit(-1);
	}

	snprintf(buffer, 1024, "%s/archivers.ini", configpath);
	if (ini_parse(buffer, archiver_config_handler, NULL) <0) {
		fprintf(stderr, "Unable to load configuration ini %s\n", buffer);
		exit(-1);
	}

    for (i=0;i<file_directory_count;i++) {
		if (file_directories[i]->path[0] == '/') {
    		snprintf(buffer, PATH_MAX, "%s",  file_directories[i]->path);
		} else {
	        snprintf(buffer, PATH_MAX, "%s/%s", bbspath, file_directories[i]->path);
		}
        if (ini_parse(buffer, file_sub_handler, file_directories[i])) {
            fprintf(stderr, "Unable to load %s\n", buffer);
            exit(-1);
        }
    }
    cursesWin = initscr();
    cdkscreen = initCDKScreen(cursesWin);

	desc_win = newwin(10, 46, 14, 1);
	instruction_win = newwin(10, 32, 14, 47);

	waddstr(instruction_win, instructions);

	wrefresh(instruction_win);

    scrollList  = newCDKScroll(cdkscreen, 2, 1, 1, 12, 36, "</48>File Directories<!48>", NULL, 0, FALSE, A_REVERSE, TRUE, TRUE);
    if (!scrollList) {
        fprintf(stderr, "Unable to make scrolllist!");
		destroyCDKScreen(cdkscreen);
		endCDK();
		exit(-1);
    }

    filedirs = (char **)malloc(sizeof(char *) * file_directory_count);

    for (i=0;i<file_directory_count;i++) {
        filedirs[i] = strdup(file_directories[i]->name);
    }
    
    setCDKScrollItems(scrollList, filedirs, file_directory_count, FALSE);

    while(1) {
		selection = activateCDKScroll(scrollList, 0);
		if (scrollList->exitType == vESCAPE_HIT) {
			break;
		} else if (scrollList->exitType == vNORMAL) {
            list_subdirs(selection);
        }
	}

	destroyCDKScroll(scrollList);
	destroyCDKScreen(cdkscreen);
	endCDK();
}