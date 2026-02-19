#include <curses.h>
#include <cdk.h>
#include <sqlite3.h>
#include <stdio.h>
#include <libgen.h>
#include <sys/stat.h>

struct files {
	char *name;
	char *description;
	int approved;
};

struct files **f;
char **filenames;
int fcount = 0;
sqlite3 *db;
CDKSCREEN *cdkscreen = 0;

static int deleteFile(EObjectType cdktype, void *object, void *clientData, chtype input) {
	int i;
	CDKSCROLL *s = (CDKSCROLL *)object;
	sqlite3_stmt *res;
	int rc;
	struct stat st;
	char sql_delete[] = "DELETE FROM files WHERE filename LIKE ?";
	int index = getCDKScrollCurrent(s);
	if (index >= fcount) {
		return FALSE;
	}
	rc = sqlite3_prepare_v2(db, sql_delete, -1, &res, 0);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "Error deleting file! : %s\r\n", sqlite3_errmsg(db));
		return FALSE;
	}
	sqlite3_bind_text(res, 1, f[index]->name, -1, 0);

	sqlite3_step(res);
	sqlite3_finalize(res);
	
	if (stat(f[index]->name, &st) == 0) {
		remove(f[index]->name);
	}	

	for (i=index;i<fcount-1;i++) {
		filenames[i] = filenames[i+1];
		f[i] = f[i+1];
	}
	free(filenames[fcount-1]);
	free(f[fcount-1]);


	fcount--;
	if (fcount == 0) {
		free(filenames);
		free(f);
		filenames = NULL;
		f = NULL;
		
		
	} else {
		filenames = realloc(filenames, sizeof(char *) * fcount);
		f = realloc(f, sizeof(struct files) * fcount);
		setCDKScrollItems(s, filenames, fcount, FALSE);
		refreshCDKScreen(cdkscreen);
		
	}
	return FALSE;
}

static void doApprove(int index) {
		char sql_approve[] = "UPDATE files SET approved=1 WHERE filename LIKE ?";
		sqlite3_stmt *res;
		int rc;
		struct stat st;

		if (stat(f[index]->name, &st) == 0) {
			f[index]->approved = 1;
			sprintf(filenames[index], "</24>%s (approved)<!24>", basename(f[index]->name));
			rc = sqlite3_prepare_v2(db, sql_approve, -1, &res, 0);
			if (rc != SQLITE_OK) {
				fprintf(stderr, "Error approving file! : %s\r\n", sqlite3_errmsg(db));
				return;
			}
			sqlite3_bind_text(res, 1, f[index]->name, -1, 0);

			sqlite3_step(res);

			sqlite3_finalize(res);
		}
}

static void doDisapprove(int index) {
	char sql_approve[] = "UPDATE files SET approved=0 WHERE filename LIKE ?";
	sqlite3_stmt *res;
	int rc;
	struct stat s;
	f[index]->approved = 0;
	if (stat(f[index]->name, &s) != 0) {
		sprintf(filenames[index], "</16>%s (missing)<!16>", basename(f[index]->name));
	} else {
		sprintf(filenames[index], "</32>%s (unapproved)<!32>", basename(f[index]->name));
	}
	rc = sqlite3_prepare_v2(db, sql_approve, -1, &res, 0);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "Error approving file! : %s\r\n", sqlite3_errmsg(db));
		return;
	}
	sqlite3_bind_text(res, 1, f[index]->name, -1, 0);

	sqlite3_step(res);

	sqlite3_finalize(res);
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
	refreshCDKScreen(cdkscreen);
	return FALSE;
}

int main(int argc, char **argv) {

	CDKSCROLL *scrollList = 0;
	CDKLABEL *instructions = 0;
	WINDOW *cursesWin = 0;
	char *message[] = {"Press A to toggle Activation", "Press D to Delete file", "Press ESC to exit"};
	char sql_read[] = "SELECT filename, description, approved FROM files";
	CDK_PARAMS params;

  sqlite3_stmt *res;
  int rc;
	int i;
	int selection;
	struct stat s;

	CDKparseParams(argc, argv, &params, "d:" CDK_CLI_PARAMS);

	cursesWin = initscr();
	cdkscreen = initCDKScreen(cursesWin);
	initCDKColor();

	char title[256];

	sprintf(title, "</48>%s<!48>",basename(CDKparamString (&params, 'd')));

	instructions = newCDKLabel (
                      cdkscreen,
                      40,
                      1,
                      message,
                      3,
                      TRUE,
                      TRUE);
	drawCDKLabel(instructions, TRUE);
	scrollList = newCDKScroll(cdkscreen, 2,	1, 1, 36, 36, title, NULL, 0, FALSE, A_REVERSE, TRUE, TRUE);
	if (scrollList == 0) {
		fprintf(stderr, "Unable to make scrolllist!");
		destroyCDKScreen(cdkscreen);
		endCDK();
		exit(-1);
	}

	// populate scroll list
	rc = sqlite3_open(CDKparamString (&params, 'd'), &db);
	

	if (rc != SQLITE_OK) {
		fprintf(stderr, "Cannot open database: %s", sqlite3_errmsg(db));
		sqlite3_close(db);
		destroyCDKScreen(cdkscreen);
		endCDK();
		exit(1);
	}
	sqlite3_busy_timeout(db, 5000);
	rc = sqlite3_prepare_v2(db, sql_read, -1, &res, 0);

	if (rc != SQLITE_OK) {
		fprintf(stderr, "Cannot prepare statement: %s", sqlite3_errmsg(db));
		sqlite3_close(db);
		destroyCDKScreen(cdkscreen);
		endCDK();
		exit(1);
	}

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
		if (!f || !filenames) {
			fprintf(stderr, "OOM");
			sqlite3_close(db);
			destroyCDKScreen(cdkscreen);
			endCDK();
			exit(1);
		}
		f[fcount] = (struct files *)malloc(sizeof(struct files));
		f[fcount]->name = strdup((char *)sqlite3_column_text(res, 0));
		f[fcount]->description = strdup((char *)sqlite3_column_text(res, 1));
		f[fcount]->approved = sqlite3_column_int(res, 2);

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

	setCDKScrollItems(scrollList, filenames, fcount, FALSE);

	bindCDKObject (vSCROLL, scrollList, 'a', approveFile, NULL);
	bindCDKObject (vSCROLL, scrollList, 'd', deleteFile, NULL);

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

	free(f);
	free(filenames);
	destroyCDKLabel(instructions);
	destroyCDKScroll(scrollList);
	destroyCDKScreen(cdkscreen);
	sqlite3_close(db);
	endCDK();
	return 0;
}
