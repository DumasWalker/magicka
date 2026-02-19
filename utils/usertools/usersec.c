#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sqlite3.h>

int main(int argc, char **argv) {
	sqlite3 *db;
	sqlite3_stmt *res;
    int rc;
    int seclevel;
    const char *id_sql = "SELECT Id FROM users WHERE loginname = ?";
    const char *sql = "UPDATE users SET sec_level = ? WHERE loginname = ?";

    if (argc < 4) {
        printf("Usage: \n    ./usersec users.sq3 \"[loginname]\" \"[seclevel]\"\n");
        return -1;
    }

    seclevel = atoi(argv[3]);

 	rc = sqlite3_open(argv[1], &db);
	if (rc != SQLITE_OK) {
        printf("Unable to open database: %s\n", argv[1]);
        exit(1);
    }

    rc = sqlite3_prepare_v2(db, id_sql, -1, &res, 0);
	if (rc != SQLITE_OK) {
		printf("Cannot prepare statement: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		exit(1);
    }

    sqlite3_bind_text(res, 1, argv[2], -1, 0);

    if (sqlite3_step(res) != SQLITE_ROW) {
        printf("No such user \"%s\"!\n", argv[2]);
        sqlite3_finalize(res);
        sqlite3_close(db);
        return 0;
    }
    sqlite3_finalize(res);

    rc = sqlite3_prepare_v2(db, sql, -1, &res, 0);
	if (rc != SQLITE_OK) {
		printf("Cannot prepare statement: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		exit(1);
    }
    sqlite3_bind_int(res, 1, seclevel);
    sqlite3_bind_text(res, 2, argv[2], -1, 0);

    rc = sqlite3_step(res);
    if (rc != SQLITE_DONE) {
        printf("Failed %s\n", sqlite3_errmsg(db));
    } else {
        printf("Success\n");
    }
    sqlite3_finalize(res);
    sqlite3_close(db);

    return 0;
}
