#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sqlite3.h>

int main(int argc, char **argv) {
	sqlite3 *db;
	sqlite3_stmt *res;


    char *id_sql = "SELECT Id FROM users WHERE loginname = ?";
	char *delete_sql = "DELETE FROM users WHERE Id = ?";
    char *sub_sql = "DELETE FROM msg_subs WHERE uid = ?";
    char *flag_sql = "DELETE FROM user_flags WHERE uid = ?";
    char *msgflags_sql = "DELETE FROM msg_flags WHERE uid = ?";
	char *err_msg = 0;
	int id;
	int rc;
	char *password;
	char *hash;
	char *salt;
    char c;
    if (argc < 3) {
        printf("Usage: \n    ./userdel users.sq3 \"[loginname]\"\n");
        return -1;
    }

 	rc = sqlite3_open(argv[1], &db);

    rc = sqlite3_prepare_v2(db, id_sql, -1, &res, 0);
	if (rc != SQLITE_OK) {
		printf("Cannot prepare statement: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		exit(1);
	}
    sqlite3_bind_text(res, 1, argv[2], -1, 0);

    if (sqlite3_step(res) == SQLITE_ROW) {
        id = sqlite3_column_int(res, 0);

        sqlite3_finalize(res);

        printf("Really delete %s ? ", argv[2]);
        c = getchar();
        if (c == 'y' || c == 'Y') {
            printf("\nDeleting %s...\n", argv[2]);
            rc = sqlite3_prepare_v2(db, delete_sql, -1, &res, 0);
            if (rc != SQLITE_OK) {
                printf("Cannot prepare statement: %s\n", sqlite3_errmsg(db));
                sqlite3_close(db);
                exit(1);
            }
            sqlite3_bind_int(res, 1, id);
            sqlite3_step(res);
            sqlite3_finalize(res);

            printf("Deleting Message Base Subscriptions for %s...\n", argv[2]);
            rc = sqlite3_prepare_v2(db, sub_sql, -1, &res, 0);
            if (rc != SQLITE_OK) {
                printf("Cannot prepare statement: %s\n", sqlite3_errmsg(db));
                sqlite3_close(db);
                exit(1);
            }
            sqlite3_bind_int(res, 1, id);
            sqlite3_step(res);
            sqlite3_finalize(res);

            printf("Deleting Message Base Flags for %s...\n", argv[2]);
            rc = sqlite3_prepare_v2(db, msgflags_sql, -1, &res, 0);
            if (rc != SQLITE_OK) {
                printf("Cannot prepare statement: %s\n", sqlite3_errmsg(db));
                sqlite3_close(db);
                exit(1);
            }
            sqlite3_bind_int(res, 1, id);
            sqlite3_step(res);
            sqlite3_finalize(res);

            printf("Deleting User Flags for %s...\n", argv[2]);
            rc = sqlite3_prepare_v2(db, flag_sql, -1, &res, 0);
            if (rc != SQLITE_OK) {
                printf("Cannot prepare statement: %s\n", sqlite3_errmsg(db));
                sqlite3_close(db);
                exit(1);
            }
            sqlite3_bind_int(res, 1, id);
            sqlite3_step(res);
            sqlite3_finalize(res);

            sqlite3_close(db);
            printf("Done!\n");
            return 0;
        } else {
            printf("\nAborting...\n");
            sqlite3_close(db);
            return 0;
        }

    } else {
        printf("User not found...\n");
        sqlite3_close(db);
        return 0;
    }
}