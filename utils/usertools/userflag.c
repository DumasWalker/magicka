#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sqlite3.h>

int main(int argc, char **argv) {
	sqlite3 *db;
	sqlite3_stmt *res;


    static const char *id_sql = "SELECT Id FROM users WHERE loginname = ?";
    static const char *check_sql = "SELECT COUNT(*) FROM user_flags WHERE userid = ? and flag = ?";
	static const char *create_sql = "CREATE TABLE IF NOT EXISTS user_flags (userid INTEGER, flag TEXT COLLATE NOCASE);";
    static const char *set_sql = "INSERT INTO user_flags (userid, flag) VALUES(?, ?)";
    static const char *unset_sql = "DELETE FROM user_flags WHERE userid = ? AND flag = ?";
	char *err_msg = 0;
	int id;
	int rc;
	char *password;
	char *hash;
	char *salt;
    char c;
    int hasflag;

    if (argc < 5) {
        printf("Usage: \n    ./userdel users.sq3 [loginname] [SET|UNSET] [flag]\n");
        return -1;
    }

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

    if (sqlite3_step(res) == SQLITE_ROW) {
        id = sqlite3_column_int(res, 0);
        sqlite3_finalize(res);

    	rc = sqlite3_exec(db, create_sql, 0, 0, &err_msg);
        if (rc != SQLITE_OK) {
            sqlite3_close(db);
            printf("Error creating flag table: %s\n", err_msg);
            sqlite3_free(err_msg);
            exit(1);
        }

        rc = sqlite3_prepare_v2(db, check_sql, -1, &res, 0);
        if (rc != SQLITE_OK) {
		    printf("Cannot prepare statement: %s\n", sqlite3_errmsg(db));
	    	sqlite3_close(db);
    		exit(1);
        }
        hasflag = 0;
        sqlite3_bind_int(res, 1, id);
        if (sqlite3_step(res) == SQLITE_ROW) {
            if (sqlite3_column_int(res, 0) != 0) {
                hasflag = 1;
            }
        }
        sqlite3_finalize(res);
        if (strcasecmp(argv[3], "set") == 0) {
            if (hasflag) {
                printf("User already has flag: %s\n", argv[4]);
                sqlite3_close(db);
                exit(0);
            }
            rc = sqlite3_prepare_v2(db, set_sql, -1, &res, 0);
            if (rc != SQLITE_OK) {
                printf("Cannot prepare statement: %s\n", sqlite3_errmsg(db));
                sqlite3_close(db);
                exit(1);
            }
            sqlite3_bind_int(res, 1, id);
            sqlite3_bind_text(res, 2, argv[4], -1, 0);
            sqlite3_step(res);
            sqlite3_finalize(res);
        } else if (strcasecmp(argv[3], "unset") == 0) {
            if (!hasflag) {
                printf("User does not have flag: %s\n", argv[4]);
                sqlite3_close(db);
                exit(0);
            }
            rc = sqlite3_prepare_v2(db, unset_sql, -1, &res, 0);
            if (rc != SQLITE_OK) {
                printf("Cannot prepare statement: %s\n", sqlite3_errmsg(db));
                sqlite3_close(db);
                exit(1);
            }
            sqlite3_bind_int(res, 1, id);
            sqlite3_bind_text(res, 2, argv[4], -1, 0);
            sqlite3_step(res);
            sqlite3_finalize(res);           
        }
        sqlite3_close(db);
        printf("Done!\n");
        return 0;

    } else {
        printf("User not found...\n");
        sqlite3_close(db);
        return 0;
    }
    
}