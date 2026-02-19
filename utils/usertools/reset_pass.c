#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <ctype.h>
#include <openssl/evp.h>

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined (LIBRESSL_VERSION_NUMBER)
#define EVP_MD_CTX_new EVP_MD_CTX_create
#define EVP_MD_CTX_free EVP_MD_CTX_destroy
#endif

char *hash_sha256(char *pass, char *salt) {
	char *buffer = (char *)malloc(strlen(pass) + strlen(salt) + 1);
	char *shash = NULL;
	unsigned char hash[EVP_MAX_MD_SIZE];
	unsigned int length_of_hash = 0;
	int i;

	if (!buffer) {
		fprintf(stderr, "Out of memory!\n");
		exit(-1);
	}

	sprintf(buffer, "%s%s", pass, salt);


	EVP_MD_CTX *context = EVP_MD_CTX_new();

	if (context != NULL) {
		if(EVP_DigestInit_ex(context, EVP_sha256(), NULL)) {
			if(EVP_DigestUpdate(context, buffer, strlen(buffer))) {
				if(EVP_DigestFinal_ex(context, hash, &length_of_hash)) {

					shash = (char *)malloc(length_of_hash * 2 + 1);
        	        for(i = 0; i < length_of_hash; i++) {
						sprintf(shash + (i * 2), "%02x", (int)hash[i]);
                        
                    }
					EVP_MD_CTX_free(context);
					free(buffer);
					return shash;
                }
			}
		}
		EVP_MD_CTX_free(context);
	}

	free(buffer);
	fprintf(stderr, "Error creating hash!\n");
	exit(-1);
}

void gen_salt(char **s) {
	FILE *fptr;
	int i;
	char c;
	*s = (char *)malloc(11);
	char *salt = *s;

	if (!salt) {
		printf("Out of memory..");
		exit(-1);
	}
	fptr = fopen("/dev/urandom", "rb");
	if (!fptr) {
		printf("Unable to open /dev/urandom!");
		exit(-1);
	}
	for (i=0;i<10;i++) {
		fread(&c, 1, 1, fptr);
		salt[i] = (char)((abs(c) % 93) + 33);
	}
	fclose(fptr);
	salt[10] = '\0';
}

int main(int argc, char **argv) {
	sqlite3 *db;
	sqlite3_stmt *res;

	char *update_sql = "UPDATE users SET password=?, salt=? WHERE loginname LIKE ?";
	char *err_msg = 0;
	int id;
	int rc;
	char *password;
	char *hash;
	char *salt;

    if (argc < 4) {
        printf("Usage: \n    ./reset_pass users.sq3 [loginname] [New Password]\n");
        return -1;
    }

 	rc = sqlite3_open(argv[1], &db);

	password = argv[3];

	gen_salt(&salt);
	hash = hash_sha256(password, salt);

	rc = sqlite3_prepare_v2(db, update_sql, -1, &res, 0);
	if (rc != SQLITE_OK) {
		printf("Cannot prepare statement: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		exit(1);
	}
	sqlite3_bind_text(res, 1, hash, -1, 0);
	sqlite3_bind_text(res, 2, salt, -1, 0);
	sqlite3_bind_text(res, 3, argv[2], -1, 0);

	rc = sqlite3_step(res);

	if (rc != SQLITE_DONE) {
		printf("Error: %s\n", sqlite3_errmsg(db));
		exit(1);
	}
	
	printf("reset!\n");
	sqlite3_finalize(res);
	sqlite3_close(db);
}
