#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../../src/inih/ini.h"

struct bbs_entry_t {
    char *bbsname;
	char *sysopname;
	char *location;
	char *software;
	char *url;
	int tport;
	int sport;
	char *comment;
};

static int handler(void* user, const char* section, const char* name,
                   const char* value)
{
	struct bbs_entry_t *bbs_entry = (struct bbs_entry_t *)user;
	
	if (strcasecmp(section, "main") == 0) {
		if (strcasecmp(name, "bbs name") == 0) {
            bbs_entry->bbsname = strdup(value);
		} else if (strcasecmp(name, "sysop name") == 0) {
			bbs_entry->sysopname = strdup(value);
		} else if (strcasecmp(name, "location") == 0) {
            bbs_entry->location = strdup(value);
        } else if (strcasecmp(name, "software") == 0) {
            bbs_entry->software = strdup(value);
        } else if (strcasecmp(name, "address") == 0) {
            bbs_entry->url = strdup(value);
        } else if (strcasecmp(name, "telnet port") == 0) {
            bbs_entry->tport = atoi(value);
            if (bbs_entry->tport < 0 || bbs_entry->tport > 65535) {
                bbs_entry->tport = -1;
            }
        } else if (strcasecmp(name, "ssh port") == 0) {
            bbs_entry->sport = atoi(value);
            if (bbs_entry->sport < 0 || bbs_entry->sport > 65535) {
                bbs_entry->sport = -1;
            }          
        } else if (strcasecmp(name, "comment") == 0) {
            bbs_entry->comment = strdup(value);
        }
	}
	return 1;
}

int main(int argc, char **argv) {
    struct bbs_entry_t entry;
	if (argc < 3) {
		printf("Usage: %s inifile outputfile\n", argv[0]);
		exit(1);
	}

    memset(&entry, 0, sizeof(struct bbs_entry_t));
    entry.tport = -1;
    entry.sport = -1;

	if (ini_parse(argv[1], handler, &entry) <0) {
		fprintf(stderr, "Unable to load configuration ini (%s)!\n", argv[1]);
		exit(-1);
	}

    if (entry.url == NULL) {
        fprintf(stderr, "Missing Address!\n");
        exit(-1);
    }
    if (entry.bbsname == NULL) {
        fprintf(stderr, "Missing BBS Name!\n");
        exit(-1);
    }

    FILE *fptr = fopen(argv[2], "w");
    if (!fptr) {
        fprintf(stderr, "Unable to open %s\n", argv[2]);
        exit(-1);
    } 
    fprintf(fptr, "BEGIN BBSENTRY >>>\n");
    fprintf(fptr, "%s\n", entry.bbsname);
    fprintf(fptr, "%s\n", entry.sysopname);
    fprintf(fptr, "%s\n", entry.location);
    fprintf(fptr, "%s\n", entry.software);
    fprintf(fptr, "%s\n", entry.url);
    fprintf(fptr, "%d\n", entry.tport);
    fprintf(fptr, "%d\n", entry.sport);
    fprintf(fptr, "%s\n", entry.comment);
    fprintf(fptr, "END BBSENTRY >>>\n");

    fclose(fptr);

    printf("BBS Entry file (%s) written...\n", argv[2]);
    printf("Please post with mgpost, with the subject \"MBBSLIST\"\n");

    return 0;
}
