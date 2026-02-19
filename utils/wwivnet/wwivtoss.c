#include <limits.h>
#include <dirent.h>
#include "wwivnet.h"
#include "../../deps/jamlib/jam.h"
#include "../../src/inih/ini.h"

char *config_file;
char *inbound_dir = NULL;
char *outbound_dir = NULL;
uint16_t wwivnet_node = 0;

static int handler(void* user, const char* section, const char* name,
                   const char* value)
{
    if (strcasecmp(section, "main") == 0) {
        if (strcasecmp(name, "inbound") == 0) {
            inbound_dir = strdup(value);
        } else if (strcasecmp(name, "outbound") == 0) {
            outbound_dir = strdup(value);
        } else if (strcasecmp(name, "wwiv node") == 0) {
            wwivnet_node = atoi(value);
        }
    }
    return 1;
}

void main_type_new_post(struct net_header_rec *msg_hdr, char *msg_txt) {
    char *subtype;
    char *ptr;
    char *title;

    subtype = strdup(msg_txt);

    ptr = msg_txt;
    while (*ptr != '\0') {
        ptr++;
    }
    ptr++;

    title = strdup(ptr);
    while (*ptr != '\0') {
        ptr++;
    }
    ptr++;

    
}

int process_file(char *filename) {
    char buffer[PATH_MAX];
    FILE *fptr;
    struct net_header_rec msg_hdr;
    char *msg_txt;

    snprintf(buffer, PATH_MAX, "%s/%s", inbound_dir, filename);



    fptr = fopen(buffer, "rb");
    if (!fptr) {
        return 0;
    }

    while (!feof(fptr)) {
        if (fread(&msg_hdr, sizeof(struct net_header_rec), 1, fptr) != 1) {
            break;
        }

        if (msg_hdr.length > 0) {
            msg_txt = (char *)malloc(msg_hdr.length);
            if (fread(msg_txt, 1, msg_hdr.length, fptr) != msg_hdr.length) {
                free(msg_txt);
                fprintf(stderr, "Short read on message.\n");
                break;
            }
        } else {
            msg_txt = NULL;
        }

        switch(msg_hdr.main_type) {
            case 0x0001:
                // main_type_net_info
                fprintf(stderr, "Got main_type_net_info\n");
                break;
            case 0x0002:
                // main_type_email
                fprintf(stderr, "Got main_type_email\n");
                break;
            case 0x0007:
                // main_type_email_name
                fprintf(stderr, "Got main_type_email_name\n");                
                break;
            case 0x0009:
                // main_type_sub_list
                fprintf(stderr, "Got main_type_sub_list\n");
                break;
            case 0x000f:
                // main_type_ssm
                fprintf(stderr, "Got main_type_ssm\n");
                break;
            case 0x0010:
                // main_type_sub_add_req
                fprintf(stderr, "Got main_type_sub_add_req\n");
                break;
            case 0x0011:
                // main_type_sub_drop_req
                fprintf(stderr, "Got main_type_sub_drop_req\n");
                break;
            case 0x0012:
                // main_type_sub_add_resp
                fprintf(stderr, "Got main_type_sub_add_resp\n");
                break;
            case 0x0013:
                // main_type_sub_drop_resp
                fprintf(stderr, "Got main_type_sub_drop_resp\n");
                break;
            case 0x0014:
                // main_type_sub_list_info
                fprintf(stderr, "Got main_type_sub_list_info\n");
                break;
            case 0x001a:
                // main_type_new_post
                main_type_new_post(&msg_hdr, msg_txt);
                break;
            default:
                fprintf(stderr, "Unsupported main type 0x%x\n", msg_hdr.main_type);
                break;
        }
        if (msg_txt != NULL) {
            free(msg_txt);
        }
    }

    fclose(fptr);
    return 1;
}

int main(int argc, char **argv) {
    DIR *inb;
    struct dirent *dent;
    char buffer[256];

    if (argc < 2) {
        fprintf(stderr, "Usage:\n    ./wwivtoss config.ini\n");
        return -1;
    }
	config_file = argv[1];

	if (ini_parse(config_file, handler, NULL) <0) {
		fprintf(stderr, "Unable to load configuration ini (%s)!\n", config_file);
		exit(-1);
	}

    snprintf(buffer, 256, "s%d.net", wwivnet_node);

	inb = opendir(inbound_dir);
	if (!inb) {
		fprintf(stderr, "Error opening inbound directory\n");
		return -1;
	}
	while ((dent = readdir(inb)) != NULL) {
        if (strncmp(dent->d_name, buffer, strlen(buffer)) == 0) {
            if(process_file(dent->d_name)) {
                rewinddir(inb);
            }
        }
    }
    closedir(inb);
}
