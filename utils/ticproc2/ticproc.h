#ifndef __TICPROC_H__
#define __TICPROC_H__

struct downlink_t {
	char *address;
	char *outbox;
	char *password;
};

struct filearea_t {
	char *name;
	char *path;
	char *database;
	int passthrough;
	char *downlink_file;
	int downlink_count;	
	char **downlinks;
};

struct network_t {
	char *name;
	char *config;
	char *uplink;
	char *uplink_password;
	int filearea_count;
	struct filearea_t **file_areas;
	char *netmail_base;
	int netmail_type;
	char *downlink_config;
	int downlink_count;
	struct downlink_t **downlinks;
};

struct ticproc_t {
	int case_insensitve;
	char *inbound;
	char *bad;
	int network_count;
	struct network_t **networks;
};

struct ticfile_t {
	char *area;
	char *password;
	char *file;
	char *lname;
	char *origin;
	char *from_addr;
	char *to_addr;
	int ldesc_lines;
	char **ldesc;
	char *desc;
	char *replaces;
	char *crc;
	char *size;
	char *date;
	char *magic;
	int path_lines;
	char **path;
	int seenby_lines;
	char **seenby;
};

#endif
