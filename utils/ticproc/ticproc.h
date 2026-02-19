#ifndef __TICPROC_H__
#define __TICPROC_H__

struct filearea_t {
	char *name;
	char *password;
	char *path;
	char *database;
};

struct ticproc_t {
	int ignore_pass;
	int case_insensitve;
	char *inbound;
	char *bad;
	int do_not_delete;
	int filearea_count;
	struct filearea_t **file_areas;
};

struct ticfile_t {
	char *area;
	char *password;
	char *file;
	char *lname;
	int desc_lines;
	char **desc;
	char *replaces;
	char *crc;
};

#endif
