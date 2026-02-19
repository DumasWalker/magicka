#ifndef __FILECENTER_H__
#define __FILECENTER_H__

struct file_sub {
	char *name;
	char *database;
	char *upload_path;
	int upload_sec_level;
	int download_sec_level;
};

struct file_directory {
	char *name;
	char *path;
	int sec_level;
	int display_on_web;
	int file_sub_count;
	struct file_sub **file_subs;
};

struct archiver {
	char *name;
	char *extension;
	char *unpack;
	char *pack;
};

#endif
