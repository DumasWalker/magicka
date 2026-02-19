#ifndef __CCENTER_H__
#define __CCENTER_H__

#define NETWORK_FIDO 1
#define NETWORK_WWIV 2

#define TYPE_LOCAL_AREA    0
#define TYPE_NETMAIL_AREA  1
#define TYPE_ECHOMAIL_AREA 2
#define TYPE_NEWSGROUP_AREA 3

struct fido_addr {
	unsigned short zone;
	unsigned short net;
	unsigned short node;
	unsigned short point;
};

struct text_file {
	char *name;
	char *path;
};

struct door_config {
	char *name;
	char key;
	char *command;
	int stdio;
};

struct mail_area {
	char *name;
	char *path;
	char *qwkname;
	int read_sec_level;
	int write_sec_level;
	int type;
};

struct mail_conference {
	char *name;
	char *path;
	char *tagline;
	int networked;
	int nettype;
	int realnames;
	int sec_level;
	int mail_area_count;
	struct mail_area **mail_areas;
	struct fido_addr *fidoaddr;
	int wwivnode;
};

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
	int file_sub_count;
	struct file_sub **file_subs;
};

struct archiver {
	char *name;
	char *extension;
	char *unpack;
	char *pack;
};

struct protocol {
	char *name;
	char *upload;
	char *download;
	int internal_zmodem;
	int stdio;
	int upload_prompt;
};

struct bbs_config {
	char *bbs_name;
	char *bwave_name;
	char *sysop_name;
	char *pid_file;
	char *ansi_path;
	char *bbs_path;
	char *log_path;
	char *script_path;
	char *echomail_sem;
	char *netmail_sem;
	char *default_tagline;
	int telnet_port;
	int www_server;
	int www_port;
	char *www_path;
	int ssh_server;
	int ssh_port;
	char *ssh_dsa_key;
	char *ssh_rsa_key;
	char *string_file;
	char *mgchat_server;
	int mgchat_port;
	char *mgchat_bbstag;
	int bwave_max_msgs;
	struct fido_addr *main_aka;
	
	char *external_editor_cmd;
	int external_editor_stdio;
	int fork;
	
	int nodes;
	int newuserlvl;
	int automsgwritelvl;
	int broadcast_enable;
	int broadcast_port;
	char *broadcast_address;
	
	int ipguard_enable;
	int ipguard_timeout;
	int ipguard_tries;
	
	int mail_conference_count;
	struct mail_conference **mail_conferences;
	int door_count;
	struct door_config **doors;
	int file_directory_count;
	struct file_directory **file_directories;
	int text_file_count;
	struct text_file **text_files;
	
	char *config_path;
	int archiver_count;
	struct archiver **archivers;
	
	int protocol_count;
	struct protocol **protocols;
};

struct sec_level_t {
	int timeperday;
};

struct user_record {
	int id;
	char *loginname;
	char *password;
	char *salt;
	char *firstname;
	char *lastname;
	char *email;
	char *location;
	int sec_level;
	struct sec_level_t *sec_info;
	time_t laston;
	int timeleft;
	int cur_mail_conf;
	int cur_mail_area;
	int cur_file_dir;
	int cur_file_sub;
	int timeson;
	int bwavepktno;
	int defarchiver;
	int defprotocol;
};
extern void choose_sec_level(int *result, int x, int y, int selected);
extern int get_valid_seclevels(int **levels, int *count);
extern struct fido_addr *parse_fido_addr(const char *str);
extern int load_ini_file(char *ini_file);
extern void system_config(void);
extern void system_paths();
extern void mail_conferences();
extern void edit_mail_areas(int confer);
extern void file_directories();
extern void edit_file_subdirs(int fdir);
extern void textfiles();
#endif
