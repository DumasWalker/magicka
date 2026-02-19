#ifndef __BBS_H__
#define __BBS_H__

#include <sys/types.h>

#include <stddef.h>
#include <time.h>
#include <termios.h>
#ifdef __APPLE__
#include <grp.h>
#endif
#if defined(ENABLE_WWW)
#include <microhttpd.h>
#endif
#include <string.h>
#include "lua/lua.h"
#include "lua/lauxlib.h"
#include "jamlib/jam.h"

#include "stralloc/stralloc.h"

#ifndef __linux__
#define HAVE_STRLCPY
#endif

#define VERSION_MAJOR 0
#define VERSION_MINOR 15
#define VERSION_STR "alpha"

#define NETWORK_FIDO 1
#define NETWORK_WWIV 2
#define NETWORK_MAGI 3
#define NETWORK_QWK 4

#define TYPE_LOCAL_AREA 0
#define TYPE_NETMAIL_AREA 1
#define TYPE_ECHOMAIL_AREA 2
#define TYPE_NEWSGROUP_AREA 3

#define IAC 255
#define IAC_WILL 251
#define IAC_WONT 252
#define IAC_DO 253
#define IAC_DONT 254
#define IAC_TRANSMIT_BINARY 0
#define IAC_SUPPRESS_GO_AHEAD 3
#define IAC_ECHO 1

struct ptr_vector {
	size_t len;
	size_t capacity;
	void **ptrs;
};

static const struct ptr_vector EMPTY_PTR_VECTOR = {0, 0, NULL};

struct fido_addr {
	unsigned short zone;
	unsigned short net;
	unsigned short node;
	unsigned short point;
};

struct last10_callers {
	char name[17];
	char location[33];
	time_t time;
	int calls;
} __attribute__((packed));

struct text_file {
	char *name;
	char *path;
};

struct door_config {
	char *name;
	char *command;
	int stdio;
	char *codepage;
};

struct mail_area {
	char *name;
	char *path;
	char *qwkname;
	int qwkconfno;
	int read_sec_level;
	int write_sec_level;
	struct ptr_vector rd_req_flags;
	struct ptr_vector rd_not_flags;
	struct ptr_vector wr_req_flags;
	struct ptr_vector wr_not_flags;
	int type;
	int base_type;
	int realnames;
};

struct mail_conference {
	char *name;
	char *path;
	char *tagline;
	char *domain;
	char *header;
	char *semaphore;
	int networked;
	int nettype;
	int realnames;
	int sec_level;
	struct ptr_vector mail_areas;
	struct ptr_vector vis_req_flags;
	struct ptr_vector vis_not_flags;
	struct fido_addr *fidoaddr;
	int maginode;
};

struct file_sub {
	char *name;
	char *database;
	char *upload_path;
	int upload_sec_level;
	int download_sec_level;
	int display_on_web;
	struct ptr_vector up_req_flags;
	struct ptr_vector up_not_flags;
	struct ptr_vector down_req_flags;
	struct ptr_vector down_not_flags;
};

struct file_directory {
	char *name;
	char *path;
	int sec_level;
	int display_on_web;
	struct ptr_vector vis_req_flags;
	struct ptr_vector vis_not_flags;
	struct ptr_vector file_subs;
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

#define IP_STATUS_UNKNOWN 0
#define IP_STATUS_WHITELISTED 1
#define IP_STATUS_BLACKLISTED 2

struct ip_address_guard {
	int status;
	time_t last_connection;
	int connection_count;
};

struct bbs_config {
	uid_t uid;
	gid_t gid;
	int codepage;
	int ipv6;
	int idletimeout;
	char *external_address;
	char *ipdata_location;
	char *bbs_location;
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
	char *www_url;
	int www_server;
	int www_port;
	char *www_path;
	int www_redirect_ssl;
	int ssh_server;
	int ssh_port;
	char *ssh_dsa_key;
	char *ssh_rsa_key;
	char *ssh_ed25519_key;
	char *ssh_ecdsa_key;
	char *string_file;
	char *mgchat_server;
	int mgchat_port;
	char *mgchat_bbstag;
	int bwave_max_msgs;
	int date_style;
	char *upload_checker;
	char *upload_checker_codepage;
	struct fido_addr *main_aka;
	char *new_user_pass;
	char *root_menu;
	char *menu_path;
	char *external_editor_cmd;
	int external_editor_stdio;
	char *external_editor_codepage;
	int fork;

	int nodes;
	int newuserlvl;
	int automsgwritelvl;
	int broadcast_enable;
	int broadcast_port;
	char *broadcast_address;
	char *broadcast_topic;
	char *broadcast_user;
	char *broadcast_pass;
	char *ssl_cert;
	char *ssl_key;
	char *ssl_url;
	int ssl_only;
	int ssl_port;
	int ipguard_enable;
	int ipguard_timeout;
	int ipguard_tries;

	int msg_quote_bg;
	int msg_quote_fg;

	int msg_tag_bg;
	int msg_tag_fg;

	struct ptr_vector mail_conferences;
	struct ptr_vector doors;
	struct ptr_vector file_directories;
	struct ptr_vector text_files;

	char *config_path;
	struct ptr_vector archivers;

	struct ptr_vector protocols;
};

struct sec_level_t {
	int timeperday;
	int idle_timeout;
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
	char *signature;
	int autosig;
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
	int nodemsgs;
	int codepage;
	int exteditor;
	int bwavestyle;
	int dopipe;
	int qwke;
};

struct blog_entry_t {
	char *subject;
	char *author;
	char *body;
	time_t date;
};

struct ipdata_t {
	char *countrycode;
	char *country;
	char *region;
	char *city;
};

#include "msglib/msglib.h"

extern void init_ptr_vector(struct ptr_vector *vec);
extern void ptr_vector_clear(struct ptr_vector *vec);
extern void *ptr_vector_get(struct ptr_vector *vec, size_t i);
extern int ptr_vector_put(struct ptr_vector *vec, void *p, size_t i);
extern int ptr_vector_ins(struct ptr_vector *vec, void *p, size_t i);
extern void *ptr_vector_del(struct ptr_vector *vec, size_t i);
extern int ptr_vector_append(struct ptr_vector *vec, void *p);
extern size_t ptr_vector_len(struct ptr_vector *vec);
extern void ptr_vector_apply(struct ptr_vector *vec, void (*f)(void *arg));
extern void **ptr_vector_ptrs(struct ptr_vector *vec);
extern void **consume_ptr_vector(struct ptr_vector *vec);
extern void destroy_ptr_vector(struct ptr_vector *vec);
extern int ptr_vector_append_if_unique(struct ptr_vector *vec, void *p);
extern FILE *fopen_bbs_path(const char *filename, const char *mode);
extern FILE *fopen_node_path(const char *filename, const char *mode);
extern int check_security(struct user_record *user, int level, struct ptr_vector *req_flags, struct ptr_vector *not_flags);

extern char *str_replace(const char *orig, const char *rep, const char *with);
extern int copy_file(char *src, char *dest);
extern int recursive_delete(const char *dir);
extern void automessage_write();
extern void automessage_display();
extern void automessage();
extern void dolog(const char *fmt, ...);
extern void dolog_www(char *ipaddr, char *fmt, ...);
extern void runbbs_ssh(char *ipaddress);
extern void runbbs(int sock, char *ipaddress);
extern struct fido_addr *parse_fido_addr(const char *str);
extern void s_putchar(char c);
extern void s_printf(char *fmt, ...);
extern void s_putstring(char *c);
extern void s_displayansi_pause(char *file, int pause);
extern void s_displayansi_p(char *file);
extern void s_displayansi(char *file);
extern char s_getchar();
extern void s_readpass(char *buffer, int max);
extern void s_readstring(char *buffer, int max);
extern void s_readstring_inject(char *buffer, int max, char *inject);
extern char s_getc();
extern void disconnect(char *calledby);
extern void display_info();
extern void display_last10_callers(struct user_record *user);
extern void do_logout();
extern void broadcast(char *mess, ...);

extern void gen_salt(char **s);
extern char *hash_sha256(char *pass, char *salt);
extern int save_user(struct user_record *user);
extern int check_user(char *loginname);
extern int check_fullname_j(char *firstandlastname);
extern int check_fullname(char *firstname, char *lastname);
extern struct user_record *new_user();
extern struct user_record *check_user_pass(char *loginname, char *password);
extern void list_users(struct user_record *user);
extern int msgbase_sub_unsub(int conference, int msgbase);
extern int msgbase_is_subscribed(int conference, int msgbase);
extern int msgbase_flag_unflag(struct user_record *user, int conference, int msgbase, int msgid);
extern int msgbase_is_flagged(struct user_record *user, int conference, int msgbase, int msgid);
extern char *get_username(int id);
extern char *get_username_from_fullname(char *firstname, char *lastname);
extern char *get_username_from_fullname_j(char *firstandlastname);
extern int user_check_flag(struct user_record *user, char *flag);

extern void active_nodes();
extern void send_node_msg();
extern void display_bulletins();
extern void display_textfiles();

extern time_t utc_to_local(time_t utc);
extern void mail_scan(struct user_record *user);
extern char *editor(struct user_record *user, char *quote, int qlen, char *from, int email, int sig);
extern char *external_editor(struct user_record *user, char *to, char *from, char *quote, int qlen, char *qfrom, char *subject, int email, int sig);
extern unsigned long generate_msgid();
extern void read_mail(struct user_record *user);
extern void list_messages(struct user_record *user);
extern int choose_conference();
extern int choose_area(int confr);
extern void next_mail_conf(struct user_record *user);
extern void prev_mail_conf(struct user_record *user);
extern void next_mail_area(struct user_record *user);
extern void prev_mail_area(struct user_record *user);
extern void post_message(struct user_record *user);
extern void msg_conf_sub_bases();
extern void msgbase_reset_pointers(int conference, int msgarea, int readm, int msgno);
extern void msgbase_reset_all_pointers(int readm);
extern void full_mail_scan(struct user_record *user);
extern void full_mail_scan_personal(struct user_record *user);
extern int read_new_msgs(struct user_record *user, struct msg_headers *msghs);
extern int new_messages(struct user_record *user, int conference, int area);
extern char *wrap_quotes(char *body, char initial1, char initial2);

extern void rundoor(struct user_record *user, char *cmd, int stdio, char *codepage);
extern int runexternal(struct user_record *user, char *cmd, int stdio, char **argv, char *cwd, int raw, char *codepage);

extern void bbs_list();

extern void chat_system(struct user_record *user, char *mserver, int mport);

extern int mail_getemailcount(struct user_record *user);
extern void send_email(struct user_record *user);
extern void list_emails(struct user_record *user);
extern void commit_email(char *recipient, char *subject, char *msg);
extern void full_email_scan();

extern void download_zmodem(struct user_record *user, char *filename);
extern void settings_menu(struct user_record *user);
extern void upload_zmodem(struct user_record *user, char *upload_p);
extern int ttySetRaw(int fd, struct termios *prevTermios);
extern int do_upload(struct user_record *user, char *final_path);
extern int do_download(struct user_record *user, char *file);
extern void choose_directory();
extern void choose_subdir();
extern void list_files(struct user_record *user);
extern void upload(struct user_record *user);
extern void download(struct user_record *user);
extern void clear_tagged_files();
extern void next_file_dir(struct user_record *user);
extern void prev_file_dir(struct user_record *user);
extern void next_file_sub(struct user_record *user);
extern void prev_file_sub(struct user_record *user);
extern void file_scan();
extern void file_search();
extern void genurls();

extern void lua_push_cfunctions(lua_State *L);
extern void do_lua_script(char *script);

extern void bwave_create_packet();
extern void bwave_upload_reply();

extern void qwk_create_packet();
extern void qwk_upload_reply();

extern void load_strings();
extern char *get_string(int offset);
extern void chomp(char *string);
extern char **split_on_space(char *str, size_t *lenp);
extern char **split_args(char *str, size_t *lenp);
extern void split_to_ptr_vector(const char *str, struct ptr_vector *pv);

extern void die(const char *msg);
extern void *malloz(size_t size);
extern char *file2str(const char *path);
extern stralloc file2stralloc(const char *path);
extern char *str5dup(const char *a, const char *b, const char *c, const char *d, const char *e);
extern char *str4dup(const char *a, const char *b, const char *c, const char *d);
extern char *str3dup(const char *a, const char *b, const char *c);
extern char *str2dup(const char *a, const char *b);

#if !defined(HAVE_STRLCPY)
extern size_t strlcat(char *dst, const char *src, size_t dsize);
extern size_t strlcpy(char *dst, const char *src, size_t dsize);
#endif

#if defined(ENABLE_WWW)
extern void www_init();
extern void *www_logger(void *cls, const char *uri, struct MHD_Connection *con);
extern void www_request_completed(void *cls, struct MHD_Connection *connection, void **con_cls, enum MHD_RequestTerminationCode toe);
/*extern int www_handler(void *cls, struct MHD_Connection *connection, const char *url, const char *method, const char *version, const char *upload_data, size_t *upload_data_size, void **ptr); */
extern enum MHD_Result www_handler(void *cls, struct MHD_Connection *connection, const char *url, const char *method, const char *version, const char *upload_data, size_t *upload_data_size, void **ptr);
extern char *www_email_summary(struct MHD_Connection *connection, struct user_record *user);
extern char *www_email_display(struct MHD_Connection *connection, struct user_record *user, int email);
extern int www_send_email(struct user_record *user, char *recipient, char *subject, char *body);
extern char *www_new_email(struct MHD_Connection *connection);
extern int www_email_delete(struct MHD_Connection *connection, struct user_record *user, int id);
extern char *www_msgs_arealist(struct MHD_Connection *connection, struct user_record *user);
extern char *www_msgs_messagelist(struct MHD_Connection *connection, struct user_record *user, int conference, int area, int skip);
extern char *www_msgs_messageview(struct MHD_Connection *connection, struct user_record *user, int conference, int area, int msg);
extern char *www_sent_msg_page(struct MHD_Connection *connection, int conference, int area);
extern int www_send_msg(struct user_record *user, char *to, char *subj, int conference, int area, int replyid, char *body);
extern char *www_new_msg(struct MHD_Connection *connection, struct user_record *user, int conference, int area);
extern char *www_last10(struct MHD_Connection *connection);
extern void www_expire_old_links();
extern char *www_create_link(int dir, int sub, int fid);
extern char *www_decode_hash(char *hash);
extern char *www_sanitize(char *inp);
extern char *www_files_display_listing(struct MHD_Connection *connection, int dir, int sub);
extern char *www_files_areas(struct MHD_Connection *connection);
extern char *www_files_get_from_area(int dir, int sub, char *file);
extern char *www_blog(struct MHD_Connection *connection);
extern char *www_blog_rss(struct MHD_Connection *connection);
extern char *www_get_my_url(struct MHD_Connection *con);
extern char *www_script_parse(struct MHD_Connection *connection, char *script);
#endif
extern int menu_system(char *menufile);

extern char *nl_get_bbsname(struct fido_addr *addr, char *domain);
extern void nl_browser();

extern void blog_display();
extern void blog_write();
extern struct ptr_vector blog_load(void);
extern int blog_get_entry_count();
extern char *blog_get_entry(int i);
extern char *blog_get_author(int i);
extern char *blog_get_title(int i);
extern time_t blog_get_date(int i);

extern void free_ip_data(struct ipdata_t *data);
extern struct ipdata_t *get_ip_data();

#endif
