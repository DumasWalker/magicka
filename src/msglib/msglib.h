#ifndef __MSGLIB_H__
#define __MSGLIB_H__

#include "../bbs.h"

#define BASE_TYPE_JAM 1
#define BASE_TYPE_SQ3 2

struct msg_t {
	int msg_no;
	void *msg_h;
	char *from;
	char *to;
	char *subject;
	char *oaddress;
	char *daddress;
	char *msgid;
	char *replyid;
	time_t msgwritten;
	long tz_offset;
	char *seenby;
	int isutf8;
	int next_msg_no;
	int prev_msg_no;
};

struct msg_headers {
	struct msg_t **msgs;
	int msg_count;
	int base_type;
};

struct msg_base_t {
	int base_type;
	struct mail_conference *mc;
	struct mail_area *ma;
	union msg_base_data {
		s_JamBase *jam;
	} data;
};

extern int msg_is_to(struct user_record *user, const char *addressed_from, const char *address, int type, int rn, struct mail_conference *mc);
extern int msg_is_from(struct user_record *user, const char *addressed_from, const char *address, int type, int rn, struct mail_conference *mc);
extern void free_message_headers(struct msg_headers *msghs);
extern struct msg_headers *read_message_headers(int msgconf, int msgarea, struct user_record *user, int personal);
extern struct msg_base_t *open_message_base(int msgconf, int msgarea);
extern void close_message_base(struct msg_base_t *mb);
extern int get_message_number(struct msg_headers *hdrs, int id);
extern int get_message_lastread(struct msg_base_t *, int userid);
extern int get_message_highread(struct msg_base_t *, int userid);
extern int get_message_issent(struct msg_headers *hdrs, int id);
extern int get_message_islocal(struct msg_headers *hdrs, int id);
extern int get_header_isprivate(struct msg_base_t *mb, struct msg_t *hdr);
extern void write_lasthighread(struct msg_base_t *mb, struct user_record *user, int lastread, int highread);
extern struct msg_t *load_message_hdr(struct msg_base_t *mb, int id);
extern struct msg_t *load_message_hdr_offset(struct msg_base_t *mb, int id);
extern char *load_message_text(struct msg_base_t *mb, struct msg_t *msg);
extern void free_message_hdr(struct msg_t *msg);
extern int write_message(struct msg_base_t *mb, const char *to, const char *from, const char *subj, const char *body, const char *destaddr, struct msg_t *inreplyto, time_t *dwritten, int dosem);
extern int new_message_count(struct msg_base_t *mb, struct user_record *user);
extern int get_active_msg_count(struct msg_base_t *mb);
extern void save_message_hdr(struct msg_base_t *mb, struct msg_t *hdr);
extern int get_next_reply(struct msg_headers *hdrs, int curr);
extern int get_prev_reply(struct msg_headers *hdrs, int curr);
extern int get_up_reply(struct msg_headers *hdrs, int curr);
extern int get_down_reply(struct msg_headers *hdrs, int curr);
#endif
