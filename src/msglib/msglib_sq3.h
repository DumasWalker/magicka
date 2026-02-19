#ifndef __MSGLIB_SQ3_H__
#define __MSGLIB_SQ3_H__

#include "../bbs.h"
#include "libuuid/uuid.h"

#define SQ3_MSG_LOCAL 0x00000001L
#define SQ3_MSG_SENT 0x00000002L
#define SQ3_MSG_PRIVATE 0x00000004L

extern struct msg_headers *sq3_read_message_headers(int msgconf, int msgarea, struct user_record *user, int personal);
extern int sq3_message_lastread(const char *db, int uid);
extern int sq3_message_highread(const char *db, int uid);
extern void sq3_write_lasthighread(const char *db, struct user_record *user, int lastread, int highread);
extern int sq3_write_message(struct msg_base_t *mb, const char *to, const char *from, const char *subj, const char *body, const char *destaddr, struct msg_t *inreplyto, time_t *dwritten, int dosem);
extern struct msg_t *sq3_message_header(const char *db, int id, int offset);
extern char *sq3_fetch_body(const char *db, int mid);
extern int sq3_new_message_count(struct msg_base_t *mb, struct user_record *user);
extern int sq3_get_active_msg_count(const char *db);
#endif
