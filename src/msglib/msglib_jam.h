#ifndef __MSGLIB_JAM_H__
#define __MSGLIB_JAM_H__

#include "jamlib/jam.h"
#include "../bbs.h"
#include "libuuid/uuid.h"

extern void *jam_open_base(char *path);
extern struct msg_headers *jam_read_message_headers(int msgconf, int msgarea, struct user_record *user, int personal);
extern int jam_message_lastread(s_JamBase *jb, int uid);
extern int jam_message_highread(s_JamBase *jb, int uid);
extern void jam_write_lasthighread(s_JamBase *jb, struct user_record *user, int lastread, int highread);
extern int jam_write_message(struct msg_base_t *mb, const char *to, const char *from, const char *subj, const char *body, const char *destaddr, struct msg_t *inreplyto, time_t *dwritten, int dosem);
extern struct msg_t *jam_message_header(struct msg_base_t *mb, int id, int offset);
extern int jam_new_message_count(struct msg_base_t *mb, struct user_record *user);
extern int jam_get_active_msg_count(s_JamBase *jb);
#endif
