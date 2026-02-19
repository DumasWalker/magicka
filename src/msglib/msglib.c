#include "../bbs.h"
#include "../mail_utils.h"
#include "msglib.h"
#include "msglib_jam.h"
#include "msglib_sq3.h"
#include "../../deps/jamlib/jam.h"
#include <unistd.h>


int msg_is_to(struct user_record *user, const char *addressed_to, const char *address, int type, int rn, struct mail_conference *mc) {
	char *myname;
	if (rn) {
		myname = str3dup(user->firstname, " ", user->lastname);
	} else {
		myname = strdup(user->loginname);
	}
	if (type == NETWORK_FIDO && address != NULL) {
		if (strcasecmp(myname, addressed_to) == 0) {
			struct fido_addr *dest = parse_fido_addr(address);
			if (mc->fidoaddr->zone == dest->zone &&
			    mc->fidoaddr->net == dest->net &&
			    mc->fidoaddr->node == dest->node &&
			    mc->fidoaddr->point == dest->point) {
				free(dest);
				free(myname);
				return 1;
			}
			free(dest);
		}
		free(myname);
		return 0;
	} else if (type == NETWORK_MAGI && address != NULL) {
		if (strcasecmp(myname, addressed_to) == 0) {
			int magi_dest = atoi(address);
			if (magi_dest == mc->maginode) {
				free(myname);
				return 1;
			}
		}
		free(myname);
		return 0;
	} else {
		if (strcasecmp(myname, addressed_to) == 0) {
			free(myname);
			return 1;
		}
		free(myname);
		return 0;
	}
}

int msg_is_from(struct user_record *user, const char *addressed_from, const char *address, int type, int rn, struct mail_conference *mc) {
	char *myname;

	if (rn) {
		myname = str3dup(user->firstname, " ", user->lastname);
	} else {
		myname = strdup(user->loginname);
	}

	if (type == NETWORK_FIDO && address != NULL) {
		if (strcasecmp(myname, addressed_from) == 0) {
			struct fido_addr *orig = parse_fido_addr(address);
			if (mc->fidoaddr->zone == orig->zone &&
			    mc->fidoaddr->net == orig->net &&
			    mc->fidoaddr->node == orig->node &&
			    mc->fidoaddr->point == orig->point) {
				free(orig);
				free(myname);
				return 1;
			}
			free(orig);
		}
		free(myname);
		return 0;
	} else if (type == NETWORK_MAGI && address != NULL) {
		if (strcasecmp(myname, addressed_from) == 0) {
			int magi_orig = atoi(address);
			if (magi_orig == mc->maginode) {
				free(myname);
				return 1;
			}
		}
		free(myname);
		return 0;
	} else {
		if (strcasecmp(myname, addressed_from) == 0) {
			free(myname);
			return 1;
		}
		free(myname);
		return 0;
	}
}

void free_message_hdr(struct msg_t *msg) {
	free(msg->msg_h);
	free(msg->from);
	free(msg->to);
	free(msg->subject);
	free(msg->oaddress);
	free(msg->daddress);
	free(msg->msgid);
	free(msg->replyid);
	free(msg->seenby);
	free(msg);
}

void free_message_headers(struct msg_headers *msghs) {
	int i;

	for (i = 0; i < msghs->msg_count; i++) {
		free_message_hdr(msghs->msgs[i]);
	}
	if (msghs->msg_count > 0) {
		free(msghs->msgs);
	}
	free(msghs);
}

struct msg_headers *read_message_headers(int msgconf, int msgarea, struct user_record *user, int personal) {
	struct mail_area *ma = get_area(msgconf, msgarea);

	switch (ma->base_type) {
		case BASE_TYPE_SQ3:
			return sq3_read_message_headers(msgconf, msgarea, user, personal);
		case BASE_TYPE_JAM:
		default:
			return jam_read_message_headers(msgconf, msgarea, user, personal);
	}
}

struct msg_base_t *open_message_base(int msgconf, int msgarea) {
	struct mail_area *ma = get_area(msgconf, msgarea);

	struct msg_base_t *ret = malloz(sizeof(struct msg_base_t));

	switch (ma->base_type) {
		case BASE_TYPE_SQ3:
			ret->base_type = BASE_TYPE_SQ3;
			ret->ma = ma;
			ret->mc = get_conf(msgconf);
			break;
		case BASE_TYPE_JAM:
		default:
			ret->base_type = BASE_TYPE_JAM;
			ret->ma = ma;
			ret->mc = get_conf(msgconf);
			ret->data.jam = jam_open_base(ma->path);
			if (ret->data.jam == NULL) {
				free(ret);
				return NULL;
			}
			break;
	}

	return ret;
}

int get_message_number(struct msg_headers *hdrs, int id) {
	switch (hdrs->base_type) {
		case BASE_TYPE_SQ3:
			return hdrs->msgs[id]->msg_no;
		case BASE_TYPE_JAM:
		default:
			return ((s_JamMsgHeader *)hdrs->msgs[id]->msg_h)->MsgNum;
	}
}

int get_message_lastread(struct msg_base_t *base, int userid) {
	switch (base->base_type) {
		case BASE_TYPE_SQ3:
			return sq3_message_lastread(base->ma->path, userid);
		case BASE_TYPE_JAM:
		default:
			return jam_message_lastread(base->data.jam, userid);
	}
}

int get_message_highread(struct msg_base_t *base, int userid) {
	switch (base->base_type) {
		case BASE_TYPE_SQ3:
			return sq3_message_highread(base->ma->path, userid);
		case BASE_TYPE_JAM:
		default:
			return jam_message_highread(base->data.jam, userid);
	}
}

int get_message_issent(struct msg_headers *hdrs, int id) {
	switch (hdrs->base_type) {
		case BASE_TYPE_SQ3:
			return *(uint32_t *)hdrs->msgs[id]->msg_h & SQ3_MSG_SENT;
		case BASE_TYPE_JAM:
		default:
			return (((s_JamMsgHeader *)hdrs->msgs[id]->msg_h)->Attribute & JAM_MSG_SENT);
	}
}

int get_message_islocal(struct msg_headers *hdrs, int id) {
	switch (hdrs->base_type) {
		case BASE_TYPE_SQ3:
			return *(uint32_t *)hdrs->msgs[id]->msg_h & SQ3_MSG_LOCAL;
		case BASE_TYPE_JAM:
		default:
			return (((s_JamMsgHeader *)hdrs->msgs[id]->msg_h)->Attribute & JAM_MSG_LOCAL);
	}
}

int get_header_isprivate(struct msg_base_t *mb, struct msg_t *hdr) {
	switch (mb->base_type) {
		case BASE_TYPE_SQ3:
			return *(uint32_t *)hdr->msg_h & SQ3_MSG_PRIVATE;
		case BASE_TYPE_JAM:
		default:
			return (((s_JamMsgHeader *)hdr->msg_h)->Attribute & JAM_MSG_PRIVATE);
	}
}

char *load_message_text(struct msg_base_t *mb, struct msg_t *msg) {
	char *ret = NULL;

	switch (mb->base_type) {
		case BASE_TYPE_SQ3:
			return sq3_fetch_body(mb->ma->path, msg->msg_no);
		case BASE_TYPE_JAM:
		default:
			ret = (char *)malloz(((s_JamMsgHeader *)msg->msg_h)->TxtLen + 1);
			JAM_ReadMsgText(mb->data.jam, ((s_JamMsgHeader *)msg->msg_h)->TxtOffset, ((s_JamMsgHeader *)msg->msg_h)->TxtLen, (char *)ret);
			break;
	}

	return ret;
}

void write_lasthighread(struct msg_base_t *mb, struct user_record *user, int lastread, int highread) {
	switch (mb->base_type) {
		case BASE_TYPE_SQ3:
			sq3_write_lasthighread(mb->ma->path, user, lastread, highread);
			break;
		case BASE_TYPE_JAM:
		default:
			jam_write_lasthighread(mb->data.jam, user, lastread, highread);
			break;
	}
}

void close_message_base(struct msg_base_t *mb) {
	switch (mb->base_type) {
		case BASE_TYPE_SQ3:
			free(mb);
			return;
		case BASE_TYPE_JAM:
		default:
			JAM_CloseMB(mb->data.jam);
			free(mb->data.jam);
			free(mb);
			return;
	}
}

int link_message(struct msg_base_t *mb, int msgid, int replyid) {
	struct msg_t *msg;
	struct msg_t *rep;
	struct msg_t *nth;
	msg = load_message_hdr(mb, msgid);
	if (msg == NULL) {
		return 0;
	}
	rep = load_message_hdr(mb, replyid);
	if (rep == NULL) {
		free_message_hdr(msg);
		return 0;
	}

	switch (mb->base_type) {
		case BASE_TYPE_SQ3:
			return 0;
		case BASE_TYPE_JAM:
		default:
			if (((s_JamMsgHeader *)msg->msg_h)->Reply1st == 0) {
				((s_JamMsgHeader *)rep->msg_h)->ReplyTo = msgid;
				((s_JamMsgHeader *)msg->msg_h)->Reply1st = replyid;
				save_message_hdr(mb, msg);
				save_message_hdr(mb, rep);
			} else {
				nth = load_message_hdr(mb, ((s_JamMsgHeader *)msg->msg_h)->Reply1st);
				if (nth == NULL) {
					free_message_hdr(msg);
					free_message_hdr(rep);
					return 0;
				}
				while (((s_JamMsgHeader *)nth->msg_h)->ReplyNext != 0) {
					int nxt = ((s_JamMsgHeader *)nth->msg_h)->ReplyNext;
					free_message_hdr(nth);
					nth = load_message_hdr(mb, nxt);
					if (nth == NULL) {
						free_message_hdr(msg);
						free_message_hdr(rep);
						return 0;
					}
				}
				((s_JamMsgHeader *)rep->msg_h)->ReplyTo = msgid;
				((s_JamMsgHeader *)nth->msg_h)->ReplyNext = replyid;
				((s_JamMsgHeader *)rep->msg_h)->ReplyNext = 0;
				save_message_hdr(mb, nth);
				save_message_hdr(mb, rep);
				free_message_hdr(nth);
			}
			free_message_hdr(msg);
			free_message_hdr(rep);
			return 1;
	}
}

int write_message(struct msg_base_t *mb, const char *to, const char *from, const char *subj, const char *body, const char *destaddr, struct msg_t *inreplyto, time_t *dwritten, int dosem) {
	int newid;

	switch (mb->base_type) {
		case BASE_TYPE_SQ3:
			return sq3_write_message(mb, to, from, subj, body, destaddr, inreplyto, dwritten, dosem);
		case BASE_TYPE_JAM:
		default:
			newid = jam_write_message(mb, to, from, subj, body, destaddr, inreplyto, dwritten, dosem);
			if (newid == -1) {
				return 0;
			}
/*			if (inreplyto != NULL) {
				link_message(mb, ((s_JamMsgHeader *)inreplyto->msg_h)->MsgNum, newid);
			} */
                        if (inreplyto != NULL && inreplyto->msg_h != NULL) {
                                s_JamMsgHeader *jhdr = (s_JamMsgHeader *)inreplyto->msg_h;
                                link_message(mb, jhdr->MsgNum, newid);
                        }
			return 1;
	}
}

/*struct msg_t *load_message_hdr_offset(struct msg_base_t *mb, int id) {
	switch (mb->base_type) {
		case BASE_TYPE_SQ3:
			return sq3_message_header(mb->ma->path, id, 1);
		case BASE_TYPE_JAM:
		default:
			return jam_message_header(mb, id, 1);
	}
}*/

struct msg_t *load_message_hdr_offset(struct msg_base_t *mb, int id) {
    struct msg_t *msg = NULL;

    switch (mb->base_type) {
        case BASE_TYPE_SQ3:
            msg = sq3_message_header(mb->ma->path, id, 1);
            break;
        case BASE_TYPE_JAM:
        default:
            msg = jam_message_header(mb, id, 1);
            break;
    }

    // --- NEW SANITY CHECK BLOCK ---
    if (msg == NULL) {
        fprintf(stderr, "Error: Could not load message %d from base.\n", id);
        return NULL;
    }

    // Ensure mandatory strings are not NULL before the BBS tries to print them
    if (!msg->from || !msg->to || !msg->subject) {
        fprintf(stderr, "Corruption detected: Message %d has NULL header fields.\n", id);
        // Important: free the partial msg here if your jam_message_header doesn't cleanup
        return NULL; 
    }
    // ------------------------------

    return msg;
}


int get_next_reply(struct msg_headers *hdrs, int curr) {
	int nxt_msgno;
	switch (hdrs->base_type) {
		case BASE_TYPE_SQ3:
			return curr;
		case BASE_TYPE_JAM:
		default:
			nxt_msgno = ((s_JamMsgHeader *)hdrs->msgs[curr]->msg_h)->ReplyNext;
			if (nxt_msgno == 0) {
				return curr;
			} else {
				for (int i=0;i<hdrs->msg_count;i++) {
					if (((s_JamMsgHeader *)hdrs->msgs[i]->msg_h)->MsgNum == nxt_msgno) {
						return i;
					}
				}

				return curr;
			}
	}
}

int get_prev_reply(struct msg_headers *hdrs, int curr) {
	int cur_msgno;
	switch (hdrs->base_type) {
		case BASE_TYPE_SQ3:
			return curr;
		case BASE_TYPE_JAM:
		default:
			cur_msgno = ((s_JamMsgHeader *)hdrs->msgs[curr]->msg_h)->MsgNum;
			for (int i=0;i<hdrs->msg_count;i++) {
				if (((s_JamMsgHeader *)hdrs->msgs[i]->msg_h)->ReplyNext == cur_msgno) {
					return i;
				}
			}
			return curr;
	}
}

int get_up_reply(struct msg_headers *hdrs, int curr) {
	int nxt_msgno;
	switch (hdrs->base_type) {
		case BASE_TYPE_SQ3:
			return curr;
		case BASE_TYPE_JAM:
		default:
			nxt_msgno = ((s_JamMsgHeader *)hdrs->msgs[curr]->msg_h)->ReplyTo;
			for (int i=0;i<hdrs->msg_count;i++) {
				if (((s_JamMsgHeader *)hdrs->msgs[i]->msg_h)->MsgNum == nxt_msgno) {
					return i;
				}
			}
			return curr;
	}
}

int get_down_reply(struct msg_headers *hdrs, int curr) {
	int nxt_msgno;
	switch (hdrs->base_type) {
		case BASE_TYPE_SQ3:
			return curr;
		case BASE_TYPE_JAM:
		default:
			nxt_msgno = ((s_JamMsgHeader *)hdrs->msgs[curr]->msg_h)->Reply1st;
			for (int i=0;i<hdrs->msg_count;i++) {
				if (((s_JamMsgHeader *)hdrs->msgs[i]->msg_h)->MsgNum == nxt_msgno) {
					return i;
				}
			}
			return curr;
	}
}


void save_message_hdr(struct msg_base_t *mb, struct msg_t *hdr) {
	int z, i, k, found;
	s_JamBaseHeader jbh;
	s_JamMsgHeader jmh;

	switch (mb->base_type) {
		case BASE_TYPE_SQ3:
			return; // TODO!!!
		case BASE_TYPE_JAM:
		default:
			while (1) {
				z = JAM_LockMB(mb->data.jam, 100);
				if (z == 0) {
					break;
				} else if (z == JAM_LOCK_FAILED) {
					sleep(1);
				} else {
					dolog("Failed to lock msg base!");
					return;
				}
			}
			JAM_ReadMBHeader(mb->data.jam, &jbh);
			k = 0;
			found = 0;
			for (i=0;i<jbh.ActiveMsgs;k++) {
				z = JAM_ReadMsgHeader(mb->data.jam, k, &jmh, NULL);
				if (z != 0) {
					return;
				}
				if (jmh.Attribute & JAM_MSG_DELETED) {
					continue;
				}
				if (jmh.MsgNum == ((s_JamMsgHeader *)hdr->msg_h)->MsgNum) {
					found = 1;
					break;
				}
				i++;
			}
			if (found == 1) {
				JAM_ChangeMsgHeader(mb->data.jam, i, (s_JamMsgHeader *)hdr->msg_h);
			}
			JAM_UnlockMB(mb->data.jam);
			return;
	}
}

struct msg_t *load_message_hdr(struct msg_base_t *mb, int id) {
	switch (mb->base_type) {
		case BASE_TYPE_SQ3:
			return sq3_message_header(mb->ma->path, id, 0);
		case BASE_TYPE_JAM:
		default:
			return jam_message_header(mb, id, 0);
	}
}

int new_message_count(struct msg_base_t *mb, struct user_record *user) {
	switch (mb->base_type) {
		case BASE_TYPE_SQ3:
			return sq3_new_message_count(mb, user);
		case BASE_TYPE_JAM:
		default:
			return jam_new_message_count(mb, user);
	}
}

int get_active_msg_count(struct msg_base_t *mb) {
	switch (mb->base_type) {
		case BASE_TYPE_SQ3:
			return sq3_get_active_msg_count(mb->ma->path);
		case BASE_TYPE_JAM:
		default:
			return jam_get_active_msg_count(mb->data.jam);
	}
}
