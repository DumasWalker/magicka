#include <string.h>
#include <sys/file.h>
#include <fcntl.h>
#include <libgen.h>
#include <unistd.h>
#include <sys/stat.h>
#include "../../deps/libuuid/uuid.h"
#include "../../deps/jamlib/jam.h"
#include "../bbs.h"
#include "../mail_utils.h"
extern struct bbs_config conf;

extern int count_msgs_above_msgno(void *msghs, int high_read);

// --- HELPER FUNCTION TO PREVENT DUPLICATION ---
void parse_tz_offset(struct msg_t *jamm, const char *buf, uint32_t len, int start_offset) {
    if (buf == NULL || len <= (uint32_t)start_offset) return;

    int isneg = 0;
    int hour = 0;
    int gothour = 0;
    int min = 0;
    jamm->tz_offset = 0;

    for (int h = start_offset; h < len; h++) {
        switch (buf[h]) {
            case '-':
                isneg = 1;
                break;
            case '+':
                isneg = 0; // Explicitly handle plus just in case
                break;
            default:
                if (buf[h] >= '0' && buf[h] <= '9') {
                    if (gothour < 2) {
                        hour = hour * 10 + (buf[h] - '0');
                        gothour++;
                    } else if (gothour < 4) { // Prevent overflow if string is long
                        min = min * 10 + (buf[h] - '0');
                        gothour++;
                    }
                }
                break;
        }
    }
    
    long total_seconds = ((hour * 60) + min) * 60;
    jamm->tz_offset = isneg ? -total_seconds : total_seconds;
}

void *jam_open_base(char *path) {
	int ret;
	s_JamBase *jb;

	ret = JAM_OpenMB((char *)path, &jb);

	if (ret != 0) {
		if (ret == JAM_IO_ERROR) {
			free(jb);
			ret = JAM_CreateMB((char *)path, 1, &jb);
			if (ret != 0) {
				free(jb);
				return NULL;
			}
		} else {
			free(jb);
			dolog("Got %d", ret);
			return NULL;
		}
	}
	return jb;
}

time_t gettz() {
	time_t offset;
	struct tm date_time;
	time_t utc = time(NULL);
	localtime_r(&utc, &date_time);

#ifdef __sun
	offset = gmtoff(utc);
#else
	offset = date_time.tm_gmtoff;
#endif
	return offset;
}

struct msg_headers *do_jam_read_message_headers(struct mail_conference *mc, struct mail_area *area, struct user_record *user, int personal, s_JamBase *jb) {
	s_JamBaseHeader jbh;
	s_JamMsgHeader jmh;
	s_JamSubPacket *jsp;
	struct msg_t *jamm = NULL;
	struct ptr_vector vec;
	int to_us;
	int i;
	int z;
	int j;
	int k;
	int failed = 0;
	struct fido_addr *dest;
	struct msg_headers *msghs = NULL;
	int prev_msg_no = -1;

	JAM_ReadMBHeader(jb, &jbh);

	if (jbh.ActiveMsgs <= 0) {

		return NULL;
	}
	init_ptr_vector(&vec);
	msghs = (struct msg_headers *)malloz(sizeof(struct msg_headers));
	msghs->msg_count = 0;
	msghs->base_type = BASE_TYPE_JAM;
	k = 0;
	for (i = 0; k < jbh.ActiveMsgs; i++) {
		memset(&jmh, 0, sizeof(s_JamMsgHeader));
		z = JAM_ReadMsgHeader(jb, i, &jmh, &jsp);
		if (z != 0) {
			if (z != 7) {
				failed++;
				k++;
			}
			if (failed == 5000) {
				break;
			}
			continue;
		}

		if (jmh.Attribute & JAM_MSG_DELETED) {
			JAM_DelSubPacket(jsp);
			continue;
		}

		stralloc seenbybuff = EMPTY_STRALLOC;

		if (jamm != NULL) {
			jamm->next_msg_no = jmh.MsgNum;
		} 

		jamm = (struct msg_t *)malloz(sizeof(struct msg_t));
		jamm->msg_no = jmh.MsgNum;
		jamm->msg_h = (s_JamMsgHeader *)malloz(sizeof(s_JamMsgHeader));
		memcpy(jamm->msg_h, &jmh, sizeof(s_JamMsgHeader));
		jamm->from = NULL;
		jamm->to = NULL;
		jamm->subject = NULL;
		jamm->oaddress = NULL;
		jamm->daddress = NULL;
		jamm->msgid = NULL;
		jamm->replyid = NULL;
		jamm->msgwritten = jmh.DateWritten;
		jamm->seenby = NULL;
		jamm->isutf8 = 0;
		jamm->tz_offset = 0;
		if (prev_msg_no != -1) {
			jamm->prev_msg_no = prev_msg_no;
		}
		prev_msg_no = jamm->msg_no;

		for (z = 0; z < jsp->NumFields; z++) {
			if (jsp->Fields[z]->LoID == JAMSFLD_SUBJECT) {
				jamm->subject = strndup(jsp->Fields[z]->Buffer, jsp->Fields[z]->DatLen);
			} else if (jsp->Fields[z]->LoID == JAMSFLD_SENDERNAME) {
				jamm->from = strndup(jsp->Fields[z]->Buffer, jsp->Fields[z]->DatLen);
			} else if (jsp->Fields[z]->LoID == JAMSFLD_RECVRNAME) {
				jamm->to = strndup(jsp->Fields[z]->Buffer, jsp->Fields[z]->DatLen);
			} else if (jsp->Fields[z]->LoID == JAMSFLD_DADDRESS) {
				jamm->daddress = strndup(jsp->Fields[z]->Buffer, jsp->Fields[z]->DatLen);
			} else if (jsp->Fields[z]->LoID == JAMSFLD_OADDRESS) {
				jamm->oaddress = strndup(jsp->Fields[z]->Buffer, jsp->Fields[z]->DatLen);
			} else if (jsp->Fields[z]->LoID == JAMSFLD_MSGID) {
				if (jsp->Fields[z]->Buffer != NULL) {
					jamm->msgid = strndup(jsp->Fields[z]->Buffer, jsp->Fields[z]->DatLen);
					stralloc_cats(&seenbybuff, "MSGID: ");
					stralloc_catb(&seenbybuff, jsp->Fields[z]->Buffer, jsp->Fields[z]->DatLen);
					stralloc_append1(&seenbybuff, '\r');
				}
			} else if (jsp->Fields[z]->LoID == JAMSFLD_REPLYID) {
				if (jsp->Fields[z]->Buffer != NULL) {
					jamm->replyid = strndup(jsp->Fields[z]->Buffer, jsp->Fields[z]->DatLen);
					stralloc_cats(&seenbybuff, "REPLYID: ");
					stralloc_catb(&seenbybuff, jsp->Fields[z]->Buffer, jsp->Fields[z]->DatLen);
					stralloc_append1(&seenbybuff, '\r');
				}
			} else if (jsp->Fields[z]->LoID == JAMSFLD_SEENBY2D) {
				if (jsp->Fields[z]->Buffer != NULL) {
					stralloc_cats(&seenbybuff, "SEEN-BY: ");
					stralloc_catb(&seenbybuff, jsp->Fields[z]->Buffer, jsp->Fields[z]->DatLen);
					stralloc_append1(&seenbybuff, '\r');
				}
			} else if (jsp->Fields[z]->LoID == JAMSFLD_PATH2D) {
				if (jsp->Fields[z]->Buffer != NULL) {
					stralloc_cats(&seenbybuff, "PATH: ");
					stralloc_catb(&seenbybuff, jsp->Fields[z]->Buffer, jsp->Fields[z]->DatLen);
					stralloc_append1(&seenbybuff, '\r');
				}
/*			} else if (jsp->Fields[z]->LoID == JAMSFLD_TZUTCINFO) {
				if (jsp->Fields[z]->Buffer != NULL) {
					stralloc_cats(&seenbybuff, "TZUTC: ");
					stralloc_catb(&seenbybuff, jsp->Fields[z]->Buffer, jsp->Fields[z]->DatLen);
					stralloc_append1(&seenbybuff, '\r');
					int isneg = 0;
					int hour = 0;
					int gothour = 0;
					int min = 0;
					jamm->tz_offset = 0;
					for (int h = 0; h < jsp->Fields[z]->DatLen; h++) {
						switch (jsp->Fields[z]->Buffer[h]) {
							case '-':
								isneg = 1;
								break;
							default:
								if (jsp->Fields[z]->Buffer[h] >= '0' && jsp->Fields[z]->Buffer[h] <= '9') {
									if (gothour < 2) {
										hour = hour * 10 + (jsp->Fields[z]->Buffer[h] - '0');
										gothour++;
									} else {
										min = min * 10 + (jsp->Fields[z]->Buffer[h] - '0');
									}
								}
								break;
						}
					}
					if (isneg) {
						jamm->tz_offset -= ((hour * 60) + min) * 60;
					} else {
						jamm->tz_offset += ((hour * 60) + min) * 60;
					}
				}
			} else if (jsp->Fields[z]->LoID == JAMSFLD_FTSKLUDGE) {
				if (jsp->Fields[z]->Buffer != NULL) { */
                        } else if (jsp->Fields[z]->LoID == JAMSFLD_TZUTCINFO) {
                                if (jsp->Fields[z]->Buffer != NULL) {
                                // KEEP: This adds it to the metadata string for the user
                                    stralloc_cats(&seenbybuff, "TZUTC: ");
                                    stralloc_catb(&seenbybuff, jsp->Fields[z]->Buffer, jsp->Fields[z]->DatLen);
                                    stralloc_append1(&seenbybuff, '\r');

                                // REPLACE: Use the helper to safely set the numeric offset
                                    parse_tz_offset(jamm, jsp->Fields[z]->Buffer, jsp->Fields[z]->DatLen, 0);
                                    }
                        } else if (jsp->Fields[z]->LoID == JAMSFLD_FTSKLUDGE) {
                                if (jsp->Fields[z]->Buffer != NULL && jsp->Fields[z]->DatLen > 6) {  
					stralloc_catb(&seenbybuff, jsp->Fields[z]->Buffer, jsp->Fields[z]->DatLen);
					stralloc_append1(&seenbybuff, '\r');

                                                if (strncmp(jsp->Fields[z]->Buffer, "TZUTC:", 6) == 0) {
                                                    parse_tz_offset(jamm, jsp->Fields[z]->Buffer, jsp->Fields[z]->DatLen, 6);
                                                }
                                           }
                                        }

/*					if (strncmp(jsp->Fields[z]->Buffer, "CHRS:", 5) == 0) {
						if (strncmp(&jsp->Fields[z]->Buffer[6], "UTF-8", 5) == 0) {
							jamm->isutf8 = 1;
						}
					} else if (strncmp(jsp->Fields[z]->Buffer, "TZUTC:", 6) == 0) {
						int isneg = 0;
						int hour = 0;
						int gothour = 0;
						int min = 0;
						jamm->tz_offset = 0;
						for (int h = 7; h < jsp->Fields[z]->DatLen; h++) {
							switch (jsp->Fields[z]->Buffer[h]) {
								case '-':
									isneg = 1;
									break;
								default:
									if (jsp->Fields[z]->Buffer[h] >= '0' && jsp->Fields[z]->Buffer[h] <= '9') {
										if (gothour < 2) {
											hour = hour * 10 + (jsp->Fields[z]->Buffer[h] - '0');
											gothour++;
										} else {
											min = min * 10 + (jsp->Fields[z]->Buffer[h] - '0');
										}
									}
									break;
							}
						}

						if (isneg) {
							jamm->tz_offset -= ((hour * 60) + min) * 60;
						} else {
							jamm->tz_offset += ((hour * 60) + min) * 60;
						}
					}
				}  */
                          
		}
		JAM_DelSubPacket(jsp);

		if (seenbybuff.len > 0) {
			stralloc_cats(&seenbybuff, "JAM_REPLYTO: ");
			stralloc_cat_long(&seenbybuff, jmh.ReplyTo);
			stralloc_append1(&seenbybuff, '\r');
			stralloc_cats(&seenbybuff, "JAM_REPLY1ST: ");
			stralloc_cat_long(&seenbybuff, jmh.Reply1st);
			stralloc_append1(&seenbybuff, '\r');
			stralloc_cats(&seenbybuff, "JAM_REPLYNEXT: ");
			stralloc_cat_long(&seenbybuff, jmh.ReplyNext);
			stralloc_append1(&seenbybuff, '\r');
			stralloc_0(&seenbybuff);
			jamm->seenby = seenbybuff.s;
		}

		if (jamm->subject == NULL) {
			jamm->subject = strdup("(No Subject)");
		}
		if (jamm->from == NULL) {
			jamm->from = strdup("(No Sender)");
		}
		if (jamm->to == NULL) {
			jamm->to = strdup("(No Recipient)");
		}

		if (mc->nettype == NETWORK_FIDO && jamm->oaddress == NULL) {
			// try and pull the oaddress out of the message
			char *body = (char *)malloz(jmh.TxtLen + 1);
			char *ptr1, *ptr2;

			JAM_ReadMsgText(jb, jmh.TxtOffset, jmh.TxtLen, (char *)body);
			ptr1 = strrchr(body, '(');
			ptr2 = strrchr(body, ')');


			if (ptr1 != NULL && ptr2 != NULL) {
				ptr1++;
				*ptr2 = '\0';
				struct fido_addr *faddr = parse_fido_addr(ptr1);
				if (faddr != NULL) {
					free(faddr);
					jamm->oaddress = strdup(ptr1);
				}
			}
			free(body);
		}

		if (jmh.Attribute & JAM_MSG_PRIVATE) {
			if (!msg_is_to(user, jamm->to, jamm->daddress, mc->nettype, area->realnames, mc) &&
			    !msg_is_from(user, jamm->from, jamm->oaddress, mc->nettype, area->realnames, mc) &&
			    !msg_is_to(user, jamm->to, jamm->daddress, mc->nettype, !area->realnames, mc) &&
			    !msg_is_from(user, jamm->from, jamm->oaddress, mc->nettype, !area->realnames, mc)) {
				free(jamm->seenby);
				free(jamm->subject);
				free(jamm->from);
				free(jamm->to);
				free(jamm->oaddress);
				free(jamm->daddress);
				free(jamm->msgid);
				free(jamm->replyid);
				free(jamm->msg_h);
				free(jamm);
				jamm = NULL;
				k++;
				continue;
			}
		} else if (personal) {
			if (!msg_is_to(user, jamm->to, jamm->daddress, mc->nettype, area->realnames, mc) &&
			    !msg_is_to(user, jamm->to, jamm->daddress, mc->nettype, !area->realnames, mc)) {
				free(jamm->seenby);
				free(jamm->subject);
				free(jamm->from);
				free(jamm->to);
				free(jamm->oaddress);
				free(jamm->daddress);
				free(jamm->msgid);
				free(jamm->replyid);
				free(jamm->msg_h);
				free(jamm);
				jamm = NULL;
				k++;
				continue;
			}
		}

		ptr_vector_append(&vec, jamm);
		k++;
	}
	msghs->msg_count = ptr_vector_len(&vec);
	msghs->msgs = (struct msg_t **)consume_ptr_vector(&vec);

	if (failed > 0) {
		dolog("Failed to read %d messages, possible corrupt msg base (%s -> %s)?", failed, mc->name, area->name);
	}

	return msghs;
}

struct msg_headers *jam_read_message_headers(int msgconf, int msgarea, struct user_record *user, int personal) {
	s_JamBase *jb;

	struct mail_conference *mc = ptr_vector_get(&conf.mail_conferences, msgconf);
	assert(mc != NULL);
	struct mail_area *area = ptr_vector_get(&mc->mail_areas, msgarea);
	assert(area != NULL);

	jb = jam_open_base(get_area(msgconf, msgarea)->path);
	if (!jb) {
		dolog("Error opening JAM base.. %s", get_area(msgconf, msgarea)->path);
		return NULL;
	}

	struct msg_headers *ret = do_jam_read_message_headers(mc, area, user, personal, jb);

	JAM_CloseMB(jb);
	free(jb);

	return ret;
}

int jam_message_lastread(s_JamBase *jb, int uid) {
	s_JamLastRead jlr;
	if (JAM_ReadLastRead(jb, uid, &jlr) == JAM_NO_USER) {
		return -1;
	}
	return (int)jlr.LastReadMsg;
}

int jam_message_highread(s_JamBase *jb, int uid) {
	s_JamLastRead jlr;
	if (JAM_ReadLastRead(jb, uid, &jlr) == JAM_NO_USER) {
		return -1;
	}
	return (int)jlr.HighReadMsg;
}

void jam_write_lasthighread(s_JamBase *jb, struct user_record *user, int lastread, int highread) {
	s_JamLastRead jlr;
	if (JAM_ReadLastRead(jb, user->id, &jlr) == JAM_NO_USER) {
		jlr.UserID = user->id;
		jlr.UserCRC = JAM_Crc32(user->loginname, strlen(user->loginname));
	}
	jlr.LastReadMsg = lastread;
	jlr.HighReadMsg = highread;

	JAM_WriteLastRead(jb, user->id, &jlr);
}

int jam_write_message(struct msg_base_t *mb, const char *to, const char *from, const char *subj, const char *body, const char *destaddr, struct msg_t *inreplyto, time_t *dwritten, int dosem) {
	s_JamMsgHeader jmh;
	s_JamSubPacket *jsp;
	s_JamSubfield jsf;

	char buffer[256];
	uuid_t magi_msgid;
	uuid_t qwk_msgid;
	char qwkuuid[38];
	int z;
	int sem_fd;
	JAM_ClearMsgHeader(&jmh);

	if (dwritten == NULL) {
		jmh.DateWritten = utc_to_local(time(NULL));
	} else {
		jmh.DateWritten = *dwritten;
	}
	jmh.Attribute |= JAM_MSG_LOCAL;

	jsp = JAM_NewSubPacket();
	jsf.LoID = JAMSFLD_SENDERNAME;
	jsf.HiID = 0;
	jsf.DatLen = strlen(from);
	jsf.Buffer = (char *)from;
	JAM_PutSubfield(jsp, &jsf);

	jsf.LoID = JAMSFLD_RECVRNAME;
	jsf.HiID = 0;
	jsf.DatLen = strlen(to);
	jsf.Buffer = (char *)to;
	JAM_PutSubfield(jsp, &jsf);

	jsf.LoID = JAMSFLD_SUBJECT;
	jsf.HiID = 0;
	jsf.DatLen = strlen(subj);
	jsf.Buffer = (char *)subj;
	JAM_PutSubfield(jsp, &jsf);

	time_t offset = gettz();
	int offhour = offset / 3600;
	int offmin = (offset % 3600) / 60;


	if (offhour < 0) {
		snprintf(buffer, sizeof buffer, "TZUTC: -%02d%02d", abs(offhour), offmin);
	} else {
		snprintf(buffer, sizeof buffer, "TZUTC: %02d%02d", offhour, offmin);
	}

	jsf.LoID = JAMSFLD_FTSKLUDGE;
	jsf.HiID = 0;
	jsf.DatLen = strlen(buffer);
	jsf.Buffer = (char *)buffer;
	JAM_PutSubfield(jsp, &jsf);

	snprintf(buffer, sizeof buffer, "CHRS: CP437 2");

	jsf.LoID = JAMSFLD_FTSKLUDGE;
	jsf.HiID = 0;
	jsf.DatLen = strlen(buffer);
	jsf.Buffer = (char *)buffer;
	JAM_PutSubfield(jsp, &jsf);

	if (mb->ma->type == TYPE_ECHOMAIL_AREA || mb->ma->type == TYPE_NEWSGROUP_AREA) {
		jmh.Attribute |= JAM_MSG_TYPEECHO;

		if (mb->mc->nettype == NETWORK_FIDO) {
			if (mb->mc->fidoaddr->point) {
				snprintf(buffer, sizeof buffer, "%d:%d/%d.%d",
				         mb->mc->fidoaddr->zone, mb->mc->fidoaddr->net, mb->mc->fidoaddr->node,
				         mb->mc->fidoaddr->point);
			} else {
				snprintf(buffer, sizeof buffer, "%d:%d/%d",
				         mb->mc->fidoaddr->zone, mb->mc->fidoaddr->net, mb->mc->fidoaddr->node);
			}
			jsf.LoID = JAMSFLD_OADDRESS;
			jsf.HiID = 0;
			jsf.DatLen = strlen(buffer);
			jsf.Buffer = (char *)buffer;
			JAM_PutSubfield(jsp, &jsf);

			snprintf(buffer, sizeof buffer, "%d:%d/%d.%d %08lx",
			         mb->mc->fidoaddr->zone,
			         mb->mc->fidoaddr->net,
			         mb->mc->fidoaddr->node,
			         mb->mc->fidoaddr->point,
			         generate_msgid());

			jsf.LoID = JAMSFLD_MSGID;
			jsf.HiID = 0;
			jsf.DatLen = strlen(buffer);
			jsf.Buffer = (char *)buffer;
			JAM_PutSubfield(jsp, &jsf);

			jmh.MsgIdCRC = JAM_Crc32(buffer, strlen(buffer));

			if (inreplyto != NULL && inreplyto->msgid != NULL) {
				strlcpy(buffer, inreplyto->msgid, sizeof buffer);
				jsf.LoID = JAMSFLD_REPLYID;
				jsf.HiID = 0;
				jsf.DatLen = strlen(buffer);
				jsf.Buffer = (char *)buffer;
				JAM_PutSubfield(jsp, &jsf);
				jmh.ReplyCRC = JAM_Crc32(buffer, strlen(buffer));
			}

		} else if (mb->mc->nettype == NETWORK_MAGI) {
			snprintf(buffer, sizeof buffer, "%d", mb->mc->maginode);
			jsf.LoID = JAMSFLD_OADDRESS;
			jsf.HiID = 0;
			jsf.DatLen = strlen(buffer);
			jsf.Buffer = (char *)buffer;
			JAM_PutSubfield(jsp, &jsf);
			memset(buffer, 0, sizeof buffer);
			uuid_generate(magi_msgid);
			uuid_unparse_lower(magi_msgid, buffer);

			jsf.LoID = JAMSFLD_MSGID;
			jsf.HiID = 0;
			jsf.DatLen = strlen(buffer);
			jsf.Buffer = (char *)buffer;
			JAM_PutSubfield(jsp, &jsf);

			jmh.MsgIdCRC = JAM_Crc32(buffer, strlen(buffer));

			if (inreplyto != NULL && inreplyto->msgid != NULL) {
				strlcpy(buffer, inreplyto->msgid, sizeof buffer);
				jsf.LoID = JAMSFLD_REPLYID;
				jsf.HiID = 0;
				jsf.DatLen = strlen(buffer);
				jsf.Buffer = (char *)buffer;
				JAM_PutSubfield(jsp, &jsf);
				jmh.ReplyCRC = JAM_Crc32(buffer, strlen(buffer));
			}
		} else if (mb->mc->nettype == NETWORK_QWK) {
			jsf.LoID = JAMSFLD_OADDRESS;
			jsf.HiID = 0;
			jsf.DatLen = strlen(conf.bwave_name);
			jsf.Buffer = (char *)conf.bwave_name;
			JAM_PutSubfield(jsp, &jsf);

			if (conf.external_address != NULL) {
				memset(qwkuuid, 0, sizeof qwkuuid);
				uuid_generate(qwk_msgid);
				uuid_unparse_lower(qwk_msgid, qwkuuid);
				snprintf(buffer, sizeof buffer, "<%s@%s>", qwkuuid, conf.external_address);

				jsf.LoID = JAMSFLD_MSGID;
				jsf.HiID = 0;
				jsf.DatLen = strlen(buffer);
				jsf.Buffer = (char *)buffer;
				JAM_PutSubfield(jsp, &jsf);
				jmh.MsgIdCRC = JAM_Crc32(buffer, strlen(buffer));

				if (inreplyto != NULL && inreplyto->msgid != NULL) {
					strlcpy(buffer, inreplyto->msgid, sizeof buffer);
					jsf.LoID = JAMSFLD_REPLYID;
					jsf.HiID = 0;
					jsf.DatLen = strlen(buffer);
					jsf.Buffer = (char *)buffer;
					JAM_PutSubfield(jsp, &jsf);
					jmh.ReplyCRC = JAM_Crc32(buffer, strlen(buffer));
				}
			}
		}
	} else if (mb->ma->type == TYPE_NETMAIL_AREA) {
		jmh.Attribute |= JAM_MSG_TYPENET;
		jmh.Attribute |= JAM_MSG_PRIVATE;

		if (mb->mc->nettype == NETWORK_FIDO) {
			if (mb->mc->fidoaddr->point) {
				snprintf(buffer, sizeof buffer, "%d:%d/%d.%d",
				         mb->mc->fidoaddr->zone, mb->mc->fidoaddr->net, mb->mc->fidoaddr->node,
				         mb->mc->fidoaddr->point);
			} else {
				snprintf(buffer, sizeof buffer, "%d:%d/%d",
				         mb->mc->fidoaddr->zone, mb->mc->fidoaddr->net, mb->mc->fidoaddr->node);
			}
			jsf.LoID = JAMSFLD_OADDRESS;
			jsf.HiID = 0;
			jsf.DatLen = strlen(buffer);
			jsf.Buffer = (char *)buffer;
			JAM_PutSubfield(jsp, &jsf);

			if (destaddr != NULL) {
				jsf.LoID = JAMSFLD_DADDRESS;
				jsf.HiID = 0;
				jsf.DatLen = strlen(destaddr);
				jsf.Buffer = (char *)destaddr;
				JAM_PutSubfield(jsp, &jsf);
			}
		}
	}

	while (1) {
		z = JAM_LockMB(mb->data.jam, 100);
		if (z == 0) {
			break;
		} else if (z == JAM_LOCK_FAILED) {
			sleep(1);
		} else {
			dolog("Failed to lock msg base!");
			return -1;
		}
	}

	if (JAM_AddMessage(mb->data.jam, &jmh, jsp, (char *)body, strlen(body))) {
		dolog("Failed to add message");
	} else {
		if (dosem) {
			if (mb->ma->type == TYPE_NETMAIL_AREA) {
				if (conf.netmail_sem != NULL) {
					sem_fd = open(conf.netmail_sem, O_RDWR | O_CREAT | O_TRUNC, S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH);
					close(sem_fd);
				}
			} else if (mb->ma->type == TYPE_ECHOMAIL_AREA || mb->ma->type == TYPE_NEWSGROUP_AREA) {
				if (mb->mc->semaphore != NULL) {
					sem_fd = open(mb->mc->semaphore, O_RDWR | O_CREAT | O_TRUNC, S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH);
					close(sem_fd);
				} else if (conf.echomail_sem != NULL) {
					sem_fd = open(conf.echomail_sem, O_RDWR | O_CREAT | O_TRUNC, S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH);
					close(sem_fd);
				}
			}
		}
	}

	JAM_UnlockMB(mb->data.jam);

	JAM_DelSubPacket(jsp);
	return jmh.MsgNum;
}

struct msg_t *jam_message_header(struct msg_base_t *mb, int id, int offset) {
	s_JamBase *jb = mb->data.jam;
	s_JamBaseHeader jbh;
	s_JamMsgHeader jmh;
	s_JamMsgHeader jmh_next;
	s_JamSubPacket *jsp;
	int z;
	struct msg_t *jamm;
	int k = 0;
	int i;
	JAM_ReadMBHeader(jb, &jbh);
	int found = 0;
	int next_msg_no = 0;
	int prev_msg_no = 0;


	if (jbh.ActiveMsgs <= 0) {
		return NULL;
	}

	for (i=0;i<jbh.ActiveMsgs;k++) {
		z = JAM_ReadMsgHeader(jb, k, &jmh, &jsp);
		if (z != 0) {
			if (z != 7) {
				i++;
			}
			continue;
		}
		if (jmh.Attribute & JAM_MSG_DELETED) {
			JAM_DelSubPacket(jsp);
			continue;
		}
		if (offset) {
			if (i == id) {
				found = 1;
				break;
			} else {
				prev_msg_no = jmh.MsgNum;
			}
		} else {
			if (jmh.MsgNum == id) {
				found = 1;
				break;
			} else {
				prev_msg_no = jmh.MsgNum;
			}
		}
		JAM_DelSubPacket(jsp);
		i++;
	}

	if (found == 0) {
		printf("NOT FOUND\n");
		return NULL;
	}

	for (k++;i<jbh.ActiveMsgs;k++) {
		z = JAM_ReadMsgHeader(jb, k, &jmh_next, NULL);
		if (z != 0) {
			if (z != 7) {
				i++;
			}
			continue;
		}
		next_msg_no = jmh_next.MsgNum;
		break;
	}


	jamm = (struct msg_t *)malloz(sizeof(struct msg_t));
	jamm->msg_no = jmh.MsgNum;
	jamm->msg_h = (s_JamMsgHeader *)malloz(sizeof(s_JamMsgHeader));
	memcpy(jamm->msg_h, &jmh, sizeof(s_JamMsgHeader));
	jamm->from = NULL;
	jamm->to = NULL;
	jamm->subject = NULL;
	jamm->oaddress = NULL;
	jamm->daddress = NULL;
	jamm->msgid = NULL;
	jamm->replyid = NULL;
	jamm->msgwritten = jmh.DateWritten;
	jamm->seenby = NULL;
	jamm->isutf8 = 0;
	jamm->prev_msg_no = prev_msg_no;
	jamm->next_msg_no = next_msg_no;

	stralloc seenbybuff = EMPTY_STRALLOC;

	for (z = 0; z < jsp->NumFields; z++) {
		if (jsp->Fields[z]->LoID == JAMSFLD_SUBJECT) {
			jamm->subject = strndup(jsp->Fields[z]->Buffer, jsp->Fields[z]->DatLen);
		} else if (jsp->Fields[z]->LoID == JAMSFLD_SENDERNAME) {
			jamm->from = strndup(jsp->Fields[z]->Buffer, jsp->Fields[z]->DatLen);
		} else if (jsp->Fields[z]->LoID == JAMSFLD_RECVRNAME) {
			jamm->to = strndup(jsp->Fields[z]->Buffer, jsp->Fields[z]->DatLen);
		} else if (jsp->Fields[z]->LoID == JAMSFLD_DADDRESS) {
			jamm->daddress = strndup(jsp->Fields[z]->Buffer, jsp->Fields[z]->DatLen);
		} else if (jsp->Fields[z]->LoID == JAMSFLD_OADDRESS) {
			jamm->oaddress = strndup(jsp->Fields[z]->Buffer, jsp->Fields[z]->DatLen);
		} else if (jsp->Fields[z]->LoID == JAMSFLD_MSGID) {
			if (jsp->Fields[z]->Buffer != NULL) {
				stralloc_cats(&seenbybuff, "MSGID: ");
				stralloc_catb(&seenbybuff, jsp->Fields[z]->Buffer, jsp->Fields[z]->DatLen);
				stralloc_append1(&seenbybuff, '\r');
				jamm->msgid = strndup(jsp->Fields[z]->Buffer, jsp->Fields[z]->DatLen);
			}
		} else if (jsp->Fields[z]->LoID == JAMSFLD_REPLYID) {
			if (jsp->Fields[z]->Buffer != NULL) {
				stralloc_cats(&seenbybuff, "REPLYID: ");
				stralloc_catb(&seenbybuff, jsp->Fields[z]->Buffer, jsp->Fields[z]->DatLen);
				stralloc_append1(&seenbybuff, '\r');
				jamm->replyid = strndup(jsp->Fields[z]->Buffer, jsp->Fields[z]->DatLen);
			}
		} else if (jsp->Fields[z]->LoID == JAMSFLD_SEENBY2D) {
			if (jsp->Fields[z]->Buffer != NULL) {
				stralloc_cats(&seenbybuff, "SEENBY: ");
				stralloc_catb(&seenbybuff, jsp->Fields[z]->Buffer, jsp->Fields[z]->DatLen);
				stralloc_append1(&seenbybuff, '\r');
			}
		} else if (jsp->Fields[z]->LoID == JAMSFLD_TZUTCINFO) {
			if (jsp->Fields[z]->Buffer != NULL) {
				stralloc_cats(&seenbybuff, "TZUTC: ");
				stralloc_catb(&seenbybuff, jsp->Fields[z]->Buffer, jsp->Fields[z]->DatLen);
				stralloc_append1(&seenbybuff, '\r');
				int isneg = 0;
				int hour = 0;
				int gothour = 0;
				int min = 0;
				jamm->tz_offset = 0;
				for (int h = 0; h < jsp->Fields[z]->DatLen; h++) {
					switch (jsp->Fields[z]->Buffer[h]) {
						case '-':
							isneg = 1;
							break;
						default:
							if (jsp->Fields[z]->Buffer[h] >= '0' && jsp->Fields[z]->Buffer[h] <= '9') {
								if (gothour < 2) {
									hour = hour * 10 + (jsp->Fields[z]->Buffer[h] - '0');
									gothour++;
								} else {
									min = min * 10 + (jsp->Fields[z]->Buffer[h] - '0');
								}
							}
							break;
					}
				}
				if (isneg) {
					jamm->tz_offset -= ((hour * 60) + min) * 60;
				} else {
					jamm->tz_offset += ((hour * 60) + min) * 60;
				}
			}
		} else if (jsp->Fields[z]->LoID == JAMSFLD_FTSKLUDGE) {
			if (jsp->Fields[z]->Buffer != NULL) {
				stralloc_catb(&seenbybuff, jsp->Fields[z]->Buffer, jsp->Fields[z]->DatLen);
				stralloc_append1(&seenbybuff, '\r');
				if (strncmp(jsp->Fields[z]->Buffer, "CHRS:", 5) == 0) {
					if (strncmp(&jsp->Fields[z]->Buffer[6], "UTF-8", 5) == 0) {
						jamm->isutf8 = 1;
					}
				} else if (strncmp(jsp->Fields[z]->Buffer, "TZUTC:", 6) == 0) {
					int isneg = 0;
					int hour = 0;
					int gothour = 0;
					int min = 0;
					jamm->tz_offset = 0;
					for (int h = 7; h < jsp->Fields[z]->DatLen; h++) {
						switch (jsp->Fields[z]->Buffer[h]) {
							case '-':
								isneg = 1;
								break;
							default:
								if (jsp->Fields[z]->Buffer[h] >= '0' && jsp->Fields[z]->Buffer[h] <= '9') {
									if (gothour < 2) {
										hour = hour * 10 + (jsp->Fields[z]->Buffer[h] - '0');
										gothour++;
									} else {
										min = min * 10 + (jsp->Fields[z]->Buffer[h] - '0');
									}
								}
								break;
						}
					}

					if (isneg) {
						jamm->tz_offset -= ((hour * 60) + min) * 60;
					} else {
						jamm->tz_offset += ((hour * 60) + min) * 60;
					}
				}
			}
		}
	}

	if (seenbybuff.len > 0) {
		stralloc_0(&seenbybuff);
		jamm->seenby = seenbybuff.s;
	}

	JAM_DelSubPacket(jsp);

	if (jamm->subject == NULL) {
		jamm->subject = strdup("(No Subject)");
	}
	if (jamm->from == NULL) {
		jamm->from = strdup("(No Sender)");
	}
	if (jamm->to == NULL) {
		jamm->to = strdup("(No Recipient)");
	}
	if (mb->mc->nettype == NETWORK_FIDO && jamm->oaddress == NULL) {
		// try and pull the oaddress out of the message
		char *body = (char *)malloz(jmh.TxtLen + 1);
		char *ptr1, *ptr2;

		JAM_ReadMsgText(jb, jmh.TxtOffset, jmh.TxtLen, (char *)body);
		ptr1 = strrchr(body, '(');
		ptr2 = strrchr(body, ')');

		if (ptr1 != NULL && ptr2 != NULL) {
			ptr1++;
			*ptr2 = '\0';
			struct fido_addr *faddr = parse_fido_addr(ptr1);
			if (faddr != NULL) {
				free(faddr);
				jamm->oaddress = strdup(ptr1);
			}
		}
		free(body);
	}
	return jamm;
}

int jam_new_message_count(struct msg_base_t *mb, struct user_record *user) {
	int count = 0;
	int high_read;

	struct msg_headers *msghs;

	high_read = jam_message_highread(mb->data.jam, user->id);

	msghs = do_jam_read_message_headers(mb->mc, mb->ma, user, 0, mb->data.jam);
	if (msghs != NULL) {
		if (msghs->msg_count > 0) {
			if (get_message_number(msghs, msghs->msg_count - 1) > high_read) {
				count = count_msgs_above_msgno(msghs, high_read);
			}
		}
		free_message_headers(msghs);
	}

	return count;
}

int jam_get_active_msg_count(s_JamBase *jb) {
	s_JamBaseHeader jbh;

	JAM_ReadMBHeader(jb, &jbh);

	return jbh.ActiveMsgs;
}
