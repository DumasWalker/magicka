#include "../../deps/jamlib/jam.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>


int jam_link_message(s_JamBase *jb, uint32_t baseno, uint32_t mi, uint32_t ri, uint32_t msgid, uint32_t replyid) {
   s_JamMsgHeader msg;
   s_JamMsgHeader rep;
   s_JamMsgHeader nth;

	if (JAM_ReadMsgHeader(jb, mi, &msg, NULL) != 0) {
      return 0;
   }

	if (JAM_ReadMsgHeader(jb, ri, &rep, NULL) != 0) {
      return 0;
   }

	if (msg.Reply1st == 0) {
		rep.ReplyTo = msgid;
      msg.Reply1st = replyid;


	JAM_ChangeMsgHeader(jb, mi, &msg);
    JAM_ChangeMsgHeader(jb, ri, &rep);

	} else {
      int nxt = msg.Reply1st;
      if (JAM_ReadMsgHeader(jb, nxt-baseno, &nth, NULL) != 0) {
         return 0;
      }
		while (nth.ReplyNext != 0) {
			nxt = nth.ReplyNext;

         if (JAM_ReadMsgHeader(jb, nxt-baseno, &nth, NULL) != 0) {
            return 0;
         }				
		}
      rep.ReplyTo = msgid;
	    nth.ReplyNext = replyid;

	  JAM_ChangeMsgHeader(jb, nxt-baseno, &nth);
      JAM_ChangeMsgHeader(jb, ri, &rep);
	}
   return 1;
}

int jam_linkmb(char *jam_base) {
   s_JamBase *jb;
   s_JamBaseHeader jbh;
	s_JamMsgHeader jmh;
	s_JamSubPacket *jsp;

   char *repid;

   if (JAM_OpenMB(jam_base, &jb) != 0) {
       return 0;
   }

   JAM_ReadMBHeader(jb, &jbh);
   
   int z = 0;
   uint32_t mid = 0;
   uint32_t i;
   uint32_t tot;

   if (JAM_GetMBSize(jb, &tot) != 0) {
       JAM_CloseMB(jb);
       free(jb);
      return 0;
   }

   // first strip all old reply linkage
    if(JAM_LockMB(jb,10)) {
       JAM_CloseMB(jb);
       free(jb);        
        return 0;
    }

   for (i=0;i<tot;i++) {
        z = JAM_ReadMsgHeader(jb, i, &jmh, &jsp);
		if (z != 0) {
			continue;
		}

        jmh.Reply1st = 0;
        jmh.ReplyNext = 0;
        jmh.ReplyTo = 0;
        JAM_ChangeMsgHeader(jb, i, &jmh);
   }

   for (i=0;i<tot;i++) {
      z = JAM_ReadMsgHeader(jb, i, &jmh, &jsp);
		if (z != 0) {
			continue;
		}
      if (jmh.Attribute & JAM_MSG_DELETED) {
			JAM_DelSubPacket(jsp);
			continue;
		}

      mid = jmh.MsgNum;
      repid = NULL;
      for (z = 0; z < jsp->NumFields; z++) {
         if (jsp->Fields[z]->LoID == JAMSFLD_REPLYID) {
             if (jsp->Fields[z]->DatLen != 0) {
                repid = (char *)malloc(jsp->Fields[z]->DatLen + 1);
                memset(repid, 0, jsp->Fields[z]->DatLen + 1);
                memcpy(repid, jsp->Fields[z]->Buffer, jsp->Fields[z]->DatLen);
             }
            break;
         }
      }
      
      JAM_DelSubPacket(jsp);

      if (repid == NULL) {
         continue;
      }
      for (int h=0;h<tot;h++) {
         z = JAM_ReadMsgHeader(jb, h, &jmh, &jsp);
         if (z != 0) {
            continue;
         }
         if (jmh.Attribute & JAM_MSG_DELETED) {
			   JAM_DelSubPacket(jsp);
			   continue;
		   }         
         for (z = 0; z < jsp->NumFields; z++) {
            if (jsp->Fields[z]->LoID == JAMSFLD_MSGID) {
               if (jsp->Fields[z]->Buffer != NULL && jsp->Fields[z]->DatLen == strlen(repid)) {
                  if (strncmp(jsp->Fields[z]->Buffer, repid, strlen(repid)) == 0) {
                     jam_link_message(jb, jbh.BaseMsgNum, h, i, jmh.MsgNum, mid);
                  }
               }
               break;
            }
         }

         JAM_DelSubPacket(jsp);
      }
      free(repid);
   }
   JAM_UnlockMB(jb);
   JAM_CloseMB(jb);
   free(jb);   
   return 1;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s [jam_base_path]\r\n", argv[0]);
    }

    jam_linkmb(argv[1]);

}