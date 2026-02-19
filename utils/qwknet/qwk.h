#ifndef __QWK_H__
#define __QWK_H__

struct QwkHeader {
    unsigned char   Msgstat;                /* Message status       */
    unsigned char   Msgnum[7];              /* Message number       */
    unsigned char   Msgdate[8];             /* Message date MM-DD-YY*/
    unsigned char   Msgtime[5];             /* Message time HH:MM   */
    unsigned char   MsgTo[25];              /* Message To:          */
    unsigned char   MsgFrom[25];            /* Message From:        */
    unsigned char   MsgSubj[25];            /* Message Subject:     */
    unsigned char   Msgpass[12];            /* Message password     */
    unsigned char   Msgrply[8];             /* Message reply to     */
    unsigned char   Msgrecs[6];             /* Length in records    */
    unsigned char   Msglive;                /* Message active status*/
    unsigned char   Msgarealo;              /* Lo-byte message area */
    unsigned char   Msgareahi;              /* Hi-byte message area */
    unsigned char   Msgofflo;
    unsigned char   Msgoffhi;
    unsigned char   Msgtagp;
} __attribute__((packed));

#define BASE_TYPE_JAM 1
#define BASE_TYPE_SQ3 2

#define SQ3_MSG_LOCAL       0x00000001L 
#define SQ3_MSG_SENT        0x00000002L 
#define SQ3_MSG_PRIVATE     0x00000004L

#endif
