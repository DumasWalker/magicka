#include "magimail.h"

#ifdef MSGBASE_MSG
#include "mb_msg.h"
#endif

#ifdef MSGBASE_JAM
#include "mb_jam.h"
#endif

#ifdef MSGBASE_SQ3
#include "mb_sq3.h"
#endif

struct Messagebase AvailMessagebases[] =
{
#ifdef MSGBASE_MSG
   { "MSG",
     "Standard *.msg messagebase as specified in FTS-1",
     0,
     msg_beforefunc,
     msg_afterfunc,
     msg_importfunc,
     msg_exportfunc,
     msg_rescanfunc },
#endif
#ifdef MSGBASE_JAM
   { "JAM",
     "JAM Messagebase",
     0,
     jam_beforefunc,
     jam_afterfunc,
     jam_importfunc,
     jam_exportfunc,
     jam_rescanfunc },
#endif
#ifdef MSGBASE_SQ3
   { "SQ3",
     "SQlite3 Messagebase",
     0,
     sq3_beforefunc,
     sq3_afterfunc,
     sq3_importfunc,
     sq3_exportfunc,
     sq3_rescanfunc },
#endif
   { NULL,  /* NULL here marks the end of the array */
     NULL,
     0,
     NULL,
     NULL,
     NULL,
     NULL,
     NULL
   }
};
