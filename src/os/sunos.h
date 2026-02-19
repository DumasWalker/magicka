#ifndef __SUNOS_H
#define __SUNOS_H

extern int openpty(int *amaster, int *aslave, char *name, void *termp, void *winp);
extern int forkpty(int *amaster, char *name, void *termp, void *winp);
extern long gmtoff(time_t value);
#endif
