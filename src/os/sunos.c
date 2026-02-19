#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stropts.h>
#include <fcntl.h>
#include <termios.h>
#define TM_YEAR_ORIGIN 1900

int openpty(int *amaster, int *aslave, char *name, void *termp, void *winp) {
	int ptm;
	char *pname;
	int pts;

	ptm = open("/dev/ptmx", O_RDWR);

	grantpt(ptm);
	unlockpt(ptm);

	pname = ptsname(ptm);

	if (name != NULL) {
		strcpy(name, pname);
	}

	pts = open(pname, O_RDWR);
	ioctl(pts, I_PUSH, "ptem");
	ioctl(pts, I_PUSH, "ldterm");
	ioctl(pts, I_PUSH, "ttcompat");

	if (termp != NULL) {
		tcsetattr(pts, TCSAFLUSH, termp);
	}
	if (winp != NULL) {
		ioctl(pts, TIOCSWINSZ, winp);
	}

	*amaster = ptm;
	*aslave = pts;

	return 0;
}

int forkpty(int *amaster, char *name, void *termp, void *winp) {

	int ptm;
	char *pname;
	int pts;
	pid_t pid;

	ptm = open("/dev/ptmx", O_RDWR);

	grantpt(ptm);
	unlockpt(ptm);

	pname = ptsname(ptm);

	if (name != NULL) {
		strcpy(name, pname);
	}
	pts = open(pname, O_RDWR);
	ioctl(pts, I_PUSH, "ptem");
	ioctl(pts, I_PUSH, "ldterm");
	ioctl(pts, I_PUSH, "ttcompat");

	if (termp != NULL) {
		tcsetattr(pts, TCSAFLUSH, termp);
	}
	if (winp != NULL) {
		ioctl(pts, TIOCSWINSZ, winp);
	}

	pid = fork();

	if (!pid) {
		close(ptm);
		dup2(pts, 0);
		dup2(pts, 1);
		dup2(pts, 2);
		close(pts);
	} else {
		*amaster = ptm;
	}

	return pid;
}

static long difftm(struct tm *a, struct tm *b) {
	int ay = a->tm_year + (TM_YEAR_ORIGIN - 1);
	int by = b->tm_year + (TM_YEAR_ORIGIN - 1);
	long days = (a->tm_yday - b->tm_yday + ((ay >> 2) - (by >> 2)) - (ay / 100 - by / 100) + ((ay / 100 >> 2) - (by / 100 >> 2)) + (long)(ay - by) * 365);

	return (60 * (60 * (24 * days + (a->tm_hour - b->tm_hour)) + (a->tm_min - b->tm_min)) + (a->tm_sec - b->tm_sec));
}

long gmtoff(time_t value) {
	struct tm gmt = *gmtime(&value);
	return difftm(localtime(&value), &gmt);
}
