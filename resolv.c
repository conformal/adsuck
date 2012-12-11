#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <sys/varargs.h>

#include "adsuck.h"

void
monitor_file(char *filename)
{
	char		er[256];
	int		f, kq, nev;
	struct kevent	change;
	struct kevent	event;

	kq = kqueue();
	if (kq == -1)
		fatal("kqueue failed");

	f = open(filename, O_RDONLY);
	if (f == -1) {
		snprintf(er, sizeof er, "could not open %s", filename);
		fatal(er);
	}

	EV_SET(&change, f, EVFILT_VNODE,
	    EV_ADD | EV_ENABLE | EV_ONESHOT,
	    NOTE_DELETE | NOTE_EXTEND | NOTE_WRITE | NOTE_ATTRIB,
	    0, 0);

	for (;;) {
		nev = kevent(kq, &change, 1, &event, 1, NULL);
		if (nev == -1)
			fatal("kevent failed");
		else if (nev > 0) {
			if (event.fflags & NOTE_DELETE) {
				log_info("resolv file deleted");
				break;
			}
			if (event.fflags & NOTE_EXTEND ||
			    event.fflags & NOTE_WRITE ||
			    event.fflags & NOTE_ATTRIB) {
				log_info("%s modified", filename);
				kill(getppid(), SIGHUP);
			}
		}
	}

	close(kq);
	close(f);
}

pid_t
monitor_fork(char *filename)
{
	pid_t		pid;

	switch (pid = fork()) {
	case -1:
		return (-1);
	case 0:
		/* child */
		setproctitle("[resolv monitor]");
		monitor_file(filename);
		exit(1);
		/* NOTREACHED */
	default:
		/* parent */
		return (pid);
	}
}
