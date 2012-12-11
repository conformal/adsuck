/*
 * Copyright (c) 2012 Marco Peereboom <marco@peereboom.us>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <unistd.h>

#if defined(__linux__)
#else
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>

#include <sys/event.h>
#include <sys/time.h>
#include <sys/varargs.h>

#include "adsuck.h"
#endif

#if defined(__linux__)
pid_t
monitor_fork(char *filename)
{
	/* require external stimuli */
	return (-1);
}

#else
/* this is too broad and should be tuned per OS */
void
monitor_file(char *filename)
{
	char		er[PATH_MAX];
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
	    NOTE_DELETE | NOTE_WRITE,
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
			if (event.fflags & NOTE_WRITE) {
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
#endif
