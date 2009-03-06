/* $adsuck$ */
/*
 * Copyright (c) 2009 Marco Peereboom <marco@peereboom.us>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <err.h>
#include <unistd.h>
#include <signal.h>
#include <pwd.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#include <sys/errno.h>
#include <sys/tree.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <ldns/ldns.h>

#include "adsuck.h"

#define MAXLINE		(128)
#define INBUF_SIZE	(4096)
#define LOCALIP		"127.0.0.1"
#define ADSUCK_USER	"_adsuck"
#define VERSION		"1.1"

int			entries;
int			verbose;
int			debug;
int			debugsyslog;

/* socket */
int			sock;
struct sockaddr		paddr;
socklen_t		plen = (socklen_t) sizeof(paddr);

/* resolver */
ldns_resolver		*res;
char			*resolv_conf;
char			*domainname;
volatile sig_atomic_t   newresolv;
volatile sig_atomic_t   stop;

extern char		*__progname;

struct hostnode {
	RB_ENTRY(hostnode)	hostentry;
	char			*hostname;
};

int
rb_strcmp(struct hostnode *d1, struct hostnode *d2)
{
	return (strcmp(d1->hostname, d2->hostname));
}

RB_HEAD(hosttree, hostnode) hosthead = RB_INITIALIZER(&hosthead);
RB_GENERATE(hosttree, hostnode, hostentry, rb_strcmp)

void
sighdlr(int sig)
{
	switch (sig) {
	case SIGINT:
	case SIGTERM:
		stop = 1;
		break;
	case SIGHUP:
		newresolv = 1;
		break;
	case SIGCHLD:
		while (waitpid(WAIT_ANY, NULL, WNOHANG) != -1) /* sig safe */
			;
		break;
	}
}

void
logpacket(ldns_pkt *pkt)
{
	char			*str = ldns_pkt2str(pkt);

	if (str)
		log_debug("%s", str);
	else
		log_warnx("could not convert packet to string");
	LDNS_FREE(str);
}

void
addhosts(char *filename)
{
	FILE			*f;
	char			l[MAXLINE], *p;
	int			x, newentry = 0;
	size_t			len;
	struct hostnode		*hostn;

	f = fopen(filename, "r");
	if (f == NULL)
		fatal("can't open hosts file");

	while (!feof(f)) {
		if (fgets(l, sizeof l, f) == NULL && feof(f))
			break;
		if (l[0] != '1')
			continue;
		if (strncmp(l, LOCALIP, strlen(LOCALIP)))
			continue;
		for (x = strlen(LOCALIP); x < sizeof l; x++)
			if (!isblank(l[x]))
				break;
		p = l + x;

		/* skip localhost */
		if (!strncmp(p, "localhost", strlen("localhost")))
			continue;

		/* strip of newline cariage return */
		p[strcspn(p, "\r")] = '\0';
		p[strcspn(p, "\n")] = '\0';

		/* we got one! */
		len = strlen(p);
		hostn = malloc(sizeof(struct hostnode) + len + 1);
		if (hostn == NULL)
			fatal("not enough memory");
		hostn->hostname = (char *)(hostn + 1);
		strlcpy(hostn->hostname, p, len + 1);
		if (RB_INSERT(hosttree, &hosthead, hostn))
			free(hostn); /* duplicate R/B entry */
		newentry++;
	}
	if (verbose)
		log_info("added entries: %d", newentry);
	entries += newentry;
	fclose(f);
}

int
udp_bind(int sock, u_int16_t port, char *my_address)
{
	struct sockaddr_in		addr;
	in_addr_t			maddr = INADDR_ANY;

	if (my_address)
		if (inet_pton(AF_INET6, my_address, &maddr) < 1)
			if (inet_pton(AF_INET, my_address, &maddr) < 1)
				return (EINVAL);

	addr.sin_family = AF_INET;
	addr.sin_port = (in_port_t) htons((uint16_t)port);
	addr.sin_addr.s_addr = maddr;
	return (bind(sock, (struct sockaddr *)&addr, (socklen_t) sizeof(addr)));
}

char *
hostnamefrompkt(ldns_pkt *pkt, ldns_rr **qrr)
{
	ldns_rr			*query_rr;
	char			*name = NULL, *rawname = NULL;
	ssize_t			len;
	int			i, found;

	if (pkt == NULL)
		return (NULL);

	query_rr = ldns_rr_list_rr(ldns_pkt_question(pkt), 0);
	rawname = ldns_rr2str(query_rr);
	if (rawname == NULL)
		goto done;

	len = strlen(rawname);
	if (len <= 2)
		goto freeraw;
	len -= 2;

	/* strip off everything past last .*/
	for (i = 0, found = 0; i < len; i++)
		if (rawname[i] == '.' && isblank(rawname[i + 1])) {
			found = 1;
			break;
		}

	if (found) {
		rawname[i] = '\0';
		asprintf(&name, "%s", rawname);
		if (qrr)
			*qrr = query_rr;
	}
freeraw:
	free(rawname);
done:
	return (name);
}

int
spoofquery(char *hostname, ldns_rr *query_rr, u_int16_t id)
{
	ldns_status		status;
	ldns_rr_list		*answer_an = NULL;
	ldns_rr_list		*answer_ns = NULL;
	ldns_rr_list		*answer_ad = NULL;
	ldns_rr_list		*answer_qr = NULL;
	ldns_pkt		*answer_pkt = NULL;
	size_t			answer_size;
	uint8_t			*outbuf = NULL;
	int			rv = 1;

	/* answer section */
	answer_an = ldns_rr_list_new();
	if (answer_an == NULL)
		goto unwind;

	/* authority section */
	answer_ns = ldns_rr_list_new();
	if (answer_ns == NULL)
		goto unwind;

	/* question section */
	answer_qr = ldns_rr_list_new();
	if (answer_qr == NULL)
		goto unwind;
	ldns_rr_list_push_rr(answer_qr, ldns_rr_clone(query_rr));

	/* additional section */
	answer_ad = ldns_rr_list_new();
	if (answer_ad == NULL)
		goto unwind;

	/* actual packet */
	answer_pkt = ldns_pkt_new();
	if (answer_pkt == NULL)
		goto unwind;
	
	ldns_pkt_set_qr(answer_pkt, 1);
	ldns_pkt_set_aa(answer_pkt, 1);
	ldns_pkt_set_id(answer_pkt, id);
	ldns_pkt_set_rcode(answer_pkt, LDNS_RCODE_NXDOMAIN);

	ldns_pkt_push_rr_list(answer_pkt, LDNS_SECTION_QUESTION, answer_qr);
	ldns_pkt_push_rr_list(answer_pkt, LDNS_SECTION_ANSWER, answer_an);
	ldns_pkt_push_rr_list(answer_pkt, LDNS_SECTION_AUTHORITY, answer_ns);
	ldns_pkt_push_rr_list(answer_pkt, LDNS_SECTION_ADDITIONAL, answer_ad);

	status = ldns_pkt2wire(&outbuf, answer_pkt, &answer_size);
	if (status != LDNS_STATUS_OK)
		log_warnx("can't create answer: %s",
		    ldns_get_errorstr_by_id(status));
	else {
		if (debug) {
			log_debug("spoofquery response:");
			logpacket(answer_pkt);
		}

		if (sendto(sock, outbuf, answer_size, 0, &paddr, plen) == -1)
			log_warn("spoofquery sendto");
		else {
			rv = 0;
			if (verbose)
				log_info("spoofquery: spoofing %s",
				    hostname);
		}
	}

unwind:
	if (answer_pkt)
		ldns_pkt_free(answer_pkt);
	if (outbuf)
		LDNS_FREE(outbuf);
	if (answer_qr)
		ldns_rr_list_free(answer_qr);
	if (answer_an)
		ldns_rr_list_free(answer_an);
	if (answer_ns)
		ldns_rr_list_free(answer_ns);
	if (answer_ad)
		ldns_rr_list_free(answer_ad);

	return (rv);
}

int
forwardquery(char *hostname, ldns_rr *query_rr, u_int16_t id)
{
	size_t			answer_size;
	u_int16_t		qflags = LDNS_RD;
	uint8_t			*outbuf = NULL;
	ldns_rdf		*qname = NULL;
	ldns_pkt		*respkt = NULL;
	ldns_rr_type		type;
	ldns_rr_class		clas;
	ldns_status		status;
	int			rv = 1, child = 0;

	switch (fork()) {
	case -1:
		log_warn("cannot fork"); /* we'll just do it in parent proc */
		break;
	case 0:
		signal(SIGCHLD, SIG_DFL);
		child = 1;
		break;
	default:
		return (0);
	}

	qname = ldns_dname_new_frm_str(hostname);
	if (!qname) {
		log_warnx("forwardquery: can't make qname");
		goto unwind;
	}
	type = ldns_rr_get_type(query_rr);
	clas = ldns_rr_get_class(query_rr);
	respkt = ldns_resolver_query(res, qname, type, clas, qflags);
	if (respkt == NULL) {
		log_warnx("forwardquery: no respkt");
		goto unwind;
	}
	if (debug) {
		log_info("forwardquery response:");
		logpacket(respkt);
	}

	ldns_pkt_set_id(respkt, id);
	status = ldns_pkt2wire(&outbuf, respkt, &answer_size);
	if (status != LDNS_STATUS_OK)
		log_warnx("can't create answer: %s",
		    ldns_get_errorstr_by_id(status));
	else {
		if (sendto(sock, outbuf, answer_size, 0, &paddr, plen) == -1)
			log_warn("forwardquery sendto");
		else {
			rv = 0;
			if (verbose)
				log_info("forwardquery: resolved %s",
				    hostname);
		}
	}

unwind:
	if (respkt)
		ldns_pkt_free(respkt);
	if (outbuf)
		LDNS_FREE(outbuf);
	if (qname)
		ldns_rdf_free(qname);

	if (child)
		_exit(0);

	return (rv);
}

void
setupresolver(void)
{
	ldns_status		status;
	char			*action = "using", *es;
	char			buf[128];
	ldns_rdf		*dn;
	int			i;

	if (res) {
		ldns_resolver_free(res);
		free(domainname); /* XXX is this ok for ldns? */
		res = NULL;
		domainname = NULL;
		action = "rereading";
	}

	status = ldns_resolver_new_frm_file(&res, resolv_conf);
	if (status != LDNS_STATUS_OK) {
		asprintf(&es, "bad resolv.conf file: %s",
			ldns_get_errorstr_by_id(status));
		fatalx(es);
	}

	dn = ldns_resolver_domain(res);
	if (dn == NULL) {
		domainname = NULL;
		if (gethostname(buf, sizeof buf) == -1) {
			log_warn("getdomainname failed");
			domainname = NULL;
		} else {
			i = 0;
			while (buf[i] != '.' && i < strlen(buf) -1)
				i++;

			if (buf[i] == '.' && strlen(buf) > 1) {
				i++;
				asprintf(&domainname, "%s", &buf[i]);
			}
		}
	} else {
		domainname = ldns_rdf2str(dn);
		i = strlen(domainname);
		if (i >= 1)
			i--;
		if (domainname[i] == '.')
			domainname[i] = '\0';
	}

	log_info("%s %s, serving: %s", action, resolv_conf,
	    domainname ? domainname : "no local domain set");

	newresolv = 0;
}

void
usage(void)
{
	fprintf(stderr,
	    "%s [-Ddv] [-c directory] [-f resolv.conf] [-l listen] [-p port]\n"
	    "       [-u user] hostsfile ...\n", __progname);
	exit(0);
}

int
main(int argc, char *argv[])
{
	int			c;
	ssize_t			nb;
	uint8_t			inbuf[INBUF_SIZE];
	u_int16_t		id;
	ldns_status		status;
	ldns_pkt		*query_pkt;
	struct hostnode		hostn, *n, h;
	ldns_rr			*query_rr;
	char			*listen_addr = NULL;
	u_int16_t		port = 53;
	struct sigaction	sa;
	struct passwd		*pw;
	struct stat		stb;
	char			*user = ADSUCK_USER, *s;
	char			*cdir = NULL;
	int			foreground = 0;

	log_init(1);		/* log to stderr until daemonized */

	while ((c = getopt(argc, argv, "Dc:df:l:u:p:v")) != -1) {
		switch (c) {
		case 'D':
			foreground = 1;
			break;
		case 'c':
			cdir = optarg;
			break;
		case 'd':
			debug = 1;
			break;
		case 'f':
			resolv_conf = optarg;
			break;
		case 'l':
			listen_addr = optarg;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'u':
			user = optarg;
			break;
		case 'v':
			verbose = 1;
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	/* make sure we have right permissions */
	if (geteuid())
		errx(1, "need root privileges");

	if ((pw = getpwnam(user)) == NULL)
		errx(1, "unknown user %s", user);

	sock =  socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == -1)
		err(1, "can't open socket");
	if (udp_bind(sock, port, listen_addr))
		err(1, "can't udp bind");

	/* daemonize */
	if (!foreground) {
		if (debug)
			debugsyslog = 1;
		log_init(0);
		if (daemon(1, 0))
			fatal("daemon");
	}

	log_info("start V%s", VERSION);

	/* chroot */
	if (cdir == NULL)
		cdir = pw->pw_dir;
	if (stat(cdir, &stb) == -1)
		fatal("stat");
	if (stb.st_uid != 0 || (stb.st_mode & (S_IWGRP | S_IWOTH)) != 0)
		fatalx("bad privsep dir permissions");
	if (chroot(cdir) == -1)
		fatal("chroot");
	if (chdir("/") == -1)
		fatal("chdir(\"/\")");

	/* drop privs */
	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("can't drop privileges");

	/* signaling */
	sa.sa_handler = sighdlr;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	if (sigaction(SIGCHLD, &sa, NULL) == -1)
		fatal("could not install CHLD handler");

	sa.sa_handler = sighdlr;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	if (sigaction(SIGTERM, &sa, NULL) == -1)
		fatal("could not install TERM handler");

	sa.sa_handler = sighdlr;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	if (sigaction(SIGHUP, &sa, NULL) == -1)
		fatal("could not install HUP handler");
	setupresolver();

	while (argc) {
		addhosts(argv[0]);
		argc--;
		argv++;
	}
	if (verbose)
		log_info("total entries: %d", entries);

	while (!stop) {
		nb = recvfrom(sock, inbuf, INBUF_SIZE, 0, &paddr, &plen);
		if (nb == -1) {
			if (errno == EINTR || errno == EAGAIN) {
				if (newresolv)
					setupresolver();
				continue;
			} else
				fatal("recvfrom");
		}

		status = ldns_wire2pkt(&query_pkt, inbuf, (size_t)nb);
		if (status != LDNS_STATUS_OK) {
			log_warnx("bad packet: %s",
			    ldns_get_errorstr_by_id(status));
			continue;
		} else
			if (debug) {
				log_debug("received packet:");
				logpacket(query_pkt);
			}

		hostn.hostname = hostnamefrompkt(query_pkt, &query_rr);
		id = ldns_pkt_id(query_pkt);
		if (domainname &&
		    (s = strstr(hostn.hostname, domainname)) != NULL) {
			/*
			 * if we are in our own domain strip it of and try
			 * without domain name; this is to work around
			 * software that tries to be smart about domain names
			 */
			asprintf(&h.hostname, "%s", hostn.hostname);
			h.hostname[s - hostn.hostname - 1] = '\0';
			if (RB_FIND(hosttree, &hosthead, &h))
				spoofquery(hostn.hostname, query_rr, id);
			else
				forwardquery(hostn.hostname, query_rr, id);
			free(h.hostname);
		} else {
			/* not in our domain */
			if ((n = RB_FIND(hosttree, &hosthead, &hostn)) != NULL)
				spoofquery(hostn.hostname, query_rr, id);
			else
				forwardquery(hostn.hostname, query_rr, id);
		}

		free(hostn.hostname);
		ldns_pkt_free(query_pkt);
	}

	log_info("exiting");

	return (0);
}
