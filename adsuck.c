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
#include <regex.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#include <sys/errno.h>
#ifndef __linux__
#include <sys/tree.h>
#include <sys/queue.h>
#else
#include "linux/tree.h"
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <ldns/ldns.h>

#include "adsuck.h"

#define MAXLINE		(128)
#define INBUF_SIZE	(4096)
#define LOCALIP		"127.0.0.1"
#define ADSUCK_USER	"_adsuck"
#define VERSION		"1.4"

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
char			*regexfile;
volatile sig_atomic_t   newresolv;
volatile sig_atomic_t   stop;
volatile sig_atomic_t   reread;

extern char		*__progname;

struct regexnode {
	SIMPLEQ_ENTRY(regexnode)	rlink;
	regex_t				rregex;
	char				*rname;
};

SIMPLEQ_HEAD(regexhead, regexnode);
struct regexhead	rh;

struct hostnode {
	RB_ENTRY(hostnode)	hostentry;
	char			*hostname;
	char			*ipaddr;
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
	case SIGUSR1:
		reread = 1;
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

int
parseline(char *l, char **ip, char **host)
{
	int			i, len, rv = 1;
	char			*h;
	in_addr_t		ipaddr;

	/* sanity */
	if (ip == NULL || host == NULL)
		goto done;

	/* validate we have a valid ip */
	ipaddr = inet_addr(l); /* doesn't care about trailing spaces */
	if ((int)ipaddr == -1)
		goto done;

	/* strip of newline cariage return */
	l[strcspn(l, "\r")] = '\0';
	l[strcspn(l, "\n")] = '\0';

	/* redirect to ip */
	i = 0;
	len = strlen(l);
	/* skip to hostname */
	while (!isblank(l[i]) && i < len)
		i++;
	if (i >= len)
		goto done;
	l[i] = '\0';
	i++;

	/* skip whitespace to hostname */
	while (isblank(l[i]) && i < len)
		i++;
	if (i >= len)
		goto done;
	h = &l[i];
	i++;

	/* find last char of hostname */
	while (!isblank(l[i]) && l[i] != '\0' && i < len)
		i++;
	if (i < len)
		l[i] = '\0';

	*ip = l;
	*host = h;
	rv = 0;
done:
	return (rv);
}

void
addhosts(char *filename)
{
	FILE			*f;
	char			l[MAXLINE];
	char			*ip, *host;
	int			newentry = 0, line = 0;
	size_t			len;
	struct hostnode		*hostn;

	f = fopen(filename, "r");
	if (f == NULL)
		fatal("can't open hosts file");

	while (!feof(f)) {
		line++;
		if (fgets(l, sizeof l, f) == NULL && feof(f))
			break;

		/* skip comments and other garbage */
		if (l[0] == '\0')
			continue;
		if (l[0] == '\r')
			continue;
		if (l[0] == '\n')
			continue;
		if (l[0] == '#')
			continue;

		if (parseline(l, &ip, &host)) {
			log_info("invalid entry on line %d", line);
			continue;
		}
		/* skip localhost */
		if (!strcmp(host, "localhost"))
			continue;


		/* we got one! */
		len = strlen(host) + 1;
		if (strcmp(LOCALIP, ip))
			len += strlen(ip) + 1;
		else
			ip = NULL; /* localhost */

		hostn = calloc(1, sizeof(struct hostnode) + len);
		if (hostn == NULL)
			fatal("not enough memory");

		hostn->hostname = (char *)(hostn + 1);
		strlcpy(hostn->hostname, host, strlen(host) + 1);
		if (ip) {
			hostn->ipaddr = hostn->hostname + strlen(host) + 1;
			strlcpy(hostn->ipaddr, ip, strlen(ip) + 1);
		} else
			hostn->ipaddr = NULL;
		if (RB_INSERT(hosttree, &hosthead, hostn))
			free(hostn); /* duplicate R/B entry */
		else
			newentry++;
	}
	if (verbose)
		log_info("added entries: %d", newentry);
	entries += newentry;
	fclose(f);
}

int
rereadhosts(int argc, char *argv[])
{
	struct hostnode		*n, *nxt;

	if (!RB_EMPTY(&hosthead)) {
		log_info("rereading blacklist entries");
		for (n = RB_MIN(hosttree, &hosthead); n != NULL; n = nxt) {
			nxt = RB_NEXT(hosttree, &hosthead, n);
			RB_REMOVE(hosttree, &hosthead, n);
			free(n);
			entries--;
		}
	}

	while (argc) {
		log_info("adding %s", argv[0]);

		addhosts(argv[0]);
		argc--;
		argv++;
	}

	log_info("total entries: %d", entries);

	return (0);
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
spoofquery(struct hostnode *hn, ldns_rr *query_rr, u_int16_t id)
{
	ldns_status		status;
	ldns_rr_list		*answer_an = NULL;
	ldns_rr_list		*answer_ns = NULL;
	ldns_rr_list		*answer_ad = NULL;
	ldns_rr_list		*answer_qr = NULL;
	ldns_pkt		*answer_pkt = NULL;
	ldns_rr			*myrr = NULL, *myaurr = NULL;
	ldns_rdf		*prev = NULL;
	char			buf[MAXLINE * 2];
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

	/* if we have an ip spoof it there */
	if (hn->ipaddr) {
		/* an */
		snprintf(buf, sizeof buf, "%s.\t%d\tIN\tA\t%s",
		    hn->hostname, 259200, hn->ipaddr);
		status = ldns_rr_new_frm_str(&myrr, buf, 0, NULL, &prev);
		if (status != LDNS_STATUS_OK) {
			fprintf(stderr, "can't create answer section: %s\n",
			    ldns_get_errorstr_by_id(status));
			goto unwind;
		}
		ldns_rr_list_push_rr(answer_an, myrr);
		ldns_rdf_deep_free(prev);
		prev = NULL;

		/* ns */
		snprintf(buf, sizeof buf, "%s.\t%d\tIN\tNS\t127.0.0.1.",
		    hn->hostname, 259200);
		status = ldns_rr_new_frm_str(&myaurr, buf, 0, NULL, &prev);
		if (status != LDNS_STATUS_OK) {
			fprintf(stderr, "can't create authority section: %s\n",
			    ldns_get_errorstr_by_id(status));
			goto unwind;
		}
		ldns_rr_list_push_rr(answer_ns, myaurr);
		ldns_rdf_deep_free(prev);
		prev = NULL;
	}

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
	if (hn->ipaddr == NULL)
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
				log_info("spoofquery: spoofing %s to %s",
				    hn->hostname,
				    hn->ipaddr ? hn->ipaddr : "NXdomain");
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
freeregex(void)
{
	struct regexnode	*n;

	if (SIMPLEQ_EMPTY(&rh))
		return;

	while (!SIMPLEQ_EMPTY(&rh)) {
		n = SIMPLEQ_FIRST(&rh);
		SIMPLEQ_REMOVE_HEAD(&rh, rlink);
		regfree(&n->rregex);
		free(n->rname);
		free(n);
	}
	SIMPLEQ_INIT(&rh);
}

int
setupregex(void)
{
	char			l[MAXLINE], er[MAXLINE * 2], *p;
	FILE			*f;
	int			i = 0, rv;
	struct regexnode	*n;

	if (!SIMPLEQ_EMPTY(&rh))
		freeregex();

	if (regexfile == NULL)
		return (0);

	log_info("regex file: %s", regexfile);

	f = fopen(regexfile, "r");
	if (f == NULL)
		fatal("can't open regex file");

	while (!feof(f)) {
		if (fgets(l, sizeof l, f) == NULL && feof(f))
			break;
		if (l[0] == '#')
			continue; /* comment */
		p = l;
		i++;

		/* strip of newline cariage return */
		p[strcspn(p, "\r")] = '\0';
		p[strcspn(p, "\n")] = '\0';
		if (debug)
			log_debug("regex line %s", l);

		n = malloc(sizeof *n);
		if (n == NULL)
			fatal("regex node");

		if (asprintf(&n->rname, "%s", l) == -1)
			fatal("regex asprintf");

		if ((rv = regcomp(&n->rregex, l, REG_EXTENDED | REG_NOSUB))
		    != 0) {
			regerror(rv, &n->rregex, er, PATH_MAX - 1);
			snprintf(er, sizeof er, "regcomp failed %s", l);
			fatalx(er);
		}

		SIMPLEQ_INSERT_TAIL(&rh, n, rlink);
	}

	log_info("total regex expressions: %d", i);

	fclose(f);

	return (i);
}

int
runregex(char *hostname)
{
	struct regexnode	*n;
	int			rv = 1;

	SIMPLEQ_FOREACH(n, &rh, rlink) {
		if (regexec(&n->rregex, hostname, 0, NULL, 0) != 0)
			continue;
		/* we have a match */
		if (verbose)
			log_info("regex match: %s", n->rname);
		rv = 0;
		break;
	}

	return (rv);
}

void
dosignals(int argc, char *argv[])
{
	if (newresolv)
		setupresolver();
	if (reread) {
		rereadhosts(argc, argv);
		setupregex();
		reread = 0;
	}
}

void
installsignal(int sig, char *name)
{
	struct sigaction	sa;
	char			msg[80];

	sa.sa_handler = sighdlr;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	if (sigaction(sig, &sa, NULL) == -1) {
		snprintf(msg, sizeof msg, "could not install %s handler", name);
		fatal(msg);
	}
}

void
usage(void)
{
	fprintf(stderr,
	    "%s [-Ddv] [-c directory] [-f resolv.conf] [-l listen] [-p port]\n"
	    "       [-r regexfile] [-u user] hostsfile ...\n", __progname);
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
	struct hostnode		hostn, *n = NULL, h;
	ldns_rr			*query_rr;
	char			*listen_addr = NULL;
	u_int16_t		port = 53;
	struct passwd		*pw;
	struct stat		stb;
	char			*user = ADSUCK_USER, *s;
	char			*cdir = NULL;
	int			foreground = 0, rcount = 0;

	log_init(1);		/* log to stderr until daemonized */

	while ((c = getopt(argc, argv, "Dc:df:l:u:p:r:v")) != -1) {
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
		case 'r':
			regexfile = optarg;
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
	installsignal(SIGCHLD, "CHLD");
	installsignal(SIGTERM, "TERM");
	installsignal(SIGUSR1, "USR1");
	installsignal(SIGHUP, "HUP");

	/* external resolver */
	setupresolver();

	/* blacklists */
	rereadhosts(argc, argv);

	/* regex */
	SIMPLEQ_INIT(&rh);
	rcount = setupregex();

	while (!stop) {
		nb = recvfrom(sock, inbuf, INBUF_SIZE, 0, &paddr, &plen);
		if (nb == -1) {
			if (errno == EINTR || errno == EAGAIN) {
				dosignals(argc, argv);
				continue;
			} else
				fatal("recvfrom");
		}
		dosignals(argc, argv);

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

		bzero(&hostn, sizeof hostn);
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
			if (runregex(h.hostname) == 0)
				spoofquery(&hostn, query_rr, id);
			else if ((n == RB_FIND(hosttree, &hosthead, &h)) != NULL)
				spoofquery(n, query_rr, id);
			else
				forwardquery(hostn.hostname, query_rr, id);
			free(h.hostname);
		} else {
			/* not in our domain */
			if (runregex(hostn.hostname) == 0)
				spoofquery(&hostn, query_rr, id);
			else if ((n = RB_FIND(hosttree, &hosthead, &hostn)) != NULL)
				spoofquery(n, query_rr, id);
			else
				forwardquery(hostn.hostname, query_rr, id);
		}

		free(hostn.hostname);
		ldns_pkt_free(query_pkt);
	}

	freeregex();

	log_info("exiting");

	return (0);
}
