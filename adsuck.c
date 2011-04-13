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
#include <pwd.h>
#include <regex.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#include <sys/errno.h>
#include <sys/time.h>
#ifndef __linux__
#include <sys/tree.h>
#include <sys/queue.h>
#else
#include <linux/limits.h>
#include "linux/tree.h"
#include "linux/queue.h"
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <ldns/ldns.h>
#include <event.h>

#include "adsuck.h"

#define MAXLINE		(256)
#define INBUF_SIZE	(4096)
#define LOCALIP		"127.0.0.1"
#define ADSUCK_USER	"_adsuck"
#define VERSION		"2.3"

static char		*cvs = "$adsuck$";
struct ev_args {
	char		**argv;
	int		argc;
};

/* event signals */
struct event		evmain;
struct event		evint;
struct event		evquit;
struct event		evterm;
struct event		evusr1;
struct event		evusr2;
struct event		evhup;
struct event		evchild;
struct event		evclean;

struct timeval		event_cleanup_to;

int			entries;
int			verbose;
int			debug;
int			debugsyslog;

/* socket */
int			so;
struct sockaddr		paddr;
socklen_t		plen = (socklen_t)sizeof(paddr);

/* resolver */
ldns_resolver		*resolver;
char			*resolv_conf;
char			*domainname;
char			*regexfile;

/* stats */
uint64_t		s_questions;
uint64_t		s_answers;
uint64_t		s_spoofed_answers;
uint64_t		s_cached_questions;
uint64_t		s_cached;

extern char		*__progname;

struct ev_pipe_args {
	struct event		ev;
	int			fildes[2];
};

struct regexnode {
	SIMPLEQ_ENTRY(regexnode)	rlink;
	regex_t				rregex;
	char				*rname;
};

SIMPLEQ_HEAD(regexhead, regexnode) rh = SIMPLEQ_HEAD_INITIALIZER(rh);

struct hostnode {
	RB_ENTRY(hostnode)	hostentry;
	char			*hostname;
	char			*ipaddr;
};
RB_HEAD(hosttree, hostnode) hosthead = RB_INITIALIZER(&hosthead);

struct cachenode {
	RB_ENTRY(cachenode)	cacheentry;
	char			*question;
	ldns_pkt		*respkt;
	time_t			expires;
};
RB_HEAD(cachetree, cachenode) cachehead = RB_INITIALIZER(&cachehead);

int
rb_hostnode_strcmp(struct hostnode *d1, struct hostnode *d2)
{
	return (strcmp(d1->hostname, d2->hostname));
}

int
rb_cachenode_strcmp(struct cachenode *d1, struct cachenode *d2)
{
	return (strcmp(d1->question, d2->question));
}

RB_GENERATE(hosttree, hostnode, hostentry, rb_hostnode_strcmp)
RB_GENERATE(cachetree, cachenode, cacheentry, rb_cachenode_strcmp)

void
logpacket(ldns_pkt *pkt)
{
	char			*str = ldns_pkt2str(pkt);

	if (str) {
		log_debug("%s", str);
		LDNS_FREE(str);
	} else
		log_warnx("could not convert packet to string");
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
		len = strlen(host) + 2;
		if (strcmp(LOCALIP, ip))
			len += strlen(ip) + 1;
		else
			ip = NULL; /* localhost */

		hostn = calloc(1, sizeof(struct hostnode) + len);
		if (hostn == NULL)
			fatal("not enough memory");

		hostn->hostname = (char *)(hostn + 1);
		snprintf(hostn->hostname, strlen(host) + 2, "%s.", host);
		if (ip) {
			hostn->ipaddr = hostn->hostname + strlen(host) + 2;
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
	ldns_buffer		*out = NULL;
	ldns_rdf		*rdf;
	char			*ret = NULL;

	if (pkt == NULL)
		return (NULL);

	query_rr = ldns_rr_list_rr(ldns_pkt_question(pkt), 0);
	if (query_rr == NULL) {
		log_warnx("hostnamefrompkt invalid parameters");
		goto done;
	}

	out = ldns_buffer_new(LDNS_MAX_DOMAINLEN);
	if (out == NULL) {
		log_warnx("no memory for out buffer");
		goto done;
	}

	rdf = ldns_rr_owner(query_rr);
	if (ldns_rdf2buffer_str_dname(out, rdf) != LDNS_STATUS_OK) {
		log_warnx("can't get hostname");
		goto done;
	}

	ret = strdup(ldns_buffer_begin(out));
	if (ret == NULL) {
		log_warn("no memory for hostname");
		goto done;
	}

	if (qrr)
		*qrr = query_rr;
done:
	if (out)
		ldns_buffer_free(out);

	return (ret);
}

int
send_response(char *hostname, ldns_pkt *respkt, uint16_t id)
{
	size_t			answer_size;
	ldns_status		status;
	uint8_t			*outbuf = NULL;
	int			rv = 1;

	if (hostname == NULL || respkt == NULL) {
		log_warnx("send_response: invalid parameters");
		return (NULL);
	}

	ldns_pkt_set_id(respkt, id);
	status = ldns_pkt2wire(&outbuf, respkt, &answer_size);
	if (status != LDNS_STATUS_OK)
		log_warnx("can't create answer: %s",
		    ldns_get_errorstr_by_id(status));
	else {
		if (debug) {
			log_debug("response packet:");
			logpacket(respkt);
		}
		if (sendto(so, outbuf, answer_size, 0, &paddr, plen) == -1)
			log_warn("send_response: sendto");
		else {
			rv = 0;
			if (verbose)
				log_info("send_response: resolved %s", hostname);
		}
	}

	if (outbuf)
		LDNS_FREE(outbuf);

	return (rv);
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
	uint8_t			*outbuf = NULL;
	int			rv = 1;
	char			*ipaddr = NULL, *hostname = NULL;

	if (hn) {
		ipaddr = hn->ipaddr;
		hostname = hn->hostname;
	}

	/* answer section */
	answer_an = ldns_rr_list_new();
	if (answer_an == NULL)
		goto unwind;

	/* authority section */
	answer_ns = ldns_rr_list_new();
	if (answer_ns == NULL)
		goto unwind;

	/* if we have an ip spoof it there */
	if (ipaddr) {
		/* an */
		snprintf(buf, sizeof buf, "%s\t%d\tIN\tA\t%s",
		    hostname, 259200, ipaddr);
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
		snprintf(buf, sizeof buf, "%s\t%d\tIN\tNS\t127.0.0.1.",
		    hostname, 259200);
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
	if (ipaddr == NULL)
		ldns_pkt_set_rcode(answer_pkt, LDNS_RCODE_NXDOMAIN);

	ldns_pkt_push_rr_list(answer_pkt, LDNS_SECTION_QUESTION, answer_qr);
	ldns_pkt_push_rr_list(answer_pkt, LDNS_SECTION_ANSWER, answer_an);
	ldns_pkt_push_rr_list(answer_pkt, LDNS_SECTION_AUTHORITY, answer_ns);
	ldns_pkt_push_rr_list(answer_pkt, LDNS_SECTION_ADDITIONAL, answer_ad);

	/* reply to caller */
	if (send_response(hostname, answer_pkt, id))
		log_warnx("send_response failed");

	s_spoofed_answers++;

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

void
cachenode_unwind(struct cachenode *c)
{
	if (c == NULL)
		return;

	if (c->question)
		LDNS_FREE(c->question);
	if (c->respkt)
		ldns_pkt_free(c->respkt);
	free(c);
}

struct cachenode *
check_cache(ldns_rr *query_rr, u_int16_t id)
{
	struct cachenode	cn, *c = NULL;

	if (query_rr == NULL) {
		log_warnx("check_cache: invalid parameters");
		return (NULL);
	}

	cn.question= ldns_rr2str(query_rr);
	if ((c = RB_FIND(cachetree, &cachehead, &cn)) != NULL) {
		if (c->expires - time(NULL) < 0) {
			/* entry has expired */
			RB_REMOVE(cachetree, &cachehead, c);
			cachenode_unwind(c);
			c = NULL;
			s_cached--;
			goto done;
		}

		/* found it! */
		return (c);
	}

done:
	if (cn.question)
		LDNS_FREE(cn.question);

	return (c);
}

time_t
get_ttl(char *hostname, ldns_pkt *respkt)
{
	ldns_rr_list		*rrl;
	ldns_rr			*rr;
	ldns_rdf		*rdf;
	int			i;
	ldns_buffer		*out = NULL;
	time_t			expires = 0;

	if (hostname == NULL || respkt == NULL) {
		log_warnx("get_ttl: invalid parameters");
		return (0);
	}

	rrl = ldns_pkt_answer(respkt);
	out = ldns_buffer_new(LDNS_MAX_DOMAINLEN);
	if (out == NULL) {
		log_warnx("can't allocate buffer");
		goto done;
	}

	for (i = 0; i < ldns_rr_list_rr_count(rrl); i++) {
		rr = ldns_rr_list_rr(rrl, i);
		rdf = ldns_rr_owner(rr);
		if (ldns_rdf2buffer_str_dname(out, rdf) != LDNS_STATUS_OK) {
			log_warnx("can't get dname");
			goto done;
		}

		if (!strcmp(hostname, ldns_buffer_begin(out))) {
			/* this is the domain we were looking for */
			expires = time(NULL) + ldns_rr_ttl(rr);
			goto done;
		}
		ldns_buffer_clear(out);
	}

	/*
	 * since we found nothing in the answer section try authority section
	 * this is needed for . question which webkit generates by the billions
	 * all broswers are braindead generating infinite amounts of stupid dns
	 * questions
	 */
	rrl = ldns_pkt_authority(respkt);
	for (i = 0; i < ldns_rr_list_rr_count(rrl); i++) {
		rr = ldns_rr_list_rr(rrl, i);
		rdf = ldns_rr_owner(rr);
		if (ldns_rdf2buffer_str_dname(out, rdf) != LDNS_STATUS_OK) {
			log_warnx("can't get dname");
			goto done;
		}

		if (!strcmp(hostname, ldns_buffer_begin(out))) {
			/* this is the domain we were looking for */
			expires = time(NULL) + ldns_rr_ttl(rr);
			goto done;
		}
		ldns_buffer_clear(out);
	}

done:
	if (out)
		ldns_buffer_free(out);

	return (expires);
}

/* read in parent */
void
event_pipe(int fd, short sig, void *args)
{
	struct ev_pipe_args	*a = args;
	uint8_t			wire_pkt[LDNS_MAX_PACKETLEN];
	size_t			rd;
	ldns_pkt		*respkt = NULL;
	char			*hostname = NULL;
	time_t			expires = 0;
	struct cachenode	*cachen = NULL;
	ldns_rr			*query_rr;

	if ((rd = read(fd, wire_pkt, sizeof wire_pkt)) == -1)
		log_warn("can't read from pipe");
	else {
		if (ldns_wire2pkt(&respkt, wire_pkt, rd) != LDNS_STATUS_OK) {
			log_warnx("can't convert wire packet to struct");
			goto done;
		}

		hostname = hostnamefrompkt(respkt, &query_rr);
		if ((expires = get_ttl(hostname, respkt)) != 0) {
			cachen = calloc(1, sizeof *cachen);
			if (cachen == NULL) {
				log_warn("no memory for cache record");
				goto bad;
			}

			cachen->respkt = respkt;
			respkt = NULL; /* don't free it on the way out */
			if (cachen->respkt == NULL) {
				log_warn("no memory to cache packet");
				goto bad;
			}

			cachen->question = ldns_rr2str(query_rr);
			if (cachen->question == NULL) {
				log_warn("no memory to cache question");
				goto bad;
			}

			cachen->expires = expires;
			if (RB_INSERT(cachetree, &cachehead, cachen)) {
				/* this shouldn't happen */
				log_debug("already caching %s", hostname);
				goto bad;
			}
			s_cached++;

			/* we are caching this entry */
			if (debug)
				log_debug("caching %s", hostname);
			cachen = NULL; /* don't unwind cachen */
		}
	}
bad:
	if (cachen) {
		if (cachen->question)
			LDNS_FREE(cachen->question);
		if (cachen->respkt)
			ldns_pkt_free(cachen->respkt);
		free(cachen);
	}
done:
	if (respkt)
		ldns_pkt_free(respkt);
	if (hostname)
		LDNS_FREE(hostname);
	close(fd);

	event_del(&a->ev);
	free(a);

	return;

}

int
forwardquery(char *hostname, ldns_rr *query_rr, u_int16_t id)
{
	u_int16_t		qflags = LDNS_RD;
	ldns_rdf		*qname = NULL;
	ldns_pkt		*respkt = NULL;
	ldns_rr_type		type;
	ldns_rr_class		clas;
	int			rv = 1, child = 0, childrv = 0;
	struct hostnode		hn;
	struct cachenode	*c;
	struct ev_pipe_args	*a = NULL;
	int			cached = 0;
	uint8_t			*outbuf = NULL;
	size_t			answer_size;
	ldns_status		status;

	c = check_cache(query_rr,  id);
	if (c == NULL) {
		a = malloc(sizeof *a);
		if (a == NULL) {
			log_warnx("can't get memory for pipe");
			goto unwind;
		}
		if (pipe(a->fildes) == -1) {
			log_warnx("can't create pipe");
			goto unwind;
		}
		s_answers++;
	} else {
		cached = 1;
		s_cached_questions++;
	}

	switch (fork()) {
	case -1:
		log_warn("cannot fork"); /* we'll just do it in parent proc */
		break;
	case 0:
		/* is this needed? */
		signal_del(&evchild);
		signal_del(&evusr1);
		signal_del(&evhup);

		/* close read end */
		if (a)
			close(a->fildes[0]);
		child = 1;
		break;
	default:
		/* close write end */
		if (cached)
			return (0);

		if (a)
			close(a->fildes[1]);
		event_set(&a->ev, a->fildes[0], EV_READ | EV_PERSIST,
		    event_pipe, a);
		event_add(&a->ev, NULL);
		return (0);
	}

	if (c) {
		if (send_response(hostname, c->respkt, id)) {
			log_warnx("send_response cached");
			childrv = 1;
		}
		goto exitchild;
	}

	qname = ldns_dname_new_frm_str(hostname);
	if (!qname) {
		log_debug("forwardquery: can't make qname, spoofing response "
		    "for %s", hostname);

		hn.ipaddr = NULL;
		hn.hostname = hostname;
		spoofquery(&hn, query_rr, id);
		goto unwind;
	}
	type = ldns_rr_get_type(query_rr);
	clas = ldns_rr_get_class(query_rr);
	respkt = ldns_resolver_query(resolver, qname, type, clas, qflags);
	if (respkt == NULL) {
		/* dns query failed so lets spoof it instead of timing out */
		log_debug("forwardquery: query failed, spoofing response "
		    "hostname %s", hostname);

		hn.ipaddr = NULL;
		hn.hostname = hostname;
		spoofquery(&hn, query_rr, id);
		goto unwind;
	}

	if (a) {
		status = ldns_pkt2wire(&outbuf, respkt, &answer_size);
		if (status != LDNS_STATUS_OK)
			log_warnx("can't create answer: %s",
			    ldns_get_errorstr_by_id(status));
		else {
			if (write(a->fildes[1], outbuf, answer_size) !=
			     answer_size)
				log_warn("can't write question to parent");
		}
		/* send reply regardless of results */
	}

	if (send_response(hostname, respkt, id))
		log_warnx("send_reponse uncached");
unwind:
	if (outbuf)
		LDNS_FREE(outbuf);
	if (respkt)
		ldns_pkt_free(respkt);
	if (qname)
		ldns_rdf_free(qname);
exitchild:
	if (a) {
		close(a->fildes[1]); /* close write end */
		free(a);
	}
	if (child)
		_exit(childrv);

	return (rv);
}

void
setupresolver(void)
{
	ldns_status		status;
	char			*action = "using", *es;
	char			buf[128];
	ldns_rdf		*dn;
	size_t			i;

	if (resolver) {
		ldns_resolver_free(resolver);
		LDNS_FREE(domainname);
		resolver = NULL;
		domainname = NULL;
		action = "rereading";
	}

	status = ldns_resolver_new_frm_file(&resolver, resolv_conf);
	if (status != LDNS_STATUS_OK) {
		if (asprintf(&es, "bad resolv.conf file: %s",
		    ldns_get_errorstr_by_id(status)) == -1)
			fatal("setupresolver");
		fatalx(es);
	}

	dn = ldns_resolver_domain(resolver);
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
				if (asprintf(&domainname, "%s", &buf[i]) == -1)
					fatal("setupresolver");
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

void
freerb(void)
{
	struct hostnode		*n, *nxt;

	if (RB_EMPTY(&hosthead))
		return;

	for (n = RB_MIN(hosttree, &hosthead); n != NULL; n = nxt) {
		nxt = RB_NEXT(hosttree, &hosthead, n);
		RB_REMOVE(hosttree, &hosthead, n);
		free(n);
		entries--;
	}
	RB_INIT(&hosthead);
}

int
rereadhosts(int argc, char *argv[])
{
	freerb();

	log_info("rereading blacklist entries");

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
setupregex(void)
{
	char			l[MAXLINE], er[MAXLINE * 2], *p;
	FILE			*f;
	int			i = 0, rv;
	struct regexnode	*n;

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
usage(void)
{
	fprintf(stderr,
	    "%s [-DdVv] [-c directory] [-f resolv.conf] [-l listen] [-p port]\n"
	    "       [-r regexfile] [-u user] hostsfile ...\n", __progname);
	exit(0);
}

void
purge_cache(void)
{
	struct cachenode	*c, *next;

	for (c = RB_MIN(cachetree, &cachehead); c != NULL; c = next) {
		next = RB_NEXT(cachetree, &cachehead, c);
		RB_REMOVE(cachetree, &cachehead, c);
		cachenode_unwind(c);
		s_cached--;
	}

	if (RB_EMPTY(&cachehead))
		log_info("cache purged");
	else
		log_warnx("cache wasn't completly purged");
}
/* this is not in signal context so we can run stuff in here */
void
sighdlr(int sig, short flags, void *args)
{
	pid_t			pid;
	int			status;
	struct ev_args		*a = args;

	switch (sig) {
	case SIGINT:
	case SIGTERM:
	case SIGQUIT:
		event_loopexit(NULL);
		break;
	case SIGHUP:
		setupresolver();
		purge_cache();
		break;
	case SIGCHLD:
		while ((pid = waitpid(WAIT_ANY, &status, WNOHANG)) != 0) {
			if (pid == -1) {
				if (errno == EINTR)
					continue;
				if (errno != ECHILD) {
					/* waitpid */
				}
				break;
			}

			if (WIFEXITED(status)) {
				if (WEXITSTATUS(status) != 0) {
					/* child exit status bad */
				}
			} else {
				/* child is terminated abnormally */
			}
		}
		break;
	case SIGUSR1:
		rereadhosts(a->argc, a->argv);
		setupregex();
		purge_cache();
		break;
	case SIGUSR2:
		log_info("DNS requests        : %llu", s_questions);
		log_info("DNS uncached replies: %llu", s_answers);
		log_info("DNS spoofed replies : %llu", s_spoofed_answers);
		log_info("DNS cached replies  : %llu", s_cached_questions);
		log_info("Cache entries       : %llu", s_cached);
	}
}

void
event_cleanup(int fd, short sig, void *args)
{
	struct cachenode	*c, *next;

	for (c = RB_MIN(cachetree, &cachehead); c != NULL; c = next) {
		next = RB_NEXT(cachetree, &cachehead, c);
		if (c->expires - time(NULL) < 0) {
			/* entry expired, purge it */
			RB_REMOVE(cachetree, &cachehead, c);
			cachenode_unwind(c);
			s_cached--;
		}
	}

	evtimer_add(&evclean, &event_cleanup_to);
}

void
event_main(int fd, short sig, void *args)
{
	uint8_t			inbuf[INBUF_SIZE];
	u_int16_t		id;
	ssize_t			nb;
	ldns_status		status;
	ldns_pkt		*query_pkt;
	struct hostnode		hostn, *n = NULL, h;
	ldns_rr			*query_rr;
	char			*s;

	nb = recvfrom(so, inbuf, INBUF_SIZE, 0, &paddr, &plen);
	if (nb == -1) {
		if (errno == EINTR || errno == EAGAIN)
			return;
		else
			fatal("recvfrom");
	}

	status = ldns_wire2pkt(&query_pkt, inbuf, (size_t)nb);
	if (status != LDNS_STATUS_OK) {
		log_warnx("bad packet: %s",
		    ldns_get_errorstr_by_id(status));
		return;
	} else
		if (debug) {
			log_debug("received packet:");
			logpacket(query_pkt);
		}

	s_questions++;
	bzero(&hostn, sizeof hostn);
	hostn.hostname = hostnamefrompkt(query_pkt, &query_rr);
	id = ldns_pkt_id(query_pkt);
	if (hostn.hostname == NULL || !strcmp(hostn.hostname, "")) {
		/* if we have an invalid hostname forward it */
		forwardquery(hostn.hostname, query_rr, id);
	} else if (domainname &&
	    (s = strstr(hostn.hostname, domainname)) != NULL &&
	    s != hostn.hostname) {
		/*
		 * if we are in our own domain strip it of and try
		 * without the domain name; this is to work around
		 * software that tries to be smart about domain names
		 */
		if (asprintf(&h.hostname, "%s", hostn.hostname) == -1)
			fatal("hostname");
		h.hostname[s - hostn.hostname - 1] = '\0';
		if (runregex(h.hostname) == 0)
			spoofquery(&hostn, query_rr, id);
		else if ((n = RB_FIND(hosttree, &hosthead, &h)) != NULL)
			spoofquery(n, query_rr, id);
		else
			forwardquery(hostn.hostname, query_rr, id);
		free(h.hostname);
	} else {
		/* either exactly our search domain or not in our domain */
		if (runregex(hostn.hostname) == 0)
			spoofquery(&hostn, query_rr, id);
		else if ((n = RB_FIND(hosttree, &hosthead, &hostn)) != NULL)
			spoofquery(n, query_rr, id);
		else
			forwardquery(hostn.hostname, query_rr, id);
	}

	if (hostn.hostname)
		free(hostn.hostname);
	ldns_pkt_free(query_pkt);
}

int
main(int argc, char *argv[])
{
	int			c;
	char			*listen_addr = NULL;
	u_int16_t		port = 53;
	struct passwd		*pw;
	struct stat		stb;
	char			*user = ADSUCK_USER;
	char			*cdir = NULL;
	int			foreground = 0, rcount = 0;
	struct ev_args		eva;

	log_init(1);		/* log to stderr until daemonized */

	while ((c = getopt(argc, argv, "Dc:df:l:u:p:r:vV")) != -1) {
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
		case 'V':
			fprintf(stderr, "version: %s cvs: %s\n", VERSION, cvs);
			exit(0);
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

	so = socket(AF_INET, SOCK_DGRAM, 0);
	if (so == -1)
		err(1, "can't open socket");
	if (udp_bind(so, port, listen_addr))
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
		fatal("invalid chroot directory");
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

	/* external resolver */
	setupresolver();

	/* blacklists */
	rereadhosts(argc, argv);

	/* regex */
	rcount = setupregex();

	/* setup events */
	event_init();
	eva.argv = argv;
	eva.argc = argc;

	event_set(&evmain, so, EV_READ | EV_PERSIST, event_main, &eva);
	event_add(&evmain, NULL);

	signal_set(&evint, SIGINT, sighdlr, &eva);
	signal_add(&evint, NULL);

	signal_set(&evquit, SIGQUIT, sighdlr, &eva);
	signal_add(&evquit, NULL);

	signal_set(&evterm, SIGTERM, sighdlr, &eva);
	signal_add(&evterm, NULL);

	signal_set(&evusr1, SIGUSR1, sighdlr, &eva);
	signal_add(&evusr1, NULL);

	signal_set(&evusr2, SIGUSR2, sighdlr, &eva);
	signal_add(&evusr2, NULL);

	signal_set(&evhup, SIGHUP, sighdlr, &eva);
	signal_add(&evhup, NULL);

	signal_set(&evchild, SIGCHLD, sighdlr, &eva);
	signal_add(&evchild, NULL);

	event_cleanup_to.tv_sec = 60 * 60; /* every hour */
	evtimer_set(&evclean, event_cleanup, NULL);
	evtimer_add(&evclean, &event_cleanup_to);

	event_dispatch();

	freeregex();
	freerb();

	log_info("exiting");

	return (0);
}
