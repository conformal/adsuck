/* $adsuck$ */
/* copyright 2009 Marco Peereboom, all rights reserved */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <err.h>
#include <unistd.h>

#include <netinet/in.h>

#include <arpa/inet.h>

#include <sys/errno.h>
#include <sys/tree.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <ldns/ldns.h>

#define MAXLINE		(128)
#define INBUF_SIZE	(4096)
#define LOCALIP		"127.0.0.1"

int			entries;
int			verbose;
int			debug;

/* socket */
int			sock;
struct sockaddr		paddr;
socklen_t		plen = (socklen_t) sizeof(paddr);

/* resolver */
ldns_resolver		*res;

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
addhosts(char *filename)
{
	FILE			*f;
	char			l[MAXLINE], *p;
	int			x, newentry = 0;
	size_t			len;
	struct hostnode		*hostn;

	f = fopen(filename, "r");
	if (f == NULL)
		err(1, "can't open file %s", filename);

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
			err(1, "not enough memory");
		hostn->hostname = (char *)(hostn + 1);
		strlcpy(hostn->hostname, p, len + 1);
		if (RB_INSERT(hosttree, &hosthead, hostn))
			free(hostn); /* duplicate R/B entry */
		newentry++;
	}
	if (verbose)
		printf("added entries: %d\n", newentry);
	entries += newentry;
	fclose(f);
}

int
udp_bind(int sock, int port, char *my_address)
{
	struct sockaddr_in		addr;
	in_addr_t			maddr = INADDR_ANY;

	/* XXX this doesn't work */
	if (my_address)
		if (inet_pton(AF_INET6, my_address, &maddr) < 1)
			if (inet_pton(AF_INET, my_address, &maddr) < 1)
				return (EINVAL);

	addr.sin_family = AF_INET;
	addr.sin_port = (in_port_t) htons((uint16_t)port);
	addr.sin_addr.s_addr = maddr;
	return (bind(sock, (struct sockaddr *)&addr, (socklen_t) sizeof(addr)));
}

void
usage(void)
{
	fprintf(stderr, "%s [-dv][hostsfile ...]\n", __progname);
	exit(0);
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
	ldns_rr			*myrr = NULL, *myaurr = NULL;
	ldns_rdf		*prev = NULL;
	ldns_rr_list		*answer_an = NULL;
	ldns_rr_list		*answer_ns = NULL;
	ldns_rr_list		*answer_ad = NULL;
	ldns_rr_list		*answer_qr = NULL;
	ldns_pkt		*answer_pkt = NULL;
	size_t			answer_size;
	uint8_t			*outbuf = NULL;
	char			buf[128];
	int			rv = 1;

	/* answer section */
	answer_an = ldns_rr_list_new();
	snprintf(buf, sizeof buf, "%s.\t%d\tIN\tA\t127.0.0.1",
	    hostname, 259200);
	status = ldns_rr_new_frm_str(&myrr, buf, 0, NULL, &prev);
	if (status != LDNS_STATUS_OK) {
		fprintf(stderr, "can't create answer section: %s\n",
		    ldns_get_errorstr_by_id(status));
		goto unwind;
	}
	ldns_rr_list_push_rr(answer_an, myrr);
	ldns_rdf_deep_free(prev);
	prev = NULL;

	/* authority section */
	answer_ns = ldns_rr_list_new();
	snprintf(buf, sizeof buf, "%s.\t%d\tIN\tNS\t127.0.0.1.",
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

	/* question section */
	answer_qr = ldns_rr_list_new();
	ldns_rr_list_push_rr(answer_qr, ldns_rr_clone(query_rr));

	/* actual packet */
	answer_pkt = ldns_pkt_new();
	answer_ad = ldns_rr_list_new();
	
	ldns_pkt_set_qr(answer_pkt, 1);
	ldns_pkt_set_aa(answer_pkt, 1);
	ldns_pkt_set_id(answer_pkt, id);

	ldns_pkt_push_rr_list(answer_pkt, LDNS_SECTION_QUESTION, answer_qr);
	ldns_pkt_push_rr_list(answer_pkt, LDNS_SECTION_ANSWER, answer_an);
	ldns_pkt_push_rr_list(answer_pkt, LDNS_SECTION_AUTHORITY, answer_ns);
	ldns_pkt_push_rr_list(answer_pkt, LDNS_SECTION_ADDITIONAL, answer_ad);

	status = ldns_pkt2wire(&outbuf, answer_pkt, &answer_size);
	if (status != LDNS_STATUS_OK)
		fprintf(stderr, "can't create answer: %s\n",
		    ldns_get_errorstr_by_id(status));
	else {
		if (debug) {
			fprintf(stderr, "spoofquery response:\n");
			ldns_pkt_print(stderr, answer_pkt);
		}

		if (sendto(sock, outbuf, answer_size, 0, &paddr, plen) == -1)
			warn("spoofquery sendto");
		else {
			rv = 0;
			if (verbose)
				fprintf(stderr, "spoofquery: spoofing %s\n",
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
	int			rv = 1;

	qname = ldns_dname_new_frm_str(hostname);
	if (!qname) {
		fprintf(stderr, "forwardquery: can't make qname\n");
		goto unwind;
	}
	type = ldns_rr_get_type(query_rr);
	clas = ldns_rr_get_class(query_rr);
	respkt = ldns_resolver_query(res, qname, type, clas, qflags);
	if (respkt == NULL) {
		fprintf(stderr, "forwardquery: no respkt\n");
		goto unwind;
	}
	if (debug) {
		fprintf(stderr, "forwardquery response:\n");
		ldns_pkt_print(stderr, respkt);
	}

	ldns_pkt_set_id(respkt, id);
	status = ldns_pkt2wire(&outbuf, respkt, &answer_size);
	if (status != LDNS_STATUS_OK)
		fprintf(stderr, "can't create answer: %s\n",
		    ldns_get_errorstr_by_id(status));
	else {
		if (sendto(sock, outbuf, answer_size, 0, &paddr, plen) == -1)
			warn("forwardquery sendto");
		else {
			rv = 0;
			if (verbose)
				fprintf(stderr, "forwardquery: resolved %s\n",
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

	return (rv);
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
	struct hostnode		hostn, *n;
	ldns_rr			*query_rr;
	char			*resolv_conf = NULL;

	while ((c = getopt(argc, argv, "df:v")) != -1) {
		switch (c) {
		case 'd':
			debug = 1;
			break;
		case 'f':
			resolv_conf = optarg;
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

	while (argc) {
		addhosts(argv[0]);
		argc--;
		argv++;
	}
	if (verbose)
		printf("total entries: %d\n", entries);

	sock =  socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == -1)
		err(1, "can't open socket");
	//if (udp_bind(sock, 53, "localhost"))
	if (udp_bind(sock, 53, NULL))
		err(1, "can't udp bind");

	/* setup resolver */
	status = ldns_resolver_new_frm_file(&res, resolv_conf);
	if (status != LDNS_STATUS_OK) {
		printf("bad resolv.conf file: %s\n", ldns_get_errorstr_by_id(status));
		exit(1);
	}

	for (;;) {
		nb = recvfrom(sock, inbuf, INBUF_SIZE, 0, &paddr, &plen);
		if (nb == -1) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			else
				err(1, "recvfrom");
		}

		status = ldns_wire2pkt(&query_pkt, inbuf, (size_t)nb);
		if (status != LDNS_STATUS_OK) {
			fprintf(stderr, "bad packet: %s\n",
			    ldns_get_errorstr_by_id(status));
			continue;
		} else
			if (debug) {
				fprintf(stderr, "received packet:\n");
				ldns_pkt_print(stderr, query_pkt);
			}

		hostn.hostname = hostnamefrompkt(query_pkt, &query_rr);
		id = ldns_pkt_id(query_pkt);
		if ((n = RB_FIND(hosttree, &hosthead, &hostn)) != NULL)
			spoofquery(hostn.hostname, query_rr, id);
		else
			forwardquery(hostn.hostname, query_rr, id);

		free(hostn.hostname);
		ldns_pkt_free(query_pkt);
	}

	return (0);
}
