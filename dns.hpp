#include <sys/types.h>
#include <sys/socket.h>

#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <pthread.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#define uloga(f, a...) fprintf(stderr, f, ##a)
#define ulog_err(f, a...) uloga(f ": %s [%d].\n", ##a, strerror(errno), errno)

#define QUERY_DEBUG

#ifdef QUERY_DEBUG
#define ulog(f, a...) uloga(f, ##a)
#else
#define ulog(f, a...) do {} while (0)
#endif

#define QUERY_FLAGS_RESPONSE		0x8000	/* 0 - query, 1 - response */

#define QUERY_FLAGS_OPCODE_SHIFT	11
#define QUERY_FLAGS_OPCODE_MASK		0xf
#define QUERY_FLAGS_OPCODE_STANDARD	0	/* a standrad query: QUERY */
#define QUERY_FLAGS_OPCODE_INVERS	1	/* an inverse query: IQUERY */
#define QUERY_FLAGS_OPCODE_STATUS	2	/* a server status request: STATUS */

#define QUERY_FLAGS_AA			0x0400	/* authoritative answer */
#define QUERY_FLAGS_TC			0x0200	/* truncation bit */
#define QUERY_FLAGS_RD			0x0100	/* recursion desired */
#define QUERY_FLAGS_RA			0x0080	/* recursion available */

#define QUERY_FLAGS_RCODE_SHIFT		0
#define QUERY_FLAGS_RCODE_MASK		0xf
#define QUERY_FLAGS_RCODE_NOERROR	0	/* no error response code */
#define QUERY_FLAGS_RCODE_FORMAT_ERROR	1	/* format error response code */
#define QUERY_FLAGS_RCODE_FAIL		2	/* server failure response code */
#define QUERY_FLAGS_RCODE_NAME_ERROR	3	/* name error response code */
#define QUERY_FLAGS_RCODE_NOT_IMPL	4	/* not implemented response code */
#define QUERY_FLAGS_RCODE_REFUSED	5	/* refused response code */

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;

static inline void query_set_flags_opcode(__u16 *flags, __u16 opcode)
{
	*flags |= (opcode & QUERY_FLAGS_OPCODE_MASK) << QUERY_FLAGS_OPCODE_SHIFT;
}

static inline void query_set_flags_rcode(__u16 *flags, __u16 rcode)
{
	*flags |= (rcode & QUERY_FLAGS_RCODE_MASK) << QUERY_FLAGS_RCODE_SHIFT;
}

struct query_header
{
	unsigned short		id;
	unsigned short		flags;
	unsigned short		question_num;
	unsigned short		answer_num;
	unsigned short		auth_num;
	unsigned short		addon_num;
};

#define QUERY_RR_NAME_MAX_SIZE	256

struct rr
{
	char			name[QUERY_RR_NAME_MAX_SIZE];
	int			namelen;

	__u16			type;
	__u16			qclass;
	__u32			ttl;
	__u16			rdlen;
	unsigned char		rdata[0];
};

enum query_class {
	QUERY_CLASS_IN = 1,	/* Internet */
	QUERY_CLASS_CS,		/* CSNET */
	QUERY_CLASS_CH,		/* CHAOS */
	QUERY_CLASS_HS,		/* Hesoid */
	QUERY_CLASS_ANY = 255,	/* any class */
};

enum query_type {
	QUERY_TYPE_A = 1,	/* a host address */
	QUERY_TYPE_NS,		/* an authoritative name server */
	QUERY_TYPE_MD,		/* a mail destination */
	QUERY_TYPE_MF,		/* a mail forwarder */
	QUERY_TYPE_CNAME,	/* the canonical name for the alias */
	QUERY_TYPE_SOA,		/* marks the start of a zone authority */
	QUERY_TYPE_MB,		/* a mailbox domain name */
	QUERY_TYPE_MG,		/* a mail group member */
	QUERY_TYPE_MR,		/* a mail rename domain name */
	QUERY_TYPE_NULL,	/* a null RR */
	QUERY_TYPE_WKS,		/* a well known service description */
	QUERY_TYPE_PTR,		/* a domain name pointer */
	QUERY_TYPE_HINFO,	/* host information */
	QUERY_TYPE_MINFO,	/* mailbox or mail list information */
	QUERY_TYPE_MX,		/* mail exchange */
	QUERY_TYPE_TXT,		/* text strings */
	QUERY_TYPE_AXFR = 252,	/* a request for a transfer of an entire zone */
	QUERY_TYPE_MAILB,	/* a request for mailbox-related records (MB, MG or MR) */
	QUERY_TYPE_ALL,		/* A request for all records */
};

class dns {
	public:
		void parse(const u_char *data, size_t size) {
			if (size < sizeof(struct query_header))
				return;

			query_parse_answer(data);
		}

	private:
		void query_header_convert(struct query_header *h) {
			h->id = ntohs(h->id);
			h->flags = ntohs(h->flags);
			h->question_num = ntohs(h->question_num);
			h->answer_num = ntohs(h->answer_num);
			h->auth_num = ntohs(h->auth_num);
			h->addon_num = ntohs(h->addon_num);
		}

		void query_parse_header(struct query_header *h) {
			__u16 opcode, rcode;

			query_header_convert(h);

			opcode = (h->flags >> QUERY_FLAGS_OPCODE_SHIFT) & QUERY_FLAGS_OPCODE_MASK;
			rcode = (h->flags >> QUERY_FLAGS_RCODE_SHIFT) & QUERY_FLAGS_RCODE_MASK;

			uloga("id: %04x: flags: resp: %d, opcode: %d, auth: %d, trunc: %d, RD: %d, RA: %d, rcode: %d.\n",
					h->id,
					!!(h->flags & QUERY_FLAGS_RESPONSE),
					opcode,
					!!(h->flags & QUERY_FLAGS_AA),
					!!(h->flags & QUERY_FLAGS_TC),
					!!(h->flags & QUERY_FLAGS_RD),
					!!(h->flags & QUERY_FLAGS_RA),
					rcode);
			uloga("question: %d, answer: %d, auth: %d, addon: %d.\n",
					h->question_num, h->answer_num, h->auth_num, h->addon_num);
		}

		int query_parse_name(const u_char *message, const u_char *nptr, char *dst, int *off) {
			unsigned char len;
			int err, name_len;

			len = 0;
			name_len = 0;
			*off = 0;

			while ((len = *nptr)) {
				if (len & 0xc0) {
					__u16 o = ((__u16 *)nptr)[0];
					__u16 offset = ntohs(o) & ~0xc000;

					err = query_parse_name(message, message + offset, dst, off);
					dst += err;
					name_len += err;
					nptr += 2;
					*off = 2;
					return name_len;
				} else {
					nptr++;
					strncpy(dst, (char *)nptr, len);
					dst += len;
					*dst++ = '.';
					nptr += len;
					name_len += len + 1;
				}
			}
			*dst = '\0';
			name_len++;

			*off = name_len;

			return name_len;
		}

		int query_parse_rdata_ns(const u_char *message, const u_char *rdata,
				__u16 rlen __attribute__ ((unused)), char *dst,
				int dsize __attribute__ ((unused)))
		{
			int offset;
			return query_parse_name(message, rdata, dst, &offset);
		}

		int query_parse_rdata_a(const u_char *message __attribute__ ((unused)),
				const u_char *rdata, __u16 rlen, char *dst, int dsize)
		{
			if (rlen != 4)
				return -EINVAL;

			return snprintf(dst, dsize, "%s", inet_ntoa(*((struct in_addr *)rdata)));
		}

		struct rr *query_parse_rr(const u_char *message, const u_char *data, unsigned int *off)
		{
			struct rr *rr;
			__u16 rlen;
			int name_len, offset, header_inner_size = 10;
			char name[QUERY_RR_NAME_MAX_SIZE];

			name_len = query_parse_name(message, data, name, &offset);
			data += offset;

			rlen = ntohs(((__u16 *)data)[4]);

			if (!rlen)
				return NULL;

			rr = (struct rr *)malloc(sizeof(struct rr) + rlen + 1);
			if (!rr)
				return NULL;

			memset(rr, 0, sizeof(rr) + rlen + 1);

			rr->namelen = snprintf(rr->name, sizeof(rr->name), "%s", name);
			rr->type = ntohs(((__u16 *)data)[0]);
			rr->qclass = ntohs(((__u16 *)data)[1]);
			rr->ttl = ntohl(((__u32 *)data)[1]);
			rr->rdlen = rlen;
			memcpy(rr->rdata, data + header_inner_size, rr->rdlen);

			uloga("name: '%s', type: %d, class: %d, ttl: %u, rdlen: %d",
					rr->name, rr->type, rr->qclass, rr->ttl, rr->rdlen);

			char rdata[QUERY_RR_NAME_MAX_SIZE];
			switch (rr->type) {
				case QUERY_TYPE_A:
					query_parse_rdata_a(message, rr->rdata, rr->rdlen, rdata, sizeof(rdata));
					uloga(", rdata: %s", rdata);
					break;
				case QUERY_TYPE_NS:
					query_parse_rdata_ns(message, rr->rdata, rr->rdlen, rdata, sizeof(rdata));
					uloga(", rdata: %s", rdata);
					break;
			}

			uloga("\n");

			*off = offset + rlen + header_inner_size;
			return rr;
		}

		int query_parse_question(const u_char *message, const u_char *data,
				char *name, __u16 *type, __u16 *qclass)
		{
			int name_len, offset;

			name_len = query_parse_name(message, data, name, &offset);
			data += offset;

			*type = ntohs(((__u16 *)data)[0]);
			*qclass = ntohs(((__u16 *)data)[1]);

			uloga("question: name: '%s', type: %d, class: %d.\n",
					name, *type, *qclass);

			return offset + 4;
		}

		int query_parse_answer(const u_char *data)
		{
			u_char *rrh;
			struct query_header *h = (struct query_header *)data;
			struct rr *rr;
			int i;
			unsigned int offset;
			char name[QUERY_RR_NAME_MAX_SIZE];
			__u16 type, qclass;

			query_parse_header(h);

			rrh = (u_char *)(h + 1);

			for (i=0; i<h->question_num; ++i) {
				rrh += query_parse_question(data, rrh, name, &type, &qclass);
			}

			for (i=0; i<h->answer_num + h->auth_num + h->addon_num; ++i) {
				offset = 0;
				rr = query_parse_rr(data, rrh, &offset);
				if (!rr)
					break;

				free(rr);

				rrh += offset;
			}

			if (!rr)
				return -EINVAL;

			return 0;
		}

		int query_add_rr_noname(__u16 *a, struct rr *rr)
		{
			__u32 *ttl;

			a[0] = htons(rr->type);
			a[1] = htons(rr->qclass);
			ttl = (__u32 *)&a[2];
			ttl[0] = htonl(rr->ttl);
			a[4] = htons(rr->rdlen);
			memcpy(&a[5], rr->rdata, rr->rdlen);

			return rr->rdlen + 10;
		}

		int query_add_rr(u_char *answer, struct rr *rr)
		{
			__u16 *a = (__u16 *)answer;

			a[0] = htons(0xc000 | sizeof(struct query_header));

			return 2 + query_add_rr_noname(&a[1], rr);
		}
};
