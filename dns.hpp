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

#include <boost/regex.hpp>

#define uloga(f, a...) fprintf(stdout, f, ##a)
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

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;

static inline void query_set_flags_opcode(u16 *flags, u16 opcode)
{
	*flags |= (opcode & QUERY_FLAGS_OPCODE_MASK) << QUERY_FLAGS_OPCODE_SHIFT;
}

static inline void query_set_flags_rcode(u16 *flags, u16 rcode)
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
	QUERY_TYPE_AAAA = 28,	/* ipv6 host address */
	QUERY_TYPE_AXFR = 252,	/* a request for a transfer of an entire zone */
	QUERY_TYPE_MAILB,	/* a request for mailbox-related records (MB, MG or MR) */
	QUERY_TYPE_ALL,		/* A request for all records */
};

class qname {
	public:
		qname(const std::string &name) {
			m_namelen = snprintf(m_name, sizeof(m_name), "%s", name.c_str());
			m_consumed = 0;
		}

		qname(const u_char *message, size_t offset, size_t max_size) : m_namelen(0), m_consumed(0) {
			memset(m_name, 0, sizeof(m_name));
			parse(message, message + offset, max_size);
		}

		size_t consumed() const {
			return m_consumed;
		}

		const char *name() const {
			return m_name;
		}

		std::string pack() const {
			std::ostringstream ss;
			unsigned char len;

			size_t start = 0;
			for (size_t i = 0; i < m_namelen; ++i) {
				if (m_name[i] == '.') {
					len = i - start;

					ss << len;
					ss.write(&m_name[start], len);

					start = i + 1;
				}
			}

			ss << '\0';
			return ss.str();
		}

	private:
		char m_name[QUERY_RR_NAME_MAX_SIZE];
		size_t m_namelen;
		size_t m_consumed;

		void parse(const u_char *message, const u_char *nptr, size_t max_size) {
			unsigned char len;

			while (nptr && (len = *nptr)) {
				m_consumed += 1;

				if (len & 0xc0) {
					u16 o = ((u16 *)nptr)[0];
					u16 offset = ntohs(o) & ~0xc000;

					size_t old_consumed = m_consumed;
					parse(message, message + offset, max_size);
					m_consumed = old_consumed + 1;
					return;
				} else {
					if (m_namelen + len + 1 >= sizeof(m_name)) {
						std::ostringstream ss;
						ss << "qname: parser went out of name bounds: current-name-len: " << m_namelen << ", new-chunk-len: " << len << ", max: " << sizeof(m_name);
						throw std::runtime_error(ss.str());
					}

					nptr++;
					strncpy(m_name + m_namelen, (char *)nptr, len);
					nptr += len;

					m_name[m_namelen + len] = '.';
					m_namelen += len + 1;

					m_consumed += len;
				}

				if (m_consumed >= max_size) {
					std::ostringstream ss;
					ss << "qname: parser went out of message bounds: namelen: " << m_namelen << ", message-size: " << max_size;
					throw std::runtime_error(ss.str());
				}
			}

			m_consumed += 1; // name section is terminated with 0-byte

			m_namelen--; // drop last '.'
			m_name[m_namelen] = '\0';
		}
};

class question {
	public:
		question(const u_char *message, size_t offset, size_t size) : m_name(message, offset, size) {
			const u16 *data = (const u16 *)(message + offset + m_name.consumed());

			m_type = ntohs(data[0]);
			m_class = ntohs(data[1]);

			uloga("question: name: '%s', type: %d, class: %d.\n", m_name.name(), m_type, m_class);
		}

		std::string name() const {
			return m_name.name();
		}

		size_t consumed() const {
			return m_name.consumed() + 2 * 2;
		}

		u16 qclass() const {
			return m_class;
		}

		std::string pack() const {
			std::ostringstream ss;

			ss << m_name.pack() <<
				htons(m_type) <<
				htons(m_class);

			return ss.str();
		}

	private:
		qname m_name;
		u16 m_type, m_class;
};

class rr {
	public:
		rr(const std::string &name, u16 qtype, u16 qclass, u32 ttl, const std::string &rdata) : m_name(name), m_type(qtype), m_class(qclass), m_ttl(ttl), m_rdata(rdata) {
		}

		rr(const u_char *message, size_t offset, size_t size) : m_name(message, offset, size) {
			const u16 *data = (const u16 *)(message + offset + m_name.consumed());
			for (size_t i = 0; i < size; ++i) {
				printf("%02x ", message[i]);
			}
			printf("\noffset: %zd, consumed: %zd\n", offset, m_name.consumed());

			m_type = ntohs(data[0]);
			m_class = ntohs(data[1]);
			m_ttl = ntohl(*(u32 *)(data + 2));

			u16 rdlen = ntohs(data[4]);
			m_rdata.assign((char *)message + offset + m_name.consumed() + 10, rdlen);

			uloga("rr: name: '%s', type: %d, class: %d, ttl: %d, rdlen: %d.\n", m_name.name(), m_type, m_class, m_ttl, rdlen);
		}

		u16 type() const {
			return m_type;
		}

		std::string rdata() const {
			return m_rdata;
		}

		void set_rdata(const std::string &rdata) {
			m_rdata = rdata;
		}

		size_t consumed() const {
			return m_name.consumed() + 10 + m_rdata.size();
		}

		std::string pack() const {
			std::ostringstream ss;

			ss << m_name.pack() <<
				htons(m_type) <<
				htons(m_class) <<
				htonl(m_ttl) <<
				htons(m_rdata.size()) <<
				m_rdata;

			return ss.str();
		}

	private:
		qname m_name;

		u16 m_type;
		u16 m_class;
		u32 m_ttl;

		std::string m_rdata;
};

class query {
	public:
		query(const u_char *message, size_t size) {
			if (size < sizeof(struct query_header))
				return;

			const struct query_header *h = (const struct query_header *)message;

			m_header = *h;
			query_parse_header(&m_header);

			size_t offset = sizeof(struct query_header);
			for (int i = 0; i < m_header.question_num; ++i) {
				question q(message, offset, size);
				offset += q.consumed();

				m_questions.emplace_back(std::move(q));
			}

			for (int i = 0; i < m_header.answer_num + m_header.auth_num + m_header.addon_num; ++i) {
				rr r(message, offset, size);
				offset += r.consumed();

				m_rrs.emplace_back(std::move(r));
			}
		}

		bool match(const boost::regex &question_repl) const {
			// we are too late - this is already a response
			if (m_header.flags & QUERY_FLAGS_RESPONSE)
				return false;

			for (auto & q : m_questions) {
				if (regex_match(q.name(), question_repl)) {
					return true;
				}
			}

			return false;
		}

		std::string pack(const std::map<u16, std::string> &rrs, u32 ttl) const {
			std::ostringstream ss;

			struct query_header header = m_header;

			header.answer_num = rrs.size() * m_questions.size();
			header.auth_num = 0;
			header.addon_num = 0;

			query_header_convert(&header);

			ss.write((char *)&header, sizeof(struct query_header));

			for (auto & q : m_questions) {
				ss << q.pack();
			}

			for (auto & q : m_questions) {
				for (auto & r : rrs) {
					rr obj(q.name(), r.first, q.qclass(), ttl, r.second);
					ss << obj.pack();
				}
			}

			std::cout << "query: packed data to be injected" << std::endl;
			return ss.str();
		}

	private:
		struct query_header m_header;
		std::vector<question> m_questions;
		std::vector<rr> m_rrs;

		void query_header_convert(struct query_header *h) const {
			h->id = ntohs(h->id);
			h->flags = ntohs(h->flags);
			h->question_num = ntohs(h->question_num);
			h->answer_num = ntohs(h->answer_num);
			h->auth_num = ntohs(h->auth_num);
			h->addon_num = ntohs(h->addon_num);
		}

		void query_parse_header(struct query_header *h) const {
			u16 opcode, rcode;

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

#define CHECK_INVAL(x) do { \
	if ((x) > 100) \
		throw std::runtime_error(#x); \
	} while (0);
			CHECK_INVAL(h->question_num);
			CHECK_INVAL(h->answer_num);
			CHECK_INVAL(h->auth_num);
			CHECK_INVAL(h->addon_num);
		}
};
