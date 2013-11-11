#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif

#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <iostream>
#include <cstdlib>

#include <pcap.h>

#include <boost/program_options.hpp>

#include "dns.hpp"

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

			std::cout << "device: " << m_dev << std::endl;

			int promisc = 1;
			int ms = 1000;

			m_session = pcap_open_live(m_dev.c_str(), max_size, promisc, ms, errbuf);
			if (!m_session) {
				std::ostringstream ss;

				ss << "pcap: failed to open live stream on '" << m_dev << "': " << errbuf;
				throw std::runtime_error(ss.str());
			}

			std::cerr << "datalink: " << pcap_datalink(m_session) << std::endl;
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

struct basic_process {
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

		std::cout << header->ts << ": " << dump_eth(eth) << " : " << dump_addr(ip, udp) << std::endl;
		dns d;

		u_char *data = (u_char *)(((u_char *)udp) + 8);
		d.parse(data, ntohs(udp->len));
	}
};

int main(int argc, char *argv[])
{
	namespace bpo = boost::program_options;

	bpo::options_description generic("Parser options");

	std::string device;
	int max_size;
	generic.add_options()
		("help", "This help message")
		("size", bpo::value<int>(&max_size)->default_value(1000), "Maximum capture size for single packet")
		("device", bpo::value<std::string>(&device), "Sniffing device")
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

	basic_process process;

	pcap p(device, max_size);
	p.run(filter.str(), std::bind(&basic_process::got_packet, &process, std::placeholders::_1, std::placeholders::_2));

	return 0;	
}
