#include <sys/types.h>
#include <sys/socket.h>

#include <netdb.h>
#include <string.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <iostream>
#include <cstdlib>

namespace ioremap { namespace dpoison {

class socket {
	public:
		socket() {
			m_sock = ::socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
			if (m_sock < 0) {
				std::ostringstream ss;

				ss << "socket: error construction: " << strerror(errno) << ": " << -errno;
				throw std::runtime_error(ss.str());
			}
		}

		~socket() {
			close(m_sock);
		}

		void send(const struct ether_header *orig_eth, const struct ip *orig_ip, const struct udphdr *orig_udp, const std::string &data) {
			struct sockaddr_in sin;

			std::ostringstream ss;

			memset(&sin, 0, sizeof(struct sockaddr_in));
			sin.sin_family = AF_INET;
			sin.sin_port = orig_udp->source;
			sin.sin_addr = orig_ip->ip_src;

			struct ether_header eth;

			memcpy(eth.ether_shost, orig_eth->ether_dhost, ETH_ALEN);
			memcpy(eth.ether_dhost, orig_eth->ether_dhost, ETH_ALEN);
			eth.ether_type = orig_eth->ether_type;

			//ss.write((char *)&eth, sizeof(struct ether_header));

			struct iphdr ip;

			ip.ihl = 5;
			ip.version = 4;
			ip.tos = 0;
			ip.tot_len = htons(data.size() + sizeof(struct udphdr) + sizeof(struct ip));
			ip.id = 0xbb;
			ip.frag_off = 0;
			ip.ttl = 0xb;
			ip.protocol = IPPROTO_UDP;
			ip.check = 0;
			ip.saddr = orig_ip->ip_dst.s_addr;
			ip.daddr = orig_ip->ip_src.s_addr;

			ip.check = in_cksum((u16 *)&ip, ip.ihl*4, 0);

			ss.write((char *)&ip, sizeof(struct iphdr));

			struct udphdr udp;

			udp.source = orig_udp->dest;
			udp.dest = orig_udp->source;
			udp.len = htons(data.size() + sizeof(struct udphdr));
			udp.check = 0;

			std::ostringstream tmp;
			tmp.write((char *)&udp, sizeof(struct udphdr));
			tmp << data;

			udp.check = udp_cksum(ip.daddr, ip.saddr, (const udphdr *)tmp.str().c_str(), sizeof(struct udphdr) + data.size());

			ss.write((char *)&udp, sizeof(struct udphdr));
			ss << data;

			ssize_t err = ::sendto(m_sock, ss.str().c_str(), ss.str().size(), 0, (struct sockaddr *)&sin, sizeof(sin));
			if (err != (ssize_t)ss.str().size()) {
				std::ostringstream ess;

				ess << "socket: failed to send data: size: " << ss.str().size() << ", err: " << err << ", errno: " << strerror(errno) << " [" << -errno << "]";
				throw std::runtime_error(ess.str());
			}
		}

	private:
		int m_sock;

		u16 in_cksum(const u16 *addr, register unsigned int len, int csum) {
			int nleft = len;
			const u16 *w = addr;
			u16 answer;
			int sum = csum;

			/*
			 *  Our algorithm is simple, using a 32 bit accumulator (sum),
			 *  we add sequential 16 bit words to it, and at the end, fold
			 *  back all the carry bits from the top 16 bits into the lower
			 *  16 bits.
			 */
			while (nleft > 1)  {
				sum += *w++;
				nleft -= 2;
			}
			if (nleft == 1)
				sum += htons(*(unsigned char *)w<<8);

			/*
			 * add back carry outs from top 16 bits to low 16 bits
			 */
			sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
			sum += (sum >> 16);			/* add carry */
			answer = ~sum;				/* truncate to 16 bits */
			return (answer);
		}


		int udp_cksum(u32 daddr, u32 saddr, const struct udphdr *udp, unsigned int len) {
			union phu {
				struct phdr {
					u32 src;
					u32 dst;
					u8 mbz;
					u8 proto;
					u16 len;
				} ph;
				u16 pa[6];
			} phu;
			register const u16 *sp;

			/* pseudo-header.. */
			phu.ph.len = htons((u16)len);
			phu.ph.mbz = 0;
			phu.ph.proto = IPPROTO_UDP;
			phu.ph.src = saddr;
			phu.ph.dst = daddr;

			sp = &phu.pa[0];
			return in_cksum((u16 *)udp, len, sp[0]+sp[1]+sp[2]+sp[3]+sp[4]+sp[5]);
		}
};

}} // namespace ioremap::dpoison
