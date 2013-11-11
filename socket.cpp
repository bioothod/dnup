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

class rsocket {
	public:
		rsocket(int port, int proto) {
			int m_sock = socket(AF_INET, SOCK_RAW, proto);
			if (m_sock < 0) {
				std::ostringstream ss;

				ss << "socket: error construction: " << strerror(errno) << ": " << -errno;
				throw std::runtime_error(ss.str());
			}

			struct sockaddr_in sin;
			memset(&sin, 0, sizeof(struct sockaddr_in));

			sin.sin_port = htons(port);
			sin.sin_family = AF_INET;

			int err = bind(m_sock, (struct sockaddr *)&sin, sizeof(struct sockaddr_in));
			if (err < 0) {
				close(m_sock);

				std::ostringstream ss;

				ss << "socket: error binding: " << strerror(errno) << ": " << -errno;
				throw std::runtime_error(ss.str());
			}

			err = 1;
			setsockopt(m_sock, 0, IP_HDRINCL, &err, sizeof(err));
		}

		void send() {
			char packetBuf[1024];
			struct sockaddr_in sin;

			memset(&sin, 0, sizeof(struct sockaddr_in));
			sin.sin_family = AF_INET;
			sin.sin_port = htons(55000);
			sin.sin_addr.s_addr = inet_addr("127.0.0.1");	//IP to send packet to
			
			unsigned short buffer_size = sizeof(struct ip) + sizeof(struct tcphdr);//+ sizeof(data);
			std::cout << "Buffer size: " << buffer_size << std::endl;
			
			struct ip *IPheader = (struct ip *) packetBuf;
			struct tcphdr *TCPheader = (struct tcphdr *) (packetBuf + sizeof (struct ip));
			
			//Fill out IP Header information:
			IPheader->ip_hl = 5;
			IPheader->ip_v = 4;		//IPv4
			IPheader->ip_tos = 0;		//type of service
			IPheader->ip_len = htons(buffer_size);	//length
			IPheader->ip_id = htonl(54321);
			IPheader->ip_off = 0;
			IPheader->ip_ttl = 255;	//max routers to pass through
			IPheader->ip_p = 6;		//tcp
			IPheader->ip_sum = 0;	//Set to 0 before calulating later
			IPheader->ip_src.s_addr = inet_addr("123.4.5.6");	//source IP address
			IPheader->ip_dst.s_addr = inet_addr("127.0.0.1");	//destination IP address
			
			//Fill out TCP Header information:
			TCPheader->source = htons(55000);	//source port
			TCPheader->dest = htons(55000);			//destination port
			TCPheader->seq = random();
			TCPheader->ack = 0;	//Only 0 on initial SYN 
			TCPheader->doff = 0;
			TCPheader->syn = 1;	//SYN flag set
			TCPheader->window = htonl(65535);	//used for segmentation
			TCPheader->check = 0;				//Kernel fill this out
			TCPheader->urg_ptr = 0;
			
			//Now fill out the checksum for the IPheader
			IPheader->ip_sum = csum((unsigned short *) packetBuf, IPheader->ip_len >> 1);
			std::cout << "IP Checksum: " << IPheader->ip_sum << std::endl;
			//create raw socket for sending ip packet
			size_t sendErr = sendto(m_sock, packetBuf, sizeof(packetBuf), 0, (struct sockaddr *)&sin, sizeof(sin));
			if (sendErr < sizeof(packetBuf))
			{
				std::cout << sendErr << " out of " << sizeof(packetBuf) << " were sent.\n";
				exit(1);
			}else{
				std::cout << "<" << sendErr << "> Sent message!!!		:-D\n";
			}
			
		}

	private:
		int m_sock;

		unsigned short csum(unsigned short *buf,int nwords) {
			//this function returns the checksum of a buffer
			unsigned long sum;
			for (sum = 0; nwords > 0; nwords--){sum += *buf++;}
			sum = (sum >> 16) + (sum & 0xffff);
			sum += (sum >> 16);
			return (unsigned short) (~sum);
		}
};


