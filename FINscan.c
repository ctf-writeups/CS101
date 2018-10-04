#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <net/if.h>

#define TRUE 1
#define OP_FI 1
#define CLOSE 0

void scan(int fd, unsigned short port, struct hostent *name);
int recv_response(int fd);
unsigned short in_cksum(unsigned short *addr, int len);

struct pseudo_header{
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char place_holder;
	unsigned char protocol;
	unsigned short length;
};

char *device;

int main(int argc, char **argv){

	int sock_fd;
	struct hostent *hostname;
	struct servent *service;

	if(argc < 3){
		fprintf(stderr, "Usage: %s <interface> <target address>\n", argv[0]);
		fprintf(stderr, "Optional arguments can also be specified:\n");
		fprintf(stderr, "to specify a port number just write it as third parameter\n");
		fprintf(stderr, "to specify a list of port numbers do as follows:\n");
		fprintf(stderr, "%s <interface> <target address> 20 21 22 23\n", argv[0]);
		exit(1);
	}

	device = argv[1];

	if((sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1){
		fprintf(stderr, "%s\n", strerror(errno));
		exit(2);
	}
	setuid(getuid());

	if((hostname = gethostbyname(argv[2])) == NULL){
		fprintf(stderr, "%s\n", strerror(errno));
		exit(3);
	}

	int ret;

	if(argc == 3){
		for(int i = 1; i < 65536; i++){
			scan(sock_fd, (unsigned short)i, hostname);
			if((ret = recv_response(sock_fd)) == OP_FI){
				if((service = getservbyport(htons(i), "tcp")) != NULL)
					printf("Open | Filtered: %d/tcp (%s)\n", i, service->s_name);
				else
					printf("Open | Filtered: %d/tcp (unknown)\n", i);
			}
			fflush(stdout);
		}
	}
	else{
		for(int j = 3; j < argc; j++){
			scan(sock_fd, (unsigned short)atoi(argv[j]), hostname);
			if((ret = recv_response(sock_fd)) == OP_FI){
				if((service = getservbyport(htons(atoi(argv[j])), "tcp")) != NULL)
					printf("Open | Filtered: %s/tcp (%s)\n", argv[j], service->s_name);
				else
					printf("Open | Filtered: %s/tcp (unknown)\n", argv[j]);
			}
			fflush(stdout);
		}
	}

	return 0;
}

void scan(int fd, unsigned short port, struct hostent *name){

	struct sockaddr_in target, source;
	struct tcphdr tcp;
	struct pseudo_header pshdr;
	struct ifreq *ifr;
	char buffer[1024];
	char pseudo_packet[sizeof(struct pseudo_header) + sizeof(struct tcphdr)];

	memset(&target, 0, sizeof(target));
	target.sin_family = AF_INET;
	target.sin_port = htons(port);
	target.sin_addr = *((struct in_addr *)name->h_addr);

	ifr = (struct ifreq *)buffer;
	sprintf(ifr->ifr_name, "%s", device);
	ioctl(fd, SIOCGIFADDR, ifr);
	memcpy((char*)&source, (char*)&(ifr->ifr_addr), sizeof(struct sockaddr));

	pshdr.source_address = source.sin_addr.s_addr;
	pshdr.dest_address = target.sin_addr.s_addr;
	pshdr.place_holder = 0;
	pshdr.protocol = IPPROTO_TCP;
	pshdr.length = htons(sizeof(struct tcphdr));

	tcp.source = getpid();
	tcp.dest = htons(port);
	tcp.seq = 0;
	tcp.ack_seq = 0;
	tcp.res1 = 0;
	tcp.doff = 5;
	tcp.urg = 0;
	tcp.ack = 0;
	tcp.psh = 0;
	tcp.rst = 0;
	tcp.syn = 0;
	tcp.fin = 1;
	tcp.res2 = 0;
	tcp.window = htons(5840); 
	tcp.check = 0;
	tcp.urg_ptr = 0;

	memcpy(pseudo_packet, (char *)&pshdr, sizeof(struct pseudo_header));
	memcpy(pseudo_packet + sizeof(struct pseudo_header), (char *)&tcp, sizeof(struct tcphdr));
	tcp.check = in_cksum((unsigned short *)pseudo_packet, sizeof(struct pseudo_header) + sizeof(struct tcphdr));

	if(sendto(fd, &tcp, sizeof(struct tcphdr), 0, (struct sockaddr *)&target, sizeof(target)) == -1){
		fprintf(stderr, "%s\n", strerror(errno));
		exit(4);
	}
}

int recv_response(int fd){

	char recvbuf[1500] = {0};
	struct tcphdr *tcp;
	fd_set set;
	struct timeval wait;

	wait.tv_sec = 0;
	wait.tv_usec = 10000;

	FD_ZERO(&set);
	FD_SET(fd, &set);

	tcp = (struct tcphdr *)(recvbuf + sizeof(struct iphdr));

	while(TRUE){
		if(select(fd + 1, &set, NULL, NULL, &wait) > 0){ 
			recv(fd, recvbuf, sizeof(recvbuf), 0);
			if(tcp->dest == getpid()){
				if(tcp->rst == 1)
					return CLOSE;
			}
		}
		else
			return OP_FI;
	}
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
