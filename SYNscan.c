#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <arpa/inet.h>

#define TRUE 1

void scan(int sock_fd, unsigned short port, struct hostent *hostname);
int recv_response(int sock_fd);
unsigned short in_cksum(unsigned short *addr, int len);

struct pseudo_header{
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char place_holder;
	unsigned char protocol;
	unsigned short length;
};

char *device;

int main(int argc, char *argv[]){

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

	if(argc == 3){
		for(int i = 1; i < 65536; i++){
			scan(sock_fd, (unsigned short)i, hostname);
			if(recv_response(sock_fd) == 1){
				if((service = getservbyport(htons((unsigned short)i), "tcp")) != NULL)
					printf("Open: %d/tcp (%s)\n", i, service->s_name);
				else
					printf("Open: %d/tcp (unknown)\n", i);
				fflush(stdout);
			}
		}
	}
	else{
		for(int j = 3; j < argc; j++){
			scan(sock_fd, (unsigned short)atoi(argv[j]), hostname);
			if(recv_response(sock_fd) == 1){
				if((service = getservbyport(htons(j), "tcp")) == NULL)
					printf("Open: %d/tcp (%s)\n", j, service->s_name);
				else
					printf("Open: %d/tcp (unknown)\n", j);
			}
			fflush(stdout);
		}
	}

	return 0;
}

void scan(int sock_fd, unsigned short port, struct hostent *hostname){

	struct tcphdr tcp;
	struct pseudo_header pshdr;
	struct ifreq *ifr;
	char buffer[1024];
	struct sockaddr_in source, target;
	char checksum[sizeof(struct pseudo_header) + sizeof(struct tcphdr)];

	memset(&target, 0, sizeof(target));
	target.sin_family = AF_INET;
	target.sin_addr = *((struct in_addr *)hostname->h_addr);
	target.sin_port = htons(port);

	ifr = (struct ifreq *)buffer;
	sprintf(ifr->ifr_name, "%s", device) ,
	ioctl(sock_fd, SIOCGIFADDR, ifr);
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
	tcp.syn = 1;
	tcp.fin = 0;
	tcp.res2 = 0;
	tcp.window = htons(5840); /* Maximum allowed window size */
	tcp.check = 0;
	tcp.urg_ptr = 0;

	memcpy(checksum, (char *)&pshdr, sizeof(struct pseudo_header));
	memcpy(checksum + sizeof(struct pseudo_header), (char *)&tcp, sizeof(struct tcphdr));
	tcp.check = in_cksum((unsigned short *)checksum, sizeof(struct pseudo_header) + sizeof(struct tcphdr));

	if(sendto(sock_fd, &tcp, sizeof(struct tcphdr), 0, (struct sockaddr *)&target, sizeof(target)) == -1){
		fprintf(stderr, "%s\n", strerror(errno));
		exit(4);
	}
}

int recv_response(int sock_fd){

	char recvbuf[1500] = {0};
	struct tcphdr *tcphdr;
	fd_set set;
	struct timeval wait;

	wait.tv_sec = 0;
	wait.tv_usec = 10000;

	FD_ZERO(&set);
	FD_SET(sock_fd, &set);

	tcphdr = (struct tcphdr *)(recvbuf + sizeof(struct iphdr));

	while(TRUE){
		if(select(sock_fd + 1, &set, NULL, NULL, &wait) > 0){
			recv(sock_fd, recvbuf, sizeof(recvbuf), 0);
			if(tcphdr->dest == getpid()){
				if(tcphdr->syn == 1 && tcphdr->ack == 1)
					return 1;
				else
					return 0;
			}
		}
		else
			return 0;
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
