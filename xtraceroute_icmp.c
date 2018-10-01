#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX_TTL 30
#define FALSE 0
#define TRUE 1

int recv_packet();
unsigned short in_cksum(unsigned short *addr, int len);
void tv_sub(struct timeval *time_1, struct timeval *time_2);

int icmp_fd, packetsSent = 0, seq = 0;
struct sockaddr_in target, recvInfo, test;
struct timeval currentTime;
char recvbuffer[1024];

int main(int argc, char *argv[]){

	struct hostent *host, *name;
	struct icmp *icmp;
	int ttl, flag = FALSE, probe, len, ret, n;
	char sendbuffer[1024];

	if(argc != 2){
		fprintf(stderr, "Usage: %s <hostname>\n", argv[0]);
		exit(1);
	}

	if((icmp_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1){
		fprintf(stderr, "%s\n", strerror(errno));
		exit(2);
	}
	setuid(getuid());

	if((host = gethostbyname(argv[1])) == NULL){
		fprintf(stderr, "%s\n", strerror(errno));
		exit(3);	
	}

	memset(&target, 0, sizeof(target));
	target.sin_family = AF_INET;
	target.sin_addr = *((struct in_addr *)host->h_addr);
	len = sizeof(recvInfo);	

	printf("traceroute to %s (%s), 30 hops max, 60 byte packets\n", argv[1], inet_ntoa(target.sin_addr));
	for(ttl = 1; ttl <= MAX_TTL && flag == FALSE; ttl++){
		printf("%d ", ttl);
		setsockopt(icmp_fd, SOL_IP, IP_TTL, &ttl, sizeof(int));
		for(probe = 0; probe < 3; probe++){
			icmp = (struct icmp *)sendbuffer;
			icmp->icmp_type = ICMP_ECHO;
			icmp->icmp_code = 0;
			icmp->icmp_id = getpid();
			icmp->icmp_seq = seq++;
			gettimeofday((struct timeval *)icmp->icmp_data, NULL);
			icmp->icmp_cksum = 0;
			icmp->icmp_cksum = in_cksum((unsigned short *)icmp, 64);

			if(sendto(icmp_fd, (char *)icmp, 64, 0, (struct sockaddr *)&target, sizeof(target)) == -1){
				fprintf(stderr, "%s\n", strerror(errno));
				exit(4);
			}

			/* Receive packets */
			if((ret = recv_packet()) != -3){
				tv_sub(&currentTime, (struct timeval *)icmp->icmp_data);
				if(memcmp(&recvInfo.sin_addr, &test.sin_addr, sizeof(recvInfo.sin_addr)) != 0){
					if((name = gethostbyaddr(&recvInfo.sin_addr.s_addr, sizeof(recvInfo.sin_addr.s_addr), recvInfo.sin_family)) != NULL)
						printf("%s (%s) ", name->h_name, inet_ntoa(recvInfo.sin_addr));
					else
						printf("%s (%s) ", inet_ntoa(recvInfo.sin_addr), inet_ntoa(recvInfo.sin_addr));

					test.sin_addr = recvInfo.sin_addr;
				}
				printf(" %.3f ms ", currentTime.tv_sec * 1000 + (float)currentTime.tv_usec / 1000);

				if(ret == -2)
					flag = TRUE;
			}
			else
				printf(" * ");

			fflush(stdout);
		}
		printf("\n");
	}

	return 0;
}

int recv_packet(){

	struct timeval timer;
	struct ip *ip;
	struct icmp *icmp;
	fd_set set;
	int len = sizeof(recvInfo), n;

	FD_ZERO(&set);
	FD_SET(icmp_fd, &set);

	timer.tv_sec = 4;
	timer.tv_usec = 0;

	if(select(icmp_fd + 1, &set, NULL, NULL, &timer)){
		if(recvfrom(icmp_fd, recvbuffer, sizeof(recvbuffer), 0, (struct sockaddr *)&recvInfo, &len)){
			gettimeofday(&currentTime, NULL);
			ip = (struct ip *)recvbuffer;
			icmp = (struct icmp *)(recvbuffer + (ip->ip_hl << 2));

			if(icmp->icmp_type == ICMP_TIMXCEED && icmp->icmp_code == ICMP_TIMXCEED_INTRANS)
				return -1;
			else if(icmp->icmp_type == ICMP_ECHOREPLY)
				return -2;
		}
	}
	else if(!FD_ISSET(icmp_fd, &set))
		return -3;
	else{
		fprintf(stderr, "%s\n", strerror(errno));
		exit(5);
	}
}

void tv_sub(struct timeval *time_1, struct timeval *time_2){

	time_1->tv_sec -= time_2->tv_sec;
	if((time_1->tv_usec -= time_2->tv_usec) < 0){
		time_1->tv_sec--;
		time_1->tv_usec += 1000000;
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