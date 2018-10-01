#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#define SIZE 1024
#define MAX_TTL 30
#define FALSE 0
#define TRUE 1

int recv_packet(int dPort);
void tv_sub(struct timeval *time_1, struct timeval *time_2);

struct outdata {
	int outdata_seq;
	int outdata_ttl;
	struct timeval outdata_tv;
};

int icmp_fd, udp_fd, srcPort, dstPort = 33434;
struct sockaddr_in target, bindInfo, recvInfo, test;
struct timeval rttCalculator;

int main(int argc, char *argv[]){

	struct hostent *hp;
	struct outdata *data;
	struct hostent *name;
	char sendbuf[SIZE];
	int ttl, host = 0, nprobes = 3, probes, seq = 1, ret;

	if(argc != 2){
		fprintf(stderr, "Usage: %s <hostname>\n", argv[1]);
		exit(1);
	}

	/* Create two sockets: one to send UDP packets and the other to receive ICMP packets */
	if((icmp_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1){
		fprintf(stderr, "%s\n", strerror(errno));
		exit(2);
	}
	/* First restore privileges */
	setuid(getuid());
	/* Now the other socket */
	if((udp_fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1){
		fprintf(stderr, "%s\n", strerror(errno));
		exit(3);
	}
	if((hp = gethostbyname(argv[1])) == NULL){
		fprintf(stderr, "%s\n", strerror(errno));
		exit(4);
	}

	srcPort = (getpid() & 0xffff) | 0x8000;
	/* Fill the needed data structures for communication */
	memset(&target, 0, sizeof(target)); /* First we need a structure to indicate the target */
	target.sin_family = AF_INET;
	target.sin_addr = *(struct in_addr *)hp->h_addr; /* The port number will be added later */

	memset(&bindInfo, 0, sizeof(bindInfo)); /* Then a structure to bind the UDP socket to a specific port */
	bindInfo.sin_family = AF_INET;
	bindInfo.sin_port = htons(srcPort);

	//fflush(stdout);

	/* Bind the socket to the source port */
	if(bind(udp_fd, (struct sockaddr *)&bindInfo, sizeof(bindInfo)) == -1){
		fprintf(stderr, "%s\n", strerror(errno));
		exit(5);
	}
	printf("traceroute to %s (%s), 30 hops max, 60 byte packets\n", argv[1], inet_ntoa(target.sin_addr));
	/* Start sending probes: every time increase the TTL field with the setsockopt function */
	for(ttl = 1; ttl <= MAX_TTL && host == FALSE; ttl++){
		printf("%d ", ttl);
		setsockopt(udp_fd, SOL_IP, IP_TTL, &ttl, sizeof(ttl));
		/* To increase the chances of hitting a closed port on the final host send three probes per ttl */
		for(probes = 0; probes < nprobes; probes++){
			data = (struct outdata *)sendbuf;
			data->outdata_seq = seq++;
			data->outdata_ttl = ttl;
			gettimeofday(&data->outdata_tv, NULL);
			/* Add the port number */
			target.sin_port = htons(dstPort + seq);

			if(sendto(udp_fd, sendbuf, sizeof(sendbuf), 0, (struct sockaddr *)&target, sizeof(target)) == -1){
				fprintf(stderr, "%s\n", strerror(errno));
				exit(6);
			}

			/* Implement a function to receive packets back */
			if((ret = recv_packet(dstPort + seq)) != -3){
				tv_sub(&rttCalculator, &data->outdata_tv);
				if(memcmp(&recvInfo.sin_addr, &test.sin_addr, sizeof(recvInfo.sin_addr)) != 0){
					if((name = gethostbyaddr(&recvInfo.sin_addr.s_addr, sizeof(recvInfo.sin_addr.s_addr), recvInfo.sin_family)) != NULL)
						printf("%s (%s) ", name->h_name, inet_ntoa(recvInfo.sin_addr));
					else
						printf("%s (%s) ", inet_ntoa(recvInfo.sin_addr), inet_ntoa(recvInfo.sin_addr));
					
					test.sin_addr = recvInfo.sin_addr;
				}
				printf(" %.3f ms ", rttCalculator.tv_sec * 1000 + (float)rttCalculator.tv_usec / 1000);

				if(ret == -2)
					host = TRUE;
			}
			else
				printf(" * ");

			fflush(stdout);
		}
		printf("\n");
	}

	return 0;
}

int recv_packet(int dPort){

	char recvbuffer[SIZE];
	struct timeval count;
	fd_set set;
	struct ip *ip_header_1, *ip_header_2;
	struct icmp *icmp_header;
	struct udphdr *udp;
	int len1, len2;

	count.tv_sec = 4;
	count.tv_usec = 0;

	FD_ZERO(&set);
	FD_SET(icmp_fd, &set);

	int recvsize = sizeof(recvInfo);

	/* Receive packet, wait up to 4 seconds */
	if(select(icmp_fd + 1, &set, NULL, NULL, &count) > 0){
		recvfrom(icmp_fd, recvbuffer, sizeof(recvbuffer), 0, (struct sockaddr *)&recvInfo, &recvsize);
		/* 1- time exceeded packet
		   2- host unreachable packet */
		gettimeofday(&rttCalculator, NULL);
		ip_header_1 = (struct ip *)recvbuffer;
		len1 = ip_header_1->ip_hl << 2;
		icmp_header = (struct icmp *)(recvbuffer + len1);
		ip_header_2 = (struct ip *)(recvbuffer + len1 + 8);
		len2 = ip_header_2->ip_hl << 2;
		udp = (struct udphdr *)(recvbuffer + len1 + 8 + len2);
		/* Check for the time exceeded packet */
		if(icmp_header->icmp_type == ICMP_TIMXCEED && icmp_header->icmp_code == ICMP_TIMXCEED_INTRANS){
			/* Check if the packet is formatted correctly */
			if(ip_header_2->ip_p == IPPROTO_UDP && udp->source == htons(srcPort) && udp->dest == htons(dPort))
				return -1;
		}
		else if(icmp_header->icmp_type == ICMP_UNREACH && icmp_header->icmp_code == ICMP_UNREACH_PORT){
			if(ip_header_2->ip_p == IPPROTO_UDP && udp->source == htons(srcPort) && udp->dest == htons(dPort))
				return -2;
		}
	}
	else if(!FD_ISSET(icmp_fd, &set))
		return -3;
	else{
		fprintf(stderr, "%s\n", strerror(errno));
		exit(7);
	}
}

void tv_sub(struct timeval *time_1, struct timeval *time_2){

	time_1->tv_sec -= time_2->tv_sec;
	if((time_1->tv_usec -= time_2->tv_usec) < 0){
		time_1->tv_sec--;
		time_1->tv_usec += 1000000;
	}
}