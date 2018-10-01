#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>

#define TRUE 1
#define _GNU_SOURCE

void signalCatcher(int signum);
void sendRequests();
void displayResults(int len, char *buffer, struct timeval *currentTime);
void getTripTime(struct timeval *time_1, struct timeval *time_2);
unsigned short in_cksum(unsigned short *addr, int len);

struct sockaddr_in target, receiver;
int sock_fd, packetsSent = 0, packetsReceived = 0;
double tmin = 999999999.0, tmax = 0, tsum = 0;
char *host;

int main(int argc, char **argv){

	struct itimerval timer;
	struct sigaction act;
	struct hostent *address;
	char recvbuffer[1024];
	struct timeval finaltime;
	int n;

	if(argc != 2){
		fprintf(stderr, "Usage: %s <hostname>\n", argv[0]);
		exit(-1);
	}
	else
		host = argv[1];
	/* Create raw socket */
	if((sock_fd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0){
		fprintf(stderr, "[+] Error creating socket...quitting\n");
		exit(1);
	}
	/* Raw socket created: the program needs root privileges for this */
	/* The set-user-id bit will be set, now that it's done remove privileges */
	setuid(getuid());
	if((address = gethostbyname(argv[1])) == NULL){
		fprintf(stderr, "[+] Error: unknown host\n");
		exit(2);
	}
	/* Set signal handler to handle SIGALRM signals */
	memset(&act, 0, sizeof(act));
	act.sa_handler = &signalCatcher;
	sigaction(SIGALRM, &act, NULL);
	/* But also SIGINT signals to stop the program in a certain way when CRTL+C is pressed */
	sigaction(SIGINT, &act, NULL);
	/* Set timer to send SIGALRM every second */
	timer.it_interval.tv_sec = 1;	/* Alarm will run every second */
	timer.it_interval.tv_usec = 0;	/* the microsecond field is therefore set to zero */
	/* Alarm will start from 1 microsecond after the setitimer() function will be called */
	timer.it_value.tv_sec = 0;
	timer.it_value.tv_usec = 1;
	setitimer(ITIMER_REAL, &timer, NULL);

	/* Set the target host */
	memset(&target, 0, sizeof(target));
	target.sin_family = AF_INET;
	target.sin_addr = *((struct in_addr *)address->h_addr);/* Address in network byte order */
	/* ICMP echo requests and responses are managed by the IP subsystem so there is no need to specify any port number */
	memset(recvbuffer, 0, sizeof(recvbuffer));
	/* Make an endless loop to receive packets*/
	int recvsize = sizeof(receiver);
	printf("PING %s 56(84) bytes of data.\n", argv[1]);
	fflush(stdout);
	while(TRUE){
		if((n = recvfrom(sock_fd, recvbuffer, sizeof(recvbuffer), 0, (struct sockaddr *)&receiver, &recvsize)) < 0){
			/* Check if the error doesn't come from an interrupt */
			if(errno = EINTR)
				continue;
			else{
				fprintf(stderr, "[+] Error receiving the packets\n");
				exit(4);
			}
		}
		gettimeofday(&finaltime, NULL);
		displayResults(n, recvbuffer, &finaltime);
	}
	return 0;
}

void signalCatcher(int signum){

	if(signum == SIGALRM){
		sendRequests();
		return;
	}
	else if(signum == SIGINT){
		/* Print final statistics */
		printf("\n--- %s ping statistics ---\n", host);
		printf("%d packets transmitted, %d received, %d%% packet loss\n", packetsSent, packetsReceived, 
			((packetsSent - packetsReceived) / packetsSent) * 100);
		printf("rtt min/avg/max = %.03f/%.03f/%.03f ms\n", tmin, tsum / packetsReceived, tmax);
		fflush(stdout);
		exit(0);
	}
}

void sendRequests(){

	struct icmp *icmpPacket;

	/* Allocate space for the ICMP Packet */
	icmpPacket = (struct icmp *)malloc(128);
	/* Populate the packet fields */
	icmpPacket->icmp_type = ICMP_ECHO; /* It's an echo request */
	icmpPacket->icmp_code = 0; /* LOOK UP */
	icmpPacket->icmp_id = getpid(); /* Use the process id for the icmp id */
	icmpPacket->icmp_seq = packetsSent++; /* Set the sequence number of the packet */
	/* The data field is set to the current time of day in order to calculate the trip time */
	gettimeofday((struct timeval*)icmpPacket->icmp_data, NULL);
	icmpPacket->icmp_cksum = 0; /* This field needs to be set to zero before the checksum is calculated */
	icmpPacket->icmp_cksum = in_cksum((unsigned short*)icmpPacket, 64); /* Calculate the checksum with the standard function */

	/* Send packets */
	if(sendto(sock_fd, (char *)icmpPacket, 64, 0, (struct sockaddr *)&target, sizeof(target)) < 0){
		fprintf(stderr, "[+] Error sending packets...quitting\n");
		printf("%s\n", strerror(errno));
		exit(3);
	}
	free(icmpPacket);
}

void displayResults(int len, char *buffer, struct timeval *currentTime){

	struct ip *ipPacket;
	struct icmp *icmpPacket; 
	int ipLen;
	double rtt;

	/* Check if the packet is not corrupted */
	ipPacket = (struct ip *)buffer;
	ipLen = ipPacket->ip_hl << 2; /* There is a char in the structure: the first four bytes represent the lenght, 
	the other four the version; shifting two bytes is sufficient to get the correct lenght */
	icmpPacket = (struct icmp *)(buffer + ipLen);
	if((len - ipLen) < 8)
		fprintf(stderr, "[+] Error icmp packet lenght not correct: packet corrupted\n");
	/* Check if the packet is an echo reply and belongs to this process */
	if(icmpPacket->icmp_type == ICMP_ECHOREPLY){
		if(icmpPacket->icmp_id == getpid()){
			/* Calculate the round trip time in milliseconds */
			getTripTime(currentTime, (struct timeval *)icmpPacket->icmp_data);
			rtt = currentTime->tv_sec * 1000 + (float)currentTime->tv_usec / 1000;
			/* Increase the total number of packets received, update the sum of the trip time to
			 calculate the average and also min and max */
			tsum += rtt;
			if(rtt < tmin)
				tmin = rtt;
			if(rtt > tmax)
				tmax = rtt;
			packetsReceived++;
			printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.03f ms\n", 
				len, host, icmpPacket->icmp_seq, ipPacket->ip_ttl, rtt);
			fflush(stdout);
		}
	}
}

void getTripTime(struct timeval *time_1, struct timeval *time_2){

	time_1->tv_sec -= time_2->tv_sec;
	/* The microseconds field can be less in time_1 (ex. 4.1 seconds - 3.3 seconds) */
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
