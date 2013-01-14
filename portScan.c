#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <pthread.h>
#include <math.h>
#include <sys/time.h>
#include <netinet/in.h>
#include<errno.h>
#include <netdb.h>
#include<netinet/ether.h>
#include<netinet/ip.h>
#include<netinet/tcp.h>
#include<netinet/udp.h>
#include<netinet/ip_icmp.h>
#include<time.h>
#include<malloc.h>
#include<arpa/inet.h>

int flag1=0,synFlag=0, finFlag=0, ackFlag=0, nullFlag=0, xmasFlag=0,tcpFlag=0,udpFlag=0;
			
struct pseudohdr
{
	struct tcphdr tcp;
	struct in_addr srcIp;
	struct in_addr dstIp;
	unsigned char padd;
	unsigned char protoNo;
	unsigned short length;
};

struct portip 
{
	char *ipaddr;
	int pstart;
	int pend;	
};

unsigned short checksum(unsigned short *addr,int length)
{
	register int add = 0;
	u_short ans = 0;
	register u_short *w = addr;
	register int nleft = length;

	while (nleft > 1)
	{
		add += *w++;
		nleft -= 2;
	}

	if (nleft == 1)
	{
		*(u_char *)(&ans) = *(u_char *)w ;
		add += ans;
	}

	add = (add >> 16) + (add &0xffff);
	add += (add >> 16);
	ans = ~add;
	return(ans);
}

int recvTimeout(int filedes, char *buf, int len, int timeout) // reference - beej
{
    fd_set fds;
    int n;
    struct timeval tv; 

    // set up the file descriptor set
    FD_ZERO(&fds);
    FD_SET(filedes, &fds);

    // set up the struct timeval for the timeout
    tv.tv_sec = timeout;
    tv.tv_usec = 0;

    // wait until timeout or data received
    n = select(filedes+1, &fds, NULL, NULL, &tv);
    if (n == 0) return -2; // timeout!
    if (n == -1) return -1; // error

	
    // data must be here, so do a normal recv()
    return recv(filedes, buf, len, 0);
}

char *stripNewline(char *str, int size)	// remove new line character 	
{
    int i;   
    for (  i = 0; i < size; ++i )
    {
        if ( str[i] == '\n' )
        {
            str[i] = '\0';           
            return str;   
        }
    }  
    return str;    
}

void findService(char *IP,int port_no)
{
	char port[10];
	snprintf(port, 10,"%d",port_no);
		
	struct addrinfo hints, *res;
	char *p,buf[256],serviceName[20],*temp="a",msg[512] = "GET ";
	char *service[10] = {"SSH","HTTP","SMTP","POP","IMAP","WHOIS","FTP"};
	struct servent *appl_name;	
	int test, byte_count, iArgs,iIndex=0,i,k,stream_socket,dgram_socket,flag=0,connectID,n,arrIPsIndex=0;	
	fd_set fds;	 
	int state;
    	struct timeval tv; 
	int errValue;	
	char *strServ;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC; // AF_INET or AF_INET6 to force version									
						
	if(flag1==1)	// for tcp or no protocol specified	
	{
	
		hints.ai_socktype = SOCK_STREAM;
		if ((test = getaddrinfo(IP,port,&hints, &res)) != 0) 
		{					
			//printf("%s\t%s\n",PortVal,gai_strerror(test));
			//return 2;
		}		
		stream_socket = socket(res->ai_family, res->ai_socktype, res->ai_protocol);	//create socket compatible with tcp ports
			
		tv.tv_sec = 10;		// 10 second timeout
		tv.tv_usec = 0;
		state = setsockopt(stream_socket,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));
		state = setsockopt(stream_socket,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));

		connectID = connect(stream_socket, res->ai_addr, res->ai_addrlen);	//establish connection

		if(connectID != -1)	// port is open
		{							
			//byte_count = recv(stream_socket, serviceName, sizeof serviceName, 0);				
			if(strcmp(port,"43") == 0)//WHOIS
			{
				strcpy(msg,"WHOIS -h com.whois-servers.net ");
				strcat(msg,IP);
				send(stream_socket,msg,strlen(msg)+1,MSG_OOB);
				n = recvTimeout(stream_socket, buf, sizeof buf, 10);
			}
			if(strcmp(port,"80") == 0) //HTTP
			{
				strcat(msg,IP);
				strcat(msg," HTTP/1.1\n\n");									
				send(stream_socket,msg,strlen(msg)+1,MSG_OOB);
				n = recvTimeout(stream_socket, buf, sizeof buf, 10); // 10 second timeout
				
			}
			if(strcmp(port,"143") == 0)	//IMAP
			{
				strcpy(msg,"fetch 1");
				send(stream_socket,msg,strlen(msg)+1,MSG_OOB);
				n = recvTimeout(stream_socket, buf, sizeof buf, 10);
			}
			else	//other services
			{
				/*n = getnameinfo(res->ai_addr,sizeof res->ai_addr,fileName,sizeof fileName,serviceName,sizeof serviceName,0);
				printf("**Service %s %s %d\t",serviceName,gai_strerror(n),n);*/
				//appl_name = getservbyport(htons(22),"tcp");
				//printf("-serv %s\t",(char *)appl_name->s_name);
				n = recvTimeout(stream_socket, buf, sizeof buf, 10);
			}					

			if (n == -1) 
			{
				// error occurred						
				//printf("\n");
			}
			else if (n == -2) 
			{
				// timeout occurred
				//printf("\n");
			} 
			else 
			{
				// got some data in buf	
				buf[n] = '\0';
				if(strcmp(port,"80")==0)
				{
					flag = 1;
					strServ = (char *)malloc(10);
					strxfrm(strServ,buf,9);
					printf("%s\t%s\tOpen\t%s\tTCP\n",stripNewline(IP,strlen(IP)),port,strServ);					
				}
				else if(strcmp(port,"22")==0)
				{
					flag = 1;
					strServ = (char *)malloc(10);
					strServ = strstr(buf,"Open");
					strServ = stripNewline(strServ,strlen(strServ));
					printf("%s\t%s\tOpen\t%s\tTCP\n",stripNewline(IP,strlen(IP)),port,strServ);					
				}
				else
				{
					for(k=0;k<7;k++)
					{
				  		p = strstr(buf,service[k]);	// to get exact service name					 
				  		if(p)
				   		{
							flag = 1;
							printf("%s\t%s\tOpen\t%s\t\tTCP\n",stripNewline(IP,strlen(IP)),port,service[k]);						
							break;
				   		}
				   		k++;
					}
				}	
				if(flag == 0)
				{					
					printf("%s\t%s\tOpen\t%s\t\tTCP\n",stripNewline(IP,strlen(IP)),port,buf);
					//printf("%s\n",buf);
				}				
			}						
		}
		else
		{
			//printf("closed");
			printf("%s\t%s\tClosed\t\t\tTCP\n",stripNewline(IP,strlen(IP)),port);			
		}		
	}		
	
}	

void portScan (struct portip info)
{
	int port,nbytes,icmpnbytes;
	char hostname[1024],buf[4096],buf_icmp[4096];
	struct addrinfo hints, *servinfo, *p;
	char s[INET6_ADDRSTRLEN];
	char ipaddr[30];
	char finalip[100],fileName[20];
	int k,j,l,m;
	struct portip tpi;
	tpi=info;
		
	for (port=tpi.pstart; port<=tpi.pend; port++)	
	{
		
		//TCP SCAN

		if(tcpFlag==1)
		{
		
			char bbuf[10];
			snprintf(bbuf, 10, "%d", port);
			int h,z;	
			h=gethostname(hostname,100);
			struct hostent *hstent;
			struct in_addr **addr_list;
			hstent=gethostbyname(hostname);
			addr_list=(struct in_addr**)hstent->h_addr_list;
			for(z=0;addr_list[z]!=NULL;z++)
			{
				strcpy(finalip,inet_ntoa(*addr_list[z]));
				break;
				label:;
			}
			
			//SYN SCAN
			
			if(synFlag==1)
			{
				int sock_tcp = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
				int s_icmp = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP);
				char packet[4096];
				struct ip *iphdr = (struct ip *) packet;
				struct tcphdr *tcphddr = (struct tcphdr *) (packet + sizeof(struct ip));
				struct sockaddr_in sin;
				struct sockaddr_storage pin;

				sin.sin_family = AF_INET;
				sin.sin_port = htons (port);
				sin.sin_addr.s_addr = inet_addr(tpi.ipaddr);

				memset (packet, 0, 4096);
				iphdr->ip_hl = 5;
				iphdr->ip_v = 4;
				iphdr->ip_tos = 0;
				iphdr->ip_len = sizeof (struct ip) + sizeof (struct tcphdr);
				iphdr->ip_id = htonl (54321);
				iphdr->ip_off = 0;
				iphdr->ip_ttl = 255;
				iphdr->ip_p = 6;
				iphdr->ip_sum = 0;
				iphdr->ip_src.s_addr = inet_addr (finalip);
				iphdr->ip_dst.s_addr = sin.sin_addr.s_addr;

				tcphddr->source = htons (1234);
				tcphddr->dest = htons (port);
				tcphddr->seq = htonl(random ());
				tcphddr->ack_seq = 0;
				tcphddr->doff = 5;
				tcphddr->syn = 1;
				tcphddr->window = ntohs(65535);
				tcphddr->check = 0;
				tcphddr->urg_ptr = 0;

				struct pseudohdr pseudoheader;
				memset(&pseudoheader, 0, sizeof(struct pseudohdr));
				pseudoheader.srcIp.s_addr = iphdr->ip_src.s_addr;
				pseudoheader.dstIp.s_addr = iphdr->ip_dst.s_addr;
				pseudoheader.padd = 0;
				pseudoheader.protoNo = IPPROTO_TCP;
				pseudoheader.length = htons(sizeof(struct tcphdr));
				memcpy(&(pseudoheader.tcp), (unsigned short *)tcphddr, sizeof(struct tcphdr));

				tcphddr->check = checksum ((unsigned short *) &pseudoheader, sizeof(struct pseudohdr));
				iphdr->ip_sum = checksum ((unsigned short *) packet, sizeof(struct ip));

				int t=1;
				const int *val = &t;
			
				int t_icmp=1;
				const int *val_icmp = &t_icmp;
			
				if (setsockopt (sock_tcp, IPPROTO_IP, IP_HDRINCL, val, sizeof (t)) < 0){}
				//printf ("HDRINCL cannot be set.\n");
			
				if (setsockopt (s_icmp, IPPROTO_IP, IP_HDRINCL, val_icmp, sizeof (t_icmp)) < 0){}
				//printf ("HDRINCL for ICMP cannot be set.\n");

				int i;
				if (sendto(sock_tcp, packet,iphdr->ip_len,0,(struct sockaddr*)&sin, sizeof(sin))<0){}
				//printf("Error in sending packet\n");
			
				if (sendto(s_icmp, packet,iphdr->ip_len,0,(struct sockaddr*)&sin, sizeof(sin))<0){}
				//printf("Error in sending packet\n");
				else
				printf("Packet sent successfully\n");

				for (i=0;i<100;i++)
				{
					struct timeval tv;
					tv.tv_sec = 2;
					tv.tv_usec = 100000;

					setsockopt(sock_tcp, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
					setsockopt(sock_tcp, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

					setsockopt(s_icmp, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
					setsockopt(s_icmp, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));


					nbytes=0;
					memset(buf,0,4096);
					int fromlen = sizeof (pin);

					//fcntl(sock_tcp, F_SETFL, O_NONBLOCK);
					fcntl(s_icmp, F_SETFL, O_NONBLOCK);
		
					nbytes = recvfrom(sock_tcp, buf, 4096 , 0,(struct sockaddr *)&pin, &fromlen);	
						
					icmpnbytes = recvfrom(s_icmp,buf_icmp,4096, 0,(struct sockaddr *)&pin,&fromlen);
									
					
					struct ip *iphdr_icmp = (struct ip *)(buf_icmp);
						struct icmp *icmphdr = (struct icmp *)(buf_icmp + sizeof(struct ip));
					
					if(iphdr_icmp->ip_p==1)
					{	
						
						
						if(icmpnbytes>0)
						{
							printf("Got an ICMP packet\n");
							printf("ICMP type:\t%u\n",icmphdr->icmp_type);
							printf("ICMP code:\t%u\n",icmphdr->icmp_code);

							if((icmphdr->icmp_type == 3 && icmphdr->icmp_code ==1) || (icmphdr->icmp_type ==3 && icmphdr->icmp_code ==2) || (icmphdr->icmp_type == 3 && icmphdr->icmp_code ==3) || (icmphdr->icmp_type == 3 && icmphdr->icmp_code ==9) || (icmphdr->icmp_type == 3 && icmphdr->icmp_code ==10) || (icmphdr->icmp_type == 3 && icmphdr->icmp_code ==13))

							{
								printf("ICMP type:\t%u\n",icmphdr->icmp_type);
								printf("ICMP code:\t%u\n",icmphdr->icmp_code);
								printf("\n Port: %d is filtered\n", port);
							}
							else if(icmphdr->icmp_type == 3)
							printf("The Destination is unreachable\n");
						}
			
					}
					
					if(nbytes>0)
					{
						
						struct ip *iphrcvd = (struct ip *) buf;
						struct tcphdr *tcphrcvd = (struct tcphdr *) (buf + sizeof (struct ip));
						
						if((strcmp(inet_ntoa(iphrcvd->ip_src),inet_ntoa(iphdr->ip_dst))==0))
						{	
							if(ntohs(tcphrcvd->source)==port)
							{
								if ((tcphrcvd->syn==1) && (tcphrcvd->ack==1))
								{
									printf("SYN SCAN: port %d is open\n",port);
									tcphddr->syn = 0;
									tcphddr->rst = 1;
									sendto(sock_tcp, packet,iphdr->ip_len,0,(struct sockaddr*)&sin, sizeof(sin));
									break;
								}
						
								else if (tcphrcvd->rst==1)
								{
									printf("SYN SCAN: port %d is closed\n",port);
									break;
								}
							

							}
						}
					}

					if(i==99)
					{
						printf("SYN SCAN: port %d may be open/closed (filtered)\n",port);
					}
				
				}

			}

			//ACK SCAN

			if(ackFlag==1)
			{
				int sock_tcp = socket (AF_INET, SOCK_RAW, IPPROTO_TCP);
				//int s_icmp = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP);
				char packet[4096];
				struct ip *iphdr = (struct ip *) packet;
				struct tcphdr *tcphddr = (struct tcphdr *) (packet + sizeof(struct ip));
				struct sockaddr_in sin;
				struct sockaddr_storage pin;

				sin.sin_family = AF_INET;
				sin.sin_port = htons (port);
				sin.sin_addr.s_addr = inet_addr (tpi.ipaddr);

				memset (packet, 0, 4096);
				iphdr->ip_hl = 5;
				iphdr->ip_v = 4;
				iphdr->ip_tos = 0;
				iphdr->ip_len = sizeof (struct ip) + sizeof (struct tcphdr);
				iphdr->ip_id = htonl (54321);
				iphdr->ip_off = 0;
				iphdr->ip_ttl = 255;
				iphdr->ip_p = 6;
				iphdr->ip_sum = 0;
				iphdr->ip_src.s_addr = inet_addr (finalip);
				iphdr->ip_dst.s_addr = sin.sin_addr.s_addr;

				tcphddr->source = htons (1235);
				tcphddr->dest = htons (port);
				tcphddr->seq = htonl(random ());
				tcphddr->ack_seq = 0;
				tcphddr->doff = 5;
				tcphddr->ack = 1;

				tcphddr->window = ntohs(65535);
				tcphddr->check = 0;
				tcphddr->urg_ptr = 0;

				struct pseudohdr pseudoheader;
				memset(&pseudoheader, 0, sizeof(struct pseudohdr));
				pseudoheader.srcIp.s_addr = iphdr->ip_src.s_addr;
				pseudoheader.dstIp.s_addr = iphdr->ip_dst.s_addr;
				pseudoheader.padd = 0;
				pseudoheader.protoNo = IPPROTO_TCP;
				pseudoheader.length = htons(sizeof(struct tcphdr));
				memcpy(&(pseudoheader.tcp), (unsigned short *)tcphddr, sizeof(struct tcphdr));

				tcphddr->check = checksum ((unsigned short *) &pseudoheader, sizeof(struct pseudohdr));
				iphdr->ip_sum = checksum ((unsigned short *) packet, sizeof(struct ip));

				int t=1;
				const int *val = &t;
				int t_icmp=1;
				const int *val_icmp = &t_icmp;
			
				if (setsockopt (sock_tcp, IPPROTO_IP, IP_HDRINCL, val, sizeof (t)) < 0){}
				//printf ("HDRINCL cannot be set.\n");

				//if (setsockopt (s_icmp, IPPROTO_IP, IP_HDRINCL, val_icmp, sizeof (t_icmp)) < 0)
				//printf ("HDRINCL for ICMP cannot be set.\n");

				int i;

				if (sendto(sock_tcp, packet,iphdr->ip_len,0,(struct sockaddr*)&sin, sizeof(sin))<0){}
				//printf("Error in sending packet\n");
			
				//if (sendto(s_icmp, packet,iphdr->ip_len,0,(struct sockaddr*)&sin, sizeof(sin))<0)
				//printf("Error in sending packet using ICMP socket\n");

				//else
				//printf("Packet sent successfully\n");

				for (i=0;i<100;i++)
				{
					struct timeval tv;
					tv.tv_sec = 2;
					tv.tv_usec = 100000;

					setsockopt(sock_tcp, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
					setsockopt(sock_tcp, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

					nbytes=0;
					memset(buf,0,4096);
					int fromlen = sizeof (pin);

					nbytes = recvfrom(sock_tcp, buf, 4096 , 0,(struct sockaddr *)&pin, &fromlen);
					//numbytes_icmp = recvfrom(s_icmp,buf_icmp,4096, 0,(struct sockaddr *)&pin,&fromlen);
				
				/*	if(numbytes_icmp>0)
					{
					
						struct ip *iphdr_icmp = (struct ip *)buf_icmp;
						struct icmp *icmphdr = (struct icmp *)(buf_icmp + sizeof(struct ip));
						if(iphdr_icmp->ip_p == 1)
						{
							printf("Got an ICMP packet:\n");
							printf("ICMP type:\t%u\n",icmphdr->icmp_type);
							printf("ICMP code:\t%u\n",icmphdr->icmp_code);
						}
				
					}*/
				
				
					if(nbytes>0)
					{
						struct ip *iphrcvd = (struct ip *) buf;
						struct tcphdr *tcphrcvd = (struct tcphdr *) (buf + sizeof (struct ip));

						if((strcmp(inet_ntoa(iphrcvd->ip_src),inet_ntoa(iphdr->ip_dst))==0))
						{
							if(ntohs(tcphrcvd->source)==port)
							{

								if(tcphrcvd->rst==1)
								{
									printf("ACK SCAN: port %d is unfiltered\n",port);
									break;
								}
							}
						}
					}
					if(i==99)
					{
						printf("ACK SCAN: port %d is filtered\n",port);
					}
				}
			}	

			//FIN SCAN
			
			if(finFlag==1)
			{
				int sock_tcp = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
				char packet[4096];
				struct ip *iphdr = (struct ip *) packet;
				struct tcphdr *tcphddr = (struct tcphdr *) (packet + sizeof(struct ip));
				struct sockaddr_in sin;
				struct sockaddr_storage pin;

				sin.sin_family = AF_INET;
				sin.sin_port = htons (port);
				sin.sin_addr.s_addr = inet_addr (tpi.ipaddr);

				memset (packet, 0, 4096);
				iphdr->ip_hl = 5;
				iphdr->ip_v = 4;
				iphdr->ip_tos = 0;
				iphdr->ip_len = sizeof (struct ip) + sizeof (struct tcphdr);
				iphdr->ip_id = htonl (54321);
				iphdr->ip_off = 0;
				iphdr->ip_ttl = 255;
				iphdr->ip_p = 6;
				iphdr->ip_sum = 0;
				iphdr->ip_src.s_addr = inet_addr (finalip);
				iphdr->ip_dst.s_addr = sin.sin_addr.s_addr;

				tcphddr->source = htons (1236);
				tcphddr->dest = htons (port);
				tcphddr->seq = htonl(random ());
				tcphddr->ack_seq = 0;
				tcphddr->doff = 5;
				tcphddr->fin=1;

				tcphddr->window = ntohs(65535);
				tcphddr->check = 0;
				tcphddr->urg_ptr = 0;

				struct pseudohdr pseudoheader ;
				memset(&pseudoheader, 0, sizeof(struct pseudohdr));
				pseudoheader.srcIp.s_addr = iphdr->ip_src.s_addr;
				pseudoheader.dstIp.s_addr = iphdr->ip_dst.s_addr;
				pseudoheader.padd = 0;
				pseudoheader.protoNo = IPPROTO_TCP;
				pseudoheader.length = htons(sizeof(struct tcphdr));
				memcpy(&(pseudoheader.tcp), (unsigned short *)tcphddr, sizeof(struct tcphdr));

				tcphddr->check = checksum ((unsigned short *) &pseudoheader, sizeof(struct pseudohdr));
				iphdr->ip_sum = checksum ((unsigned short *) packet, sizeof(struct ip));

				int t=1;
				const int *val = &t;
				if (setsockopt (sock_tcp, IPPROTO_IP, IP_HDRINCL, val, sizeof (t)) < 0){}
				//printf ("HDRINCL cannot be set.\n");

				int i;

				if (sendto(sock_tcp, packet,iphdr->ip_len,0,(struct sockaddr*)&sin, sizeof(sin))<0){}
				//printf("Error in sending packet\n");

				for (i=0;i<100;i++)
				{

					struct timeval tv;
					tv.tv_sec = 2;
					tv.tv_usec = 100000;

					setsockopt(sock_tcp, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
					setsockopt(sock_tcp, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

					nbytes=0;
					memset(buf,0,4096);
					int fromlen = sizeof (pin);

					nbytes = recvfrom(sock_tcp, buf, 4096 , 0,(struct sockaddr *)&pin, &fromlen);
					if(nbytes>0)
					{
						struct ip *iphrcvd = (struct ip *) buf;
						struct tcphdr *tcphrcvd = (struct tcphdr *) (buf + sizeof (struct ip));

						if((strcmp(inet_ntoa(iphrcvd->ip_src),inet_ntoa(iphdr->ip_dst))==0))
						{
							if(ntohs(tcphrcvd->source)==port)
							{
								if(tcphrcvd->rst==1)
								{
									printf("FIN SCAN: port %d is closed\n",port);
									break;

								}
							}
						}
					}
					if(i==99)
					{
						printf("FIN SCAN: port %d is open or filtered\n",port);
					}
				}
			}

			//NULL SCAN
			
			if(nullFlag==1)
			{
				int sock_tcp = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
				char packet[4096];
				struct ip *iphdr = (struct ip *) packet;
				struct tcphdr *tcphddr = (struct tcphdr *) (packet + sizeof(struct ip));
				struct sockaddr_in sin;
				struct sockaddr_storage pin;

				sin.sin_family = AF_INET;
				sin.sin_port = htons (port);
				sin.sin_addr.s_addr = inet_addr (tpi.ipaddr);

				memset (packet, 0, 4096);
				iphdr->ip_hl = 5;
				iphdr->ip_v = 4;
				iphdr->ip_tos = 0;
				iphdr->ip_len = sizeof (struct ip) + sizeof (struct tcphdr);
				iphdr->ip_id = htonl (54321);
				iphdr->ip_off = 0;
				iphdr->ip_ttl = 255;
				iphdr->ip_p = 6;
				iphdr->ip_sum = 0;
				iphdr->ip_src.s_addr = inet_addr (finalip);
				iphdr->ip_dst.s_addr = sin.sin_addr.s_addr;

				tcphddr->source = htons (1237);
				tcphddr->dest = htons (port);
				tcphddr->seq = htonl(random ());
				tcphddr->ack_seq = 0;
				tcphddr->doff = 5;

				tcphddr->window = ntohs(65535);
				tcphddr->check = 0;
				tcphddr->urg_ptr = 0;

				struct pseudohdr pseudoheader ;
				memset(&pseudoheader, 0, sizeof(struct pseudohdr));
				pseudoheader.srcIp.s_addr = iphdr->ip_src.s_addr;
				pseudoheader.dstIp.s_addr = iphdr->ip_dst.s_addr;
				pseudoheader.padd = 0;
				pseudoheader.protoNo = IPPROTO_TCP;
				pseudoheader.length = htons(sizeof(struct tcphdr));
				memcpy(&(pseudoheader.tcp), (unsigned short *)tcphddr, sizeof(struct tcphdr));

				tcphddr->check = checksum ((unsigned short *) &pseudoheader, sizeof(struct pseudohdr));
				iphdr->ip_sum = checksum ((unsigned short *) packet, sizeof(struct ip));

				int t=1;
				const int *val = &t;
				if (setsockopt (sock_tcp, IPPROTO_IP, IP_HDRINCL, val, sizeof (t)) < 0){}
				//printf ("HDRINCL cannot be set.\n");

				int i;

				if (sendto(sock_tcp, packet,iphdr->ip_len,0,(struct sockaddr*)&sin, sizeof(sin))<0){}
				//printf("Error in sending packet\n");


				for (i=0;i<100;i++)
				{

					struct timeval tv;
					tv.tv_sec = 2;
					tv.tv_usec = 100000;

					setsockopt(sock_tcp, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
					setsockopt(sock_tcp, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

					nbytes=0;

					memset(buf,0,4096);
					int fromlen = sizeof (pin);

					nbytes = recvfrom(sock_tcp, buf, 4096 , 0,(struct sockaddr *)&pin, &fromlen);
					if(nbytes>0)
					{
						struct ip *iphrcvd = (struct ip *) buf;
						struct tcphdr *tcphrcvd = (struct tcphdr *) (buf + sizeof (struct ip));


						if((strcmp(inet_ntoa(iphrcvd->ip_src),inet_ntoa(iphdr->ip_dst))==0))
						{
							if(ntohs(tcphrcvd->source)==port)
							{
								if(tcphrcvd->rst==1)
								{
									//null_set=2;
									printf("NULL SCAN: port %d is closed\n",port);
									break;
								}
							}
						}
					}
					if(i==99)
					{
						//null_set=1;
						printf("NULL SCAN: port %d is open or filtered\n",port);
					}
				}
			}

			//XMAS SCAN		

			if(xmasFlag==1)
			{
				int sock_tcp = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);
				char packet[4096];
				struct ip *iphdr = (struct ip *) packet;
				struct tcphdr *tcphddr = (struct tcphdr *) (packet + sizeof(struct ip));
				struct sockaddr_in sin;
				struct sockaddr_storage pin;


				sin.sin_family = AF_INET;
				sin.sin_port = htons (port);
				sin.sin_addr.s_addr = inet_addr (tpi.ipaddr);

				memset (packet, 0, 4096);
				iphdr->ip_hl = 5;
				iphdr->ip_v = 4;
				iphdr->ip_tos = 0;
				iphdr->ip_len = sizeof (struct ip) + sizeof (struct tcphdr);
				iphdr->ip_id = htonl (54321);
				iphdr->ip_off = 0;
				iphdr->ip_ttl = 255;
				iphdr->ip_p = 6;
				iphdr->ip_sum = 0;
				iphdr->ip_src.s_addr = inet_addr (finalip);
				iphdr->ip_dst.s_addr = sin.sin_addr.s_addr;

				tcphddr->source = htons (1238);
				tcphddr->dest = htons (port);
				tcphddr->seq=htonl(0);
				tcphddr->ack_seq = 0;
				tcphddr->doff = 5;
				tcphddr->urg=1;
				tcphddr->psh=1;
				tcphddr->fin=1;

				tcphddr->window = ntohs(65535);
				tcphddr->check = 0;
				tcphddr->urg_ptr = 0;

				struct pseudohdr pseudoheader ;
				memset(&pseudoheader, 0, sizeof(struct pseudohdr));
				pseudoheader.srcIp.s_addr = iphdr->ip_src.s_addr;
				pseudoheader.dstIp.s_addr = iphdr->ip_dst.s_addr;
				pseudoheader.padd = 0;
				pseudoheader.protoNo = IPPROTO_TCP;
				pseudoheader.length = htons(sizeof(struct tcphdr));
				memcpy(&(pseudoheader.tcp), (unsigned short *)tcphddr, sizeof(struct tcphdr));

				tcphddr->check = checksum ((unsigned short *) &pseudoheader, sizeof(struct pseudohdr));
				iphdr->ip_sum = checksum ((unsigned short *) packet, sizeof(struct ip));

				int t=1;
				const int *val = &t;
				if (setsockopt (sock_tcp, IPPROTO_IP, IP_HDRINCL, val, sizeof (t)) < 0){}
				//printf ("HDRINCL cannot be set.\n");

				int i;

				if (sendto(sock_tcp, packet,iphdr->ip_len,0,(struct sockaddr*)&sin, sizeof(sin))<0){}
				//printf("Error in sending packet\n");

				for (i=0;i<100;i++)
				{

					struct timeval tv;
					tv.tv_sec = 2;
					tv.tv_usec = 100000;

					setsockopt(sock_tcp, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
					setsockopt(sock_tcp, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

					nbytes=0;

					memset(buf,0,4096);
					int fromlen = sizeof (pin);

					nbytes = recvfrom(sock_tcp, buf, 4096 , 0,(struct sockaddr *)&pin, &fromlen);
					if(nbytes>0)
					{
						struct ip *iphrcvd = (struct ip *) buf;
						struct tcphdr *tcphrcvd = (struct tcphdr *) (buf + sizeof (struct ip));

						if((strcmp(inet_ntoa(iphrcvd->ip_src),inet_ntoa(iphdr->ip_dst))==0))
						{
							if(ntohs(tcphrcvd->source)==port)
							{

								if(tcphrcvd->rst==1)
								{
									printf("XMAS SCAN: port %d is closed\n",port);
									break;
								}
							}
						}
					}
					if(i==99)
					{
						printf("XMAS SCAN: port %d is open or filtered\n",port);
					}
				}
			}

		}

		//findService(ipaddr,port);

		//UDP SCAN	
		
		if(udpFlag==1)
		{
		
			char buf[4096],buf_icmp4udp[4096],buf_udp[4096];
			char *data;
			
			struct addrinfo hints, hints1, *servinfo, *p;	
			struct sockaddr_in sin;
			
			struct ip *iphdr = (struct ip *) buf;
			struct udphdr *udp=(struct udphdr*)(buf+sizeof(struct ip));
			struct dnshdr *dns = (struct dnshdr*)(buf+sizeof(struct ip) + sizeof(struct udphdr));
			
			int sock_udp=socket(AF_INET,SOCK_RAW,IPPROTO_UDP);
			int sock_icmp4udp=socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
			
			if(sock_udp < 0)
			{
				//perror("socket() error");
			}
			
			if(sock_icmp4udp< 0)
			{
				//perror("socket() error for ICMP");
			}

			sin.sin_family = AF_INET;
			sin.sin_port = htons (port);
			sin.sin_addr.s_addr = inet_addr (tpi.ipaddr);

			memset (buf, 0, 4096);
			iphdr->ip_hl = 5;
			iphdr->ip_v = 4;
			iphdr->ip_tos = 0;
			iphdr->ip_len = sizeof (struct ip) + sizeof (struct udphdr);
			iphdr->ip_id = htonl (54321);
			iphdr->ip_off = 0;
			iphdr->ip_ttl = 255;
			iphdr->ip_p = 17;
			iphdr->ip_sum = 0;
			iphdr->ip_src.s_addr = inet_addr (finalip);
			iphdr->ip_dst.s_addr = sin.sin_addr.s_addr;

			udp->source=htons(1240);
			udp->dest=htons(port);
			
			data=(char*)buf+sizeof(struct iphdr)+sizeof(struct udphdr);
			strcpy(data,"p");

			udp->len=htons(sizeof(struct udphdr)+strlen(data));
			//udp->check=checksum((unsigned short*) udp,8+strlen(data));
			udp->check=0;
			iphdr->ip_sum = checksum ((unsigned short *) buf, sizeof(struct ip));

			int t=1;
			const int *val = &t;
			int t_icmp4udp=1;
			const int *val_icmp4udp = &t_icmp4udp;
			
			if (setsockopt (sock_udp, IPPROTO_IP, IP_HDRINCL, val, sizeof (t)) < 0){}
				//printf ("HDRINCL cannot be set.\n");
				
			if (setsockopt (sock_icmp4udp, IPPROTO_IP, IP_HDRINCL, val_icmp4udp, sizeof (t_icmp4udp)) < 0){}
				//printf ("HDRINCL for ICMP cannot be set.\n");	

			struct sockaddr_in f;
			bzero(&f,sizeof(f));
			f.sin_family=AF_INET;
			f.sin_port=htons(port);
			f.sin_addr.s_addr = inet_addr (tpi.ipaddr);
			//inet_pton(AF_INET,ipaddr,&d.sin_addr.s_addr);
			
			if(sendto(sock_udp,buf,sizeof(struct ip)+sizeof(struct udphdr)+strlen(data),0,(struct sockaddr*) &f,sizeof(f))<0)
			{
				//printf("Error in sending UDP socket");
			}

			if(sendto(sock_icmp4udp,buf,sizeof(struct ip)+sizeof(struct udphdr)+strlen(data),0,(struct sockaddr*) &f,sizeof(f))<0)	
			{
				printf("sendto() is OK.\n");
			}

			int numbytes_udp=0;
			int numbytes_icmp4udp=0;
			struct sockaddr_storage d;
			int flen=sizeof(d);

			fcntl(sock_udp, F_SETFL, O_NONBLOCK);
			fcntl(sock_icmp4udp, F_SETFL, O_NONBLOCK);
			
			numbytes_udp=recvfrom(sock_udp,buf_udp,4096 , 0,(struct sockaddr*)&d, &flen);
			if(numbytes_udp>0)
			{
				printf("Received %d bytes of udp data\n",numbytes_udp);
			}
			numbytes_icmp4udp=recvfrom(sock_icmp4udp,buf_icmp,4096,0,(struct sockaddr*)&d, &flen);
			
			struct ip *iphrcvd = (struct ip *) buf_udp;
			
			if((strcmp(inet_ntoa(iphrcvd->ip_src),inet_ntoa(iphdr->ip_dst))==0))
			{
				if(numbytes_udp==-1)
				{
					int count;
					int flag_temp=0;
					//printf("errno=\t%d\n",errno);
					for(count=0;count<3;count++)
					{
						//printf("Sending udp packet %d time after a lack of response\n",count+1);
						if(sendto(sock_udp,buf,sizeof(struct ip)+sizeof(struct udphdr)+strlen(data),0,(struct sockaddr*) &f,sizeof(f))<0)
						{
							//printf("Error in sending UDP socket");
						}
						numbytes_udp=recvfrom(sock_udp,buf_udp,4096,0,(struct sockaddr*)&d, &flen);
						if(numbytes_udp==-1)
						{
							//perror("");
							//printf("errno=\t%d\n",errno);
						}
						if(numbytes_udp>0)
						{
							printf("UDP port is open\n");
							printf("received bytes:%d",numbytes_udp);
							break;
						}
						flag_temp++;
					}
					
					if(flag_temp==3)
					{
						printf("UDP port %d is Open|Filtered\n\n",port);
					}	
					
				}
			}	
		
			if(numbytes_icmp4udp>0)
			{
				struct ip *iphdr_icmp = (struct ip *)(buf_icmp);
				struct icmp *icmphdr4udp = (struct icmp *)(buf_icmp + sizeof(struct ip));
				if(iphdr_icmp->ip_p==1)
				{
					if(icmphdr4udp->icmp_type==3 && icmphdr4udp->icmp_code==3)
					{ 
					
						printf(" In UDP\n");
						printf("port %d is closed\n",port);
					}	
					
					if(icmphdr4udp->icmp_type==3 && icmphdr4udp->icmp_code==1 || icmphdr4udp->icmp_type==3 && icmphdr4udp->icmp_code==2 || icmphdr4udp->icmp_type==3 && icmphdr4udp->icmp_code==9 || icmphdr4udp->icmp_type==3 && icmphdr4udp->icmp_code==10 || icmphdr4udp->icmp_type==3 && icmphdr4udp->icmp_code==13)
					{ 
					
						
						printf("port %d is filtered\n",port);
					}					
					
				}
			}	
			//printf("Received bytes: %d\n",numbytes_udp);
			close(sock_udp);
		}

	}	

}

int main(int argc, char *argv[])
{
	char ipaddr[50],trans_pro[5],fileName[30];	
	char *arrIP[50][50],port_start[30],port_end[30];
	int arrIndex=0;
	char *ptr1,*ptr2;
	int store_port[8192];
	int start_port,end_port,pstart,pend,no_threads;
	int ptr_trans,ptr_ps,ptr_pe,ptr_ipfile;
	int i=0,k,j,l,m,n=0;
	int opt1,opt2;
	int flag2=0,flag3=0,flag4=0;
	int ipCount;
	struct portip td;
	FILE *fileObj;
	
	if (argc < 2)
	{
		printf("Please input ip or prefix or file or --help\n");
		return 0;
	}

	for(k=0;k<argc;k++)
	{	

		if (strcmp("--help",argv[k]) == 0)
       	{
			 printf("\nOptions");
			 printf("\n--help <display invocation options>");
			 printf("\n--ports <ports to scan>");
			 printf("\n--ip <IP address to scan>");
			 printf("\n--prefix <IP prefix to scan>");
			 printf("\n--file <file name containing IP addresses to scan>");
			 printf("\n--transport <TCP or UDP>");
			 printf("\n--speedup <parallel threads to use>");
			 printf("\n--scan <One or more scans>\n");
			 return 0;
       	}
	
		if(strcmp("--ports",argv[k])==0)
		{
			ptr_ps=strcpy (port_start,argv[k+1]);
			start_port= atoi(port_start);
			flag1=1;
			ptr_pe=strcpy (port_end, argv[k+2]);
			end_port= atoi(port_end);
			flag2=1;
		}

		if (strcmp("--ip",argv[k])==0)
		{	
			opt1=1;
			strcpy (ipaddr,argv[k+1]);
		}
		
		if (strcmp("--file",argv[k]) == 0)	// read IPs from a file
		{		
			opt2 =1 ;
			char line [128];
			strcpy(fileName,argv[k+1]);	
			fileObj = fopen(fileName, "r" );
			if (fileObj==NULL)
			{
			perror("Error opening file");
			}
			
			while (!feof(fileObj) ) 
			{
			
				fscanf(fileObj,"%s",arrIP[arrIndex]);
				arrIndex++;
			}
			fclose(fileObj);			
				
		}
		
		if(strcmp("--transport",argv[k])==0)
		{	
			flag3=1;
			for(l=k;l<argc-1;l++)
			{
				ptr_trans=strcpy(trans_pro,argv[l+1]);
				if(strcmp("TCP",trans_pro)==0)
				{	
					tcpFlag=1;
				}
				if(strcmp("UDP",trans_pro)==0)
				{
					udpFlag=1;
				}
			
			}
		}
		
		if (strcmp("--speedup",argv[k])==0)
		{
			no_threads=atoi(argv[k+1]);
		}
		
		if(strcmp("--scan",argv[k])==0)
		{
			flag4=1;
			for(j=k;j<argc-1;j++)
			{
				if(strcmp("SYN", argv[j+1])==0)
				{
				synFlag=1;
				}
				else if(strcmp("FIN", argv[j+1])==0)
				{
				finFlag=1;
				}

				else if(strcmp("ACK", argv[j+1])==0)
				{ 
				ackFlag=1;
				}
				else if(strcmp("NULL", argv[j+1])==0)
				{
				nullFlag=1;
				}
				else if(strcmp("XMAS", argv[j+1])==0)
				{
				xmasFlag=1;
				}
				else if(strncmp("--", argv[j+1],2)==0)
				{
				break;
				}
							
			}
		}

	}	

		if(flag4==0)
		{
			synFlag=1;
			ackFlag=1;
			finFlag=1;
			nullFlag=1;
			xmasFlag=1;
		}
		
		if(flag3==0)
		{
			tcpFlag=1;
			udpFlag=1;
		}		
		
		if(flag1==0 && flag2==0)
		{
			start_port=1;
			end_port=1024;
		}
	
	for(i=start_port;i<=end_port;i++)
	{
		store_port[j]=i;
		j++;
	}
		
		if(opt2==1)
		{	
			printf("Scanning ports for a number of IP addresses\n");
			for(ipCount=0;ipCount<arrIndex;ipCount++)
			{
				td.ipaddr=arrIP[ipCount];
				td.pstart=start_port;
				td.pend=end_port;
				printf("scanning ports for ip %s\n",arrIP[ipCount]);
				portScan(td);
			}
		}
		else if(opt1==1)
		{
			td.ipaddr=ipaddr;
			td.pstart=start_port;
			td.pend=end_port;
			portScan(td);
		}
		
		printf("ip:%s\t startport:%d \t endport:%d\n",td.ipaddr,td.pstart,td.pend);				
		


}	
