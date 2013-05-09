#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "pcap.h"
#include "mypcap.h"

#include <netinet/if_ether.h>      /* ethhdr struct */ 
#include <net/if.h>                /* ifreq struct */ 
#include <netinet/in.h>             /* in_addr structure */ 
#include <netinet/ip.h>             /* iphdr struct */ 
#include <netinet/udp.h>            /* udphdr struct */ 
#include <netinet/tcp.h>            /*tcphdr struct*/
#include <string.h>									/*string*/
#include <time.h>

#define OTHER 0
#define ARP   1
#define TCP   2
#define UDP   3

void saveResult(FILE * logFile, struct pcap_pkthdr *header, const u_char *pkt_data) {
	struct ethhdr * myethhdr = (struct ethhdr *)pkt_data;
	struct iphdr * myiphdr = NULL;
	struct tcphdr * mytcphdr = NULL;
	struct udphdr * myudphdr = NULL;
	int type = 0;
	unsigned int ipSize = 0;
	unsigned long sIp = 0;
	unsigned long dIp = 0;
	unsigned short sPort = 0;
	unsigned short dPort = 0;
	
	time_t local_tv_sec;
	struct tm *ltime;
	char timestr[16];
	
	switch (ntohs(myethhdr->h_proto))
	{
		case 0x0800:
			myiphdr = (struct iphdr *)(pkt_data + 14);
			ipSize = myiphdr->ihl * 4;
			sIp = myiphdr->saddr;
			dIp = myiphdr->daddr;
			switch (myiphdr->protocol)
			{
				case 6:
					type = TCP;
					mytcphdr = (struct tcphdr *)(pkt_data + 14 + ipSize);
					sPort = mytcphdr->source;
					dPort = mytcphdr->dest;
					break;
				case 17:
					type = UDP;
					myudphdr = (struct udphdr *)(pkt_data + 14 + ipSize);
					sPort = myudphdr->source;
					dPort = myudphdr->dest;
					break;			
			}
			local_tv_sec = header->ts.tv_sec;
			ltime=localtime(&local_tv_sec);
			strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
			fprintf(logFile, "%s\t%d\t%X\t%X\t%d\t%d\t%d \n",timestr,type,sIp,dIp,sPort,dPort,header->len);	
			break;
		case 0x0806:
			type= ARP;
			break;
		default:
			type = OTHER;
	}
}

int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i=0, j=0;
	pcap_t *adhandle;
	int res;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header;
	const u_char *pkt_data;

	struct ethhdr * myethhdr;
	struct iphdr * myiphdr;
	
	time_t timer;//time_t就是long int 类型  
	struct tm *tblock;  
	char date[10];

	FILE * logFile;
	
	
	memset(date, 0, 10);
	timer = time(NULL);//这一句也可以改成time(&timer);  
	tblock = localtime(&timer);  
	sprintf(date,"%d_%d",tblock->tm_mon+1, tblock->tm_mday);  
	printf("%s\n", date);

		
	if( (logFile=fopen(date, "w"))==NULL ) {
		printf("Open file error(log/log.txt)\n");
		exit(-1);	
	}
	
	/* Retrieve the device list */
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		return -1;
	}
    
    /* Print the list */
    for(d=alldevs; d; d=d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }
	
    if(i==0)
    {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return -1;
    }
    
    printf("Enter the interface number (1-%d):",i);
    scanf("%d", &inum);
    
    if(inum < 1 || inum > i)
    {
        printf("\nInterface number out of range.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }
	
    /* Jump to the selected adapter */
    for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
    
	/* Open the adapter */
	if ((adhandle= pcap_open_live(d->name,	// name of the device
							 65536,			// portion of the packet to capture. 
											// 65536 grants that the whole packet will be captured on all the MACs.
							 0,				// 1 promiscuous mode (nonzero means promiscuous)
							 1000,			// read timeout
							 errbuf			// error buffer
							 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
    
    printf("\nlistening on %s...\n", d->description);
	
    /* At this point, we don't need any more the device list. Free it */
    pcap_freealldevs(alldevs);
	
	/* Retrieve the packets */
	while((res = pcap_next_ex( adhandle, &header, &pkt_data)) >= 0 && j++ < 1000){
		//if(j%10 == 0)
		//	printf("number:%d\n", j);
		if(res == 0)
			/* Timeout elapsed */
			continue;
		saveResult(logFile, header, pkt_data);
	}
	
	if(res == -1){
		printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
		return -1;
	}
	printf("Caught packet success\n");
	pcap_close(adhandle);  
	fclose(logFile);
	return 0;
}
