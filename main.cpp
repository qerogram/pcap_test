#include <pcap.h>
#include <stdio.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void print_mac(const u_char* mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip(const u_char* ip) {
        printf("%d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
}

void print_port(const u_char* port) {
        printf("%d\n", (port[0] << 8) | port[1]);
}


int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    if(packet[12] == 8 && packet[13] == 0) { // Exist IP Header.
        printf("======================\n");
        printf("%u bytes captured\n", header->caplen);
        printf("[*] dMac : "); print_mac(&packet[0]);
        printf("[*] sMac : "); print_mac(&packet[6]);
        int IPHEADER_OFFSET = 14;
        int IPHEADER_SIZE = (packet[IPHEADER_OFFSET + 2] << 16) | packet[IPHEADER_OFFSET + 3];
        printf("[*] IP Header Size : %d\n", IPHEADER_SIZE);
        printf("[*] DIP : "); print_ip(&packet[IPHEADER_OFFSET + 12]);
        printf("[*] SIP : "); print_ip(&packet[IPHEADER_OFFSET + 16]);

        if(packet[IPHEADER_OFFSET + 9] == 6) {
            int TCPHEADER_OFFSET = IPHEADER_OFFSET + 20;
            printf("[*] DPORT : "); print_port(&packet[TCPHEADER_OFFSET]);
            printf("[*] SPORT : "); print_port(&packet[TCPHEADER_OFFSET + 2]);
            int TCP_Hlen = (packet[TCPHEADER_OFFSET+12] >> 4) * 4;
            if(TCP_Hlen+TCPHEADER_OFFSET < header->caplen) {
                printf("[*] DATA STREAM : ");
                for(int i = 0; i < 10 && TCP_Hlen+TCPHEADER_OFFSET+i < header->caplen; ++i) {
                    printf("%02x ", packet[TCP_Hlen+TCPHEADER_OFFSET+i]);
                }
                printf("\n======================\n");
            }
            printf("full size = %d\n", IPHEADER_OFFSET + IPHEADER_SIZE);
            //if(TCPHEADER_OFFSET + TCP_Hlen > )


        }
	}
  }

  pcap_close(handle);
  return 0;
}
