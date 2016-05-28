#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <libnet.h>
#include <iostream>

int main()
{
    char *dev, errbuf[PCAP_ERRBUF_SIZE];

    dev = pcap_lookupdev(errbuf);

    if (dev == NULL){
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }

    pcap_t *handle;
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL){
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }

    while(1){
        const u_char *p;
        struct pcap_pkthdr *h;
        struct libnet_ethernet_hdr *eth_header;
        int res = pcap_next_ex(handle, &h, &p);
        unsigned int ptype = ntohs(eth_header->ether_type);

        eth_header = (struct libnet_ethernet_hdr*)p;

        if(res == -1) break;
        if(res == 1){
            if(ptype == ETHERTYPE_IP){
                struct libnet_ipv4_hdr *ip_header = (struct libnet_ipv4_hdr*)(p + sizeof(struct libnet_ethernet_hdr));

                if(ip_header->ip_p == IPPROTO_TCP){
                    struct libnet_tcp_hdr *tcp_header = (struct libnet_tcp_hdr*)(ip_header + 1);
                    int tcp_hdr_len = tcp_header->th_off * sizeof(uint32_t);
                    int tcp_data_len = ntohs(ip_header->ip_len) - ip_header->ip_hl * 4 - tcp_hdr_len;
                    u_int8_t* tcp_data = (u_int8_t*)(tcp_header) + tcp_hdr_len;

                    if(tcp_data_len > 0 && (tcp_data[0] == 0x47 &&
                                            tcp_data[1] == 0x45 &&
                                            tcp_data[2] == 0x54 &&
                                            tcp_data[3] == 0x20)){

                        u_char fw_rst_buf[sizeof(libnet_ethernet_hdr) + sizeof(libnet_ipv4_hdr) + sizeof(libnet_tcp_hdr)] =  {0,};
                        libnet_ethernet_hdr* fw_rst_eth = (libnet_ethernet_hdr*)fw_rst_buf;
                        libnet_ipv4_hdr* fw_rst_ip = (libnet_ipv4_hdr*)(fw_rst_buf + sizeof(libnet_ethernet_hdr));
                        libnet_tcp_hdr* fw_rst_tcp = (libnet_tcp_hdr*)(fw_rst_ip + 1);

                        memcpy(fw_rst_eth, eth_header, sizeof(libnet_ethernet_hdr));

                        memcpy(fw_rst_ip, ip_header, sizeof(libnet_ipv4_hdr));
                        fw_rst_ip->ip_tos = 0x77;
                        fw_rst_ip->ip_len = htons(sizeof(libnet_ipv4_hdr) + sizeof(libnet_tcp_hdr));
                        fw_rst_ip->ip_ttl = 255;

                        memcpy(fw_rst_tcp, tcp_header, sizeof(libnet_tcp_hdr));
                        fw_rst_tcp->th_flags = TH_RST;
                        fw_rst_tcp->th_win = 0;

                        if(pcap_sendpacket(handle, (u_char*)fw_rst_buf, sizeof(libnet_ethernet_hdr) + sizeof(libnet_ipv4_hdr) + sizeof(libnet_tcp_hdr)) != 0)
                            std::cout<<"RST packet error\n";

                        else std::cout<<"Send RST packet\n";
                    }

                    //else std::cout<<"No tcp data"<<std::endl;
                }

                //else std::cout<<"No tcp protocol\n";
            }

            //else std::cout<<"No ip protocol\n";
        }
    }

    return(0);
}
