#include "common.h"

int main()
{
    char buffer[PACKET_LEN];
    memset(buffer, 0, PACKET_LEN);

    ipheader *ip = (ipheader *)buffer;
    udpheader *udp = (udpheader *)(buffer + sizeof(ipheader));

    // add data
    char *data = (char *)udp + sizeof(udpheader);
    int data_len = strlen(CLIENT_IP);
    strncpy(data, CLIENT_IP, data_len);

    // copied from lecture 21 slides
    // create udp header
    udp->udp_sport = htons(CLIENT_PORT);   //set up source & destination ports
    udp->udp_dport = htons(SERVER_PORT);
    udp->udp_ulen = htons(sizeof(udpheader) + data_len);    //length of udp packet
    udp->udp_sum = 0; 

    // create ip header
    ip->iph_ver = 4;  //ip v4
    ip->iph_ihl = 5;  //header length
    ip->iph_ttl = 20;   //time to live
    ip->iph_sourceip.s_addr = inet_addr(SPOOF_IP);      //source ip (spoofed)
    ip->iph_destip.s_addr = inet_addr(SERVER_IP);           //destination ip
    ip->iph_protocol = IPPROTO_UDP;                             //protocol = udp
    ip->iph_len = htons(sizeof(ipheader) + sizeof(udpheader) + data_len);   //length of ip packet

    // send packet
    send_raw_ip_packet(ip);

    return 0;
}