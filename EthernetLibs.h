#include<iostream>
#include<crafter.h>
#include<string>
using namespace std;
using namespace Crafter;
int NextSeqNumber(TCP* tcp_layer){
    long seq_num = tcp_layer->GetSeqNumber();
    int len = tcp_layer->GetPayloadSize();
    return seq_num+len;
}
/*take to pointer of to packets and compere the ip and the mac adresses to check if there is connection betwen them*/
bool sameaddr(Packet* packet1, Packet* packet2){
    bool ip_verfiy= false;
    bool mac_verfiy = false;
    IP* ip_layer_packet1 = packet1->GetLayer<IP>();
    IP* ip_layer_packet2 = packet2->GetLayer<IP>();
    Ethernet* Ether_layer_packet1 = packet1->GetLayer<Ethernet>();
    Ethernet* Ether_layer_packet2 = packet2->GetLayer<Ethernet>();
    string IP_dst_packet1= ip_layer_packet1->GetDestinationIP();
    string IP_dst_packet2 = ip_layer_packet2->GetDestinationIP();
    string Destination_ip_packet1 = ip_layer_packet1->GetSourceIP();
    string Destination_ip_packet2 = ip_layer_packet2->GetSourceIP();
    string MAC_src_packet1 = Ether_layer_packet1->GetSourceMAC();
    string MAC_src_packet2 = Ether_layer_packet2->GetSourceMAC();
    string MAC_dst_packet1 = Ether_layer_packet1->GetDestinationMAC();
    string MAC_dst_packet2 = Ether_layer_packet2->GetDestinationMAC();
    if(IP_dst_packet1 == Destination_ip_packet2 && IP_dst_packet2 == Destination_ip_packet1){
        ip_verfiy = true;
    }
    if (MAC_src_packet1 == MAC_dst_packet2 && MAC_src_packet2 == MAC_dst_packet1){
        mac_verfiy = true;
    }
    if (mac_verfiy && ip_verfiy){
        return true;
    }
    return false;


}

bool verfiySYN_ACK(Packet* packet1, Packet* packet2){
    if (sameaddr(packet1, packet2)){
        /*start checking */
    }
    

}
void tcp_flags(Packet* sniff_packet){
	TCP* tcp_layer = sniff_packet->GetLayer<TCP>();
	cout<<"tcp ack number: "<< tcp_layer->GetAckNumber()<<endl;
	cout<<"packet flags: "<< tcp_layer->GetFlags()<< endl;
	cout<< "tcp FIN Flag:"<< tcp_layer->GetFIN()<<endl;
	cout<<"tcp CWR Flag:"<< tcp_layer->GetCWR()<< endl;
	cout << "tcp ECE Flag:"<< tcp_layer->GetECE() << endl;
	cout << "tcp PSH Flag:"<< tcp_layer->GetPSH()<< endl;
	cout << "tcp RST Flag:"<< tcp_layer->GetRST() << endl;
	cout<< "tcp SYN Flag:"<< tcp_layer->GetSYN() << endl;
	cout << "tcp URG Flag:"<< tcp_layer->GetURG() <<endl;
}