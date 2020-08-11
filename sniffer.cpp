/*
 * Simple Sniffer
 *
 * Simple program to illustrate how to use the Sniffer class
 */
#include <iostream>
#include <string.h>
#include <map>
#include "EthernetLibs.h"
#include <crafter.h>
#include <bits/stdc++.h>

using namespace std;
using namespace Crafter;

/*packet_expulison doset work yet 
**after programing the layer 5 protocols idenefision ill handule that*/

	

void packet_expulsion(Packet* sniff_packet, void* user){
	size_t NumberOfLayers = sniff_packet->GetLayerCount();
	TCP* tcp_layer = sniff_packet->GetLayer<TCP>();
	UDP* udp_layer = sniff_packet->GetLayer<UDP>();
	RawLayer* raw_layer = sniff_packet->GetLayer<RawLayer>();
	byte* raw_ptr;

	if (tcp_layer){
		Layer* top_layer = tcp_layer->GetTopLayer();
		Payload payload = top_layer->GetPayload();
		size_t data = top_layer->GetData(raw_ptr);
		cout <<data<<endl;
	}
	if (udp_layer){
		Layer* top_layer = udp_layer->GetTopLayer();
		Payload payload = top_layer->GetPayload();
		size_t data = top_layer->GetData(raw_ptr);
		cout <<data<<endl;
	}
	Layer* top_layer = raw_layer->GetTopLayer(); 

	byte*  payload_bytes;

	Payload payload = top_layer->GetPayload();
	size_t data = top_layer->GetRawData(raw_ptr);
	cout <<data<<endl;
	/*
	size_t payload_size_t = top_layer->GetPayload(payload_bytes);
	cout<< "payload:\n\n"<< endl;
	cout<<payload.GetString()<<endl;
	cout<<"\n\n payload (bytes)\n\n"<<endl;
	cout<<payload_bytes.G<<endl;
	cout<<"\n"<< payload_size_t<<endl;
	*/


	
	
}
void Http_opsions(string payload){
	
	
	if(payload.substr(0,3).compare("GET")==0){
		cout <<"GET request:\n";
		cout <<payload<<endl;
	}
	else if(payload.substr(0,4).compare("POST")==0){
		cout << "POST request: \n";
		cout << payload <<endl;
	}
	else if (payload.substr(0,8).compare("HTTP/1.1")==0)
	{
		cout << "HTTP Respone:\n";
		cout <<payload<<endl;
	}
	else
	{
		cout << "encrepted message/ cant idenfiy:\n";
		cout << payload << endl;
	}
	
	

	
		

	}



void Http_check(Packet* sniff_packet){
	RawLayer* raw_payload = sniff_packet->GetLayer<RawLayer>();
	if (raw_payload){

		cout <<"raw_payload"<<endl;	
		if(raw_payload->GetPayloadSize()>0){
			string payload = raw_payload->GetStringPayload();
			Http_opsions(payload);

		}
	


}
	}

	






/* Function for handling a packet */
void PacketHandler(Packet* sniff_packet, void* user) {
	/* sniff_packet -> pointer to the packet captured */
	/* user -> void pointer to the data supplied by the user */

	/* Check if there is a payload */
	RawLayer* raw_payload = sniff_packet->GetLayer<RawLayer>();
	UDP* udp_layer = sniff_packet->GetLayer<UDP>();
	Ethernet* ether_layer = sniff_packet->GetLayer<Ethernet>();
	TCP* tcp_layer = sniff_packet->GetLayer<TCP>();
	IP* ip_layer = sniff_packet->GetLayer<IP>();
	ARP* arp_layer = sniff_packet->GetLayer<ARP>();
	ICMP* icmp_layer = sniff_packet->GetLayer<ICMP>();
	if (tcp_layer) {cout << "[+] ----  TCP_PACKET  ---- [+]\n\n" << endl;}
	if (udp_layer) {cout << "[+] ----  UDP_PACKET  ---- [+]\n\n" << endl;}
	if (arp_layer) {cout << "[+] ----  ARP_PACKET  ---- [+]\n\n" << endl;}
	if (icmp_layer) {cout << "[+] ----  ICMP_PACKET  ---- [+]\n\n" << endl;}


	if (ip_layer){
		/*Summarize some data for it layer*/
		cout << "[+] --- INFO FROM IP LAYER --- [+] \n\n"<< endl;
		cout << "[#] IP Packet ID:" <<ip_layer->GetID()<<endl;
		cout << "[#] IP Packet name:" <<ip_layer->GetName()<<endl;
		cout << "[#] IP Packet Source IP:" <<ip_layer->GetSourceIP()<<endl;
		cout << "[#] IP Packet Destination IP:" <<ip_layer->GetDestinationIP()<<endl;
		cout << "[#] IP Packet Identification:" <<ip_layer->GetIdentification()<<endl;
		cout << "[#] IP Packet Protocol:" <<ip_layer->GetProtocol()<<endl;
		cout << "[#] IP Packet TTL:" <<ip_layer->GetTTL()<<endl;
		cout << "[#] IP Packet Flags:" <<ip_layer->GetFlags()<<endl;
		
		










	}
	if (icmp_layer){
		/*Summarize some data for icmp layer*/
		cout << "[+] --- INFO FROM ICMP LAYER --- [+] \n\n"<< endl;
		cout << "[#] ICMP Packet ID:" <<icmp_layer->GetID()<<endl;
		cout << "[#] ICMP Packet Name:" <<icmp_layer->GetName()<<endl;
		cout << "[#] ICMP Packet Identifier:" << icmp_layer->GetIdentifier()<<endl;
		cout << "[#] ICMP Packet Gateway:" <<icmp_layer->GetGateway()<<endl;
		cout << "[#] ICMP Packet Type: " << icmp_layer->GetType()<<endl;
		cout << "[#] ICMP Packet SequenceNumber: " << icmp_layer-> GetSequenceNumber()<<endl;
	}
	if (arp_layer){
		/*Summarize some data for arp layer*/
		cout << "[+] --- INFO FROM ARP LAYER --- [+] \n\n"<< endl;
		cout << "[#] ARP Packet ID: " <<arp_layer->GetID() << endl;
		cout << "[#] ARP Packet Name: " <<arp_layer->GetName() << endl;
		cout << "[#] ARP Packet Operation: " <<arp_layer->GetOperation() << endl;
		cout << "[#] ARP Packet Sender IP: " <<arp_layer->GetSenderIP() << endl;
		cout << "[#] ARP Packet Target IP: " <<arp_layer->GetTargetIP() << endl;
		cout << "[#] ARP Packet Target MAC: " <<arp_layer->GetTargetMAC() << endl;
		cout << "[#] ARP Packet Sender MAC: " <<arp_layer->GetSenderMAC() << endl;
		cout << "[#] ARP Packet Protocol: " <<arp_layer->GetProtocolType() << endl;
		cout<<"\n"<<endl;
	}
	if (ether_layer){
		/*Summarize some data for ethernet layer*/
		cout << "[+] --- INFO FROM Ethernet LAYER --- [+] \n\n"<< endl;
		cout << "[#] Ethernet Packet ID: " << ether_layer->GetID() << endl;
		cout << "[#] Ethernet Packet Name: " << ether_layer->GetName() << endl;
		cout << "[#] Ethernet Packet Type " << ether_layer->GetType() << endl;
		cout << "[#] Ethernet Packet Source MAC: " << ether_layer->GetSourceMAC() << endl;
		cout << "[#] Ethernet Packet Destination MAC: " << ether_layer->GetDestinationMAC() << endl;
		cout << "[#] Ethernet Packet First field: " << ether_layer->GetField(0) << endl;
		cout <<"\n"<<endl; 
	}
	if (tcp_layer){
		/* Summarize some data for tcp layer */
		cout << "[+] --- INFO FROM TCP LAYER --- [+] \n\n"<< endl;
		cout << "[#] TCP Packet ID: " << tcp_layer->GetID() << endl;
		cout << "[#] TCP Packet Name: " << tcp_layer->GetName() << endl;
		cout << "[#] TCP Packet Source Port: " << tcp_layer->GetSrcPort() << endl;
		cout << "[#] TCP Packet Destination Port: " << tcp_layer->GetDstPort() << endl;
		cout << "[#] TCP Packet Seq Number: " << tcp_layer->GetSeqNumber() << endl;
		cout << "[#] TCP Packet Ack Number: " << tcp_layer->GetAckNumber() << endl;
		//string payload = tcp_layer->GetStringPayload();
		//cout << payload << endl;

	}
	if (udp_layer)
	{
		cout << "[+] --- INFO FROM UDP LAYER --- [+] \n\n"<< endl;
		cout << "[#] UDP Packet ID: " << udp_layer->GetID()<<endl;
		cout << "[#] UDP Packet Name: " << udp_layer->GetName()<<endl;
		cout << "[#] UDP Packet Source Port: " << udp_layer-> GetSrcPort()<<endl;
		cout << "[#] UDP Packet Destination: " << udp_layer-> GetDstPort()<<endl;
		cout << "[#] UDP Packet Header Size:" << udp_layer->GetHeaderSize()<< endl;

	}
	
	if(raw_payload) {
		/* Summarize some data for rawpayload */
		cout << "[+] --- INFO FROM RAW_PAYLOAD --- [+] \n\n"<< endl;
		cout << "[#] RAW Packet ID: " << raw_payload->GetID() << endl;
		cout << "[#] RAW Packet Name: " << raw_payload->GetName() << endl;
		cout << "[#] RAW Packet PayloadSize: " << raw_payload->GetPayloadSize() << endl;
		string payload = raw_payload->GetStringPayload();
		cout << payload << endl;


	cout<<"xxxx\n";
	}
	Http_check(sniff_packet);

	cout << "[==========================================================================]\n\n";

}




int main() {

	/* Set the interface */
	Sniffer sniff_tcp("tcp", iface, PacketHandler);
	sniff_tcp.Capture(-1);

	return 0;
}