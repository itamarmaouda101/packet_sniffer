#ifndef httpLib_h
#define httpLib_h
#include<iostream>
#include<crafter.h>
#include<string>
#include <algorithm>
#include <vector>
#include"EthernetLibs.hpp"
#include <bits/stdc++.h>
#define iface "ens33"
using namespace std;
using namespace Crafter;

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

#endif