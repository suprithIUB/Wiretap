#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <string.h>
#include <netinet/tcp.h>
#include <linux/icmp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <net/if_arp.h>
#include <linux/if_ether.h>
#include <pcap/bpf.h>
#include <iostream>
#include <time.h>
#include <arpa/inet.h>
#include <map>
#include<iomanip>


typedef struct arphdr_t {
        __be16          ar_hrd;         /* format of hardware address   */
        __be16          ar_pro;         /* format of protocol address   */
        unsigned char   ar_hln;         /* length of hardware address   */
        unsigned char   ar_pln;         /* length of protocol address   */
        __be16          ar_op;          /* ARP opcode (command)         */
        unsigned char           ar_sha[ETH_ALEN];       /* sender hardware address      */
        unsigned char           ar_sip;              /* sender IP address            */
        unsigned char           ar_tha[ETH_ALEN];       /* target hardware address      */
        unsigned char           ar_tip;              /* target IP address            */
}myARPstruct;

using namespace std;

/*
 * addToMap
 *
 * For the given map, add the key,if already existing increment the value
 * */
void addToMap(map<string,int> &targetMap,string key){
	auto value = targetMap.find(key);
	int temp;
	if(value != targetMap.end()) {
		temp = value->second;
		temp = temp+1;
		value->second = temp;
	}
	else
		targetMap.insert(pair<string,int>{key,1});
}

/**
 * convertTimeToEpocSeconds
 *
 * convert the time to epoch seconds
 */
long convertTimeToEpocSeconds(char* timeString,const char* timeFormat){
	struct tm tmTime;
	strptime(timeString,timeFormat,&tmTime);
	time_t requiredTime = mktime(&tmTime);
	return long(requiredTime);
}

/**
 * addFLAGSToMap
 *
 * add flags to the map, mainly for tcp flags
 */
void addFLAGSToMap(map<string,int> &targetMap,string key, int value){
	auto curr = targetMap.find(key);
	int temp;
	if(value > 0){
	
		if(curr != targetMap.end()) {
			temp = curr->second;
			temp = temp+1;
			curr->second = temp;

		}
		targetMap.insert(pair<string,int>{key,1});
	}
	else
		targetMap.insert(pair<string,int>{key,0});
}


/**
 * printMyMap
 *
 * Print the map
 */
void printMyMap(map<string,int> &targetMap){
	for(map<string, int>::const_iterator it = targetMap.begin(); it != targetMap.end(); ++it)
			{
			    cout << setw(40) << left << it->first << setw(5)<< right << it->second<< endl;
			}
}


/*
 * readTCPOptions
 *
 *
 * Read the tcp options and add them to the map
 * */

void readTCPOptions(u_char *packetTracker,int maxTcpOptLen,map<string,int> &tcpOptionDict) {

	u_int8_t optLength;
	bool isNoOperation = false;
	char buf[10];
	while(maxTcpOptLen > 0 && *packetTracker != 0) {

			if(*packetTracker == 1) {
				packetTracker++;
				maxTcpOptLen--;
				isNoOperation = true;
		}
		else {

			sprintf(buf,"%d (0x%02x)",*packetTracker,*packetTracker);
			addToMap(tcpOptionDict,string(buf));
			optLength = *(packetTracker+1);
			packetTracker += optLength;
			maxTcpOptLen -= optLength;
		}
	}
	if(isNoOperation) {
		sprintf(buf,"%d (0x%02x)",1,1);
		addToMap(tcpOptionDict,string(buf));
	}
}




/*
 * readTCPHeader
 *
 *
 * Read the tcp header in the packet including ports,flags and options
 * */
void readTCPHeader(u_char *ptrToPacketData,map<string,int> &tcpSourcePort,map<string,int> &tcpDestPort,
		map<string,int> &tcpFLAGs,map<string,int> &tcpOptions) {

	struct tcphdr *ptrToTCPHeader;
	ptrToTCPHeader = (struct tcphdr *)ptrToPacketData;
	addToMap(tcpSourcePort,to_string(ntohs(ptrToTCPHeader->source)));
	addToMap(tcpDestPort,to_string(ntohs(ptrToTCPHeader->dest)));
	addFLAGSToMap(tcpFLAGs,"ACK", ntohs(ptrToTCPHeader->ack));
	addFLAGSToMap(tcpFLAGs,"FIN",ntohs(ptrToTCPHeader->fin));
	addFLAGSToMap(tcpFLAGs,"PSH",ntohs(ptrToTCPHeader->psh));
	addFLAGSToMap(tcpFLAGs,"RST",ntohs(ptrToTCPHeader->rst));
	addFLAGSToMap(tcpFLAGs,"SYN",ntohs(ptrToTCPHeader->syn));
	addFLAGSToMap(tcpFLAGs,"URG", ntohs(ptrToTCPHeader->urg));
	ptrToPacketData += sizeof(*ptrToTCPHeader);
	int maxOptLength = ptrToTCPHeader->doff * 4 - sizeof(*ptrToTCPHeader);
	readTCPOptions(ptrToPacketData,maxOptLength,tcpOptions);
}



/*
 * readUDPHeader
 *
 * read the udp packet header to get the udp source and dest ports
 * */
void readUDPHeader(u_char *ptrToPacketData,map<string,int> &udpSPort,map<string,int> &udpDPort){
	struct udphdr *ptrToUDPHeader = (struct udphdr *)ptrToPacketData;
	addToMap(udpSPort,to_string(ntohs(ptrToUDPHeader->source)));
	addToMap(udpDPort,to_string(ntohs(ptrToUDPHeader->dest)));
}

/*
 * read ethernet address
 *
 * return the mac address in a colon separated octet format
 * */
string readEthernetAddress(struct ether_addr* ethernetAddresses) {

	char buf[18];
	sprintf(buf,"%02x:%02x:%02x:%02x:%02x:%02x",ethernetAddresses->ether_addr_octet[0],ethernetAddresses->ether_addr_octet[1],
												ethernetAddresses->ether_addr_octet[2],ethernetAddresses->ether_addr_octet[3],
												ethernetAddresses->ether_addr_octet[4],ethernetAddresses->ether_addr_octet[5]);

	return string(buf);
}

/**
 * readARPPacketHeader
 *
 *
 * read ARP packet header
 */
void readARPPacketHeader(u_char *ptrToPacketData,map<string,int> &arpAddressSource) {
	myARPstruct *ptrToARPHeader = (myARPstruct *)ptrToPacketData;
	string arpAddressString = readEthernetAddress((struct ether_addr *)&ptrToARPHeader->ar_sha);
	arpAddressString += "/" + (string)(inet_ntoa(*(struct in_addr *)&ptrToARPHeader->ar_sip));
	addToMap(arpAddressSource, arpAddressString);
}

/*
 * readICMPHeader
 *
 *
 * Read the ICMP types and codes
 */
void readICMPHeader(u_char *ptrToPacketData,map<string,int> &icmpTypes,map<string,int> &icmpCodes) {
	struct icmphdr *ptrToICMPHeader = (struct icmphdr *)ptrToPacketData;
	addToMap(icmpTypes, to_string(ptrToICMPHeader->type));
	addToMap(icmpCodes, to_string(ptrToICMPHeader->code));
}


void printPacketTimeDetails(char* lastCaptured,char* captureStart){

	const char* timeFormat = "%Y-%m-%d:%H:%M:%S";
	cout << "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" << endl;
	cout << "=========Packet capture summary========="  << endl;
	cout << "Given PCAP is captured on an ethernet interface" << endl;
	cout << "Capture Start Date: " << captureStart << endl;
	cout << "Capture End Date: " << lastCaptured << endl;
	cout << "Duration : " << convertTimeToEpocSeconds(lastCaptured,timeFormat) - convertTimeToEpocSeconds(captureStart,timeFormat) << " seconds" << endl;
}


void printPacketSizeStatistics(int numberOfPackets,int minPacketLength,int maxPacketLength,int totalPacketsSize) {

	cout << setw(40) << left << "Packets in capture: " << setw(5) << right << numberOfPackets << endl;
	cout << setw(40) << left << "Minimum packet size: " << setw(5) << right << minPacketLength << endl;
	cout << setw(40) << left << "Maximum packet size: " << setw(5) << right << maxPacketLength << endl;
	float avg = (float)totalPacketsSize/numberOfPackets;
	printf("%-40s%5.2f\n","Average packet size:",avg);

}


void printLinkLayerPacketDetails(map<string,int> &etherAddrSource,map<string,int> &etherAddrDest){
		cout << "=========Link layer=========" << endl;
		cout <<"---------Source ethernet addresses---------" << endl;
		printMyMap(etherAddrSource);
		cout <<"---------Destination ethernet addresses---------" << endl;
		printMyMap(etherAddrDest);
}


void printNetworkLayerPacketDetails(int numberOfIPPackets,int numberOfARPPackets,int numberOfIPV6Packets,int numberOfOtherPackets){

	cout << "=========Network layer=========" << endl;

	cout << "---------Network layer protocols---------		" << endl;
	cout << setw(40) << left << "Number of IP Packets:" << setw(5) << right << numberOfIPPackets << endl;
	cout << setw(40) << left << "Number of ARP Packets:" << setw(5) << right << numberOfARPPackets << endl;
	cout << setw(40) << left << "Number of IPV6 Packets:" << setw(5) << right << numberOfIPV6Packets << endl;
	cout << setw(40) << left << "Number of Other Packets:" << setw(5) << right << numberOfOtherPackets << endl;


}


void printTransportLayerPacketDetails(int numberOfTCPConns,int numberOfUDPConns,int numberOfICMPConns,int numberOfOtherIPPackets,
										map<string,int>	 otherIPPackets)
{
	cout << "---------Transport layer protocols---------" << endl;
	cout << setw(40) << left << "TCP" << setw(5) << right << numberOfTCPConns << endl;
	cout << setw(40) << left << "UDP" << setw(5) << right << numberOfUDPConns << endl;
	cout << setw(40) << left << "ICMP" << setw(5) << right << numberOfICMPConns << endl;
	cout << setw(40) << left << "Number of Other Protocol Packets:" << setw(5) << right << numberOfOtherIPPackets << endl;
	cout << "Breakdown of Other Packets: "<< endl;
	printMyMap(otherIPPackets);

}


void printTCPPacketDetails(map<string,int> &tcpSourcePort,map<string,int> &tcpDestPort,map<string,int> &tcpFLAGs,map<string,int> &tcpOptions){

	cout << "=========Transport layer: TCP=========" << endl;
	cout << "---------Source TCP ports---------" << endl;
	printMyMap(tcpSourcePort);
	cout << "---------Destination TCP ports---------"<< endl;
	printMyMap(tcpDestPort);
	cout << "---------TCP flags---------" << endl;
	printMyMap(tcpFLAGs);
	cout << "---------TCP options---------" << endl;
	printMyMap(tcpOptions);
}


void printUDPandICMPPacketDetails(map<string,int> &udpSPort,map<string,int> &udpDPort,map<string,int> &icmpTypes,map<string,int> &icmpCodes){

	cout << "=========Transport layer: UDP=========" << endl;
	cout << "---------Source UDP ports---------" << endl;
	printMyMap(udpSPort);
	cout << "---------Destination UDP ports---------" << endl;
	printMyMap(udpDPort);
	cout <<"=========Transport layer: ICMP=========" << endl;
	cout <<"---------ICMP types---------" << endl;
	printMyMap(icmpTypes);
	cout <<"---------ICMP codes---------" << endl;
	printMyMap(icmpCodes);
}

void printAddressOfArpIPandOtherPackets(map<string,int> &otherPacketTypes,map<string,int> &ipAddressSource,map<string,int> &ipAddressDest,map<string,int> &arpAddressSource) {

	cout << "Breakdown of Other Packets: "<< endl;
	printMyMap(otherPacketTypes);
	cout << "---------Source IP addresses---------" << endl;
	printMyMap(ipAddressSource);
	cout <<"-----Destination IP addresses---------" << endl;
	printMyMap(ipAddressDest);
	cout << "---------Unique ARP participants---------" << endl;
	printMyMap(arpAddressSource);

}

/*
 * readEthernetHeader
 *
 * reads the ethernet header and returns the packet type
 * */
int readEthernetHeader(u_char* packetPointer,map<string,int> &etherAddrSource,map<string,int> &etherAddrDest) {

	struct ether_header *ptrToEthernetHeader;
	ptrToEthernetHeader = (struct ether_header *) packetPointer;
	int packetType = ntohs (ptrToEthernetHeader->ether_type);
	addToMap(etherAddrDest,readEthernetAddress((struct ether_addr *)&ptrToEthernetHeader->ether_dhost));
	addToMap(etherAddrSource,readEthernetAddress((struct ether_addr *)&ptrToEthernetHeader->ether_shost));
	return ntohs(ptrToEthernetHeader->ether_type);
}


void readPacketHeader(struct pcap_pkthdr *packetHeader,int* numberOfPackets,int* maxPacketLength,int* minPacketLength,int* totalPacketsSize) {

	unsigned int packetLength = packetHeader->len;
	if(*numberOfPackets == 0) {
		*maxPacketLength  = packetLength;
		*minPacketLength = packetLength;
	}
	else {
		if(packetLength > *maxPacketLength)
			*maxPacketLength = packetLength;
		if(packetLength < *minPacketLength)
			*minPacketLength = packetLength;
	}
	(*numberOfPackets)++;
	*totalPacketsSize += packetLength;
}


int main(int argc, char **argv) 
{ 

	if (argc < 2) {
		    cout <<"Usage: ./wiretap input.pcap" << endl;
		    exit(1);
	}
	else if(strcmp(argv[1],"--help") == 0)
		cout <<"Usage: ./wiretap input.pcap" << endl;
	else if(argc == 3 && strcmp(argv[1],"--open") == 0) {

		map<string, int> etherAddrSource,etherAddrDest,otherPacketTypes,ipAddressSource,ipAddressDest,arpAddressDest;;
		map<string, int> arpAddressSource,arpSenderHardware,arpTargetHardware,tcpSourcePort,tcpDestPort,udpSPort;
		map<string, int> udpDPort,tcpFLAGs,tcpOptions,otherIPPackets,icmpTypes,icmpCodes;
		const char* timeFormat = "%Y-%m-%d:%H:%M:%S";
		int numberOfPackets = 0, totalPacketsSize = 0;
		int minPacketLength = 0, maxPacketLength = 0;
		int numberOfIPPackets = 0, numberOfARPPackets = 0, numberOfOtherPackets= 0, numberOfIPV6Packets =0, numberOfTCPConns=0, numberOfICMPConns= 0, numberOfUDPConns=0, numberOfOtherIPPackets=0;
		struct tm * startTime, endTime;
		myARPstruct *ptrToARPHeader;
		char* lastCaptured = new char[65];
		char* captureStart = new char[65];
		int packetSeek = 0;
		const u_char *packetPointer;
		struct ip *ptrToIPHeader;
		struct pcap_pkthdr packetHeader;
		pcap_t *pcapHandle;
		char errbuf[PCAP_ERRBUF_SIZE];
		pcapHandle = pcap_open_offline(argv[2], errbuf);
		if (pcapHandle != NULL && pcap_datalink(pcapHandle) == DLT_EN10MB) {
			cout << "PCAP OPEN SUCCESS" << endl;

			while (packetPointer = pcap_next(pcapHandle,&packetHeader)) {

				u_char *ptrToPacketData = (u_char *)packetPointer;
				if(numberOfPackets == 0)
					strftime(captureStart,64,timeFormat,localtime(&packetHeader.ts.tv_sec));

				readPacketHeader(&packetHeader,&numberOfPackets,&maxPacketLength,&minPacketLength,&totalPacketsSize);
				strftime(lastCaptured,64,timeFormat,localtime(&packetHeader.ts.tv_sec));

				int packetType = readEthernetHeader(ptrToPacketData,etherAddrSource,etherAddrDest);
				if(packetType == ETH_P_IP) {
					ptrToPacketData += ETH_HLEN;
					ptrToIPHeader = (struct ip *)ptrToPacketData;
					numberOfIPPackets++;
					addToMap(ipAddressSource, (string) inet_ntoa(ptrToIPHeader->ip_src));
					addToMap(ipAddressDest, (string) inet_ntoa(ptrToIPHeader->ip_dst));
					ptrToPacketData += sizeof(struct ip);
					switch(ptrToIPHeader->ip_p) {

						case  IPPROTO_TCP	:	numberOfTCPConns++;
												readTCPHeader(ptrToPacketData,tcpSourcePort,tcpDestPort,tcpFLAGs,tcpOptions);
												break;
						case IPPROTO_UDP	:	numberOfUDPConns++;
												readUDPHeader(ptrToPacketData,udpSPort,udpDPort);
												break;
						case IPPROTO_ICMP	:	numberOfICMPConns++;
												readICMPHeader(ptrToPacketData,icmpTypes,icmpCodes);
												break;
						default	:
												numberOfOtherIPPackets++;
												addToMap(otherIPPackets,to_string(ptrToIPHeader->ip_p));
												break;

					}
				}
				else if(packetType == ETH_P_ARP) {
					ptrToPacketData += ETH_HLEN;
					numberOfARPPackets++;
					readARPPacketHeader(ptrToPacketData,arpAddressSource);
				}
				else if(packetType == ETH_P_IPV6) {
					numberOfIPV6Packets++;
				}
				else {
					char buf[10];
					sprintf(buf,"%d (0x%02x)",packetType,packetType);
					addToMap(otherPacketTypes,string(buf));
					numberOfOtherPackets++;
				}
			}
			pcap_close (pcapHandle);
			printPacketTimeDetails(lastCaptured,captureStart);
			printPacketSizeStatistics(numberOfPackets,minPacketLength,maxPacketLength,totalPacketsSize);
			printLinkLayerPacketDetails(etherAddrSource,etherAddrDest);
			printNetworkLayerPacketDetails(numberOfIPPackets,numberOfARPPackets,numberOfIPV6Packets,numberOfOtherPackets);
			printAddressOfArpIPandOtherPackets(otherPacketTypes,ipAddressSource,ipAddressDest,arpAddressSource);
			printTransportLayerPacketDetails(numberOfTCPConns,numberOfUDPConns,numberOfICMPConns,numberOfOtherIPPackets,otherIPPackets);
			printTCPPacketDetails(tcpSourcePort,tcpDestPort,tcpFLAGs,tcpOptions);
			printUDPandICMPPacketDetails(udpSPort,udpDPort,icmpTypes,icmpCodes);
		}
		else{


			cout << "EITHER FAILED TO OPEN THE PCAP FILE: " << argv[2] << endl;
			cout << "OR GIVEN PCAP IS CAPTURED ON AN INTERFACE THAT IS NOT SUPPORTED BY THE PROGRAM" << endl;
			cout << " Error : "<< errbuf <<  endl;
			if(pcapHandle != NULL)
				pcap_close (pcapHandle);
		}
		delete[] lastCaptured;
		delete[] captureStart;
	}
	else {
		cout <<"Usage: ./wiretap input.pcap" << endl;
	}
}
