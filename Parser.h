#ifndef PARSEPACKET_PARSER_H
#define PARSEPACKET_PARSER_H

#include <sstream>
#include <string>
#include <time.h>
#include <string>
#include <arpa/inet.h>
#include <iomanip>
#include "Packet.h"
#include "MacAddress.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"


std::string getProtocolTypeAsString(pcpp::ProtocolType protocolType);


class Parser {
private:
    pcpp::Packet *packet;
    std::string info = "";

    void parse();
    
    void genInfo();


    // for frame
    time_t currTimeStamp = 0;
    long currTimeStampNSec = 0;
    int packetNumber = 0;
    std::string time_str = "";
    time_t time_delta = 0;
    long time_deltaNSec = 0;
    time_t time_relative = 0;
    long time_relativeNSec = 0;
    int frameLen = 0;
    std::string protocols = "";

    void parseFrame();

    std::string timeStampToString(time_t timeStamp);

    int getFrameLen();

    time_t getFrameTimeStamp();

    long getFrameTimeStampNSec();

    std::string getFrameProtocols();


    // for eth
    pcpp::EthLayer *ethLayer = nullptr;
    pcpp::MacAddress srcMac = pcpp::MacAddress();
    pcpp::MacAddress dstMac = pcpp::MacAddress();
    uint16_t ethType = 0;
    size_t ethHeaderLen = 0;

    void parseEth();

    pcpp::MacAddress getEthDstMac();

    pcpp::MacAddress getEthSrcMac();

    uint16_t getEthType();


    // for IP
    bool isV6 = false;
    uint8_t ip_version = 0;

    // for IPv4
    pcpp::IPv4Layer *ip4_ipLayer = nullptr;
    pcpp::IPv4Address ip4_srcIp = pcpp::IPv4Address();
    pcpp::IPv4Address ip4_dstIp = pcpp::IPv4Address();

    void parseIPv4();


    // for IPv6
    pcpp::IPv6Layer *ip6_ipLayer = nullptr;
    pcpp::IPv6Address ip6_srcIp = pcpp::IPv6Address();
    pcpp::IPv6Address ip6_dstIp = pcpp::IPv6Address();

    void parseIPv6();


public:
    Parser(int packetNumber, pcpp::Packet *packet) {
        this->packetNumber = packetNumber;
        this->packet = packet;
        this->parse();
        this->genInfo();
    }

    time_t getCurrTimeStamp() {
        return this->currTimeStamp;
    }

    long getCurrTimeStampNSec() {
        return this->currTimeStampNSec;
    }

    int getInfoLen() {
        return this->info.length();
    }

    std::string getInfo();
};


#endif //PARSEPACKET_PARSER_H
