#ifndef PARSEPACKET_PARSER_H
#define PARSEPACKET_PARSER_H

#include <sstream>
#include <string>
#include <time.h>
#include <string>
#include <arpa/inet.h>
#include "Packet.h"
#include "MacAddress.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "TcpLayer.h"


std::string getProtocolTypeAsString(pcpp::ProtocolType protocolType);


class Parser {
private:
    pcpp::Packet packet;

    void parse();


    // for frame
    long startTimeStamp;
    long currTimeStamp;
    long prevTimeStamp;
    int packetNumber;
    std::string time_str;
    long time_delta;
    long time_relative;
    int frameLen;
    std::string protocols;

    void parseFrame();

    std::string timeStampToString(time_t timeStamp);

    int getFrameLen();

    time_t getFrameTimeStamp();

    long getFrameTimeStampNSec();

    std::string getFrameProtocols();


    // for eth
    pcpp::EthLayer *ethLayer;
    pcpp::MacAddress srcMac;
    pcpp::MacAddress dstMac;
    uint16_t ethType;
    size_t ethHeaderLen;

    void parseEth();

    pcpp::MacAddress getEthDstMac();

    pcpp::MacAddress getEthSrcMac();

    uint16_t getEthType();


    // for IP
    bool isV6;
    uint8_t ip_version;
    size_t ip_headerLen;

    // for IPv4
    pcpp::IPv4Layer *ip4_ipLayer;
    uint8_t ip4_dsfield;
    uint8_t ip4_dscp;
    uint8_t ip4_ecn;
    uint16_t ip4_len;
    uint16_t ip4_id;
    uint8_t ip4_ttl;
    uint16_t ip4_flags;
    bool ip4_flags_rb;
    bool ip4_flags_df;
    bool ip4_flags_mf;
    uint16_t ip4_offset;
    uint8_t ip4_protocol;
    uint16_t ip4_checksum;
    pcpp::IPv4Address ip4_srcIp;
    pcpp::IPv4Address ip4_dstIp;

    void parseIPv4();


    // for IPv6
    pcpp::IPv6Layer *ip6_ipLayer;
    uint8_t ip6_trafficClass;
    uint8_t ip6_flowLabel[3];
    uint16_t ip6_payloadLength;
    uint8_t ip6_nextHeader;
    uint8_t ip6_hopLimit;
    pcpp::IPv6Address ip6_srcIp;
    pcpp::IPv6Address ip6_dstIp;

    void parseIPv6();


    // for TCP
    pcpp::TcpLayer *tcpLayer;
    size_t tcp_headerLen;
    uint16_t tcp_srcPort;
    uint16_t tcp_dstPort;
    uint32_t tcp_seqNum;
    uint32_t tcp_ackNum;
    size_t tcp_segLen;
    uint16_t tcp_flags;
    void parseTCP();

public:
    Parser(int packetNumber, pcpp::Packet &packet) {
        this->packetNumber = packetNumber;
        this->packet = packet;
        this->parse();
    }

    Parser(int packetNumber, pcpp::Packet &packet, long startTimeStamp, long prevTimeStamp) {
        this->packetNumber = packetNumber;
        this->packet = packet;
        this->startTimeStamp = startTimeStamp;
        this->prevTimeStamp = prevTimeStamp;
        this->parse();
    }

    long getStartTimeStamp() {
        return this->startTimeStamp;
    }

    long getCurrTimeStamp() {
        return this->currTimeStamp;
    }

};


#endif //PARSEPACKET_PARSER_H
