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
    size_t ip_headerLen = 0;
    uint8_t ip_protocol = 0;

    // for IPv4
    pcpp::IPv4Layer *ip4_ipLayer = nullptr;
    uint8_t ip4_dsfield = 0;
    uint8_t ip4_dscp = 0;
    uint8_t ip4_ecn = 0;
    uint16_t ip4_len = 0;
    uint16_t ip4_id = 0;
    uint8_t ip4_ttl = 0;
    uint16_t ip4_flags = 0;
    bool ip4_flags_rb = false;
    bool ip4_flags_df = false;
    bool ip4_flags_mf = false;
    uint16_t ip4_offset = 0;
    uint16_t ip4_checksum = 0;
    pcpp::IPv4Address ip4_srcIp = pcpp::IPv4Address();
    pcpp::IPv4Address ip4_dstIp = pcpp::IPv4Address();

    void parseIPv4();


    // for IPv6
    pcpp::IPv6Layer *ip6_ipLayer = nullptr;
    uint8_t ip6_trafficClass = 0;
    uint8_t ip6_flowLabel[3] = {0};
    uint16_t ip6_payloadLength = 0;
    uint8_t ip6_hopLimit = 0;
    pcpp::IPv6Address ip6_srcIp = pcpp::IPv6Address();
    pcpp::IPv6Address ip6_dstIp = pcpp::IPv6Address();

    void parseIPv6();


    // for TCP
    pcpp::TcpLayer *tcpLayer = nullptr;
    size_t tcp_headerLen = 0;
    uint16_t tcp_srcPort = 0;
    uint16_t tcp_dstPort = 0;
    uint32_t tcp_seqNum = 0;
    uint32_t tcp_ackNum = 0;
    size_t tcp_segLen = 0;
    uint32_t tcp_nextSeq = 0;
    uint16_t tcp_flags = 0;
    uint8_t tcp_flags_res = 0;
    uint8_t tcp_flags_ns = 0;
    uint8_t tcp_flags_cwr = 0;
    uint8_t tcp_flags_ecn = 0;
    uint8_t tcp_flags_urg = 0;
    uint8_t tcp_flags_ack = 0;
    uint8_t tcp_flags_push = 0;
    uint8_t tcp_flags_reset = 0;
    uint8_t tcp_flags_syn = 0;
    uint8_t tcp_flags_fin = 0;
    uint16_t tcp_windowSize = 0;
    uint16_t tcp_checksum = 0;
    uint16_t tcp_urgentPointer = 0;
    size_t tcp_dataSize = 0;
    uint8_t *tcp_payload = nullptr;

    void parseTCP();


    //for UDP
    pcpp::UdpLayer *udpLayer = nullptr;
    uint16_t udp_srcPort = 0;
    uint16_t udp_dstPort = 0;
    uint16_t udp_length = 0;
    size_t udp_dataSize = 0;
    uint16_t udp_checksum = 0;
    uint8_t *udp_payload = 0;

    void parseUDP();

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
