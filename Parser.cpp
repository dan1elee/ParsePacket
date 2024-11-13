//
// Created by DELL on 2024/11/13 013.
//

#include "Parser.h"
#include <stdio.h>

std::string getProtocolTypeAsString(pcpp::ProtocolType protocolType) {
    switch (protocolType) {
        case pcpp::UnknownProtocol:
            return "UnknownProtocol";
        case pcpp::Ethernet:
            return "Ethernet";
        case pcpp::IPv4:
            return "IPv4";
        case pcpp::IPv6:
            return "IPv6";
        case pcpp::TCP:
            return "TCP";
        case pcpp::UDP:
            return "UDP";
        case pcpp::HTTPRequest:
        case pcpp::HTTPResponse:
            return "HTTP";
        case pcpp::ARP:
            return "ARP";
        case pcpp::VLAN:
            return "VLAN";
        case pcpp::ICMP:
            return "ICMP";
        case pcpp::PPPoESession:
            return "PPPoESession";
        case pcpp::PPPoEDiscovery:
            return "PPPoEDiscovery";
        case pcpp::DNS:
            return "DNS";
        case pcpp::MPLS:
            return "MPLS";
        case pcpp::GREv0:
            return "GREv0";
        case pcpp::GREv1:
            return "GREv1";
        case pcpp::PPP_PPTP:
            return "PPP_PPTP";
        case pcpp::SSL:
            return "SSL";
        case pcpp::SLL:
            return "SLL";
        case pcpp::DHCP:
            return "DHCP";
        case pcpp::NULL_LOOPBACK:
            return "NULL_LOOPBACK";
        case pcpp::IGMPv1:
            return "IGMPv1";
        case pcpp::IGMPv2:
            return "IGMPv2";
        case pcpp::IGMPv3:
            return "IGMPv3";
        case pcpp::GenericPayload:
            return "GenericPayload";
        case pcpp::VXLAN:
            return "VXLAN";
        case pcpp::SIPRequest:
            return "SIPRequest";
        case pcpp::SIPResponse:
            return "SIPResponse";
        case pcpp::SDP:
            return "SDP";
        case pcpp::PacketTrailer:
            return "PacketTrailer";
        case pcpp::Radius:
            return "Radius";
        case pcpp::GTPv1:
            return "GTPv1";
        case pcpp::EthernetDot3:
            return "EthernetDot3";
        case pcpp::BGP:
            return "BGP";
        case pcpp::SSH:
            return "SSH";
        case pcpp::AuthenticationHeader:
            return "AuthenticationHeader";
        case pcpp::ESP:
            return "ESP";
        case pcpp::DHCPv6:
            return "DHCPv6";
        case pcpp::NTP:
            return "NTP";
        case pcpp::Telnet:
            return "Telnet";
        case pcpp::FTP:
            return "FTP";
        case pcpp::ICMPv6:
            return "ICMPv6";
        case pcpp::STP:
            return "STP";
        case pcpp::LLC:
            return "LLC";
        case pcpp::SomeIP:
            return "SomeIP";
        case pcpp::WakeOnLan:
            return "WakeOnLan";
        case pcpp::NFLOG:
            return "NFLOG";
        case pcpp::TPKT:
            return "TPKT";
        case pcpp::VRRPv2:
            return "VRRPv2";
        case pcpp::VRRPv3:
            return "VRRPv3";
        case pcpp::COTP:
            return "COTP";
        case pcpp::SLL2:
            return "SLL2";
        case pcpp::S7COMM:
            return "S7COMM";
        case pcpp::SMTP:
            return "SMTP";
        case pcpp::LDAP:
            return "LDAP";
        case pcpp::WireGuard:
            return "WireGuard";
        default:
            return "Unknown";
    }
}

void Parser::parse() {
    this->parseFrame();
    this->parseEth();
    switch (this->ethType) {
        case 0x0800:
            this->isV6 = false;
            parseIPv4();
            break;
        case 0x86DD:
            this->isV6 = true;
            parseIPv6();
            break;
        default:
//            std::cout << "Unknown ethernet type: " << this->ethType << std::endl;
            break;
    }
    this->parseTCP();
}


// for frame
void Parser::parseFrame() {
    this->currTimeStamp = getFrameTimeStampNSec();
    if (packetNumber == 1) {
        this->startTimeStamp = this->currTimeStamp;
        this->prevTimeStamp = this->currTimeStamp;
    }
    printf("Number: %d\n", packetNumber);
    this->time_str = timeStampToString(this->getFrameTimeStamp());
    this->time_delta = this->currTimeStamp - this->prevTimeStamp;
    this->time_relative = this->currTimeStamp - this->startTimeStamp;
    this->frameLen = this->getFrameLen();
    this->protocols = this->getFrameProtocols();
}

std::string Parser::timeStampToString(time_t timeStamp) {
    char buffer[80];
    struct tm *timeInfo = gmtime(&timeStamp);
    strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", timeInfo);
    return std::string(buffer);
}

int Parser::getFrameLen() {
    return this->packet.getRawPacket()->getRawDataLen();
}

time_t Parser::getFrameTimeStamp() {
    timespec ts = this->packet.getRawPacket()->getPacketTimeStamp();
    time_t timestamp = ts.tv_sec;
    return timestamp;
}

long Parser::getFrameTimeStampNSec() {
    timespec ts = this->packet.getRawPacket()->getPacketTimeStamp();
    long timestamp = ts.tv_nsec;
    return timestamp;
}

std::string Parser::getFrameProtocols() {
    std::stringstream ss;
    pcpp::Layer *layer = packet.getFirstLayer();
    while (true) {
        ss << getProtocolTypeAsString(layer->getProtocol());
        layer = layer->getNextLayer();
        if (layer == nullptr)
            break;
        ss << ":";
    }
    return ss.str();
}


//for eth
void Parser::parseEth() {
    this->ethLayer = this->packet.getLayerOfType<pcpp::EthLayer>();
    if (this->ethLayer == nullptr) {
        return;
    }
    this->srcMac = this->getEthSrcMac();
    this->dstMac = this->getEthDstMac();
    this->ethType = this->getEthType();
    this->ethHeaderLen = this->ethLayer->getHeaderLen();
}

pcpp::MacAddress Parser::getEthDstMac() {
    return ethLayer->getDestMac();
}

pcpp::MacAddress Parser::getEthSrcMac() {
    return ethLayer->getSourceMac();
}

uint16_t Parser::getEthType() {
    return ethLayer->getNextLayer() ? ntohs(ethLayer->getEthHeader()->etherType) : 0;
}


// for IPv4
void Parser::parseIPv4() {
    this->ip4_ipLayer = packet.getLayerOfType<pcpp::IPv4Layer>();
    if (this->ip4_ipLayer == nullptr) {
        return;
    }
    pcpp::iphdr *ip4_ipHeader = ip4_ipLayer->getIPv4Header();
    this->ip_version = ip4_ipHeader->ipVersion;
    this->ip_headerLen = this->ip4_ipLayer->getHeaderLen();
    this->ip4_dsfield = ip4_ipHeader->typeOfService;
    this->ip4_dscp = this->ip4_dsfield >> 2;
    this->ip4_ecn = this->ip4_dsfield & 0x3;
    this->ip4_len = ntohs(ip4_ipHeader->totalLength);
    this->ip4_id = ntohs(ip4_ipHeader->ipId);
    this->ip4_ttl = ip4_ipHeader->timeToLive;
    this->ip4_flags = ntohs(ip4_ipHeader->fragmentOffset);
    this->ip4_flags_rb = (this->ip4_flags >> 15);
    this->ip4_flags_df = (this->ip4_flags >> 14) & 1;
    this->ip4_flags_mf = (this->ip4_flags >> 13) & 1;
    this->ip4_offset = this->ip4_flags & 0x1FFF;
    this->ip4_protocol = ip4_ipHeader->protocol;
    this->ip4_checksum = ntohs(ip4_ipHeader->headerChecksum);
    this->ip4_srcIp = this->ip4_ipLayer->getSrcIPv4Address();
    this->ip4_dstIp = this->ip4_ipLayer->getDstIPv4Address();
}


// for IPv6
void Parser::parseIPv6() {
    this->ip6_ipLayer = packet.getLayerOfType<pcpp::IPv6Layer>();
    if (this->ip6_ipLayer == nullptr) {
        return;
    }
    pcpp::ip6_hdr *ip6_ipHeader = this->ip6_ipLayer->getIPv6Header();
    this->ip_version = ip6_ipHeader->ipVersion;
    this->ip_headerLen = this->ip6_ipLayer->getHeaderLen();
    this->ip6_trafficClass = ip6_ipHeader->trafficClass;
    memcpy(this->ip6_flowLabel, ip6_ipHeader->flowLabel, 3 * sizeof(uint8_t));
    this->ip6_payloadLength = ntohs(ip6_ipHeader->payloadLength);
    this->ip6_nextHeader = ip6_ipHeader->nextHeader;
    this->ip6_hopLimit = ip6_ipHeader->hopLimit;
    this->ip6_srcIp = this->ip6_ipLayer->getSrcIPv6Address();
    this->ip6_dstIp = this->ip6_ipLayer->getDstIPv6Address();
}


// for TCP
void Parser::parseTCP() {
    this->tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
    if (this->tcpLayer == nullptr) {
        return;
    }
    pcpp::tcphdr *tcpHeader = tcpLayer->getTcpHeader();
    this->tcp_headerLen = tcpLayer->getHeaderLen();
    this->tcp_srcPort = this->tcpLayer->getSrcPort();
    this->tcp_dstPort = this->tcpLayer->getDstPort();
    this->tcp_seqNum = ntohl(tcpHeader->sequenceNumber);
    this->tcp_ackNum = ntohl(tcpHeader->ackNumber);
    this->tcp_segLen = this->tcpLayer->getDataLen() - this->tcp_headerLen;
    uint8_t *data = this->tcpLayer->getData();
    this->tcp_flags = ((uint16_t)((data[12] & 0xF) << 8)) | ((uint16_t) data[13]);
    //TODO
}