//
// Created by DELL on 2024/11/13 013.
//

#include "Parser.h"
#include <iostream>

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
            this->parseIPv4();
            break;
        case 0x86DD:
            this->isV6 = true;
            this->parseIPv6();
            break;
        default:
            break;
    }
}


// for frame
void Parser::parseFrame() {
    this->currTimeStamp = getFrameTimeStamp();
    this->currTimeStampNSec = getFrameTimeStampNSec();
    this->time_str = timeStampToString(this->getFrameTimeStamp());
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
    return this->packet->getRawPacket()->getRawDataLen();
}

time_t Parser::getFrameTimeStamp() {
    timespec ts = this->packet->getRawPacket()->getPacketTimeStamp();
    time_t timestamp = ts.tv_sec;
    return timestamp;
}

long Parser::getFrameTimeStampNSec() {
    timespec ts = this->packet->getRawPacket()->getPacketTimeStamp();
    long timestamp = ts.tv_nsec;
    return timestamp;
}

std::string Parser::getFrameProtocols() {
    std::stringstream ss;
    pcpp::Layer *layer = packet->getFirstLayer();
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
    this->ethLayer = this->packet->getLayerOfType<pcpp::EthLayer>();
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
    this->ip4_ipLayer = packet->getLayerOfType<pcpp::IPv4Layer>();
    if (this->ip4_ipLayer == nullptr) {
        return;
    }
    pcpp::iphdr *ip4_ipHeader = ip4_ipLayer->getIPv4Header();
    this->ip_version = ip4_ipHeader->ipVersion;
    this->ip4_srcIp = this->ip4_ipLayer->getSrcIPv4Address();
    this->ip4_dstIp = this->ip4_ipLayer->getDstIPv4Address();
}


// for IPv6
void Parser::parseIPv6() {
    this->ip6_ipLayer = packet->getLayerOfType<pcpp::IPv6Layer>();
    if (this->ip6_ipLayer == nullptr) {
        return;
    }
    pcpp::ip6_hdr *ip6_ipHeader = this->ip6_ipLayer->getIPv6Header();
    this->ip_version = ip6_ipHeader->ipVersion;
    this->ip6_srcIp = this->ip6_ipLayer->getSrcIPv6Address();
    this->ip6_dstIp = this->ip6_ipLayer->getDstIPv6Address();
}

void Parser::genInfo() {
    std::stringstream ss;

    // frame
    ss << time_str;
    ss << "," << currTimeStamp << "." << std::setw(9) << std::setfill('0') << currTimeStampNSec;
    ss << std::dec;
    ss << "," << packetNumber;
    ss << "," << frameLen;
    ss << "," << protocols;
    //eth
    if (ethLayer != nullptr) {
        ss << "," << dstMac.toString();
        ss << "," << srcMac.toString();
        ss << "," << std::hex << "0x" << ethType;
        ss << std::dec;
    } else {
        ss << ",,,";
    }

    if ((!isV6 && ip4_ipLayer != nullptr) || (isV6 && ip6_ipLayer != nullptr)) {
        ss << std::dec;
        ss << "," << static_cast<int>(ip_version);
    } else {
        ss << ",";
    }

    //ipv4
    if (!isV6 && ip4_ipLayer != nullptr) {
        ss << "," << ip4_srcIp.toString();
        ss << "," << ip4_dstIp.toString();
    } else {
        ss << ",,";
    }
    //ipv6
    if (isV6 && ip6_ipLayer != nullptr) {
        ss << "," << ip6_srcIp.toString();
        ss << "," << ip6_dstIp.toString();
    } else {
        ss << ",,";
    }
    this->info = ss.str();
}

std::string Parser::getInfo() {
    return this->info;
}