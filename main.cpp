#include "PcapFileDevice.h"
#include "Packet.h"
#include "EthLayer.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "TcpLayer.h"
#include <iostream>
#include <sstream>
#include <string>
#include <time.h>
#include <arpa/inet.h>


std::string getProtocolTypeAsString(pcpp::ProtocolType protocolType)
{
    switch (protocolType)
    {
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

std::string getProtocols(pcpp::Packet& packet){
    std::stringstream ss;
    pcpp::Layer* layer = packet.getFirstLayer();
    while (true) {
        ss << getProtocolTypeAsString(layer->getProtocol());
        layer = layer->getNextLayer();
        if (layer == nullptr)
            break;
        ss << ":";
    }
    return ss.str();
}

time_t getFrameTimeStamp(pcpp::Packet& packet) {
    timespec ts = packet.getRawPacket()->getPacketTimeStamp();
    time_t timestamp = ts.tv_sec;
    return timestamp;
}

long getFrameTimeStampNSec(pcpp::Packet& packet){
    timespec ts = packet.getRawPacket()->getPacketTimeStamp();
    long timestamp = ts.tv_nsec;
    return timestamp;
}

std::string timeStampToString(time_t timeStamp) {
    char buffer[80];
    struct tm *timeInfo = gmtime(&timeStamp);
    strftime(buffer,80,"%Y-%m-%d %H:%M:%S",timeInfo);
    return std::string(buffer);
}

int getFrameLen(pcpp::Packet& packet) {
    return packet.getRawPacket()->getRawDataLen();
}

std::string getEthDstMac(pcpp::EthLayer* ethLayer) {
    return ethLayer ? ethLayer->getDestMac().toString() : "";
}

std::string getEthSrcMac(pcpp::EthLayer* ethLayer) {
    return ethLayer ? ethLayer->getSourceMac().toString() : "";
}

uint16_t getEthType(pcpp::EthLayer* ethLayer) {
    return ethLayer->getNextLayer()? ntohs(ethLayer->getEthHeader()->etherType) : 0;
}

void parseIPv4(pcpp::Packet& packet) {
    pcpp::IPv4Layer* ipLayer = packet.getLayerOfType<pcpp::IPv4Layer>();
    pcpp::iphdr* ipHeader = ipLayer->getIPv4Header();
    uint8_t version = ipHeader->ipVersion;
    size_t headerLen = ipLayer->getHeaderLen();
    uint8_t dsfield = ipHeader->typeOfService;
    uint8_t dscp = dsfield >> 2;
    uint8_t ecn = dsfield & 0x3;
    uint16_t len = ntohs(ipHeader->totalLength);
    uint16_t id = ntohs(ipHeader->ipId);
    uint8_t ttl = ipHeader->timeToLive;
    uint16_t flags = ntohs(ipHeader->fragmentOffset);
    bool flags_rb = (flags >> 15);
    bool flags_df = (flags >> 14) & 1;
    bool flags_mf = (flags >> 13) & 1;
    uint16_t offset = flags & 0x1FFF;
    uint8_t protocol = ipHeader->protocol;
    uint16_t checksum = ntohs(ipHeader->headerChecksum);
    pcpp::IPv4Address srcIp = ipLayer->getSrcIPv4Address();
    pcpp::IPv4Address dstIp = ipLayer->getDstIPv4Address();
    //TODO
}

void parseIPv6(pcpp::Packet& packet) {
    pcpp::IPv6Layer* ipLayer = packet.getLayerOfType<pcpp::IPv6Layer>();
    pcpp::ip6_hdr* ipHeader = ipLayer->getIPv6Header();
    uint8_t version = ipHeader->ipVersion;
    size_t headerLen = ipLayer->getHeaderLen();

    //TODO
}

// 主函数
void analyzePcapFile(const std::string& filePath) {
    pcpp::PcapFileReaderDevice reader(filePath);
    if (!reader.open()) {
        std::cerr << "无法打开PCAP文件：" << filePath << std::endl;
        return;
    }

    pcpp::RawPacket rawPacket;
    int packetNumber = 1;
    long prevTimestamp = 0;
    long currTimestamp = 0;
    long startTimestamp = 0;

    int number = 0;
    while (reader.getNextPacket(rawPacket)) {
        pcpp::Packet parsedPacket(&rawPacket);
        if (number == 0){
            long ts = getFrameTimeStampNSec(parsedPacket);
            startTimestamp = ts;
            prevTimestamp = ts;
        }
        number++;
        std::cout << "Number: "<<number<<std::endl;
        currTimestamp = getFrameTimeStampNSec(parsedPacket);
        std::cout << "Time: "<< timeStampToString(getFrameTimeStamp(parsedPacket))<<std::endl;
        std::cout << "Delta: " << currTimestamp - prevTimestamp << std::endl;
        prevTimestamp = currTimestamp;
        std::cout << "Frame length: " << getFrameLen(parsedPacket) << std::endl;
        std::cout << "PROTOCOLS: "<<getProtocols(parsedPacket) << std::endl;
        pcpp::EthLayer* ethLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>();
        uint16_t ethtype = (uint16_t)0;
        if (ethLayer != nullptr) {
            std::cout << "Ethernet Dest MAC: " << getEthDstMac(ethLayer) << std::endl;
            std::cout << "Ethernet Src MAC: " << getEthSrcMac(ethLayer) << std::endl;
            std::cout << "Ethernet Type: " << getEthType(ethLayer) << std::endl;
            ethtype = getEthType(ethLayer);
        }
        switch(ethtype){
            case 0x0800:
                parseIPv4(parsedPacket);
                break;
            case 0x86DD:
                parseIPv6(parsedPacket);
                break;
            default:
                std::cout << "Unknown ethernet type: " << ethtype << std::endl;
                break;
        }
    }
    reader.close();
}

int main(){
    analyzePcapFile(filePath);
    return 0;
}
