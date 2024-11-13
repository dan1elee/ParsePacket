#include "PcapFileDevice.h"
#include "Packet.h"

#include "Parser.h"

#include <stdio.h>
#include <iostream>
#include <gflags/gflags.h>

DEFINE_string(filepath,
"./pcap/in.pcap", "pcap file path");

// 主函数
void analyzePcapFile(const std::string &filePath) {
    pcpp::PcapFileReaderDevice reader(filePath);
    if (!reader.open()) {
        std::cerr << "无法打开PCAP文件：" << filePath << std::endl;
        return;
    }

    pcpp::RawPacket rawPacket;
    int packetNumber = 0;
    time_t prevTimestamp = 0;
    time_t startTimestamp = 0;
    long prevTimeStampNSec = 0;
    long startTimeStampNSec = 0;
    std::cout
            << "frame.time,frame.timestamp,frame.time_delta,frame.time_relative,frame.number,frame.len,frame.protocols,"
               "eth.dst,eth.src,eth.type,"
               "ip.version,ip.hdr_len,ip.dsfield,ip.dsfield.dscp,ip.dsfield.ecn,ip.len,ip.id,"
               "ip.flags,ip.flags.rb,ip.flags.df,ip.flags.mf,ip.frag_offset,ip.ttl,ip.proto,ip.checksum,ip.src,ip.dst,"
               "ip6.version,ip6.hdr_len,ip6.trafficclass,ip6.flowlabel,ip6.payloadlen,ip6.nextHeader,ip6.ip6_hopLimit,ip6.src,ip6.dst,"
               "tcp.srcport,tcp.dstport,tcp.len,tcp.seq,tcp.nxtseq,tcp.ack,tcp.hdr_len,"
               "tcp.flags,tcp.flags.res,tcp.flags.ns,tcp.flags.cwr,tcp.flags.ecn,tcp.flags.urg,tcp.flags.ack,"
               "tcp.flags.push,tcp.flags.reset,tcp.flags.syn,tcp.flags.fin,"
               "tcp.window_size,tcp.checksum,tcp.urgent_pointer,tcp.payload,"
               "udp.srcport,udp.dstport,udp.length,udp.checksum,udp.payload"
            << std::endl;
    while (reader.getNextPacket(rawPacket)) {
        pcpp::Packet parsedPacket(&rawPacket);
        packetNumber++;
        if (packetNumber == 1) {
            Parser parser(packetNumber, parsedPacket);
            startTimestamp = parser.getStartTimeStamp();
            startTimeStampNSec = parser.getStartTimeStampNSec();

            prevTimestamp = parser.getCurrTimeStamp();
            prevTimeStampNSec = parser.getCurrTimeStampNSec();
            std::cout << parser.info() << std::endl;
        } else {
            Parser parser(packetNumber, parsedPacket, startTimestamp, prevTimestamp,
                          startTimeStampNSec, prevTimeStampNSec);
            prevTimestamp = parser.getCurrTimeStamp();
            prevTimeStampNSec = parser.getCurrTimeStampNSec();
            std::cout << parser.info() << std::endl;
        }
    }
    reader.close();
}

int main(int argc, char *argv[]) {
    gflags::ParseCommandLineFlags(&argc, &argv, true);
    analyzePcapFile(FLAGS_filepath);
    return 0;
}
