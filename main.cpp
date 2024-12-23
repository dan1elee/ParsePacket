#include "PcapFileDevice.h"
#include "Packet.h"
#include "Logger.h"

#include "Parser.h"

#include <cstdlib>
#include <cstring>
#include <thread>
#include <vector>
#include <mutex>
#include <iostream>
#include <fstream>
#include <gflags/gflags.h>

DEFINE_string(filepath,
"./pcap/in.pcap", "pcap file path");
DEFINE_string(outputfile,
"./output/output.txt", "output file path");
DEFINE_int32(thnum,
4, "thread num");
DEFINE_int32(chunksize,
1000, "chunk size");
DEFINE_int32(startnum,
0, "packet start frame number");
DEFINE_bool(parallel,
false, "parallel");

std::mutex mtx;
char **results;

void parsePacket(pcpp::Packet *packet, int packetNumber, int threadNum) {
    Parser parser(packetNumber, packet);
    int len = parser.getInfoLen();
    char *s = (char *) calloc(len + 1, sizeof(char *));
    strncpy(s, parser.getInfo().c_str(), len);
    s[len] = '\0';
    mtx.lock();
    results[(packetNumber - 1) % threadNum] = s;
    mtx.unlock();
}

// 主函数
void analyzePcapFile(const std::string &filePath, bool parallel, int thnum, std::ofstream &output) {
    pcpp::PcapFileReaderDevice reader(filePath);
    if (!reader.open()) {
        std::cerr << "无法打开PCAP文件：" << filePath << std::endl;
        return;
    }
    pcpp::RawPacket rawPacket;
    int packetNumber = FLAGS_startnum;
    time_t prevTimestamp = 0;
    time_t startTimestamp = 0;
    long prevTimeStampNSec = 0;
    long startTimeStampNSec = 0;
    std::string header = "frame.time,frame.timestamp,frame.number,frame.len,frame.protocols,"
                         "eth.dst,eth.src,eth.type,"
                         "ip.version,ip.hdr_len,ip_protocol,"
                         "ip.dsfield,ip.dsfield.dscp,ip.dsfield.ecn,ip.len,ip.id,"
                         "ip.flags,ip.flags.rb,ip.flags.df,ip.flags.mf,ip.frag_offset,ip.ttl,ip.proto,ip.checksum,ip.src,ip.dst,"
                         "ip6.trafficclass,ip6.flowlabel,ip6.payloadlen,ip6.nextHeader,ip6.ip6_hopLimit,ip6.src,ip6.dst,"
                         "tcp.srcport,tcp.dstport,tcp.len,tcp.seq,tcp.nxtseq,tcp.ack,tcp.hdr_len,"
                         "tcp.flags,tcp.flags.res,tcp.flags.ns,tcp.flags.cwr,tcp.flags.ecn,tcp.flags.urg,tcp.flags.ack,"
                         "tcp.flags.push,tcp.flags.reset,tcp.flags.syn,tcp.flags.fin,"
                         "tcp.window_size,tcp.checksum,tcp.urgent_pointer,tcp.payload,"
                         "udp.srcport,udp.dstport,udp.length,udp.data_len,udp.checksum,udp.payload";
    output << header << std::endl;
    if (!parallel) {
        std::stringstream ss;
        while (reader.getNextPacket(rawPacket)) {
            pcpp::Packet *parsedPacket = new pcpp::Packet(&rawPacket);
            pcpp::Packet *copiedPacket = new pcpp::Packet(*parsedPacket); // 复制一份就能避免PacketTrailer了？？？

            packetNumber++;
            if (packetNumber % 10000 == 0) {
                std::cout << "Parsed " << packetNumber << " packets" << std::endl;
            }
            Parser parser(packetNumber, copiedPacket);
            ss << parser.getInfo() << std::endl;
            if (packetNumber % FLAGS_chunksize == 0) {
                output << ss.rdbuf();
                ss.str(std::string());
            }
            delete copiedPacket;
            delete parsedPacket;
        }
        if (ss.tellp() != std::streampos(0)) {
            output << ss.rdbuf();
            ss.str(std::string());
        }
    } else {
        results = (char **) calloc(thnum, sizeof(char *));
        std::vector <std::thread> threads;
        while (reader.getNextPacket(rawPacket)) {
            pcpp::Packet *parsedPacket = new pcpp::Packet(&rawPacket);
            packetNumber++;
            pcpp::Packet *copiedPacket = new pcpp::Packet(*parsedPacket);
            threads.push_back(std::thread([copiedPacket, packetNumber, thnum]() {
                parsePacket(copiedPacket, packetNumber, thnum);
                delete copiedPacket;
            }));
            delete parsedPacket;
            if (threads.size() >= thnum) {
                for (auto &t: threads) {
                    t.join();
                }
                for (int i = 0; i < thnum; i++) {
                    if (results[i] != nullptr) {
                        output << results[i] << std::endl;
                        free(results[i]);
                        results[i] = nullptr;
                    }
                }
                threads.clear();
            }
        }
        for (auto &t: threads) {
            t.join();
        }
        for (int i = 0; i < thnum; i++) {
            if (results[i] != nullptr) {
                output << results[i] << std::endl;
                free(results[i]);
                results[i] = nullptr;
            }
        }
    }
    reader.close();
}

int main(int argc, char *argv[]) {
    gflags::ParseCommandLineFlags(&argc, &argv, true);
    std::ofstream outputFile;
    outputFile.open(FLAGS_outputfile);
    if (!outputFile.is_open()) {
        std::cerr << "Output File " << FLAGS_outputfile << " cannot be opened" << std::endl;
        return 1;
    }
    pcpp::Logger::getInstance().enableLogs();
    pcpp::Logger::getInstance().setAllModulesToLogLevel(pcpp::Logger::LogLevel::Debug);
    analyzePcapFile(FLAGS_filepath, FLAGS_parallel, FLAGS_thnum, outputFile);
    return 0;
}
