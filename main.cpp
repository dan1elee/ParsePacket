#include "PcapFileDevice.h"
#include "Packet.h"

#include <stdio.h>
#include <iostream>
#include "Parser.h"

// 主函数
void analyzePcapFile(const std::string &filePath) {
    pcpp::PcapFileReaderDevice reader(filePath);
    if (!reader.open()) {
        std::cerr << "无法打开PCAP文件：" << filePath << std::endl;
        return;
    }

    pcpp::RawPacket rawPacket;
    int packetNumber = 0;
    long prevTimestamp = 0;
    long startTimestamp = 0;

    while (reader.getNextPacket(rawPacket)) {
        pcpp::Packet parsedPacket(&rawPacket);
        packetNumber++;
        if (packetNumber == 1) {
            Parser parser(packetNumber, parsedPacket);
            startTimestamp = parser.getStartTimeStamp();
            prevTimestamp = parser.getCurrTimeStamp();
        } else {
            Parser parser(packetNumber, parsedPacket, startTimestamp, prevTimestamp);
            prevTimestamp = parser.getCurrTimeStamp();
        }
    }
    reader.close();
}

int main() {
    std::string filePath = "/mnt/e/traffic/actual.pcap";
    analyzePcapFile(filePath);
    return 0;
}
