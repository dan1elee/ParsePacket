#ifndef PARSEPACKET_FLOW_H
#define PARSEPACKET_FLOW_H

#include <unordered_map>
#include <iostream>
#include "TcpReassembly.h"
#include "IpAddress.h"


struct TcpReassemblyData;

typedef std::unordered_map <uint32_t, TcpReassemblyData> TcpReassemblyConnMgr;

struct TcpReassemblyData {

    // a flag indicating on which side was the latest message on this connection
    int8_t curSide;

    // stats data: num of data packets on each side, bytes seen on each side and messages seen on each side
    int numOfDataPackets[2];
    int numOfMessagesFromSide[2];
    int bytesFromSide[2];
    pcpp::IPAddress ip[2];
    uint16_t port[2];

    TcpReassemblyData() {
        clear();
    }

    ~TcpReassemblyData() {
    }

    void clear() {
        numOfDataPackets[0] = 0;
        numOfDataPackets[1] = 0;
        numOfMessagesFromSide[0] = 0;
        numOfMessagesFromSide[1] = 0;
        bytesFromSide[0] = 0;
        bytesFromSide[1] = 0;
        curSide = -1;
    }
};

static void
tcpReassemblyMsgReadyCallback(const int8_t sideIndex, const pcpp::TcpStreamData &tcpData, void *userCookie) {
    auto connMgr = (TcpReassemblyConnMgr *) userCookie;

    auto flow = connMgr->find(tcpData.getConnectionData().flowKey);
    if (flow == connMgr->end()) {
        connMgr->insert(std::make_pair(tcpData.getConnectionData().flowKey, TcpReassemblyData()));
        flow = connMgr->find(tcpData.getConnectionData().flowKey);
    }

    int8_t side = 0;

    if (sideIndex != flow->second.curSide) {
        flow->second.numOfMessagesFromSide[sideIndex]++;
        flow->second.curSide = sideIndex;
    }

    // count number of packets and bytes in each side of the connection
    flow->second.numOfDataPackets[sideIndex]++;
    flow->second.bytesFromSide[sideIndex] += (int) tcpData.getDataLength();
}

static void tcpReassemblyConnectionStartCallback(const pcpp::ConnectionData &connectionData, void *userCookie) {
    auto connMgr = (TcpReassemblyConnMgr *) userCookie;
    auto connectionMngr = connMgr->find(connectionData.flowKey);

    if (connectionMngr == connMgr->end()) {
        auto tcpRData = TcpReassemblyData();
        tcpRData.ip[0] = connectionData.srcIP;
        tcpRData.ip[1] = connectionData.dstIP;
        tcpRData.port[0] = connectionData.srcPort;
        tcpRData.port[1] = connectionData.dstPort;

        connMgr->insert(std::make_pair(connectionData.flowKey, tcpRData));
    }
}

static void tcpReassemblyConnectionEndCallback(const pcpp::ConnectionData &connectionData,
                                               pcpp::TcpReassembly::ConnectionEndReason reason, void *userCookie) {
    auto connMgr = (TcpReassemblyConnMgr *) userCookie;

    auto connection = connMgr->find(connectionData.flowKey);

    if (connection == connMgr->end())
        return;

    std::cout << std::endl;
    std::cout << "IP: " << connection->second.ip[0] << ":" << connection->second.port[0] << " "
              << connection->second.ip[1] << ":" << connection->second.port[1] << std::endl;
    std::cout << "Number of data packets in side 0:  " << connection->second.numOfDataPackets[0] << std::endl;
    std::cout << "Number of data packets in side 1:  " << connection->second.numOfDataPackets[1] << std::endl;
    std::cout << "Total number of data packets:      "
              << (connection->second.numOfDataPackets[0] + connection->second.numOfDataPackets[1]) << std::endl;
    std::cout << "Number of bytes in side 0:         " << connection->second.bytesFromSide[0] << std::endl;
    std::cout << "Number of bytes in side 1:         " << connection->second.bytesFromSide[1] << std::endl;
    std::cout << "Total number of bytes:             "
              << (connection->second.bytesFromSide[0] + connection->second.bytesFromSide[1]) << std::endl;
    std::cout << "Number of messages in side 0:      " << connection->second.numOfMessagesFromSide[0]
              << std::endl;
    std::cout << "Number of messages in side 1:      " << connection->second.numOfMessagesFromSide[1]
              << std::endl;

    std::cout << std::endl;

    connMgr->erase(connection);
}

#endif