#pragma once

#include <stdint.h>
#include <thread>
#include <unordered_map>
#include <queue>

#include "stunmsg.h"

namespace ICE {
    class Channel;
    class UDPChannel;
    class TCPChannel;
}

class PacketCarrier {
    class Session;

public:
    class Packet {
    public:
        Packet();
        ~Packet();
    };

public:
    template<class T>
    PacketCarrier(T &channel, const std::string& peer, uint16_t port);

    virtual ~PacketCarrier();

    bool RegisterListener(Session* pListener);
    bool SendPacket(const STUN::MessagePacket& packet, const std::string &receiver, uint16_t port);
    bool SendPacket(const STUN::MessagePacket& packet);

private:
    static void SendThread(PacketCarrier *pThis);
    static void RecvThread(PacketCarrier *pThis);
    static void DispatchThread(PacketCarrier *pThis);
    static void ConnectThread(PacketCarrier *pThis, const std::string &peer, uint16_t port);

private:
    using ListenerMap = std::unordered_map<std::string, Session*>;
    using PacketCache = std::queue<STUN::PACKET::stun_packet*>;

private:
    ICE::Channel &m_Channel;
    ListenerMap m_Listeners;
    std::thread m_SendThrd;
    std::thread m_RecvThrd;
    std::thread m_ConnThrd;
    std::thread m_DispThrd;

    std::mutex              m_SendPacketMutex;
    std::condition_variable m_SendPacketCond;
    PacketCache             m_SendPackets;

    std::mutex              m_RecvPacketMutex;
    std::condition_variable m_RecvPacketCond;
    PacketCache             m_RecvPackets;

    const bool m_bFraming;

private:
    static std::mutex               sFreePacketMutex;
    static std::condition_variable  sFreePacketCond;
    static PacketCache              sFreePackets;
    static STUN::PACKET::stun_packet sStunPacket[1024];
};

template<class T>
inline PacketCarrier::PacketCarrier(T & channel, const std::string& peer, uint16_t port):
    m_channel(channel), m_bFraming(std::is_base_of<ICE::TCPChannel,T>::value)
{
    static_assert(std::is_pointer<T>::value, "T Cannot be pointer");
    static_assert(std::is_base_of<ICE::Channel, T>::value, "the base class of T Must be Channel");

    m_ConnThrd = std::thread(ConnectThread, this, peer, port);
}
