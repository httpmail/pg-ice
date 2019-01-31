#pragma once

#include "stundef.h"
#include <queue>

namespace ICE {
    class Channel;

    class DataCarrier {
    private:
        using RecvCallBack = std::function<void(const void*, uint32_t)>;

    private:
        struct TransportAddress
        {
            bool operator < (const TransportAddress& other) const
            {
                if (&other == this)
                    return false;

                if (address == other.address)
                    return port < other.port;
                else
                    return address < other.address;
            }

            boost::asio::ip::address address;
            uint16_t                 port;
        };

        class Packet {
        public:
            Packet() {}
            ~Packet() {}

            STUN::PACKET::stun_packet m_packet;
            TransportAddress          m_Address;
            uint32_t                  m_size;
        };

    public:
        DataCarrier(ICE::Channel &channel);
        virtual ~DataCarrier();

        void Start();
        bool Send(const void *data, uint32_t size, const std::string &dest, uint16_t port);
        bool Register(const std::string& target, uint16_t port, RecvCallBack recvCallback);
        bool Unregister(const std::string& target, uint16_t port);

    private:
        bool IsQuit() const;

    private:
        static bool Initilize();
        static void SendThread(DataCarrier *pThis);
        static void RecvThread(DataCarrier *pThis);
        static void HandleRecvPacketsThread(DataCarrier *pThis);

    private:
        static Packet* AllocPacket();
        static void Dealloc(Packet* packet);

    private:
        static const uint16_t sPacketCacheSize = 256;
        using Buffer = std::queue<Packet*>;
        using RecvListerners = std::map<TransportAddress, RecvCallBack>;

    private:
        static std::condition_variable sFreePacketsCond;
        static std::mutex   sFreePacketsMutex;
        static Buffer       sFreePackets;
        static Packet       sPacketCache[sPacketCacheSize];
        static bool         sbInited;

    protected:
        ICE::Channel &m_Channel;
        std::thread   m_RecvThrd;
        std::thread   m_SendThrd;
        std::thread   m_HandThrd;

        Buffer                  m_SendPackets;
        mutable std::mutex      m_SendMutex;
        std::condition_variable m_SendCond;

        Buffer                  m_RecvPackets;
        mutable std::mutex      m_RecvMutex;
        std::condition_variable m_RecvCond;

        mutable std::mutex  m_QuitMutex;
        bool                m_bQuit;

        std::mutex m_StartedMutex;
        bool m_bStarted;

        RecvListerners m_RecvListerners;
    };
}