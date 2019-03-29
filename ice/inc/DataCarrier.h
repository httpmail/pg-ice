#pragma once

#include "stundef.h"
#include <queue>

namespace ICE {
    class Channel;

    class DataCarrier {
    public:
        enum class send_status {
            timeout,
            ok,
            failed
        };

    protected:
        using RecvCallBack = std::function<void(const void*, int32_t)>;
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

        enum class Status {
            init,
            starting,
            started,
            quit,
        };

    public:
        DataCarrier(ICE::Channel &channel);
        virtual ~DataCarrier();

        virtual void Start();
        virtual bool Register(const std::string& target, uint16_t port, RecvCallBack recvCallback);

    public:
        void Stop();
        send_status Send(const void *data, uint32_t size, const std::string &dest, uint16_t port, uint32_t msecTimeout = 500);
        bool Unregister(const std::string& target, uint16_t port);
        void Unregister();

    protected:
        bool StartThread();
        void SetStatus(Status eStatus);
        bool IsStatus(Status eStatus);

    public:
        static void Dealloc(const void *data);

    private:
        static bool Initilize();
        static void SendThread(DataCarrier *pThis);
        static void RecvThread(DataCarrier *pThis);
        static void HandleRecvPacketsThread(DataCarrier *pThis);

    private:
        static Packet* AllocPacket();
        static void Dealloc(Packet *packet);

    private:
        static const uint16_t sPacketCacheSize = 256;
        using Buffer = std::queue<Packet*>;
        using RecvListener = std::map<TransportAddress, RecvCallBack>;

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
        std::mutex              m_SendMutex;
        std::condition_variable m_SendCond;

        Buffer                  m_RecvPackets;
        mutable std::mutex      m_RecvMutex;
        std::condition_variable m_RecvCond;

        std::condition_variable m_StatusCond;
        std::mutex              m_StatusMutex;
        Status                  m_Status;

        std::mutex     m_ListenerMutex;
        RecvListener   m_RecvListener;
    };

    class ConnectedDataCarrier : public DataCarrier {
    public:
        ConnectedDataCarrier(ICE::Channel &channel, const std::string& dest, uint16_t port);
        virtual ~ConnectedDataCarrier();

    public:
        virtual void Start() override;
        virtual bool Register(const std::string& target, uint16_t port, RecvCallBack recvCallback);

    private:
        static void ConnectThread(ConnectedDataCarrier *pThis);

    private:
        std::thread m_ConnectedThrd;
        const std::string m_dest;
        const uint16_t    m_port;
    };
}