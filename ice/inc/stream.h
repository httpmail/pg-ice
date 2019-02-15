#pragma once

#include <stdint.h>
#include <atomic>
#include <unordered_map>
#include <thread>
#include <assert.h>


#include "candidate.h"
#include "utility.h"

namespace ICE {
    class Session;
    class Channel;
    class Media;
    class DataCarrier;

    class Stream {
    public:
        Stream(Session& session, Media &media, uint16_t comp_id, Protocol protocol, const std::string& defaultIP, uint16_t defaultPort);
        virtual ~Stream();

        Stream(const Stream&) = delete;
        Stream& operator=(const Stream&) = delete;

    public:
        bool GatherCandidates();
        bool ConnectivityCheck(const CandPeerContainer& CandPeers);
        void        GetCandidates(CandContainer &Cands) const;
        uint16_t    ComponentId() const { return m_ComponentId; }
        Protocol    GetProtocol() const { return m_Protocol; }
        const char* GetTransportProtocol() const { return "RTP/SAVP"; }
        uint16_t    GetDefaultPort() const { return m_DefaultPort; }
        const std::string& GetRemoteCandidateIP()   const { return m_ActiveChannel._rcand_ip; }
        uint16_t           GetRemoteCandidatePort() const { return m_ActiveChannel._rcand_port; }

    private:
        template<class T>
        static T* CreateChannel(const std::string& ip, uint16_t port);

        template<class T>
        static T* CreateChannel(const std::string& ip, uint16_t lowPort, uint16_t upperPort, int16_t attempts);

        static Channel* CreateChannel(Protocol protocol, const std::string &ip, uint16_t port);
        static Channel* CreateChannel(Protocol protocol, const std::string &ip, uint16_t lowport, uint16_t upperport, int16_t attempts);
        static void KeepAliveThread(Stream *pThis);

    private:
        void ReleaseCandidateChannel();
        void OnDataReceived(const void *pData, uint32_t size);

    private:
        using CandidateChannelMap = std::unordered_map<const Candidate*, Channel*>;
        enum class Status : uint8_t{
            init,
            gathering,
            gatheringdone,
            checking,
            checkingdone,
            quit,
        };

    private:
        struct ActiveChannel
        {
            Channel*         _channel    = nullptr;
            DataCarrier*     _dataCarrier = nullptr;
            const Candidate* _lcand       = nullptr;
            std::string  _rcand_ip;
            uint16_t _rcand_port;
        };

    private:
        Session &m_Session;
        Media   &m_Media;
        CandidateChannelMap m_CandChannels;
        ActiveChannel       m_ActiveChannel;
        std::atomic<Status> m_Status;
        std::thread         m_KeepAliveThrd;
        const std::string   m_DefaultIP;
        const uint16_t      m_DefaultPort;
        const uint16_t      m_ComponentId;
        const Protocol      m_Protocol;

    private:
        static const int16_t sAttempts = 5;
    };

    template<class T>
    inline T* Stream::CreateChannel(const std::string& ip, uint16_t port)
    {
        assert(port != 0);

        static_assert(!std::is_pointer<T>::value || !std::is_reference<T>::value, "channel_type cannot be pointer or ref");
        static_assert(std::is_base_of<UDPChannel, T>::value || std::is_base_of<TCPChannel, T>::value,
            "the base class of channel MUST be UDPChannel or TCPChannel");

        std::auto_ptr<T> channel(new T);
        if (!channel.get() || !channel->Bind(ip, port))
            return nullptr;
        return channel.release();
    }

    template<class T>
    inline T* Stream::CreateChannel(const std::string& ip, uint16_t lowPort, uint16_t upperPort, int16_t attempts)
    {
        assert(lowPort < upperPort);
        T* channel(nullptr);
        while (attempts--)
        {
            auto port = PG::GenerateRandom(lowPort, upperPort);
            channel   = CreateChannel<T>(ip, port);
            if (channel)
                break;
        }
        return channel;
    }
}

