#pragma once

#include <stdint.h>
#include <atomic>
#include <unordered_map>
#include <thread>
#include <queue>
#include <mutex>
#include <assert.h>

#include "candidate.h"
#include "utility.h"

namespace ICE {
    class Session;
    class Channel;
    class Media;
    class DataCarrier;

    class Stream {
        using OnRxCB = std::function<void(const void *, uint32_t)>;

    public:
        Stream(Session& session, Media &media,uint16_t comp_id,Protocol protocol,const std::string& defaultIP, uint16_t defaultPort, OnRxCB rxCB);
        virtual ~Stream();

        Stream(const Stream&) = delete;
        Stream& operator=(const Stream&) = delete;

    public:
        /**
         * Function : GatherCandidates
         * Description : none-thread-safe
         */

        bool GatherCandidates();

        /**
        * Function : ConnectivityCheck
        * Description : none-thread-safe
        */
        bool ConnectivityCheck(const CandPeerContainer& CandPeers);

        void               GetCandidates(CandContainer &Cands) const;
        uint16_t           ComponentId() const { return m_ComponentId; }
        Protocol           GetProtocol() const { return m_Protocol; }
        const char*        GetTransportProtocol() const { return "RTP/SAVP"; }
        uint16_t           GetDefaultPort() const { return m_DefaultPort; }
        const std::string& GetRemoteCandidateIP()   const { return m_ActiveChannel._rcand_ip; }
        uint16_t           GetRemoteCandidatePort() const { return m_ActiveChannel._rcand_port; }
        bool               SendData(const void *pData, uint32_t size);
        void               Shutdown();
        void               CancleConnectivityCheck();

    private:
        template<class T>
        static T* CreateChannel(const std::string& ip, uint16_t port, bool bReuse = false);

        template<class T>
        static T* CreateChannel(const std::string& ip, uint16_t lowPort, uint16_t upperPort, int16_t attempts, bool bReuse = false);

        static Channel* CreateChannel(Protocol protocol, const std::string &ip, uint16_t port);
        static Channel* CreateChannel(Protocol protocol, const std::string &ip, uint16_t lowport, uint16_t upperport, int16_t attempts);
        static void KeepAliveThread(Stream *pThis);

    private:
        using CandidateChannelMap = std::unordered_map<const Candidate*, Channel*>;
        enum class Status : uint8_t {
            init,
            gathering,
            gatheringdone,
            checking,
            checkingdone,
            quit,
        };

    private:
        void OnDataReceived(const void *pData, uint32_t size);
        bool IsStatus(Status eStatus) const;
        void SetStatus(Status eStatus);

    private:
        struct ActiveChannel
        {
            bool _bValid              = false;
            Channel* _channel         = nullptr;
            DataCarrier* _dataCarrier = nullptr;
            const Candidate* _lcand   = nullptr;
            std::string _rcand_ip;
            OnRxCB   _rx_cb;
            uint16_t _rcand_port;
        };

    private:
        Session &m_Session;
        Media   &m_Media;
        std::mutex              m_CandChannelsMutex;
        CandidateChannelMap     m_CandChannels;
        std::mutex              m_ActiveMutex;
        ActiveChannel           m_ActiveChannel;
        mutable std::mutex      m_StatusMutex;
        std::condition_variable m_StatusCond;
        Status                  m_Status;
        std::thread             m_KeepAliveThrd;
        std::condition_variable m_KeepAliveCond;
        const std::string       m_DefaultIP;
        const uint16_t          m_DefaultPort;
        const uint16_t          m_ComponentId;
        const Protocol          m_Protocol;

    private:
        static const int16_t sAttempts = 5;
    };

    template<class T>
    inline T* Stream::CreateChannel(const std::string& ip, uint16_t port, bool bReuse /*= false*/)
    {
        assert(port != 0);

        static_assert(!std::is_pointer<T>::value || !std::is_reference<T>::value, "channel_type cannot be pointer or ref");
        static_assert(std::is_base_of<UDPChannel, T>::value || std::is_base_of<TCPChannel, T>::value,
            "the base class of channel MUST be UDPChannel or TCPChannel");

        std::auto_ptr<T> channel(new T);
        if (!channel.get() || !channel->Bind(ip, port, bReuse))
            return nullptr;
        return channel.release();
    }

    template<class T>
    inline T* Stream::CreateChannel(const std::string& ip, uint16_t lowPort, uint16_t upperPort, int16_t attempts, bool bReuse /*= false*/)
    {
        assert(lowPort < upperPort);
        T* channel(nullptr);
        while (attempts--)
        {
            auto port = PG::GenerateRandom(lowPort, upperPort);
            channel   = CreateChannel<T>(ip, port, bReuse);
            if (channel)
                break;
        }
        return channel;
    }
}

