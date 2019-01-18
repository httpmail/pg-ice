#pragma once

#include <stdint.h>
#include <unordered_map>
#include <assert.h>

#include "candidate.h"
#include "stunmsg.h"

#include "pg_msg.h"
#include "pg_log.h"

#include "utility.h"

namespace ICE {

    class Channel;

    class Stream{
    public:
        Stream(uint16_t comp_id, Protocol protocol, const std::string& hostIP, uint16_t hostPort);
        virtual ~Stream();

        Stream(const Stream&) = delete;
        Stream& operator=(const Stream&) = delete;

    public:
        bool GatherCandidate();
        bool ConnectivityCheck(bool bControlling, CandPeerContainer& candPeers, const UTILITY::AuthInfo &lAuthInfo, const UTILITY::AuthInfo &rAuthInfo);

        void        GetCandidates(CandContainer &Cands) const;
        uint16_t    ComponentId() const { return m_ComponentId; }
        Protocol    GetProtocol() const { return m_LocalProtocol; }
        const char* GetTransportProtocol() const { return sTransportProtocol;}
        uint16_t    GetDefaultPort() const { return m_DefPort; }

    private:
        template<class T>
        static T* CreateChannel(const std::string& ip, uint16_t port)
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
        static T* CreateChannel(const std::string& ip, uint16_t lowPort, uint16_t upperPort, int16_t attempts)
        {
            assert(lowPort < upperPort);
            T* channel(nullptr);
            while (attempts--)
            {
                auto port = PG::GenerateRandom(lowPort, upperPort);
                channel = CreateChannel<T>(ip, port);
                if (channel)
                    break;
            }
            return channel;
        }

    private:
        bool GatherHostCandidate(const std::string& localIP, uint16_t port);
        bool GatherSvrCandidate(const std::string& localIP, uint16_t minPort, uint16_t maxPort, const std::string& stunserver, uint16_t stunport);
        bool GatherRelayedCandidate(const std::string& localIP, uint16_t minPort, uint16_t maxPort, const std::string& turnserver, uint16_t turnport);

    private:
        static Channel*     CreateChannel(Protocol protocol, const std::string &ip, uint16_t port);
        static Channel*     CreateChannel(Protocol protocol, const std::string &ip, uint16_t lowport, uint16_t upperport, int16_t tries);
        static Candidate*   CreateHostCandidte(Protocol protocol, uint32_t pri, const std::string& foundation,
            const std::string& connIP, uint16_t connPort);
        static Candidate*   CreateSvrCandidate(Protocol protocol, uint32_t pri, const std::string& foundation,
            const std::string& connIP, uint16_t connPort,
            const std::string& baseIP, uint16_t basePort);

    private:
        class GatherSession;
        class TCPGatherSession;

        class CheckSession;
        class UDPCheckSession;
        class TCPCheckSession;

        using CandChannelContainer    = std::unordered_map<const Candidate*, Channel*>;
        using GatherSessionContainer  = std::unordered_map<GatherSession*, Channel*>;
        using CheckSessionContainer   = std::unordered_map<Channel*, CheckSession*>;
        using TimeOutInterval         = std::vector<uint32_t>;

        ////////////////////// GatherSession Subscriber //////////////////////
        class GatherSubscriber : public PG::Subscriber {
        public:
            GatherSubscriber(Stream *pOwner) : m_pOwner(pOwner) { assert(m_pOwner); }
            GatherSubscriber(const GatherSubscriber&) = delete;
            GatherSubscriber& operator=(const GatherSubscriber&) = delete;
            ~GatherSubscriber() {}
            void OnPublished(const PG::Publisher *publisher, PG::MsgEntity::MSG_ID msgId, PG::MsgEntity::WPARAM wParam, PG::MsgEntity::LPARAM lParam) override;

        private:
            Stream *m_pOwner;
        };

        ////////////////////// CheckSession Subscriber ///////////////////////
        class CheckSessionSubscriber : public PG::Subscriber {
        public:
            CheckSessionSubscriber(Stream &Owner) : m_Owner(Owner) {}
            CheckSessionSubscriber(const GatherSubscriber&) = delete;
            CheckSessionSubscriber& operator=(const CheckSessionSubscriber&) = delete;
            ~CheckSessionSubscriber() {}
            void OnPublished(const PG::Publisher *publisher, PG::MsgEntity::MSG_ID msgId, PG::MsgEntity::WPARAM wParam, PG::MsgEntity::LPARAM lParam) override;

        private:
            Stream &m_Owner;
        };

    private:
        std::mutex              m_CandChannelsMutex;
        CandChannelContainer    m_CandChannels;

        std::mutex              m_GatherSessionMutex;
        std::condition_variable m_GatherSessionCond;
        GatherSessionContainer  m_GatherSessions;      /* the gathering has been done */
        GatherSessionContainer  m_PendingGatherSessions;


        GatherSubscriber        m_GatherSubscriber;

        std::mutex              m_TaMutex;
        std::condition_variable m_TaCond;

        CheckSessionContainer   m_CheckSessions;
        CheckSessionSubscriber  m_CheckSubscriber;

        UTILITY::AuthInfo       m_LocalAuthInfo;
        UTILITY::AuthInfo       m_RemoteAuthInfo;
        uint64_t                m_TieBreaker;
        const uint16_t          m_DefPort;
        const std::string       m_DefIP;

        const uint16_t          m_ComponentId;
        Protocol                m_LocalProtocol;
        bool                    m_bControlling;

    private:
        static const int16_t    m_MaxTries = 5;
        static const TimeOutInterval sUDPTimeoutInterval;
        static const TimeOutInterval sTCPTimeoutInterval;
        static const char*           sTransportProtocol;
    };
}