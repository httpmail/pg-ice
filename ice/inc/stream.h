#pragma once

#include <stdint.h>
#include <unordered_map>
#include <assert.h>

#include "streamdef.h"
#include "stunmsg.h"

#include "pg_msg.h"
#include "pg_log.h"

namespace ICE {
    class CAgentConfig;
    class Channel;
    class Candidate;

    class Stream : public PG::MsgEntity{
    public:
        enum class Message {
            Gathering,
            Checking,
        };

    public:
        using CandsContainer  = std::unordered_map<Candidate*, Channel*>;
        using TimeOutInterval = std::vector<uint32_t>;

    public:
        Stream(uint16_t compId, Protocol protocol, uint16_t localPref, const std::string& hostIp, uint16_t hostPort);

        virtual ~Stream();
        bool Create(const CAgentConfig& config);
        bool GatheringCandidate(const CAgentConfig& config);
        bool ConnectivityCheck(const Candidate* lcand, const Candidate* rcand, uint64_t tieBreaker, bool bControlling, const std::string& key, const std::string& name);

        std::string GetHostIP()   const  { return std::string(); }
        uint16_t    GetHostPort() const  { return m_HostPort;}
        std::string GetTransportProtocol() const { return "RTP/SVAP";}
        std::string GetFmtDescription() const { return "0"; }
        const CandsContainer& GetCandidates() const { return m_Cands; }
        bool IsUDP() const { return m_Protocol == Protocol::udp;}
        Protocol GetProtocol() const { return m_Protocol; }
        uint16_t ComponentId() const { return m_CompId; }

    public:
        template<class T>
        static T* CreateChannel(const std::string& ip, uint16_t port)
        {
            assert(port != 0);
            static_assert(!std::is_pointer<T>::value || !std::is_reference<T>::value, "channel_type cannot be pointer or ref");
            static_assert(std::is_base_of<UDPChannel, T>::value || std::is_base_of<TCPChannel, T>::value,
                "the base class of channel MUST be UDPChannel or TCPChannel");

            constexpr bool is_udp = std::is_base_of<UDPChannel, T>::value;
            using endpoint_type = channel_type<is_udp>::endpoint;
            using socket_type = channel_type<is_udp>::socket;
           try
            {
                std::auto_ptr<T> channel(new T);
                if (channel.get() && channel->BindSocket<is_udp>(channel->Socket(), endpoint_type(boost::asio::ip::address::from_string(ip), port)))
                    return  channel.release();
                else
                    return nullptr;
            }
           catch (const std::exception& e)
            {
               LOG_ERROR("Stream", "CreateChannel exception %s", e.what());
                return nullptr;
            }
        }

        template<class T>
        static T* CreateChannel(const std::string& ip, uint16_t lowPort, uint16_t upperPort, int16_t attempts)
        {
            assert(lowPort < upperPort);

            static_assert(!std::is_pointer<T>::value || !std::is_reference<T>::value, "channel_type cannot be pointer or ref");
            static_assert(std::is_base_of<UDPChannel, T>::value || std::is_base_of<TCPChannel, T>::value,
                "the base class of channel MUST be UDPChannel or TCPChannel");

            constexpr bool is_udp = std::is_base_of<UDPChannel, T>::value;
            using endpoint_type = channel_type<is_udp>::endpoint;
            using socket_type = channel_type<is_udp>::socket;

            try
            {
                std::auto_ptr<T> channel(new T);

                endpoint_type ep(boost::asio::ip::address::from_string(ip), 0);
                while(attempts--)
                {
                    ep.port(PG::GenerateRandom(lowPort, upperPort));
                    if (channel->BindSocket<is_udp>(channel->Socket(), ep))
                        return channel.release();
                }
                return nullptr;
            }
            catch (const std::exception& e)
            {
                LOG_ERROR("Stream", "CreateChannel exception %s", e.what());
                return nullptr;
            }
        }

    private:
        bool CheckConnectivity(Stream* pThis);
        bool GatherHostCandidate(const std::string &ip, uint16_t port, Protocol protocol);
        bool GatherReflexiveCandidate(const std::string &ip, uint16_t lowerPort, uint16_t upperPort, const std::string& stunIP, uint16_t stunPort);
        bool GatherRelayedCandidate(const std::string &ip, uint16_t lowerPort, uint16_t upperPort, const std::string& turnServer, uint16_t turnPort);

    private:
        static void WaitGatheringDoneThread(Stream *pThis);

    private:
        class StunGatherHelper;
        class GatherEventSubsciber : public PG::Subscriber {
        public:
            GatherEventSubsciber(Stream* pOwner);

            ~GatherEventSubsciber()
            {
            }
            void OnPublished(const PG::Publisher *publisher, PG::MsgEntity::MSG_ID msgId, PG::MsgEntity::WPARAM wParam, PG::MsgEntity::LPARAM lParam);

        private:
            Stream *m_pOwner;
        };

        class StunCheckHelper;

        using StunGatherHelpers = std::unordered_set<StunGatherHelper*>;

        const uint16_t      m_CompId;
        const Protocol      m_Protocol;
        const std::string   m_HostIP;
        const int16_t       m_HostPort;
        const uint16_t      m_LocalPref;
        std::thread         m_GatherThrd;
        std::mutex          m_CandsMutex;
        CandsContainer      m_Cands;
        std::atomic_bool    m_Quit;

        GatherEventSubsciber    m_GatherEventSub;
        std::mutex              m_GatherMutex;

        StunGatherHelpers   m_StunPendingGather;
        int16_t             m_PendingGatherCnt;
        CandsContainer      m_SrflxCands;
        CandsContainer      m_HostCands;

        std::mutex              m_TaMutex;
        std::condition_variable m_TaCond;

        std::mutex              m_WaitingGatherMutex;
        std::condition_variable m_WaitingGatherCond;

    private:
        static const uint16_t m_MaxTries = 5;

        class StunGatherHelper : public PG::Publisher {
        public:
            enum class PubEvent : uint8_t {
                GatheringEvent,
            };

        private:
            enum class Status {
                waiting,
                failed,
                succeed,
                quit,
            };

        public:
            StunGatherHelper(Channel *channel, const std::string& stunServer, uint16_t stunPort, STUN::FirstBindReqMsg *pMsg, const TimeOutInterval& timeout);
            ~StunGatherHelper();
            void StartGathering();
            bool IsOK() const
            {
                std::lock_guard<decltype(m_Mutex)> locker(m_Mutex);
                return m_Status == Status::succeed;
            }

        private:
            bool OnStunMsg(const STUN::FirstBindRespMsg &msg);
            bool OnStunMsg(const STUN::FirstBindErrRespMsg &msg);

        private:
            static void ReceiveThread(StunGatherHelper *pThis);
            static void GatheringThread(StunGatherHelper *pThis);

        public:
            std::string         m_ConnIP;
            uint16_t            m_ConnPort;
            const std::string   m_StunIP;
            const uint16_t      m_StunPort;
            ICE::Channel       *m_Channel;

        private:
            STUN::FirstBindReqMsg *m_pBindReqMsg;
            const TimeOutInterval  m_Timeout;

            std::thread             m_GatherThread;
            std::thread             m_RecvThread;

            mutable std::mutex      m_Mutex;
            Status                  m_Status;
            std::condition_variable m_Cond;
        };
    };
}