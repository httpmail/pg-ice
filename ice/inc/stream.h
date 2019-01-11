#pragma once

#include <stdint.h>
#include <unordered_map>
#include <assert.h>

#include "candidate.h"
#include "stunmsg.h"

#include "pg_msg.h"
#include "pg_log.h"
#include "channel.h"

#include "utility.h"

namespace ICE {
    class CAgentConfig;
    class Channel;

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
        bool ConnectivityCheck(const Candidate* lcand, const Candidate* rcand, uint64_t tieBreaker, bool bControlling,
            const std::string& lpwd, const std::string& rpwd,
            const std::string& lufrag, const std::string& rufrag);

        std::string GetHostIP()   const  { return std::string(); }
        uint16_t    GetHostPort() const  { return m_HostPort;}
        std::string GetTransportProtocol() const { return "RTP/SVAP";}
        std::string GetFmtDescription() const { return "0"; }
        const CandsContainer& GetCandidates() const { return m_Cands; }
        Protocol GetProtocol() const { return m_Protocol; }
        uint16_t ComponentId() const { return m_CompId; }

    public:
        template<class T>
        static T* CreateChannel(const typename channel_type<std::is_base_of<UDPChannel, T>::value>::endpoint &ep)
        {
            static_assert(!std::is_pointer<T>::value, "T cannot be pointer");
            static_assert(std::is_base_of<UDPChannel, T>::value || std::is_base_of<TCPChannel, T>::value,
                "the base class of T must be UDPChannel or TCPChannel");

            std::auto_ptr<T> channel(new T);
            if (!channel.get() || !channel->BindSocket(channel->Socket(), ep))
                return nullptr;

            return channel.release();
        }

        template<class T>
        static T* CreateChannel(const std::string& ip, uint16_t port)
        {
            assert(port != 0);

            static_assert(!std::is_pointer<T>::value || !std::is_reference<T>::value, "channel_type cannot be pointer or ref");
            static_assert(std::is_base_of<UDPChannel, T>::value || std::is_base_of<TCPChannel, T>::value,
                "the base class of channel MUST be UDPChannel or TCPChannel");

            using endpoint_type = channel_type<std::is_base_of<UDPChannel, T>::value>::endpoint;

            return CreateChannel<T>(endpoint_type(boost::asio::ip::address::from_string(ip), port));
        }

        template<class T>
        static T* CreateChannel(const std::string& ip, uint16_t lowPort, uint16_t upperPort, int16_t attempts)
        {
            assert(lowPort < upperPort);

            static_assert(!std::is_pointer<T>::value || !std::is_reference<T>::value, "channel_type cannot be pointer or ref");
            static_assert(std::is_base_of<UDPChannel, T>::value || std::is_base_of<TCPChannel, T>::value,
                "the base class of channel MUST be UDPChannel or TCPChannel");

            using endpoint_type = channel_type<std::is_base_of<UDPChannel, T>::value>::endpoint;

            endpoint_type ep(boost::asio::ip::address::from_string(ip), 0);

            T* channel(nullptr);

            while (attempts--)
            {
                ep.port(PG::GenerateRandom(lowPort, upperPort));
                auto channel = CreateChannel<T>(ep);
                if (nullptr != (channel = CreateChannel<T>(ep)))
                    break;
            }
            return channel;
        }

    private:
        bool GatherHostCandidate(const std::string &ip, uint16_t port, Protocol protocol);
        bool GatherReflexiveCandidate(const std::string &ip, uint16_t lowerPort, uint16_t upperPort, const std::string& stunIP, uint16_t stunPort);
        bool GatherRelayedCandidate(const std::string &ip, uint16_t lowerPort, uint16_t upperPort, const std::string& turnServer, uint16_t turnPort);

    private:
        static Channel* CreateChannel(Protocol protocol);

    private:
        static void WaitGatheringDoneThread(Stream *pThis);
        static void ConnectivityRecvThread(Stream *pThis, Channel *channel);

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
        struct peer{
            peer(const Candidate* lcand, const Candidate* rcand):
                _lcand(lcand),_rcand(rcand)
            {
            }
            const Candidate* _lcand;
            const Candidate* _rcand;
        };

        using StunGatherHelpers = std::unordered_set<StunGatherHelper*>;
        using StunCheckHelpers  = std::unordered_map<StunCheckHelper*,peer>;

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

        std::mutex          m_PendingCheckersMutex;
        StunCheckHelpers    m_PendingCheckers;

        StunGatherHelpers   m_StunPendingGather;
        int16_t             m_PendingGatherCnt;

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


namespace STUN {
    using namespace ICE;

    class Stream : public PG::MsgEntity{
    public:
        enum class Message {
            Gather,
            ConnectivityCheck,
        };

    public:
        Stream(uint16_t comp_id, Protocol protocol);
        virtual ~Stream();

        Stream(const Stream&) = delete;
        Stream& operator=(const Stream&) = delete;

    public:
        bool GatherCandidate(const std::string& localIP, uint16_t port,
            uint16_t Ta, const UTILITY::PortRange& portRange,
            const UTILITY::Servers& stunServer, const UTILITY::Servers& turnServer);

        bool ConnectivityCheck(CandPeerContainer& candPeers);

    private:
        template<class T>
        static T* CreateChannel(const typename channel_type<std::is_base_of<UDPChannel, T>::value>::endpoint &ep)
        {
            static_assert(!std::is_pointer<T>::value, "T cannot be pointer");
            static_assert(std::is_base_of<UDPChannel, T>::value || std::is_base_of<TCPChannel, T>::value,
                "the base class of T must be UDPChannel or TCPChannel");

            std::auto_ptr<T> channel(new T);
            if (!channel.get() || !channel->BindSocket(channel->Socket(), ep))
                return nullptr;

            return channel.release();
        }

        template<class T>
        static T* CreateChannel(const std::string& ip, uint16_t port)
        {
            assert(port != 0);

            static_assert(!std::is_pointer<T>::value || !std::is_reference<T>::value, "channel_type cannot be pointer or ref");
            static_assert(std::is_base_of<UDPChannel, T>::value || std::is_base_of<TCPChannel, T>::value,
                "the base class of channel MUST be UDPChannel or TCPChannel");

            using endpoint_type = channel_type<std::is_base_of<UDPChannel,T>::value>::endpoint;

            return CreateChannel<T>(endpoint_type(boost::asio::ip::address::from_string(ip), port));
        }

        template<class T>
        static T* CreateChannel(const std::string& ip, uint16_t lowPort, uint16_t upperPort, int16_t attempts)
        {
            assert(lowPort < upperPort);

            static_assert(!std::is_pointer<T>::value || !std::is_reference<T>::value, "channel_type cannot be pointer or ref");
            static_assert(std::is_base_of<UDPChannel, T>::value || std::is_base_of<TCPChannel, T>::value,
                "the base class of channel MUST be UDPChannel or TCPChannel");

            using endpoint_type = channel_type<std::is_base_of<UDPChannel, T>::value>::endpoint;

            endpoint_type ep(boost::asio::ip::address::from_string(ip), 0);

            T* channel(nullptr);

            while (attempts--)
            {
                ep.port(PG::GenerateRandom(lowPort, upperPort));
                auto channel = CreateChannel<T>(ep);
                if (nullptr != (channel = CreateChannel<T>(ep)))
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
        class CheckSession;
        using CandChannelContainer    = std::unordered_map<const Candidate*, Channel*>;
        using SessionChannelContaienr = std::unordered_map<GatherSession*,   Channel*>;
        using CheckSessionContainer   = std::unordered_map<Channel*,         CheckSession*>;
        using TimeOutInterval         = std::vector<uint32_t>;

    private:
        static const TimeOutInterval UDPTimeoutInterval;
        static const TimeOutInterval TCPTimeoutInterval;

        ////////////////////// GatherSession class //////////////////////
        class GatherSession : public PG::Publisher{
        public:
            enum class Message : uint16_t{
                StatusChange
            };

        protected:
            enum class Status : uint16_t {
                waiting_resp = 0,
                failed,
                succeed,
                quit,
            };

        public:
            GatherSession(const Stream* pOwner, const TimeOutInterval& timeout, STUN::TransIdConstRef id, Channel& channel, const std::string& targetIP, uint16_t port);
            virtual ~GatherSession();

            GatherSession(const GatherSession& other) = delete;
            GatherSession& operator=(const GatherSession& other) = delete;

        public:
            virtual bool Start();

        protected:
            virtual void OnStunMessage(const STUN::FirstBindRespMsg     &respMsg);
            virtual void OnStunMessage(const STUN::FirstBindErrRespMsg  &errRespMsg);

        protected:
            static void RecvThread(GatherSession *pThis);
            static void SendThread(GatherSession *pThis);

        protected:
            STUN::FirstBindReqMsg   m_ReqMsg;
            const TimeOutInterval  &m_timeout;
            Channel                &m_Channel;
            std::thread             m_RecvThrd;
            std::thread             m_SendThrd;
            std::mutex              m_StatusMutex;
            std::condition_variable m_StatusCond;
            Status                  m_Status;
            const std::string       m_TargetIP;
            const uint16_t          m_TargetPort;
            const Stream*           m_pOwner;
        };

        ////////////////////// GatherSession class //////////////////////
        class TCPGatherSession : public GatherSession {
        public:
            using GatherSession::GatherSession;
            ~TCPGatherSession();

        public:
            virtual bool Start() override;

        private:
            static void ConnectThread(TCPGatherSession* pThis);

        private:
            std::thread m_ConnectThrd;
        };

        ////////////////////// GatherSession Subscriber //////////////////////
        class GatherSubscriber : public PG::Subscriber {
        public:
            GatherSubscriber(Stream *pOwner) : m_pOwner(pOwner) { assert(m_pOwner); }
            GatherSubscriber(const GatherSubscriber&) = delete;
            GatherSubscriber& operator=(const GatherSubscriber&) = delete;
            ~GatherSubscriber() {}
            void OnPublished(const PG::Publisher *publisher, MsgEntity::MSG_ID msgId, MsgEntity::WPARAM wParam, MsgEntity::LPARAM lParam) override;

        private:
            Stream *m_pOwner;
        };

        ////////////////////// CheckSession class //////////////////////
        class CheckSession : public PG::Publisher{
        public:
            enum class Message {
                RoleConflict,
                ConnectivityCheck,
                Nominate
            };

        public:
            CheckSession(Stream &Owner, const UTILITY::AuthInfo &lAuthInfo, const UTILITY::AuthInfo &rAuthInfo);
            CheckSession(const CheckSession&) = delete;
            CheckSession& operator=(const CheckSession&) = delete;
            virtual ~CheckSession() = 0 {}

        public:
             bool CreateChecker(Channel &channel, const Candidate& lcand, const Candidate &rcand);
             size_t CheckerNumber() const { return m_Checks.size(); }

        public:
            virtual bool Start() = 0;

        private:
            ////////////////////// checker class /////////////////////
            class Checker {
            public:
                Checker(CheckSession &Owner, Channel& channel, const Candidate& lcand, const Candidate& rcand, STUN::TransIdConstRef id, bool bControlling, uint64_t tieBreaker);
                ~Checker();

            private:
                void OnStunMessage(const STUN::SubBindReqMsg     &reqMsg);
                void OnStunMessage(const STUN::SubBindErrRespMsg &errRespMsg);
                void OnStunMessage(const STUN::SubBindResqMsg    &RespMsg);

            private:
                CheckSession        &m_Owner;
                const Candidate     &m_LCand;
                const Candidate     &m_RCand;
                STUN::SubBindReqMsg  m_ReqMsg;
                Channel             &m_Channel;
            };

        protected:
            using CheckerContainer = std::unordered_map<std::string, Checker*>; /* std::string = ip + port */

        protected:
            std::string MakeKey(const std::string &ip, uint16_t port);
            Checker* FindChecker(const std::string& ip, uint16_t port);

        protected:
            const UTILITY::AuthInfo     &m_LocalAuthInfo;
            const UTILITY::AuthInfo     &m_RemoteAuthInfo;
            Stream                      &m_Owner;
            CheckerContainer             m_Checks;
            std::mutex                   m_Mutex;
            bool                         m_bQuit;
        };

        class UDPCheckSession : public CheckSession {
        public:
            UDPCheckSession(Stream &Owner, UDPChannel &channel, const UTILITY::AuthInfo &lAuthInfo, const UTILITY::AuthInfo &rAuthInfo);
            ~UDPCheckSession();

        public:
            bool Start() override;

        private:
            static void RecvThread(UDPCheckSession *pThis);

        private:
            std::thread m_RecvThrd;
            std::mutex  m_Mutex;
            bool        m_bQuit;
            UDPChannel  &m_Channel;
        };

        class TCPPassCheckSession : public CheckSession {
        public:
            TCPPassCheckSession(Stream &Owner, TCPPassiveChannel &channel, const UTILITY::AuthInfo &lAuthInfo, const UTILITY::AuthInfo &rAuthInfo);
        };

        class TCPActCheckSession : public CheckSession {
        public:
            TCPActCheckSession(Stream &Owner, TCPActiveChannel &channel, const UTILITY::AuthInfo &lAuthInfo, const UTILITY::AuthInfo &rAuthInfo);

        };

        ////////////////////// checker class end /////////////////////

    private:
        std::mutex              m_CandChannelsMutex;
        CandChannelContainer    m_CandChannels;
        
        std::mutex              m_SessionChannelMutex;
        SessionChannelContaienr m_SessionChannels;
        std::condition_variable m_SessionChannelCond;
        GatherSubscriber        m_GatherSubscriber;

        std::mutex              m_TaMutex;
        std::condition_variable m_TaCond;

        CheckSessionContainer   m_CheckSessions;
        int16_t                 m_SessionCnt;
        const uint16_t          m_ComponentId;
        uint32_t                m_LocalPref;
        Protocol          m_LocalProtocol;
        uint64_t          m_TieBreaker;
        bool                    m_bControlling;
        UTILITY::AuthInfo       m_LocalAuthInfo;
        UTILITY::AuthInfo       m_RemoteAuthInfo;

    private:
        static const int16_t    m_MaxTries = 5;
    };
}