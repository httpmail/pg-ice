#include "stream.h"
#include "candidate.h"
#include "stunmsg.h"
#include "agent.h"
#include "channel.h"
#include "pg_log.h"
#include "config.h"
#include <boost/lexical_cast.hpp>

namespace ICE {
    /*
    RFC4389
    For example, assuming an RTO of 500 ms,
    requests would be sent at times 0 ms, 500 ms, 1500 ms, 3500 ms, 7500
    ms, 15500 ms, and 31500 ms.  If the client has not received a
    response after 39500 ms
    */
    const Stream::TimeOutInterval Stream::sUDPTimeoutInterval = { 500, 1000,2000,4000,8000,16000, 8000 };
    const Stream::TimeOutInterval Stream::sTCPTimeoutInterval = { 39500 };
    const char* Stream::sTransportProtocol = "RTP/SAVP";

    ////////////////////// GatherSession class //////////////////////
    class Stream::GatherSession : public PG::Publisher {
    public:
        enum class Message : uint16_t {
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
        GatherSession(const Stream* pOwner, const Stream::TimeOutInterval& timeout, STUN::TransIdConstRef id, Channel& channel, const std::string& targetIP, uint16_t port);
        virtual ~GatherSession();

        GatherSession(const GatherSession& other) = delete;
        GatherSession& operator=(const GatherSession& other) = delete;

    public:
        virtual bool Initilize();
        Candidate*   GetCandidate() const { return m_pCandidate; }

    protected:
        void OnStart();

    private:
        void OnStunMessage(const STUN::FirstBindRespMsg     &respMsg);
        void OnStunMessage(const STUN::FirstBindErrRespMsg  &errRespMsg);

    private:
        static void RecvThread(GatherSession *pThis);
        static void SendThread(GatherSession *pThis);

    protected:
        STUN::FirstBindReqMsg   m_ReqMsg;
        const TimeOutInterval  &m_timeout;
        Channel                &m_Channel;

        std::mutex              m_StatusMutex;
        std::condition_variable m_StatusCond;
        Status                  m_Status;
        Candidate              *m_pCandidate;
        const std::string       m_TargetIP;
        const uint16_t          m_TargetPort;
        const Stream*           m_pOwner;

    private:
        std::thread m_RecvThrd;
        std::thread m_SendThrd;
    };

    ////////////////////// TCPGatherSession class //////////////////////
    class Stream::TCPGatherSession : public Stream::GatherSession {
    public:
        using Stream::GatherSession::GatherSession;
        ~TCPGatherSession();

    public:
        virtual bool Initilize() override;

    private:
        static void ConnectThread(TCPGatherSession* pThis);

    private:
        std::thread m_ConnectThrd;
    };

    ////////////////////// CheckSession class //////////////////////
    class Stream::CheckSession : public PG::Publisher {
    public:
        enum class Message : uint16_t {
            StatusChanged
        };

    protected:
        enum class CheckStatus : uint16_t {
            failed,
            nominated,
            passed,
        };

    public:
        CheckSession(Stream& owner, Channel &channel, const TimeOutInterval& timer, const UTILITY::AuthInfo &lauthInfo, const UTILITY::AuthInfo &rauthInfo);
        ~CheckSession();

    public:
        bool CreateChecker(uint64_t pri, const Candidate &lcand, const Candidate &rcand);
        uint64_t TieBreaker() const { return m_Owner.m_TieBreaker;}
        bool IsControlling()  const { return m_Owner.m_bControlling; }

    public:
        virtual bool Initilize() = 0;

    protected:
        void OnStart();

    private:
        class Checker;
        struct CheckListKey {
        public:
            CheckListKey() {}
            CheckListKey(const std::string &key, uint64_t pri = 0) :
                _key(key), _pri(pri)
            {
            }
            bool operator()(const CheckListKey& v1, const CheckListKey& v2) const
            {
                if (v1._pri < v1._pri)
                    return true;

                if (v1._key == v2._key)
                    return false;

                if (v1._pri == v2._pri)
                    return v1._key < v2._key;
                else
                    return v1._pri < v2._pri;
            }

            bool operator< (const CheckListKey& other) const
            {
                if (&other == this)
                    return false;

                return _key < other._key;

                if (_pri < other._pri)
                    return true;
                else if (_pri > other._pri)
                    return false;

                return _key < other._key;
#if 0
                if (_pri == other._pri)
                    return _key < other._key;

                if (_key == other._key)
                    return _key < other._key;

                return _pri < other._pri;
#endif
            }

            const std::string& Key() const { return _key; }
            uint64_t Pri() const { return _pri; }
        private:
            std::string _key;
            uint64_t    _pri;
        };
        using CheckList = std::map   <CheckListKey, Checker*>; /* @key = lcand ip + rcand ip*/

    private:
        void OnCheckerCompleted(Checker &chekcer, CheckStatus eStatus);

    private:
        static void RecvThread(CheckSession *pThis);

    protected:
        Channel               &m_Channel;
        const TimeOutInterval &m_Timer;

    private:
        Stream      &m_Owner;
        std::thread  m_RecvThrd;

    private:
        const UTILITY::AuthInfo &m_LAuthInfo;
        const UTILITY::AuthInfo &m_RAuthInfo;

    private:
        static std::mutex sCheckMutex;
        static CheckList sCheckList;
        static CheckList sFailedCheckList;
        static CheckList sPassedCheckList;
    };

    std::mutex Stream::CheckSession::sCheckMutex;
    Stream::CheckSession::CheckList Stream::CheckSession::sCheckList;
    Stream::CheckSession::CheckList Stream::CheckSession::sFailedCheckList;
    Stream::CheckSession::CheckList Stream::CheckSession::sPassedCheckList;

    /////////////////////////////////////// UDPCheckSession class ////////////////////////////////////////////////
    class Stream::UDPCheckSession : public CheckSession {
    public:
        using Stream::CheckSession::CheckSession;

    public:
        bool Initilize() override { OnStart(); return true; }
    };

    /////////////////////////////////////// TCPCheckSession class ////////////////////////////////////////////////
    class Stream::TCPCheckSession : public CheckSession {
    public:
        TCPCheckSession(Stream& owner,
                        Channel &channel,
                        const std::string& peer,
                        uint16_t port,
                        const TimeOutInterval& timer,
                        const UTILITY::AuthInfo &lauthInfo,
                        const UTILITY::AuthInfo &rauthInfo);

    public:
        bool Initilize() override;

    private:
        static void ConnectThread(TCPCheckSession *pThis);

    private:
        std::thread m_ConnThrd;
        const std::string m_peer;
        const uint16_t    m_port;
    };

    /////////////////////////////////////// Stream class ////////////////////////////////////////////////
    Stream::Stream(uint16_t comp_id, Protocol protocol, const std::string& hostIP, uint16_t hostPort) :
        m_ComponentId(comp_id), m_LocalProtocol(protocol),
        m_GatherSubscriber(this),
        m_DefIP(hostIP), m_DefPort(hostPort)
    {
        assert(hostPort);
    }

    Stream::~Stream()
    {
    }

    bool Stream::GatherCandidate()
    {
        auto & config = Configuration::Instance();
        /*
          !!!! Notice !!!! 
          in Gather Phase, just create UDPChannel or TCPChannel. DONOT create TCPPassiveChannel
         */
        // gather host candidates
        GatherHostCandidate(m_DefIP, m_DefPort);

        // gather server reflex candidates
        for (auto stun_itor = config.StunServer().begin(); stun_itor != config.StunServer().end(); ++stun_itor)
        {
            if (!GatherSvrCandidate(m_DefIP, config.GetPortRange().Min(), config.GetPortRange().Max(), stun_itor->IP(), stun_itor->Port()))
                continue;

            std::unique_lock<decltype(m_TaMutex)> locker(m_TaMutex);
            m_TaCond.wait_for(locker, std::chrono::milliseconds(config.Ta()));
        }

        std::unique_lock<decltype(m_GatherSessionMutex)> locker(m_GatherSessionMutex);
        m_GatherSessionCond.wait(locker, [this]() {
            return this->m_PendingGatherSessions.size() == 0;
        });

        for (auto itor = m_GatherSessions.begin(); itor != m_GatherSessions.end(); ++itor)
        {
            assert(itor->first && itor->second);


            auto session   = itor->first;
            auto candidate = session->GetCandidate();
            std::auto_ptr<Channel> channel(itor->second);

            if (candidate)
            {
                /*
                * !!!! Notice !!!!
                * reallocate corresponding channel, cause in gathering phase, only tcp channel
                */
                if (m_LocalProtocol != Protocol::udp)
                {
                    std::string ip = channel->IP();
                    uint16_t port = channel->Port();
                    channel->Close();
                    channel.reset(CreateChannel(m_LocalProtocol, ip, port));
                }

                if (!channel.get() || !m_CandChannels.insert(std::make_pair(candidate, channel.get())).second)
                {
                    delete candidate;
                    LOG_ERROR("Stream", "Gather failed to create channle [%s:%d]", channel->IP().c_str(), channel->Port());
                }
                else
                {
                    LOG_ERROR("Stream", "Gather succeed [%s:%d]", channel->IP().c_str(), channel->Port());
                    channel.release();
                }
            }
            else
            {
                channel->Close();
            }

            // release session
            session->Unsubscribe(&m_GatherSubscriber);
            delete session;
        }

        return m_CandChannels.size() > 0;
    }

    bool Stream::ConnectivityCheck(bool bControlling, CandPeerContainer & candPeers, const UTILITY::AuthInfo &lAuthInfo, const UTILITY::AuthInfo &rAuthInfo)
    {
        using namespace PG;

        class CheckSessionSubscriber : public PG::Subscriber {
        public:
            CheckSessionSubscriber(int16_t sess_cnt) :
                m_SessCnt(sess_cnt)
            {
                assert(m_SessCnt);
            }

            void WaitSessionDone()
            {
                std::unique_lock<decltype(m_Mutex)> locker(m_Mutex);
                m_Cond.wait(locker, [this]() {
                    return this->m_SessCnt <= 0;
                });
            }

        public:
            virtual void OnPublished(const Publisher *publisher, MsgEntity::MSG_ID msgId, MsgEntity::WPARAM wParam, MsgEntity::LPARAM lParam) override
            {
                std::lock_guard<decltype(m_Mutex)> locker(m_Mutex);
                if (m_SessCnt-- <= 0)
                    m_Cond.notify_one();
            }
        private:
            std::mutex              m_Mutex;
            std::condition_variable m_Cond;
            int16_t                 m_SessCnt;
        };

        m_LocalAuthInfo     = lAuthInfo;
        m_RemoteAuthInfo    = rAuthInfo;
        m_bControlling      = bControlling;

        CheckSessionContainer sessions;
        for (auto peer_itor = candPeers.begin(); peer_itor != candPeers.end(); ++peer_itor)
        {
            const Candidate &lcand = peer_itor->LCandidate();
            const Candidate &rcand = peer_itor->RCandidate();
            auto pri = peer_itor->Priority();

            auto candchannel_itor = m_CandChannels.find(const_cast<Candidate*>(&lcand));

            assert(candchannel_itor != m_CandChannels.end());

            auto channel = candchannel_itor->second;
            auto sess_itor = sessions.find(channel);

            CheckSession* pSession(nullptr);

            if (sess_itor == sessions.end())
            {
                if(m_LocalProtocol == Protocol::udp)
                    pSession = new UDPCheckSession(*this, *channel, sUDPTimeoutInterval, m_LocalAuthInfo, m_RemoteAuthInfo);
                else
                    pSession = new TCPCheckSession(*this, *channel, rcand.m_ConnIP, rcand.m_ConnPort, sTCPTimeoutInterval, m_LocalAuthInfo, m_RemoteAuthInfo);
            }
            else
            {
                pSession = sess_itor->second;
            }

            if (!pSession)
            {
                LOG_ERROR("Stream", "Connectivity Check failed to Create check session [%s:%d] => [%s:%d]",
                    channel->IP().c_str(), channel->Port(),
                    rcand.m_ConnIP.c_str(), rcand.m_ConnPort);
                continue;
            }

            if (!pSession->CreateChecker(pri, lcand, rcand))
            {
                LOG_ERROR("Stream", "Connectivity Check failed to Create check [%s:%d] => [%s:%d]",
                    channel->IP().c_str(), channel->Port(),
                    rcand.m_ConnIP.c_str(), rcand.m_ConnPort);

                if (sess_itor == sessions.end())
                    delete pSession;
                continue;
            }

            if (sess_itor == sessions.end() && !sessions.insert(std::make_pair(channel, pSession)).second)
            {
                LOG_ERROR("Stream", "Connectivity Check failed to insert [%p], [%s:%d] => [%s:%d]",
                    channel,
                    channel->IP().c_str(), channel->Port(),
                    rcand.m_ConnIP.c_str(), rcand.m_ConnPort);

                if (sess_itor == sessions.end())
                    delete pSession;
                continue;
            }

        }

        CheckSessionSubscriber subscriber(sessions.size());
        for (auto sess_itor = sessions.begin(); sess_itor != sessions.end(); ++sess_itor)
        {
            if (!sess_itor->second->Initilize() || !sess_itor->second->Subscribe(&subscriber, static_cast<MsgEntity::MSG_ID>(CheckSession::Message::StatusChanged)))
            {
                LOG_ERROR("Stream", "Connectivity Check cannot Start check session %lld", sess_itor->second);
                continue;
            }
        }

        subscriber.WaitSessionDone();

        //
        if (m_bControlling)
        {
        }
        return true;
    }

    void Stream::GetCandidates(CandContainer & Cands) const
    {
        std::for_each(m_CandChannels.begin(), m_CandChannels.end(), [&Cands](auto &itor) {
            Cands.push_back(itor.first);
        });
    }

    bool Stream::GatherHostCandidate(const std::string & localIP, uint16_t port)
    {
        /*
        !!!! Notice !!!!
        in Gather Phase, just create UDPChannel or TCPChannel. DONOT create TCPPassiveChannel
        */
        std::auto_ptr<Channel> channel(CreateChannel(m_LocalProtocol == Protocol::udp ? m_LocalProtocol : Protocol::tcp_act,
            localIP, port));

        if (!channel.get())
        {
            LOG_ERROR("Stream", "GatherHostCandidate Failed to creat channel : [%s:%d]", localIP.c_str(), port);
            return false;
        }

        auto foundation = Candidate::ComputeFoundations(Candidate::CandType::host, localIP, localIP, m_LocalProtocol);
        auto priority   = Candidate::ComputePriority(Candidate::CandType::host, Configuration::Instance().LocalPref(), m_ComponentId);

        std::auto_ptr<Candidate> cand(CreateHostCandidte(m_LocalProtocol, priority, foundation, localIP, port));

        if (!cand.get())
        {
            LOG_ERROR("Stream", "GatherHostCandidate Failed to Creat Candidate [%d]", m_LocalProtocol);
            return false;
        }

        {
            std::lock_guard<decltype(m_CandChannelsMutex)> locker(m_CandChannelsMutex);
            if (!m_CandChannels.insert(std::make_pair(cand.get(), channel.get())).second)
                return false;
        }

        cand.release();
        channel.release();

        return true;
    }

    bool Stream::GatherSvrCandidate(const std::string& localIP, uint16_t lowPort, uint16_t highPort, const std::string& stunserver, uint16_t stunport)
    {
        /*
            !!!!Notice !!!!
            in Gather Phase, just create UDPChannel or TCPChannel.DONOT create TCPPassiveChannel
        */

        auto protocol = m_LocalProtocol == Protocol::udp ? m_LocalProtocol : Protocol::tcp_act;
        std::auto_ptr<Channel> channel(CreateChannel(protocol, localIP, lowPort, highPort, m_MaxTries));

        if (!channel.get())
        {
            LOG_ERROR("Stream", "GatherSvrCandidate failed to creating channel : [%s] => [%s:%d]", localIP.c_str(), stunserver.c_str(), stunport);
            return false;
        }

        STUN::TransId id;
        STUN::MessagePacket::GenerateRFC5389TransationId(id);

        std::auto_ptr<GatherSession> session(nullptr);
        if (m_LocalProtocol == Protocol::udp)
            session.reset(new GatherSession(this, sUDPTimeoutInterval, id, *channel.get(), stunserver, stunport));
        else
            session.reset(new TCPGatherSession(this, sTCPTimeoutInterval, id, *channel.get(), stunserver, stunport));

        if (!session.get())
        {
            LOG_ERROR("Stream", "GatherSvrCandidate Failed to create gather session : [%s] => [%s:%d]", localIP.c_str(), stunserver.c_str(), stunport);
            return false;
        }

        if (!session->Subscribe(&m_GatherSubscriber, static_cast<PG::MsgEntity::MSG_ID>(GatherSession::Message::StatusChange)))
        {
            LOG_ERROR("Stream", "Subscribe session message error");
            return false;
        }

        std::lock_guard<decltype(m_GatherSessionMutex)> locker(m_GatherSessionMutex);
        if (!m_PendingGatherSessions.insert(std::make_pair(session.get(), channel.get())).second)
        {
            LOG_ERROR("Stream", "GatherSvrCandidate Failed to create session channel pair");
            return false;
        }

        if (!session->Initilize())
        {
            LOG_ERROR("Stream", "Start Gather Session failed");
            m_PendingGatherSessions.erase(session.get());
            return false;
        }

        session.release();
        channel.release();
        return true;
    }

    Channel* Stream::CreateChannel(Protocol protocol, const std::string &ip, uint16_t port)
    {
        switch (protocol)
        {
        case Protocol::udp:
            return CreateChannel<UDPChannel>(ip, port);

        case Protocol::tcp_act:
            return CreateChannel<TCPChannel>(ip, port);

        case Protocol::tcp_pass:
            return CreateChannel<TCPPassiveChannel>(ip, port);

        default:
            assert(0);
            return nullptr;
        }
    }

    Channel * Stream::CreateChannel(Protocol protocol, const std::string & ip, uint16_t lowport, uint16_t upperport, int16_t tries)
    {
        switch (protocol)
        {
        case Protocol::udp:
            return CreateChannel<UDPChannel>(ip, lowport, upperport, tries);

        case Protocol::tcp_act:
            return CreateChannel<TCPChannel>(ip, lowport, upperport, tries);

        case Protocol::tcp_pass:
            return CreateChannel<TCPPassiveChannel>(ip, lowport, upperport, tries);

        default:
            assert(0);
            return nullptr;
        }
    }

    Candidate * Stream::CreateHostCandidte(Protocol protocol, uint32_t pri, const std::string & foundation, const std::string & connIP, uint16_t connPort)
    {
        switch (protocol)
        {
        case Protocol::udp:
            return new HostCand(pri, foundation, connIP, connPort);

        case Protocol::tcp_act:
            return new ActiveCand(pri, foundation, connIP, connPort);

        case Protocol::tcp_pass:
            return new PassiveCand(pri, foundation, connIP, connPort);

        default:
            assert(0);
            return nullptr;
        }
    }

    Candidate * Stream::CreateSvrCandidate(Protocol protocol, uint32_t pri, const std::string & foundation, const std::string & connIP, uint16_t connPort, const std::string & baseIP, uint16_t basePort)
    {
        switch (protocol)
        {
        case Protocol::udp:
            return new  SvrCand(pri, foundation, connIP, connPort, baseIP, basePort);

        case Protocol::tcp_act:
            return new SvrActiveCand(pri, foundation, connIP, connPort, baseIP, basePort);

        case Protocol::tcp_pass:
            return new SvrPassiveCand(pri, foundation, connIP, connPort, baseIP, basePort);

        default:
            assert(0);
            return nullptr;
        }
    }

    /////////////////////////////////////// GatherSession class ////////////////////////////////////////////////
    Stream::GatherSession::GatherSession(const Stream* pOwner, const TimeOutInterval& timeout, STUN::TransIdConstRef id, Channel & channel,
        const std::string& targetIP, uint16_t port) :
        m_ReqMsg(id), m_timeout(timeout), m_Channel(channel), m_pOwner(pOwner), m_TargetIP(targetIP), m_TargetPort(port), m_Status(Status::waiting_resp),
        m_pCandidate(nullptr)
    {
        RegisterMsg(static_cast<PG::MsgEntity::MSG_ID>(Message::StatusChange));
        assert(pOwner);
    }

    Stream::GatherSession::~GatherSession()
    {
        if (m_RecvThrd.joinable())
        {
            LOG_INFO("GatherSession", "Close RecvThread");
            m_RecvThrd.join();
        }
        if (m_SendThrd.joinable())
            m_SendThrd.join();

        LOG_INFO("GatherSession", "~GatherSession");
    }

    bool Stream::GatherSession::Initilize()
    {
        assert(m_pOwner->m_LocalProtocol == Protocol::udp);

        if (!m_Channel.Connect(m_TargetIP, m_TargetPort))
        {
            LOG_ERROR("GatherSession", "Connect Remote Server Failed [%s:%d]", m_TargetIP.c_str(), m_TargetPort);
            return false;
        }

        OnStart();
        return true;
    }

    void Stream::GatherSession::OnStart()
    {
        assert(m_Status == Status::waiting_resp);
        m_SendThrd = std::thread(SendThread, this);
        m_RecvThrd = std::thread(RecvThread, this);
    }

    void Stream::GatherSession::OnStunMessage(const STUN::FirstBindRespMsg & respMsg)
    {
        LOG_INFO("Stream", "GatherSession Received Bind Response");

        bool bSucceed = false;
        std::string ip;
        uint16_t port;

        {
            const STUN::ATTR::MappedAddress *pMappedAddr(nullptr);
            const STUN::ATTR::XorMappAddress *pXormapAddr(nullptr);
            const STUN::ATTR::XorMappedAddrSvr *pXormappedAddr(nullptr);
            if (respMsg.GetAttribute(pMappedAddr))
            {
                bSucceed = true;
                ip = pMappedAddr->IP();
                port = pMappedAddr->Port();
            }
            else if (respMsg.GetAttribute(pXormapAddr))
            {
                bSucceed = true;
                ip = pXormapAddr->IP();
                port = pXormapAddr->Port();
            }
            else if (respMsg.GetAttribute(pXormappedAddr))
            {
                bSucceed = true;
                ip = pXormappedAddr->IP();
                port = pXormappedAddr->Port();
            }
        }

        if (bSucceed)
        {
            auto foundation = Candidate::ComputeFoundations(Candidate::CandType::svr_ref, m_Channel.IP(), m_TargetIP, m_pOwner->m_LocalProtocol);
            auto priority   = Candidate::ComputePriority(Candidate::CandType::svr_ref, Configuration::Instance().LocalPref(), m_pOwner->m_ComponentId);
            m_pCandidate    = Stream::CreateSvrCandidate(m_pOwner->m_LocalProtocol, priority, foundation,
                ip, port,
                m_Channel.IP(), m_Channel.Port());

            std::unique_lock<decltype(m_StatusMutex)> locker(m_StatusMutex);
            m_Status = m_pCandidate ? Status::succeed : Status::failed;
            m_StatusCond.notify_one();
        }
    }

    void Stream::GatherSession::OnStunMessage(const STUN::FirstBindErrRespMsg & errRespMsg)
    {
        LOG_INFO("Stream", "GatherSession Received Bind Error Response, Set Status to failed");
        std::unique_lock<decltype(m_StatusMutex)> locker(m_StatusMutex);
        m_Status = Status::failed;
        m_StatusCond.notify_one();
    }

    void Stream::GatherSession::RecvThread(GatherSession * pThis)
    {
        assert(pThis);

        do
        {
            STUN::PACKET::stun_packet packet;

            auto bytes = pThis->m_Channel.Recv(&packet, sizeof(packet));
            if (bytes <= 0)
            {
                // wake up send thread
                pThis->m_Status = Status::failed;
                pThis->m_StatusCond.notify_one();
                break;
            }
            else if (STUN::MessagePacket::IsValidStunPacket(packet, bytes))
            {
                switch (packet.MsgId())
                {
                case STUN::MsgType::BindingErrResp:
                    pThis->OnStunMessage(STUN::FirstBindErrRespMsg(packet, bytes));
                    break;

                case STUN::MsgType::BindingResp:
                    pThis->OnStunMessage(STUN::FirstBindRespMsg(packet, bytes));
                    break;

                default:
                    break;
                }
            }
            std::lock_guard<decltype(pThis->m_StatusMutex)> locker(pThis->m_StatusMutex);
        } while (pThis->m_Status == Status::waiting_resp);
    }

    void Stream::GatherSession::SendThread(GatherSession * pThis)
    {
        auto cnt = pThis->m_timeout.size();

        for (decltype(cnt) i = 0; i < cnt; ++i)
        {
            auto start = std::chrono::steady_clock::now();
            if (!pThis->m_ReqMsg.SendData(pThis->m_Channel))
            {
                LOG_ERROR("GatherSession", "Failed to send request message");

                std::lock_guard<decltype(pThis->m_StatusMutex)> locker(pThis->m_StatusMutex);
                pThis->m_Status = Status::failed;
                pThis->Publish(static_cast<uint16_t>(Message::StatusChange), PG::MsgEntity::WPARAM(false), nullptr);
                return;
            }

            std::unique_lock<decltype(pThis->m_StatusMutex)> locker(pThis->m_StatusMutex);

            auto ret = pThis->m_StatusCond.wait_for(locker, std::chrono::milliseconds(pThis->m_timeout[i]), [&pThis]() {
                return pThis->m_Status != Status::waiting_resp;
            });

            if (ret)
                break;

            LOG_ERROR("GatherSession", "[%s:%d] =>[%s:%d]transmit cnt (= %d)",
                pThis->m_Channel.IP().c_str(), pThis->m_Channel.Port(),
                pThis->m_TargetIP.c_str(), pThis->m_TargetPort,
                i + 1);
        }

        std::lock_guard<decltype(pThis->m_StatusMutex)> locker(pThis->m_StatusMutex);
        if (pThis->m_Status == Status::waiting_resp)
        {
            LOG_ERROR("GatherSession", "GatherSession failed because of timeout");
            pThis->m_Status = Status::failed;
        }
        pThis->Publish(static_cast<uint16_t>(Message::StatusChange), PG::MsgEntity::WPARAM(pThis->m_Status == Status::succeed), nullptr);
    }

    /////////////////////////////////////// TCPGatherSession class ////////////////////////////////////////////////
    Stream::TCPGatherSession::~TCPGatherSession()
    {
        if (m_ConnectThrd.joinable())
            m_ConnectThrd.join();
    }

    bool Stream::TCPGatherSession::Initilize()
    {
        assert(m_Status == Status::waiting_resp);
        m_ConnectThrd = std::thread(ConnectThread, this);
        return true;
    }

    void Stream::TCPGatherSession::ConnectThread(TCPGatherSession * pThis)
    {
        assert(pThis);
        assert(pThis->m_pOwner->m_LocalProtocol != Protocol::udp);

        LOG_INFO("Stream", "[%s:%d] Try to connect [%s:%d]", pThis->m_Channel.IP().c_str(), pThis->m_Channel.Port(), pThis->m_TargetIP.c_str(), pThis->m_TargetPort);

        if (!pThis->m_Channel.Connect(pThis->m_TargetIP, pThis->m_TargetPort))
        {
            LOG_ERROR("TCP GatherSession", "Connect failed [%s:%d]",
                pThis->m_TargetIP.c_str(), pThis->m_TargetPort);

            pThis->m_Status = Status::failed;
            pThis->Publish(static_cast<uint16_t>(Message::StatusChange), PG::MsgEntity::WPARAM(false), nullptr);
            return;
        }

        pThis->OnStart();
    }

    void Stream::GatherSubscriber::OnPublished(const PG::Publisher * publisher, PG::MsgEntity::MSG_ID msgId, PG::MsgEntity::WPARAM wParam, PG::MsgEntity::LPARAM lParam)
    {
        assert(m_pOwner && publisher);

        std::lock_guard<decltype(m_pOwner->m_GatherSessionMutex)> locker(m_pOwner->m_GatherSessionMutex);

        auto session = reinterpret_cast<const GatherSession*>(publisher);

        auto itor = m_pOwner->m_PendingGatherSessions.find(const_cast<GatherSession*>(session));

        assert(itor != m_pOwner->m_PendingGatherSessions.end());
        assert(static_cast<GatherSession::Message>(msgId) == GatherSession::Message::StatusChange);

        LOG_INFO("Stream", "Gather Session has been completed [%s]", wParam ? "Succeed" : "Failed");

        if (!m_pOwner->m_GatherSessions.insert(std::make_pair(itor->first, itor->second)).second)
        {
            LOG_ERROR("GatherSession", "GatherSession insert error");
        }

        m_pOwner->m_PendingGatherSessions.erase(itor);
        if (m_pOwner->m_PendingGatherSessions.empty())
            m_pOwner->m_GatherSessionCond.notify_one();

        m_pOwner->m_TaCond.notify_one();
    }

    /////////////////////////////////////// Checker class ////////////////////////////////////////////////
    class Stream::CheckSession::Checker {
    public:
        Checker(CheckSession& owner, uint64_t pri, const Candidate& lcand, const Candidate& rcand);
        ~Checker();

    protected:
        enum class Status : uint16_t {
            waiting_resp = 0,
            failed,
            succeed,
            nominated,
            quit,
        };

        enum TransmitStatus : uint8_t{
            init = 0b00000000,
            lr   = 0b00000001,
            rl   = 0b00000010,
        };

    public:
        bool Start(bool bNominated = false);
        uint64_t Priority() const { return m_Pri; }
        const Candidate& RemoteCandidate() const { return m_RemoteCandidate;}
        const Candidate& LocalCandidate()  const { return m_LocalCandidate; }
        std::string MakeCheckListKey() const;

    public:
        void OnStunMessage(const STUN::SubBindReqMsg &reqMsg, const std::string& sender, uint16_t port);
        void OnStunMessage(const STUN::SubBindRespMsg &respMsg);
        void OnStunMessage(const STUN::SubBindErrRespMsg &errRespMsg);
        void OnRecvErrorEvent();

    private:
        void SetStatus(Status eStatus);
        bool IsStatus(Status eStatus);

    private:
        static void SendThread(Checker* pThis);

    private:
        const Candidate         &m_LocalCandidate;
        const Candidate         &m_RemoteCandidate;
        CheckSession            &m_Owner;
        STUN::SubBindReqMsg     *m_pReqMsg;
        std::thread             m_SendThread;
        std::condition_variable m_SendCond;

        uint64_t                m_Pri;
        std::mutex              m_StatusMutex;
        Status                  m_Status;
        std::mutex              m_TransStatusMutex;
        uint8_t                 m_TransStatus;
    };

    Stream::CheckSession::Checker::Checker(CheckSession & owner, uint64_t pri, const Candidate & lcand, const Candidate & rcand) :
        m_Owner(owner),
        m_LocalCandidate(lcand),
        m_RemoteCandidate(rcand),
        m_pReqMsg(nullptr),
        m_Pri(pri),
        m_Status(Status::waiting_resp),
        m_TransStatus(init)
    {
    }

    Stream::CheckSession::Checker::~Checker()
    {
        delete m_pReqMsg;
        m_pReqMsg = nullptr;
        if (m_SendThread.joinable())
            m_SendThread.join();
    }

    bool Stream::CheckSession::Checker::Start(bool bNominated /*= false */)
    {
        using namespace STUN;

        delete m_pReqMsg;

        TransId id;
        MessagePacket::GenerateRFC5389TransationId(id);
        m_pReqMsg = new STUN::SubBindReqMsg(m_LocalCandidate.m_Priority,
            id,
            m_Owner.IsControlling(),
            m_Owner.TieBreaker(),
            m_Owner.m_RAuthInfo._ufrag + ":" + m_Owner.m_LAuthInfo._ufrag,
            m_Owner.m_RAuthInfo._pwd);

        if (!m_pReqMsg)
            return false;

        if (bNominated)
            m_pReqMsg->AddAttribute(ATTR::UseCandidate());

        m_SendThread = std::thread(SendThread, this);
        m_SendThread.detach();
        return true;
    }

    std::string Stream::CheckSession::Checker::MakeCheckListKey() const
    {
        try
        {
            return m_LocalCandidate.m_BaseIP + boost::lexical_cast<std::string>(m_LocalCandidate.m_BasePort) +
                m_RemoteCandidate.m_ConnIP + boost::lexical_cast<std::string>(m_RemoteCandidate.m_ConnPort);
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("Checker", "MakeCheckListKey exception [%s:%d]->[%s:%d]:%s",
                m_LocalCandidate.m_BaseIP.c_str(), m_LocalCandidate.m_BasePort,
                m_RemoteCandidate.m_ConnIP.c_str(), m_RemoteCandidate.m_ConnPort,
                e.what());
            return "";
        }
    }

    void Stream::CheckSession::Checker::OnStunMessage(const STUN::SubBindReqMsg & reqMsg, const std::string & sender, uint16_t port)
    {
        using namespace STUN;
        //RFC8445 [7.1.  STUN Extensions]
        const ATTR::Role *pRole(nullptr);
        const ATTR::Priority *pPriority(nullptr);
        const ATTR::UseCandidate *pUseCandidate(nullptr);

        if (!reqMsg.GetAttribute(pRole) && !reqMsg.GetAttribute(pPriority))
        {
            LOG_WARNING("Checker", "bind request has no role or priority attribute, ignored");
            return;
        }

        if (m_Owner.IsControlling() && reqMsg.GetAttribute(pUseCandidate))
        {
            LOG_WARNING("Checker", "Controlling agent receviced 'use-candidate', ignored");
            return;
        }

        if ( 0 == (m_TransStatus&TransmitStatus::rl)
             && pUseCandidate)
        {
            LOG_ERROR("Checker", "Must be agressive mode, just ignored");
            return;
        }

        {// RFC5389 10.2.2. Receiving a Request
            const ATTR::MessageIntegrity *pMsgIntegrity(nullptr);
            const ATTR::UserName *pUsername(nullptr);
            if (!reqMsg.GetAttribute(pMsgIntegrity) || !reqMsg.GetAttribute(pUsername))
            {
                LOG_ERROR("CheckSession", "400 MessageIntegrity unmatched");
                // 400 bad request
                SubBindErrRespMsg errRespMsg(reqMsg.TransationId(), 4, 0, "bad-request");
                errRespMsg.SendData(m_Owner.m_Channel, sender, port);
            }
            else if ((m_Owner.m_LAuthInfo._ufrag + ":" + m_Owner.m_RAuthInfo._ufrag) != pUsername->Name())
            {
                // 401 Unauthorized
                SubBindErrRespMsg errRespMsg(reqMsg.TransationId(), 4, 1, "unmatched-username");
                errRespMsg.SendData(m_Owner.m_Channel, sender, port);
            }
            else if (!MessagePacket::VerifyMsgIntegrity(reqMsg, m_Owner.m_LAuthInfo._pwd))
            {
                // 401 Unauthorized
                SubBindErrRespMsg errRespMsg(reqMsg.TransationId(), 4, 1, "unmatched-MsgIntegrity");
                errRespMsg.SendData(m_Owner.m_Channel, sender, port);
            }
            else if (reqMsg.GetUnkonwnAttrs().size())
            {
                SubBindErrRespMsg errRespMsg(reqMsg.TransationId(), 4, 20, "Unknown-Attribute");
                errRespMsg.AddUnknownAttributes(reqMsg.GetUnkonwnAttrs());
                errRespMsg.SendData(m_Owner.m_Channel, sender, port);
            }
            else if ((m_Owner.IsControlling()) == (pRole->Type() == ATTR::Id::IceControlling))
            {
                // RFC8445 [7.3.1.1.  Detecting and Repairing Role Conflicts]
                if ((m_Owner.IsControlling() && m_Owner.TieBreaker() >= pRole->TieBreaker()) ||
                    (!m_Owner.IsControlling() && m_Owner.TieBreaker() < pRole->TieBreaker()))
                {
                    SubBindErrRespMsg errRespMsg(reqMsg.TransationId(), 4, 87, "Role-Conflict");
                    errRespMsg.SendData(m_Owner.m_Channel, sender, port);
                }
                else
                {
                    //TODO switch role
                }
            }
            else
            {
                assert(!pUseCandidate || (pUseCandidate && (m_TransStatus & TransmitStatus::rl)));

                ATTR::XorMappAddress xorMapAddr;
                xorMapAddr.Port(port);

                //TODO current we only support ipv4
                assert(boost::asio::ip::address::from_string(sender).is_v4());

                xorMapAddr.Address(boost::asio::ip::address::from_string(sender).to_v4().to_uint());
                SubBindRespMsg respMsg(reqMsg.TransationId(), xorMapAddr, m_Owner.m_LAuthInfo._pwd);

                // if send response faild just set as never received this message
                if (respMsg.SendData(m_Owner.m_Channel, sender, port))
                {
                    m_TransStatus |= TransmitStatus::rl;
                    if (pUseCandidate)
                    {
                        SetStatus(Status::nominated);
                        m_SendCond.notify_one();
                    }
                }
            }
        }
    }

    void Stream::CheckSession::Checker::OnStunMessage(const STUN::SubBindRespMsg & respMsg)
    {
        using namespace STUN;

        LOG_INFO("CheckSession", "SubBindRespMsg Received");

        assert(m_pReqMsg);

        const ATTR::MessageIntegrity *pMsgIntegrity(nullptr);

        if (!respMsg.IsTransIdEqual(m_pReqMsg->TransationId()))
        {
            LOG_ERROR("Checker", "unequal transation Id");
            return;
        }

        if (!respMsg.GetAttribute(pMsgIntegrity) || !MessagePacket::VerifyMsgIntegrity(respMsg, m_Owner.m_RAuthInfo._pwd))
        {
            /*
            RFC5389 [10.1.3.  Receiving a Response]
            If the value does not match, or if
            MESSAGE-INTEGRITY was absent, the response MUST be discarded, as if
            it was never received
            */
            LOG_ERROR("Checker", "illegal message-integrity");
            return;
        }

        const ATTR::XorMappAddress *pXorMapAddr(nullptr);
        if (respMsg.GetUnkonwnAttrs().size())
        {
            /*
            RFC5389 [7.3.3.  Processing a Success Response]
            If the success response contains unknown comprehension-required
            attributes, the response is discarded and the transaction is
            considered to have failed.
            */
            LOG_ERROR("Checker", "found unkonwn-attributs, set transaction as failed");
            SetStatus(Status::failed);
            m_SendCond.notify_one();
        }
        else if (respMsg.GetAttribute(pXorMapAddr) && 
                 pXorMapAddr->IP() == m_LocalCandidate.m_BaseIP &&
                 pXorMapAddr->Port() == m_LocalCandidate.m_BasePort)
        {
            /*
            RFC5245 [7.1.3.1.  Failure Cases]
            The agent MUST check that the source IP address and port of the
            response equal the destination IP address and port to which the
            Binding request was sent, and that the destination IP address and
            port of the response match the source IP address and port from which
            the Binding request was sent.  In other words, the source and
            destination transport addresses in the request and responses are
            symmetric.  If they are not symmetric, the agent sets the state of
            the pair to Failed.
            */
            SetStatus(Status::succeed);
            m_SendCond.notify_one();
        }
        else
        {
            LOG_ERROR("Checker", "No XormappAddress or no symmetric address [%s:%d]",
                pXorMapAddr->IP().c_str(), pXorMapAddr->Port());
            SetStatus(Status::failed);
            m_SendCond.notify_one();
        }
    }

    void Stream::CheckSession::Checker::OnStunMessage(const STUN::SubBindErrRespMsg & errRespMsg)
    {
        using namespace STUN;

        assert(m_pReqMsg);

        const ATTR::ErrorCode *pErrCode(nullptr);
        const ATTR::MessageIntegrity *pMsgIntegrity(nullptr);

        LOG_INFO("CheckSession", "SubBindErrRespMsg Received");

        if (!errRespMsg.IsTransIdEqual(m_pReqMsg->TransationId()))
        {
            LOG_ERROR("Checker", "unequal transation Id");
            return;
        }

        if (!errRespMsg.GetAttribute(pMsgIntegrity) || !MessagePacket::VerifyMsgIntegrity(errRespMsg, m_Owner.m_RAuthInfo._pwd))
        {
            /*
            RFC5389[10.2.3.  Receiving a Response]
            The client looks for the MESSAGE-INTEGRITY attribute in the response
            (either success or failure).  If present, the client computes the
            message integrity over the response as defined in Section 15.4, using
            the same password it utilized for the request.  If the resulting
            value matches the contents of the MESSAGE-INTEGRITY attribute, the
            response is considered authenticated.  If the value does not match,
            or if MESSAGE-INTEGRITY was absent, the response MUST be discarded,
            as if it was never received. This means that retransmits, if
            applicable, will continue.
            */
            LOG_WARNING("Stream", "SubErrRespMsg cannot be authenticated, just discard this msg");
            return;
        }
        else if (!errRespMsg.GetAttribute(pErrCode))
        {
            /*
            there is no error code, invalid error resp message, set the status to failed
            */
            SetStatus(Status::failed);
            m_SendCond.notify_one();
            return;
        }

        auto errorCode = pErrCode->Code();

        if (errorCode == 487)
        {
            /*
            RFC8445 [7.2.5.1.  Role Conflict]
            */
            LOG_ERROR("Checker", "Role Conflict");
        }
        else if ( (errorCode >= 300 && errorCode <= 399) ||
                  (errorCode >= 400 && errorCode <= 499) )
        {
            /*
            RFC5389 [7.3.3.  Processing a Success Response]
            If the error code is 300 through 399, the client SHOULD consider
            the transaction as failed unless the ALTERNATE-SERVER extension is
            being used.  See Section 11.

            o  If the error code is 400 through 499, the client declares the
            transaction failed; in the case of 420 (Unknown Attribute), the
            response should contain a UNKNOWN-ATTRIBUTES attribute that gives
            additional information.
            */
            SetStatus(Status::failed);
        }
        else if (errorCode >= 500 && errorCode <= 599)
        {
            /*
            o  If the error code is 500 through 599, the client MAY resend the
            request; clients that do so MUST limit the number of times they do
            this.
            */
        }
    }


    void Stream::CheckSession::Checker::SetStatus(Status eStatus)
    {
        //assert(eStatus != Status::waiting_resp);

        std::lock_guard<decltype(m_StatusMutex)> locker(m_StatusMutex);
        m_Status = eStatus;
    }

    bool Stream::CheckSession::Checker::IsStatus(Status eStatus)
    {
        std::lock_guard<decltype(m_StatusMutex)> locker(m_StatusMutex);
        return m_Status  == eStatus;
    }

    void Stream::CheckSession::Checker::SendThread(Checker * pThis)
    {
        assert(pThis && pThis->m_pReqMsg);

        pThis->SetStatus(Status::waiting_resp);

        auto timer_cnt  = pThis->m_Owner.m_Timer.size();
        auto& recver_ip = pThis->RemoteCandidate().m_ConnIP;
        auto  port      = pThis->RemoteCandidate().m_ConnPort;

        std::mutex send_mutex;

        for (decltype(timer_cnt) i = 0; i < timer_cnt; ++i)
        {
            if (0 >= pThis->m_pReqMsg->SendData(pThis->m_Owner.m_Channel, recver_ip, port))
            {
                LOG_ERROR("Checker", "Cannot Send Data [%s:%d] => [%s:%d], set status to failed",
                    pThis->m_LocalCandidate.m_BaseIP.c_str(), pThis->m_LocalCandidate.m_BasePort,
                    pThis->m_RemoteCandidate.m_ConnIP.c_str(), pThis->m_RemoteCandidate.m_ConnPort);
                pThis->SetStatus(Status::failed);
                break;
            }

            if (!pThis->IsStatus(Status::waiting_resp))
                break;

                std::unique_lock<decltype(send_mutex)> locker(send_mutex);
                auto ret = pThis->m_SendCond.wait_for(locker, std::chrono::milliseconds(pThis->m_Owner.m_Timer[i]));
                if (std::_Cv_status::timeout != ret)
                    break;
        }

        std::lock_guard<decltype(pThis->m_StatusMutex)> locker(pThis->m_StatusMutex);
        if (Status::waiting_resp == pThis->m_Status)
        {
            LOG_ERROR("Checker", "Connectivity Check  timeout [%s:%d] => [%s:%d]",
                pThis->m_LocalCandidate.m_BaseIP.c_str(), pThis->m_LocalCandidate.m_BasePort,
                pThis->m_RemoteCandidate.m_ConnIP.c_str(), pThis->m_RemoteCandidate.m_ConnPort);

            pThis->m_Status = Status::failed;
        }

        CheckSession::CheckStatus status = CheckStatus::failed;
        if (pThis->m_Status == Status::succeed)
            status = CheckStatus::passed;
        else if (pThis->m_Status == Status::nominated)
            status = CheckStatus::nominated;

        pThis->m_Owner.OnCheckerCompleted(*pThis, status);
    }

    /////////////////////////////////////// CheckSession class ////////////////////////////////////////////////
    Stream::CheckSession::CheckSession(Stream & owner, Channel & channel, const TimeOutInterval& timer,
        const UTILITY::AuthInfo & lauthInfo,const UTILITY::AuthInfo & rauthInfo)
        : m_Owner(owner), m_Channel(channel), m_Timer(timer),m_LAuthInfo(lauthInfo), m_RAuthInfo(rauthInfo)
    {
        RegisterMsg(static_cast<PG::MsgEntity::MSG_ID>(Message::StatusChanged));
    }

    Stream::CheckSession::~CheckSession()
    {
        if (m_RecvThrd.joinable())
            m_RecvThrd.join();
    }

    bool Stream::CheckSession::CreateChecker(uint64_t pri, const Candidate & lcand, const Candidate & rcand)
    {
        std::auto_ptr<Checker> checker(new Checker(*this, pri, lcand, rcand));
        if (!checker.get())
            return false;

        auto list_ret = sCheckList.insert(std::make_pair(CheckListKey(checker->MakeCheckListKey(), checker->Priority()), checker.get()));

        if (!list_ret.second)
        {
            LOG_ERROR("CheckSession", "Insert sCheckList error");
            return false;
        }

        if (!checker->Start())
        {
            sCheckList.erase(list_ret.first);
            LOG_ERROR("CheckSession", "Cannot Start Checker");
            return false;
        }

        checker.release();
        return true;
    }

    void Stream::CheckSession::OnStart()
    {
        m_RecvThrd = std::thread(RecvThread, this);
    }

    void Stream::CheckSession::RecvThread(CheckSession *pThis)
    {
        assert(pThis);
        std::string local = pThis->m_Channel.IP() + boost::lexical_cast<std::string>(pThis->m_Channel.Port());

        while (1)
        {
            STUN::PACKET::stun_packet packet;
            std::string sender_ip;
            uint16_t sender_port;
            auto bytes = pThis->m_Channel.Recv(&packet, sizeof(packet), sender_ip, sender_port);

            if (STUN::MessagePacket::IsValidStunPacket(packet, bytes))
            {
                Checker *checker(nullptr);
                {
                    std::string remote = sender_ip + boost::lexical_cast<std::string>(sender_port);
                    std::lock_guard<decltype(sCheckMutex)> locker(sCheckMutex);
                    auto itor = sCheckList.find(CheckListKey(local + remote));
                    if (itor == sCheckList.end())
                    {
                        LOG_ERROR("CheckSession", "sender not in check list [%s:%d], msg [%d]",
                            sender_ip.c_str(), sender_port, packet.MsgId());
                        continue;
                    }
                    checker = itor->second;
                }

                assert(checker);
                switch (packet.MsgId())
                {

                case STUN::MsgType::BindingRequest:
                    checker->OnStunMessage(STUN::SubBindReqMsg(packet, bytes), sender_ip, sender_port);
                    break;

                case STUN::MsgType::BindingErrResp:
                    checker->OnStunMessage(STUN::SubBindErrRespMsg(packet, bytes));
                    break;

                case STUN::MsgType::BindingResp:
                    checker->OnStunMessage(STUN::SubBindRespMsg(packet, bytes));
                    break;
                default:
                    break;
                }
            }
        }
    }

    void Stream::CheckSession::OnCheckerCompleted(Checker & checker, CheckStatus eStatus)
    {
        std::unique_lock<decltype(sCheckMutex)> locker(sCheckMutex);

        CheckListKey key(checker.MakeCheckListKey(), checker.Priority());
        auto itor = sCheckList.find(key);

        if (itor == sCheckList.end())
        {
            LOG_ERROR("CheckSession", "checker [%p] is not in checklist", &checker);
            return;
        }

        if (eStatus == CheckStatus::nominated)
        {
            LOG_ERROR("CheckSession", "Connectivity Check Succeed");
            return;
        }

        if (CheckStatus::passed == eStatus && itor == sCheckList.begin() && m_Owner.m_bControlling)
        {
            // highest priority checker has been done, we can start to nominating now
            checker.Start(true);
        }

        auto& list = eStatus == CheckStatus::failed ? sFailedCheckList : sPassedCheckList;
        auto ret = list.insert(std::make_pair(key, &checker)).second;

        LOG_INFO("CheckSession", "Insert checker [%p] to [%s ] list [%s]",
            &checker,
            eStatus == CheckStatus::failed ? "sFailedCheckList" : "sPassedCheckList",
            ret ? "succedd" : "failed");

        if (sCheckList.size() == (sFailedCheckList.size() + sPassedCheckList.size()))
        {
            if (sPassedCheckList.empty())
            {
                LOG_INFO("CheckSession", "Connectivity Check Failed");
            }
            else if(m_Owner.m_bControlling)
            {
                sPassedCheckList.begin()->second->Start(true);
                LOG_INFO("CheckSession", "Connectivity Check has been done, start to nominating");
            }
            else
            {
                LOG_INFO("CheckSession", "Connectivity Check has been done, wait for nominating");
            }
        }
    }

    Stream::TCPCheckSession::TCPCheckSession(Stream & owner,
        Channel & channel,
        const std::string & peer,
        uint16_t port,
        const TimeOutInterval & timer,
        const UTILITY::AuthInfo & lauthInfo,
        const UTILITY::AuthInfo & rauthInfo) :
        CheckSession(owner, channel, timer, lauthInfo,rauthInfo), m_peer(peer),m_port(port)
    {
    }

    /////////////////////////////////////// TCPCheckSession class ////////////////////////////////////////////////
    bool Stream::TCPCheckSession::Initilize()
    {
        m_ConnThrd = std::thread(ConnectThread, this);
        return true;
    }

    void Stream::TCPCheckSession::ConnectThread(TCPCheckSession * pThis)
    {
        if (!pThis->m_Channel.Connect(pThis->m_peer, pThis->m_port))
        {
            pThis->Publish(static_cast<PG::MsgEntity::MSG_ID>(Message::StatusChanged), false, nullptr);

            LOG_ERROR("TCPCheckSession", "cannot make connection to [%s:%d]",
                pThis->m_peer.c_str(), pThis->m_port);
            return;
        }
        pThis->OnStart();
    }

    void Stream::CheckSessionSubscriber::OnPublished(const PG::Publisher * publisher, PG::MsgEntity::MSG_ID msgId, PG::MsgEntity::WPARAM wParam, PG::MsgEntity::LPARAM lParam)
    {
    }
}

