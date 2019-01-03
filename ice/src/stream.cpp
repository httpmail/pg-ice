#include "stream.h"
#include "candidate.h"
#include "stunmsg.h"
#include "agent.h"
#include "channel.h"
#include "pg_log.h"
#include <iostream>

namespace ICE {
    /*
    RFC4389
    For example, assuming an RTO of 500 ms,
    requests would be sent at times 0 ms, 500 ms, 1500 ms, 3500 ms, 7500
    ms, 15500 ms, and 31500 ms.  If the client has not received a
    response after 39500 ms
    */
    static const Stream::TimeOutInterval sTimeout = { 500, 1000,2000,4000,8000,16000, 8000 };

    //////////////////////////////  class StunCheckHelper //////////////////////////////
    class Stream::StunCheckHelper : public PG::Publisher {
    public:
        enum class Msg : uint16_t {
            Checking, /* WPARAM @true - connectivity check ok, otherwise failed. if 'ok' next step is to Nominate*/
            Nominate,
        };

    protected:
        enum class Status {
            waiting,
            failed,
            succeed,
            quit,
        };
    private:
        enum class State {
            wait_checking,
            wait_nominated,
        };
    public:
        StunCheckHelper(Stream &Owner, Channel &channel, STUN::SubBindReqMsg *pReqMsg, const Stream::TimeOutInterval& timer,
            const std::string& key, const std::string& username) :
            m_Owner(Owner), m_Channel(channel), m_pSubBindReqMsg(pReqMsg), m_State(State::wait_checking), m_Status(Status::waiting), m_Timer(timer),
            m_Key(key),m_Username(username)
        {
            assert(pReqMsg);
            RegisterMsg(static_cast<uint16_t>(Msg::Checking));
            RegisterMsg(static_cast<uint16_t>(Msg::Nominate));
        }

        ~StunCheckHelper()
        {
            if (m_RecvThrd.joinable())
                m_RecvThrd.join();

            if (m_SendThrd.joinable())
                m_SendThrd.join();

            delete m_pSubBindReqMsg;
            m_pSubBindReqMsg = nullptr;
        }

        bool StartCheck()
        {
            assert(!m_RecvThrd.joinable() && !m_SendThrd.joinable());
            m_RecvThrd = std::thread(StunCheckHelper::RecvThread, this);
            m_SendThrd = std::thread(StunCheckHelper::SendThread, this);
            return true;
        }

    private:
        void OnStunMsg(const STUN::SubBindErrRespMsg &errRespMsg)
        {
            using namespace STUN;
            const ATTR::ErrorCode *pErrCode(nullptr);
            if (!errRespMsg.GetAttribute(pErrCode))
            {
                /*
                there is no error code, invalid error resp message, set the status to failed
                */
                std::lock_guard<decltype(m_StatusMutex)> locker(m_StatusMutex);
                m_Status = Status::failed;
                m_StatusCond.notify_one();

            }
            else if (pErrCode->Number() >= 300 && pErrCode->Number() <= 399)
            {
                /*
                RFC5389 [7.3.3.  Processing a Success Response]
                If the error code is 300 through 399, the client SHOULD consider
                the transaction as failed unless the ALTERNATE-SERVER extension is
                being used.  See Section 11.
                */
                std::lock_guard<decltype(m_StatusMutex)> locker(m_StatusMutex);
                m_Status = Status::failed;
                m_StatusCond.notify_one();
            }
            else if (pErrCode->Number() >= 400 && pErrCode->Number() <= 499)
            {
                /*
                o  If the error code is 400 through 499, the client declares the
                transaction failed; in the case of 420 (Unknown Attribute), the
                response should contain a UNKNOWN-ATTRIBUTES attribute that gives
                additional information.
                */
                LOG_ERROR("Stream", "Response Error code [%d], set status as failed", pErrCode->Number());
                std::lock_guard<decltype(m_StatusMutex)> locker(m_StatusMutex);
                m_Status = Status::failed;
                m_StatusCond.notify_one();
            }
            else if (pErrCode->Number() >= 500 && pErrCode->Number() <= 599)
            {
                /*
                o  If the error code is 500 through 599, the client MAY resend the
                request; clients that do so MUST limit the number of times they do
                this.
                */
            }
            else if (pErrCode->Number() == 487)
            {
                /*
                RFC8445 [7.2.5.1.  Role Conflict]
                */
            }
        }

        void OnStunMsg(const STUN::SubBindReqMsg &reqMsg)
        {
            using namespace STUN;

            const ATTR::MessageIntegrity *pMsgIntegrity(nullptr);
            const ATTR::UserName *pUsername(nullptr);
            const ATTR::Role *pRole(nullptr);
            const ATTR::Priority *pPriority(nullptr);
            const ATTR::UseCandidate *pUseCandAttr(nullptr);

            MessagePacket *pRespMsg(nullptr);
            /*
            RFC8445 [7.1.  STUN Extensions]
            */
            if (!reqMsg.GetAttribute(pRole) && !reqMsg.GetAttribute(pPriority))
            {
                LOG_WARNING("Stream", "bind request has no role or priority attribute, just discards");
                return;
            }

            assert(pRole);

            reqMsg.GetAttribute(pUseCandAttr);
            if (pRole->Type() == ATTR::Id::IceControlled && pUseCandAttr)
            {
                /*
                RFC8445[7.1.2.  USE-CANDIDATE]

                The controlling agent MUST include the USE-CANDIDATE attribute in
                order to nominate a candidate pair (Section 8.1.1).  The controlled
                agent MUST NOT include the USE-CANDIDATE attribute in a Binding
                request.
                 */
                LOG_WARNING("Stream", "The controlled agent MUST NOT include the USE - CANDIDATE attribute in a Binding request");
                return;
            }
            /*
            RFC5389 10.2.2. Receiving a Request
            */
            if (!reqMsg.GetAttribute(pMsgIntegrity) && !reqMsg.GetAttribute(pUsername))
            {
                // 400 bad request
                SubBindErrRespMsg errRespMsg(m_pSubBindReqMsg->TransationId(), 4, 0, "bad-request");
                pRespMsg = &errRespMsg;
            }
            else if (pUsername && m_Username != pUsername->Name())
            {
                // 401 Unauthorized
                //SubBindErrRespMsg errRespMsg(m_pSubBindReqMsg->TransationId(), 4, 1, "unmatched-username");
                //pRespMsg = &errRespMsg;
            }
            else if (!MessagePacket::VerifyMsgIntegrity(reqMsg, m_Key))
            {
                // 401 Unauthorized
                SubBindErrRespMsg errRespMsg(m_pSubBindReqMsg->TransationId(), 4, 1, "unmatched-MsgIntegrity");
                pRespMsg = &errRespMsg;
            }
            else if (reqMsg.GetUnkonwnAttrs().size())
            {
                SubBindErrRespMsg errRespMsg(m_pSubBindReqMsg->TransationId(), 4, 20, "Unknown-Attribute");
                errRespMsg.AddUnknownAttributes(reqMsg.GetUnkonwnAttrs());
                pRespMsg = &errRespMsg;
            }
            else if (m_bControlling == (pRole->Type() == ATTR::Id::IceControlling))
            {
                // RFC8445 [7.3.1.1.  Detecting and Repairing Role Conflicts]
                if ((m_bControlling && m_TieBreaker >= pRole->TieBreaker()) ||
                    (!m_bControlling && m_TieBreaker < pRole->TieBreaker()))
                {
                    SubBindErrRespMsg errRespMsg(m_pSubBindReqMsg->TransationId(), 4, 87, "Role-Conflict");
                    pRespMsg = &errRespMsg;
                }
                else
                {
                    //TODO switch role
                }
            }
            else
            {
                // now we can send success response message
                ATTR::XorMappedAddress xorMapAddr;
                xorMapAddr.Port(m_Channel.PeerPort());
                assert(boost::asio::ip::address::from_string(m_Channel.PeerIP()).is_v4());
                xorMapAddr.Address(boost::asio::ip::address::from_string(m_Channel.PeerIP()).to_v4().to_uint());

                SubBindResqMsg respMsg(m_pSubBindReqMsg->TransationId(), xorMapAddr);
                pRespMsg = &respMsg;
            }

            assert(pRespMsg);
            if (!pRespMsg->SendData(m_Channel))
            {
                LOG_ERROR("Stream", "Send Response Message Failed");
            }
        }

        void OnStunMsg(const STUN::SubBindResqMsg &respMsg)
        {
            using namespace STUN;
            const ATTR::MessageIntegrity *pMsgIntegrity(nullptr);
            if (!respMsg.GetAttribute(pMsgIntegrity) || !MessagePacket::VerifyMsgIntegrity(respMsg, m_Key))
            {
                /*
                RFC5389 [10.1.3.  Receiving a Response]
                If the value does not match, or if
                MESSAGE-INTEGRITY was absent, the response MUST be discarded, as if
                it was never received
                */
            }
            else if (respMsg.GetUnkonwnAttrs().size())
            {
                /*
                RFC5389 [7.3.3.  Processing a Success Response]
                If the success response contains unknown comprehension-required
                attributes, the response is discarded and the transaction is
                considered to have failed.
                */
                std::lock_guard<decltype(m_StatusMutex)> locker(m_StatusMutex);
                m_Status = Status::failed;
                m_StatusCond.notify_one();
            }

            const ATTR::XorMappedAddress *pXorMapAddr(nullptr);
            if (!respMsg.GetAttribute(pXorMapAddr))
            {
                /*
                */
            }
            else
            {
            }
        }

    private:
        static void RecvThread(StunCheckHelper *pThis)
        {
            using namespace STUN;
            do
            {
                STUN::PACKET::stun_packet packet;
                auto bytes = pThis->m_Channel.Read(&packet, sizeof(packet));
                if (bytes && MessagePacket::IsValidStunPacket(packet, bytes))
                {
                    switch (packet.MsgId())
                    {
                    case STUN::MsgType::BindingResp:
                        pThis->OnStunMsg(SubBindResqMsg(packet, bytes));
                        break;

                    case STUN::MsgType::BindingErrResp:
                        pThis->OnStunMsg(SubBindErrRespMsg(packet, bytes));
                        break;

                    case STUN::MsgType::BindingRequest:
                        pThis->OnStunMsg(SubBindReqMsg(packet, bytes));
                        break;
                    default:
                        break;
                    }
                }
                std::lock_guard<decltype(pThis->m_StatusMutex)> locker(pThis->m_StatusMutex);
            } while (pThis->m_Status != Status::waiting);

        }
        static void SendThread(StunCheckHelper *pThis)
        {
            assert(pThis && pThis->m_pSubBindReqMsg);

            for (auto timer_itor = pThis->m_Timer.begin(); timer_itor != pThis->m_Timer.end(); ++timer_itor)
            {
                pThis->m_pSubBindReqMsg->SendData(pThis->m_Channel);

                std::unique_lock<decltype(pThis->m_StatusMutex)> locker(pThis->m_StatusMutex);
                auto ret = pThis->m_StatusCond.wait_for(locker, std::chrono::milliseconds(*timer_itor), [pThis]() {
                    return pThis->m_Status != Status::waiting;
                });

                if (ret)
                {
                    LOG_WARNING("Stream", "[%s:%d] => [%s:%d] completed, status [%s]",
                        pThis->m_Channel.IP().c_str(), pThis->m_Channel.Port(),
                        pThis->m_Channel.PeerIP().c_str(), pThis->m_Channel.PeerPort(),
                        (pThis->m_Status == Status::succeed ? "OK" : "Failed"));

                    pThis->Publish(static_cast<PG::MsgEntity::MSG_ID>(Msg::Checking), (PG::MsgEntity::LPARAM)(pThis->m_Status == Status::succeed), nullptr);
                    return;
                }

                LOG_WARNING("Stream", "[%s:%d] => [%s:%d] timeout try again",
                    pThis->m_Channel.IP().c_str(), pThis->m_Channel.Port(),
                    pThis->m_Channel.PeerIP().c_str(), pThis->m_Channel.PeerPort());
            }

            LOG_ERROR("Stream", "[%s:%d] => [%s:%d] timeout",
                pThis->m_Channel.IP().c_str(), pThis->m_Channel.Port(),
                pThis->m_Channel.PeerIP().c_str(), pThis->m_Channel.PeerPort());

            pThis->Publish(static_cast<PG::MsgEntity::MSG_ID>(Msg::Checking), false, nullptr);
        }

    private:
        std::thread              m_RecvThrd;
        std::thread              m_SendThrd;
        bool                     m_bControlling;
        uint64_t                 m_TieBreaker;
        Channel                 &m_Channel;
        Stream                  &m_Owner;
        STUN::SubBindReqMsg     *m_pSubBindReqMsg;
        const std::string       &m_Username;
        const std::string       &m_Key;
        const Stream::TimeOutInterval&  m_Timer;

        State                    m_State;
        std::mutex               m_StateMutex;
        std::condition_variable  m_StateCond;

        Status                   m_Status;
        std::mutex               m_StatusMutex;
        std::condition_variable  m_StatusCond;
    };

    ////////////////////////////// Stream //////////////////////////////
    Stream::Stream(uint16_t compId, Protocol protocol, uint16_t localPref, const std::string & hostIp, uint16_t hostPort) :
        m_CompId(compId), m_Protocol(protocol), m_LocalPref(localPref), m_HostIP(hostIp), m_HostPort(hostPort), m_Quit(false),
        m_GatherEventSub(this), m_PendingGatherCnt(0)
    {
        assert(hostPort);
        RegisterEvent(static_cast<PG::MsgEntity::MSG_ID>(Message::Gathering));
        RegisterEvent(static_cast<PG::MsgEntity::MSG_ID>(Message::Checking));
    }

    Stream::~Stream()
    {
        if (m_GatherThrd.joinable())
            m_GatherThrd.join();
    }

    bool Stream::Create(const CAgentConfig& config)
    {
        return false;
    }

    bool Stream::GatheringCandidate(const CAgentConfig& config)
    {
        // step 1> gather host candidate
        if (!GatherHostCandidate(m_HostIP, m_HostPort, m_Protocol))
        {
            LOG_ERROR("Stream", "Gather Host Candidate Failed");
            return false;
        }

        auto &stun_server   = config.StunServer();
        auto &port_range    = config.GetPortRange();

        for (auto itor = stun_server.begin(); itor != stun_server.end(); ++itor)
        {
            GatherReflexiveCandidate(config.DefaultIP(), port_range.Lower(), port_range.Upper(), itor->first, itor->second);
            std::unique_lock<decltype(m_TaMutex)> locker(m_TaMutex);
            m_TaCond.wait_for(locker, std::chrono::milliseconds(config.Ta()));
        }

        auto &turn_server = config.TurnServer();
        for (auto itor = turn_server.begin(); itor != turn_server.end(); ++itor)
        {
            GatherRelayedCandidate(config.DefaultIP(), port_range.Lower(), port_range.Upper(), itor->first, itor->second);
            std::unique_lock<decltype(m_TaMutex)> locker(m_TaMutex);
            m_TaCond.wait_for(locker, std::chrono::milliseconds(config.Ta()));
        }

        if(!m_GatherThrd.joinable())
            m_GatherThrd = std::thread(Stream::WaitGatheringDoneThread, this);

        return true;
    }

    bool Stream::ConnectivityCheck(const Candidate * lcand, const Candidate * rcand, uint64_t tieBreaker, bool bControlling, const std::string& key, const std::string& name)
    {
        assert(lcand && rcand && m_Cands.find(const_cast<Candidate*>(lcand)) != m_Cands.end());

        auto lcand_itor = m_Cands.find(const_cast<Candidate*>(lcand));
        auto channel = lcand_itor->second;

        assert(channel);

        if (lcand->m_Protocol == Protocol::udp)
        {
            auto udp_channel = dynamic_cast<UDPChannel*>(channel);
            assert(udp_channel);
            if (!udp_channel->BindRemote(rcand->m_ConnIP, rcand->m_ConnPort))
            {
                LOG_ERROR("Stream", "Bind Remote Failed [%s:%d] => [%s:%d]", channel->IP().c_str(), channel->Port(), rcand->m_ConnIP.c_str(), rcand->m_ConnPort);
                return false;
            }
        }
        else if (lcand->m_Protocol == Protocol::tcp_act)
        {
            auto act_channel = dynamic_cast<TCPActiveChannel*>(channel);
        }
        else
        {
            auto pass_channel = dynamic_cast<TCPPassiveChannel*>(channel);
        }

        STUN::TransId id;
        STUN::MessagePacket::GenerateRFC5389TransationId(id);

        std::auto_ptr<STUN::SubBindReqMsg> bindReqMsg(new STUN::SubBindReqMsg(lcand->m_Priority, id, bControlling, tieBreaker));
        std::auto_ptr<StunCheckHelper> checker( new StunCheckHelper(*this, *channel, bindReqMsg.get(), sTimeout,key, name));
        if (!checker.get() || !checker->StartCheck())
        {
            LOG_ERROR("Stream", "Cannot Start to connectivity check [%s:%d] =>[%s:%d]",
                channel->IP().c_str(), channel->Port(), rcand->m_ConnIP.c_str(), rcand->m_ConnPort);
            return false;
        }
        checker.release();
        bindReqMsg.release();
        return true;
    }

    bool Stream::GatherHostCandidate(const std::string & ip, uint16_t port, Protocol protocol)
    {
        std::auto_ptr<Channel> channel(nullptr);
        switch (protocol)
        {
        case Protocol::udp:
            channel.reset(CreateChannel<UDPChannel>(ip, port));
            break;

        case Protocol::tcp_pass:
            channel.reset(CreateChannel<TCPPassiveChannel>(ip, port));
            break;

        case Protocol::tcp_act:
            channel.reset(CreateChannel<TCPActiveChannel>(ip, port));
            break;

        default:
            break;
        }

        if (!channel.get())
            return false;

        auto foundation = Candidate::ComputeFoundations(Candidate::CandType::host, ip, ip, protocol);
        auto priority   = Candidate::ComputePriority(Candidate::CandType::host, m_LocalPref, m_CompId);
        std::auto_ptr<HostCand> cand(new HostCand(priority,foundation, ip, port));

        if(!cand.get())
            return false;
        {
            std::lock_guard<decltype(m_CandsMutex)> locker(m_CandsMutex);
            if (m_Cands.insert(std::make_pair(cand.get(), channel.get())).second)
            {
                cand.release();
                channel.release();
                LOG_INFO("Stream", "Host Candidate Created : [%s:%d]", ip.c_str(), port);
                return true;
            }
        }

        return false;
    }

    bool Stream::GatherReflexiveCandidate(const std::string & ip, uint16_t lowerPort, uint16_t upperPort, const std::string & stunIP, uint16_t stunPort)
    {
        std::auto_ptr<UDPChannel> channel(CreateChannel<UDPChannel>(ip, lowerPort, upperPort, m_MaxTries));

        if (!channel.get() || !channel->BindRemote(stunIP, stunPort))
        {
            LOG_ERROR("Stream", "Create Channel Failed while tried to gather reflexive candidate from [%s]", stunIP.c_str());
            return false;
        }

        using namespace STUN;

        // build 1st bind request message
        TransId id;
        MessagePacket::GenerateRFC5389TransationId(id);
        FirstBindReqMsg *pMsg = new FirstBindReqMsg(id);

        std::auto_ptr<StunGatherHelper> helper(new StunGatherHelper(channel.get(), stunIP, stunPort, pMsg, sTimeout));
        {
            std::lock_guard<decltype(m_GatherMutex)> locker(m_GatherMutex);
            if (!helper.get() || !m_StunPendingGather.insert(helper.get()).second)
            {
                LOG_ERROR("Stream", "Start Gathering Failed [stun: %s, local: %s:%d]", stunIP.c_str(), channel->IP().c_str(), channel->Port());
                return false;
            }
            m_PendingGatherCnt++;
        }

        helper->Subscribe(&m_GatherEventSub, static_cast<uint16_t>(StunGatherHelper::PubEvent::GatheringEvent));
        helper->StartGathering();
        helper.release();
        channel.release();
        return true;
    }

    bool Stream::GatherRelayedCandidate(const std::string & ip, uint16_t lowerPort, uint16_t upperPort, const std::string & turnServer, uint16_t turnPort)
    {
        return true;
    }

    void Stream::WaitGatheringDoneThread(Stream * pThis)
    {
        assert(pThis);

        std::unique_lock<decltype(pThis->m_WaitingGatherMutex)> locker(pThis->m_WaitingGatherMutex);

        pThis->m_WaitingGatherCond.wait(locker, [pThis] {
            return pThis->m_PendingGatherCnt <= 0;
        });

        for (auto itor = pThis->m_StunPendingGather.begin(); itor != pThis->m_StunPendingGather.end(); ++itor)
        {
            auto helper = *itor;
            if (helper->IsOK())
            {
                auto foundation = Candidate::ComputeFoundations(Candidate::CandType::svr_ref, helper->m_ConnIP, helper->m_StunIP, Protocol::udp);
                auto priority = Candidate::ComputePriority(Candidate::CandType::svr_ref, pThis->m_LocalPref, pThis->m_CompId);

                std::auto_ptr<SvrCand> cand(new SvrCand(priority,
                    foundation, helper->m_ConnIP,
                    helper->m_ConnPort,
                    helper->m_Channel->IP(),
                    helper->m_Channel->Port()));

                if (cand.get())
                {
                    std::lock_guard<decltype(pThis->m_CandsMutex)> locker(pThis->m_CandsMutex);
                    if (pThis->m_Cands.insert(std::make_pair(cand.get(), helper->m_Channel)).second)
                    {
                        LOG_INFO("Stream", "SrflxCandidate Created, [%s:%d]", helper->m_Channel->IP().c_str(), helper->m_Channel->Port());
                        cand.release();
                    }
                }
            }
            (*itor)->Unsubscribe(&pThis->m_GatherEventSub);
        }
        pThis->m_StunPendingGather.clear();
        pThis->NotifyListener(static_cast<uint16_t>(Message::Gathering), (WPARAM)pThis, (LPARAM)(pThis->m_Cands.size() > 0));
    }

    ////////////////////////////// GatherHelper class //////////////////////////////
    Stream::StunGatherHelper::StunGatherHelper(Channel * channel, const std::string& stunServer, uint16_t stunPort, STUN::FirstBindReqMsg *pMsg, const TimeOutInterval & timeout) :
        m_Channel(channel), m_pBindReqMsg(pMsg), m_Timeout(timeout), m_Status(Status::waiting),m_StunIP(stunServer),m_StunPort(stunPort)
    {
        assert(timeout.size());
        assert(channel);
        assert(pMsg);
        RegisterMsg(static_cast<uint16_t>(PubEvent::GatheringEvent));
    }

    Stream::StunGatherHelper::~StunGatherHelper()
    {
        {
            std::lock_guard<decltype(m_Mutex)> locker(m_Mutex);
            m_Status = Status::quit;
        }

        m_Channel->Close();

        if (m_RecvThread.joinable())
            m_RecvThread.join();

        if (m_GatherThread.joinable())
            m_GatherThread.join();

        delete m_pBindReqMsg;
    }

    void Stream::StunGatherHelper::StartGathering()
    {
        assert(!m_GatherThread.joinable() && !m_RecvThread.joinable());
        m_GatherThread = std::thread(StunGatherHelper::GatheringThread, this);
        m_RecvThread   = std::thread(StunGatherHelper::ReceiveThread, this);
    }

    bool Stream::StunGatherHelper::OnStunMsg(const STUN::FirstBindRespMsg & msg)
    {
        LOG_INFO("Stream", "1st Bind Request Received Success Response");

        const STUN::ATTR::XorMappedAddress *pXormapAddr = nullptr;
        if (msg.GetAttribute(pXormapAddr))
        {
            {
                std::lock_guard<decltype(m_Mutex)> locker(m_Mutex);
                m_ConnIP = pXormapAddr->IP();
                m_ConnPort = pXormapAddr->Port();
                m_Status = Status::succeed;
            }
            m_Cond.notify_one();
            return true;
        }
        else
        {
            LOG_ERROR("Stream", "1st bind Request received RESPONSE without xormapaddress attributes ,just discards");
            return false;
        }
    }

    bool Stream::StunGatherHelper::OnStunMsg(const STUN::FirstBindErrRespMsg & msg)
    {
        LOG_WARNING("Stream", "1st Bind Request Received Error Response, Just set result to failed");
        {
            std::lock_guard<decltype(m_Mutex)> locker(m_Mutex);
            m_Status = Status::failed;
        }
        m_Cond.notify_one();
        return true;
    }

    void Stream::StunGatherHelper::ReceiveThread(StunGatherHelper * pThis)
    {
        assert(pThis && pThis->m_Channel);

        using namespace STUN;

        while(pThis->m_Status == Status::waiting)
        {
            STUN::PACKET::stun_packet packet;
            auto bytes = pThis->m_Channel->Read(&packet, sizeof(packet));

            if (bytes && MessagePacket::IsValidStunPacket(packet, bytes))
            {
                auto msg_id = packet.MsgId();
                switch (msg_id)
                {
                case STUN::MsgType::BindingResp:
                    pThis->OnStunMsg(FirstBindRespMsg(packet,bytes));
                    break;

                case STUN::MsgType::BindingErrResp:
                    pThis->OnStunMsg(FirstBindErrRespMsg(packet,bytes));
                    break;

                default:
                    break;
                }
            }
        };
    }

    void Stream::StunGatherHelper::GatheringThread(StunGatherHelper * pThis)
    {
        assert(pThis && pThis->m_Channel);

        for (auto itor = pThis->m_Timeout.begin(); itor != pThis->m_Timeout.end(); ++itor)
        {
            if (!pThis->m_pBindReqMsg->SendData(*pThis->m_Channel))
            {
                LOG_ERROR("Stream", "Cannot send 1st bind request");
            }

            std::unique_lock<decltype(pThis->m_Mutex)> locker(pThis->m_Mutex);
            if (true == pThis->m_Cond.wait_for(locker, std::chrono::milliseconds(*itor), [pThis] {
                return pThis->m_Status != Status::waiting; }))
            {
                LOG_INFO("Stream", "Gather Candidate from StunServer[%s], result :%d : [%s:%d]",
                    pThis->m_StunIP.c_str(),
                    pThis->m_Status,
                    pThis->m_ConnIP.c_str(),pThis->m_ConnPort);
                break;
            }
            LOG_WARNING("Stream", "send 1st to stun :%s timout, try again()", pThis->m_Channel->PeerIP().c_str());
        }

        pThis->m_Channel->Shutdown(Channel::ShutdownType::both);  // close channel to wakeup recv thread
        pThis->Publish(static_cast<uint16_t>(PubEvent::GatheringEvent), (WPARAM)(pThis->m_Status == Status::succeed), 0);
    }

    Stream::GatherEventSubsciber::GatherEventSubsciber(Stream * pOwner) :
        m_pOwner(pOwner)
    {
        assert(m_pOwner);
    }

    /////////////////////////// GatherEventSubsciber ////////////////////
    void Stream::GatherEventSubsciber::OnPublished(const PG::Publisher * publisher, PG::MsgEntity::MSG_ID msgId, PG::MsgEntity::WPARAM wParam, PG::MsgEntity::LPARAM lParam)
    {
        assert(m_pOwner && publisher);
        assert(static_cast<StunGatherHelper::PubEvent>(msgId) == StunGatherHelper::PubEvent::GatheringEvent);

        {
            std::lock_guard<decltype(m_pOwner->m_GatherMutex)> locker(m_pOwner->m_GatherMutex);
            auto helper = dynamic_cast<const StunGatherHelper*>(publisher);
            assert(helper);
            assert(m_pOwner->m_StunPendingGather.find(const_cast<StunGatherHelper*>(helper)) != m_pOwner->m_StunPendingGather.end());
            m_pOwner->m_PendingGatherCnt--;
        }
        m_pOwner->m_TaCond.notify_one();
        if (m_pOwner->m_PendingGatherCnt <= 0)
        {
            LOG_INFO("Stream", "Gathering Stun Candidate Done");
            m_pOwner->m_WaitingGatherCond.notify_one();
        }
    }

}
