#include "stream.h"
#include "candidate.h"
#include "stunmsg.h"
#include "agent.h"
#include "channel.h"
#include "pg_log.h"
#include <boost/lexical_cast.hpp>

namespace ICE {
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
        StunCheckHelper(Stream &Owner, const Candidate* lcand, const Candidate* rcand, STUN::SubBindReqMsg *pReqMsg, const Stream::TimeOutInterval& timer,
            const std::string& lpwd, const std::string& rpwd,
            const std::string& lufrag, const std::string& rufrag) :
            m_Owner(Owner), m_LocalCand(lcand), m_RemoteCand(rcand), m_pSubBindReqMsg(pReqMsg), m_State(State::wait_checking), m_Status(Status::waiting), m_Timer(timer),
            m_LPwd(lpwd),m_RPwd(rpwd), m_LUfrag(lufrag),m_RUfrag(rufrag)
        {
            assert(pReqMsg);
            assert(lcand && rcand);
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
            assert(m_LocalCand && m_RemoteCand);
            m_RecvThrd = std::thread(StunCheckHelper::RecvThread, this);
            m_SendThrd = std::thread(StunCheckHelper::SendThread, this);
            return true;
        }

    private:
        void OnStunMsg(const STUN::SubBindErrRespMsg &errRespMsg)
        {
            using namespace STUN;
            const ATTR::ErrorCode *pErrCode(nullptr);
            const ATTR::MessageIntegrity *pMsgIntegrity(nullptr);

            if (!errRespMsg.GetAttribute(pMsgIntegrity) || !MessagePacket::VerifyMsgIntegrity(errRespMsg, m_LPwd))
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
                as if it was never received.  This means that retransmits, if
                applicable, will continue.
                 */
                LOG_WARNING("Stream", "SubErrRespMsg cannot be authenticated, just discard this msg");
            }
            else if (!errRespMsg.GetAttribute(pErrCode))
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
            reqMsg.GetAttribute(pMsgIntegrity);
            reqMsg.GetAttribute(pUsername);
            if (!pMsgIntegrity && !pUsername )
            {
                // 400 bad request
                SubBindErrRespMsg errRespMsg(m_pSubBindReqMsg->TransationId(), 4, 0, "bad-request");
                errRespMsg.SendData(*m_Channel);
            }
            else if (pUsername && (m_LUfrag + ":" + m_RUfrag) != pUsername->Name())
            {
                // 401 Unauthorized
                SubBindErrRespMsg errRespMsg(m_pSubBindReqMsg->TransationId(), 4, 1, "unmatched-username");
                errRespMsg.SendData(*m_Channel);
            }
            else if (!MessagePacket::VerifyMsgIntegrity(reqMsg, m_LPwd))
            {
                // 401 Unauthorized
                SubBindErrRespMsg errRespMsg(m_pSubBindReqMsg->TransationId(), 4, 1, "unmatched-MsgIntegrity");
                errRespMsg.SendData(*m_Channel);
            }
            else if (reqMsg.GetUnkonwnAttrs().size())
            {
                SubBindErrRespMsg errRespMsg(m_pSubBindReqMsg->TransationId(), 4, 20, "Unknown-Attribute");
                errRespMsg.AddUnknownAttributes(reqMsg.GetUnkonwnAttrs());
                errRespMsg.SendData(*m_Channel);
            }
            else if (m_bControlling == (pRole->Type() == ATTR::Id::IceControlling))
            {
                // RFC8445 [7.3.1.1.  Detecting and Repairing Role Conflicts]
                if ((m_bControlling && m_TieBreaker >= pRole->TieBreaker()) ||
                    (!m_bControlling && m_TieBreaker < pRole->TieBreaker()))
                {
                    SubBindErrRespMsg errRespMsg(m_pSubBindReqMsg->TransationId(), 4, 87, "Role-Conflict");
                    errRespMsg.SendData(*m_Channel);
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
                xorMapAddr.Port(m_Channel->PeerPort());
                assert(boost::asio::ip::address::from_string(m_Channel->PeerIP()).is_v4());
                xorMapAddr.Address(boost::asio::ip::address::from_string(m_Channel->PeerIP()).to_v4().to_uint());

                SubBindResqMsg respMsg(m_pSubBindReqMsg->TransationId(), xorMapAddr);
                respMsg.SendData(*m_Channel);
            }
        }

        void OnStunMsg(const STUN::SubBindResqMsg &respMsg)
        {
            using namespace STUN;
            const ATTR::MessageIntegrity *pMsgIntegrity(nullptr);
            if (!respMsg.GetAttribute(pMsgIntegrity) || !MessagePacket::VerifyMsgIntegrity(respMsg, m_LPwd))
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
            if (respMsg.GetAttribute(pXorMapAddr))
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
                if (pXorMapAddr->IP() == m_LocalCand->m_BaseIP && pXorMapAddr->Port() == m_LocalCand->m_BasePort)
                {
                    LOG_INFO("Stream", "valid resp msg L<=>R [%s:%d] <=>[%s:%d]",
                        m_Channel->IP().c_str(), m_Channel->Port(),
                        m_Channel->PeerIP().c_str(), m_Channel->PeerPort());
                    std::lock_guard<decltype(m_StatusMutex)> locker(m_StatusMutex);
                    m_Status = Status::succeed;
                    m_StatusCond.notify_one();
                }
                else
                {
                    LOG_ERROR("Stream", "SubRespMsg unsymmetric address");
                    std::lock_guard<decltype(m_StatusMutex)> locker(m_StatusMutex);
                    m_Status = Status::failed;
                    m_StatusCond.notify_one();
                }
            }
            else
            {
                std::lock_guard<decltype(m_StatusMutex)> locker(m_StatusMutex);
                m_Status = Status::failed;
                m_StatusCond.notify_one();
            }
        }

    private:
        static void RecvThread(StunCheckHelper *pThis)
        {
            using namespace STUN;
            do
            {
                STUN::PACKET::stun_packet packet;
                auto bytes = pThis->m_Channel->Read(&packet, sizeof(packet));
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
                if (!pThis->m_pSubBindReqMsg->SendData(*pThis->m_Channel))
                {
                    LOG_ERROR("Stream", "Connectivity Check send Requst Failed");
                    continue;
                }

                std::unique_lock<decltype(pThis->m_StatusMutex)> locker(pThis->m_StatusMutex);
                auto ret = pThis->m_StatusCond.wait_for(locker, std::chrono::milliseconds(*timer_itor), [pThis]() {
                    return pThis->m_Status != Status::waiting;
                });

                if (ret)
                {
                    LOG_WARNING("Stream", "[%s:%d] => [%s:%d] completed, status [%s]",
                        pThis->m_LocalCand->m_BaseIP.c_str(), pThis->m_LocalCand->m_BasePort,
                        pThis->m_RemoteCand->m_ConnIP.c_str(), pThis->m_RemoteCand->m_ConnPort,
                        (pThis->m_Status == Status::succeed ? "OK" : "Failed"));

                    pThis->Publish(static_cast<PG::MsgEntity::MSG_ID>(Msg::Checking), (PG::MsgEntity::LPARAM)(pThis->m_Status == Status::succeed), nullptr);
                    return;
                }

                LOG_WARNING("Stream", "connectivity check timeout retry [%s:%d] =>[%s:%d]",
                    pThis->m_LocalCand->m_BaseIP.c_str(), pThis->m_LocalCand->m_BasePort,
                    pThis->m_RemoteCand->m_ConnIP.c_str(), pThis->m_RemoteCand->m_ConnPort);
            }
            pThis->Publish(static_cast<PG::MsgEntity::MSG_ID>(Msg::Checking), false, nullptr);
        }

    private:
        std::thread              m_RecvThrd;
        std::thread              m_SendThrd;
        bool                     m_bControlling;
        uint64_t                 m_TieBreaker;
        const Candidate         *m_LocalCand;
        const Candidate         *m_RemoteCand;
        Stream                  &m_Owner;
        Channel                 *m_Channel;
        STUN::SubBindReqMsg     *m_pSubBindReqMsg;
        const std::string       &m_LPwd;
        const std::string       &m_RPwd;
        const std::string       &m_LUfrag;
        const std::string       &m_RUfrag;
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

    bool Stream::ConnectivityCheck(const Candidate * lcand, const Candidate * rcand, uint64_t tieBreaker, bool bControlling,
        const std::string& lpwd, const std::string& rpwd,
        const std::string& lufrag, const std::string& rufrag)
    {
        assert(lcand && rcand && m_Cands.find(const_cast<Candidate*>(lcand)) != m_Cands.end());

        auto lcand_itor = m_Cands.find(const_cast<Candidate*>(lcand));

        STUN::TransId id;
        STUN::MessagePacket::GenerateRFC5389TransationId(id);

        std::auto_ptr<STUN::SubBindReqMsg> bindReqMsg(new STUN::SubBindReqMsg(lcand->m_Priority, id, bControlling, tieBreaker, rufrag + ":" + lufrag, rpwd));
        std::auto_ptr<StunCheckHelper> checker( new StunCheckHelper(*this, lcand, rcand, bindReqMsg.get(), sTimeout,lpwd, rpwd, lufrag, rufrag));

        if (!checker.get() || !checker->StartCheck())
        {
            LOG_ERROR("Stream", "Cannot Start to connectivity check [%s:%d] =>[%s:%d]",
                lcand->m_BaseIP.c_str(), lcand->m_BasePort, rcand->m_ConnIP.c_str(), rcand->m_ConnPort);
            return false;
        }


        std::lock_guard<decltype(m_PendingCheckersMutex)> locker(m_PendingCheckersMutex);
        if (!m_PendingCheckers.insert(std::make_pair(checker.get(), peer(lcand, rcand))).second)
        {
            LOG_ERROR("Stream", "Cannot create pending checker [%s:%d] =>[%s:%d]",
            lcand->m_BaseIP.c_str(), lcand->m_BasePort, rcand->m_ConnIP.c_str(), rcand->m_ConnPort);
            return false;
        }

        checker.release();
        bindReqMsg.release();
        return true;
    }

    Channel * Stream::CreateChannel(Protocol protocol)
    {
        return nullptr;
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

    void Stream::ConnectivityRecvThread(Stream * pThis, Channel * channel)
    {
        assert(pThis && channel);
        while (1)
        {
        }
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

        const STUN::ATTR::XorMappedAddr *pXormapAddr = nullptr;
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

namespace STUN {
    /*
    RFC4389
    For example, assuming an RTO of 500 ms,
    requests would be sent at times 0 ms, 500 ms, 1500 ms, 3500 ms, 7500
    ms, 15500 ms, and 31500 ms.  If the client has not received a
    response after 39500 ms
    */
    const Stream::TimeOutInterval Stream::UDPTimeoutInterval = { 500, 1000,2000,4000,8000,16000, 8000 };
    const Stream::TimeOutInterval Stream::TCPTimeoutInterval = { 39500 };

    Stream::Stream(uint16_t comp_id, Protocol protocol) :
        m_ComponentId(comp_id), m_LocalProtocol(protocol), m_GatherSubscriber(this), m_LocalAuthInfo("",""),m_RemoteAuthInfo("","")
    {
    }

    Stream::~Stream()
    {
    }

    bool Stream::GatherCandidate(const std::string& localIP, uint16_t port,
        uint16_t Ta, const UTILITY::PortRange& portRange,
        const UTILITY::Servers& stunServer, const UTILITY::Servers& turnServer)
    {

        // gather host candidates
        GatherHostCandidate(localIP, port);

        // gather server reflex candidates
        for (auto stun_itor = stunServer.begin(); stun_itor != stunServer.end(); ++stun_itor)
        {
            if (!GatherSvrCandidate(localIP, portRange._min, portRange._max, stun_itor->_ip, stun_itor->_port))
                continue;

            std::unique_lock<decltype(m_TaMutex)> locker(m_TaMutex);
            m_TaCond.wait_for(locker, std::chrono::milliseconds(Ta));
        }

        std::unique_lock<decltype(m_SessionChannelMutex)> locker(m_SessionChannelMutex);
        m_SessionChannelCond.wait(locker, [this]() {
            return this->m_SessionCnt < 0;
        });

        for (auto itor = m_SessionChannels.begin(); itor != m_SessionChannels.end(); ++itor)
        {
            assert(itor->first);
            itor->first->Unsubscribe(&m_GatherSubscriber);
            delete itor->first;
        }
        return m_CandChannels.size() > 0;
    }

    bool Stream::ConnectivityCheck(CandPeerContainer & candPeers)
    {
        for (auto peer_itor = candPeers.begin(); peer_itor != candPeers.end(); ++peer_itor)
        {
            const Candidate &lcand = (*peer_itor)->LCandidate();
            const Candidate &rcand = (*peer_itor)->LCandidate();

            auto candchannel_itor = m_CandChannels.find(const_cast<Candidate*>(&lcand));

            assert(candchannel_itor != m_CandChannels.end());

            auto channel    = candchannel_itor->second;
            auto sess_itor  = m_CheckSessions.find(channel);

            CheckSession *pSession(nullptr);

            if (sess_itor == m_CheckSessions.end())
            {
                switch (lcand.m_Protocol)
                {
                case Protocol::udp:
                    {
                    auto udpchannel = dynamic_cast<UDPChannel*>(channel);
                    assert(udpchannel);
                    pSession = new UDPCheckSession(*this, *udpchannel, m_LocalAuthInfo, m_RemoteAuthInfo);
                    }
                    break;

                case Protocol::tcp_pass:
                    {
                    auto tcppasschannel = dynamic_cast<TCPPassiveChannel*>(channel);
                    assert(tcppasschannel);
                    pSession = new TCPPassCheckSession(*this, *tcppasschannel, m_LocalAuthInfo, m_RemoteAuthInfo);
                    }
                    break;

                case Protocol::tcp_act:
                    {
                        auto tcpactchannel = dynamic_cast<TCPActiveChannel*>(channel);
                        assert(tcpactchannel);
                        pSession = new TCPActCheckSession(*this, *tcpactchannel, m_LocalAuthInfo, m_RemoteAuthInfo);
                    }
                    break;

                default:
                    break;
                }
            }
            else
                pSession = sess_itor->second;

            if (!pSession)
            {
                LOG_ERROR("Stream", "Connectivity Check failed to Create check session [%s:%d] => [%s:%d]",
                    channel->IP().c_str(), channel->Port(),
                    rcand.m_ConnIP.c_str(), rcand.m_ConnPort);
                return false;
            }

            if (!pSession->CreateChecker(*candchannel_itor->second, lcand, rcand))
            {
                LOG_ERROR("Stream", "Connectivity Check failed to Create check session [%s:%d] => [%s:%d]",
                    channel->IP().c_str(), channel->Port(),
                    rcand.m_ConnIP.c_str(), rcand.m_ConnPort);
                return false;
            }

            if (!pSession->CheckerNumber())
            {
                LOG_WARNING("Stream", "CheckSession has no checker");
                if (sess_itor != m_CheckSessions.end())
                    m_CheckSessions.erase(sess_itor);
                delete pSession;
            }

            if (!m_CheckSessions.insert(std::make_pair(channel, pSession)).second)
            {
                LOG_ERROR("Stream", "Connectivity Check failed to Create check session [%s:%d] => [%s:%d]",
                    channel->IP().c_str(), channel->Port(),
                    rcand.m_ConnIP.c_str(), rcand.m_ConnPort);
                return false;
            }
        }

        for (auto sess_itor = m_CheckSessions.begin(); sess_itor != m_CheckSessions.end(); ++sess_itor)
        {
            if (!sess_itor->second->Start())
            {
                LOG_ERROR("Stream", "Connectivity Check cannot Start check session %lld", sess_itor->second);
                return false;
            }
        }
        return true;
    }

    bool Stream::GatherHostCandidate(const std::string & localIP, uint16_t port)
    {
        std::auto_ptr<Channel> channel(CreateChannel(m_LocalProtocol, localIP, port));

        if (!channel.get())
        {
            LOG_ERROR("Stream", "GatherHostCandidate Failed to creat channel : [%s:%d]", localIP.c_str(), port);
            return false;
        }

        auto foundation = Candidate::ComputeFoundations(Candidate::CandType::host, localIP, localIP, m_LocalProtocol);
        auto priority   = Candidate::ComputePriority(Candidate::CandType::host, m_LocalPref, m_ComponentId);

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
        std::auto_ptr<Channel> channel(CreateChannel(m_LocalProtocol, localIP, lowPort, highPort, m_MaxTries));

        if (!channel.get())
        {
            LOG_ERROR("Stream", "GatherSvrCandidate failed to creating channel : [%s] => [%s:%d]", localIP.c_str(), stunserver.c_str(), stunport);
            return false;
        }

        STUN::TransId id;
        STUN::MessagePacket::GenerateRFC5389TransationId(id);

        std::auto_ptr<GatherSession> session(nullptr);
        if (m_LocalProtocol == Protocol::udp)
            session.reset(new GatherSession(this, UDPTimeoutInterval, id, *channel.get(), stunserver, stunport));
        else
            session.reset(new TCPGatherSession(this, TCPTimeoutInterval, id, *channel.get(), stunserver, stunport));

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

        std::lock_guard<decltype(m_SessionChannelMutex)> locker(m_SessionChannelMutex);
        if (!m_SessionChannels.insert(std::make_pair(session.get(), channel.get())).second)
        {
            LOG_ERROR("Stream", "GatherSvrCandidate Failed to create session channel pair");
            return false;
        }

        if (!session->Start())
        {
            LOG_ERROR("Stream", "Start Gather Session failed");
            m_SessionChannels.erase(session.get());
            return false;
        }

        return true;
    }


    Channel* Stream::CreateChannel(Protocol protocol, const std::string &ip, uint16_t port)
    {
        switch (protocol)
        {
        case Protocol::udp:
            return CreateChannel<UDPChannel>(ip, port);

        case Protocol::tcp_act:
            CreateChannel<TCPActiveChannel>(ip, port);

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
            CreateChannel<TCPActiveChannel>(ip, lowport, upperport, tries);

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
            return new  SvrCand(pri, foundation, connIP, connPort,baseIP, basePort);

        case Protocol::tcp_act:
            return new SvrActiveCand(pri, foundation, connIP, connPort, baseIP, basePort);

        case Protocol::tcp_pass:
            return new SvrPassiveCand(pri, foundation, connIP, connPort, baseIP, basePort);

        default:
            assert(0);
            return nullptr;
        }
    }


    Stream::GatherSession::GatherSession(const Stream* pOwner, const TimeOutInterval& timeout, STUN::TransIdConstRef id, Channel & channel,
        const std::string& targetIP, uint16_t port) :
        m_ReqMsg(id), m_timeout(timeout), m_Channel(channel),m_pOwner(pOwner),m_TargetIP(targetIP), m_TargetPort(port),m_Status(Status::waiting_resp)
    {
        RegisterMsg(static_cast<PG::MsgEntity::MSG_ID>(Message::StatusChange));
        assert(pOwner);
    }

    Stream::GatherSession::~GatherSession()
    {
        if (m_RecvThrd.joinable())
            m_RecvThrd.join();

        if (m_SendThrd.joinable())
            m_SendThrd.join();
    }

    bool Stream::GatherSession::Start()
    {
        assert(m_pOwner->m_LocalProtocol == Protocol::udp);
        assert(m_Status == Status::waiting_resp);

        UDPChannel *pChannel = dynamic_cast<UDPChannel*>(&m_Channel);
        assert(pChannel);

        if (!pChannel->BindRemote(m_TargetIP, m_TargetPort))
        {
            LOG_ERROR("GatherSession", "Bind Remote Server Failed [%s:%d]", m_TargetIP.c_str(), m_TargetPort);
            return false;
        }

        m_RecvThrd = std::thread(RecvThread, this);
        return true;
    }

    void Stream::GatherSession::OnStunMessage(const STUN::FirstBindRespMsg & respMsg)
    {
        LOG_INFO("Stream", "GatherSession Received Bind Response");

        const STUN::ATTR::XorMappedAddr *pXormapAddr(nullptr);
        if (respMsg.GetAttribute(pXormapAddr))
        {
            auto foundation = Candidate::ComputeFoundations(Candidate::CandType::svr_ref, m_Channel.IP(), m_TargetIP, m_pOwner->m_LocalProtocol);
            auto priority   = Candidate::ComputePriority(Candidate::CandType::svr_ref, m_pOwner->m_LocalPref, m_pOwner->m_ComponentId);
            auto candidate  = Stream::CreateSvrCandidate(m_pOwner->m_LocalProtocol, priority, foundation,
                pXormapAddr->IP(), pXormapAddr->Port(),
                m_Channel.IP(), m_Channel.Port());

            std::unique_lock<decltype(m_StatusMutex)> locker(m_StatusMutex);
            if (!candidate)
            {
                m_Status = Status::failed;
                LOG_ERROR("GatherSession", "Create Candidate Failed, [%s : %d] => [%s : %d]",
                    m_Channel.IP(), m_Channel.Port(), m_TargetIP.c_str(), m_TargetPort);
            }
            else
            {
                m_Status = Status::succeed;
                LOG_INFO("GatherSession", "Create Candidate Succeed, [%s : %d] => [%s : %d]",
                    m_Channel.IP(), m_Channel.Port(), m_TargetIP.c_str(), m_TargetPort);
            }

            Publish(static_cast<uint16_t>(Message::StatusChange), PG::MsgEntity::WPARAM(m_Status == Status::succeed), PG::MsgEntity::LPARAM(candidate));
            m_StatusCond.notify_one();
        }
    }

    void Stream::GatherSession::OnStunMessage(const STUN::FirstBindErrRespMsg & errRespMsg)
    {
        LOG_INFO("Stream", "GatherSession Received Bind Error Response, Set Status to failed");
        std::unique_lock<decltype(m_StatusMutex)> locker(m_StatusMutex);
        m_Status = Status::failed;
        Publish(static_cast<uint16_t>(Message::StatusChange), PG::MsgEntity::WPARAM(m_Status == Status::succeed), nullptr);
        m_StatusCond.notify_one();
    }

    void Stream::GatherSession::RecvThread(GatherSession * pThis)
    {
        assert(pThis);

        do
        {
            STUN::PACKET::stun_packet packet;

            auto bytes = pThis->m_Channel.Read(&packet, sizeof(packet));

            if (STUN::MessagePacket::IsValidStunPacket(packet, bytes))
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
        } while (pThis->m_Status != Status::waiting_resp);
    }

    void Stream::GatherSession::SendThread(GatherSession * pThis)
    {
        auto cnt = pThis->m_timeout.size();

        for (decltype(cnt) i = 0; cnt < cnt; ++i)
        {
            auto start  = std::chrono::steady_clock::now();
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
                return;

            LOG_ERROR("GatherSession", "transmit cnt = %d", i);
        }

        LOG_ERROR("GatherSession", "time out [%s:%d] => [%s:%d]",
            pThis->m_Channel.IP(), pThis->m_Channel.Port(),
            pThis->m_Channel.PeerIP(), pThis->m_Channel.PeerPort());

        // shutdown read to force read function return
        pThis->m_Channel.Shutdown(Channel::ShutdownType::read);

        std::lock_guard<decltype(pThis->m_StatusMutex)> locker(pThis->m_StatusMutex);
        pThis->m_Status = Status::failed;
        pThis->Publish(static_cast<uint16_t>(Message::StatusChange), PG::MsgEntity::WPARAM(false), nullptr);
    }


    Stream::TCPGatherSession::~TCPGatherSession()
    {
        if (m_ConnectThrd.joinable())
            m_ConnectThrd.join();
    }

    bool Stream::TCPGatherSession::Start()
    {
        assert(m_Status == Status::waiting_resp);
        m_ConnectThrd = std::thread(ConnectThread, this);
        return true;
    }

    void Stream::TCPGatherSession::ConnectThread(TCPGatherSession * pThis)
    {
        assert(pThis);
        assert(pThis->m_pOwner->m_LocalProtocol != Protocol::udp);

        TCPChannel *channel = dynamic_cast<TCPChannel*>(&pThis->m_Channel);
        assert(channel);

        if (!channel->Connect(pThis->m_TargetIP, pThis->m_TargetPort))
        {
            LOG_ERROR("TCP GatherSession", "Connect failed [%s:%d]",
                pThis->m_TargetIP.c_str(), pThis->m_TargetPort);

            pThis->m_Status = Status::failed;
            pThis->Publish(static_cast<uint16_t>(Message::StatusChange), PG::MsgEntity::WPARAM(false), nullptr);
            return;
        }

        pThis->m_RecvThrd = std::thread(GatherSession::RecvThread, pThis);
        pThis->m_SendThrd = std::thread(GatherSession::SendThread, pThis);
    }

    void Stream::GatherSubscriber::OnPublished(const PG::Publisher * publisher, MsgEntity::MSG_ID msgId, MsgEntity::WPARAM wParam, MsgEntity::LPARAM lParam)
    {
        assert(m_pOwner && publisher);

        std::lock_guard<decltype(m_pOwner->m_SessionChannelMutex)> locker(m_pOwner->m_SessionChannelMutex);

        auto session = reinterpret_cast<const GatherSession*>(publisher);

        auto itor = m_pOwner->m_SessionChannels.find(const_cast<GatherSession*>(session));

        assert(itor != m_pOwner->m_SessionChannels.end());
        assert(static_cast<GatherSession::Message>(msgId) == GatherSession::Message::StatusChange);

        if (wParam)
        {
            assert(lParam);
            std::lock_guard<decltype(m_pOwner->m_CandChannelsMutex)> l(m_pOwner->m_CandChannelsMutex);
            //auto cand = reinterpret_cast<Candidate*>(lParam);
            if (!m_pOwner->m_CandChannels.insert(std::make_pair(reinterpret_cast<const Candidate*>(lParam), itor->second)).second)
            {
                delete reinterpret_cast<Candidate*>(lParam);
                LOG_ERROR("Stream", "Gather succeed, but create candidate channel pair failed");
            }
        }

        m_pOwner->m_TaCond.notify_one();

        if (!m_pOwner->m_SessionCnt--)
            m_pOwner->m_SessionChannelCond.notify_one();
    }

    ////////////////////// CheckSession class //////////////////////
    Stream::CheckSession::CheckSession(Stream &Owner, const UTILITY::AuthInfo & lAuthInfo, const UTILITY::AuthInfo & rAuthInfo):
        m_Owner(Owner), m_LocalAuthInfo(lAuthInfo),m_RemoteAuthInfo(rAuthInfo)
    {
        RegisterMsg(static_cast<PG::MsgEntity::MSG_ID>(Message::ConnectivityCheck));
        RegisterMsg(static_cast<PG::MsgEntity::MSG_ID>(Message::RoleConflict));
        RegisterMsg(static_cast<PG::MsgEntity::MSG_ID>(Message::Nominate));
    }

    bool Stream::CheckSession::CreateChecker(Channel &channel, const Candidate& lcand, const Candidate &rcand)
    {
        std::string key = MakeKey(rcand.m_ConnIP, rcand.m_ConnPort);

        assert(m_Checks.find(key) == m_Checks.end());

        STUN::TransId id;
        STUN::MessagePacket::GenerateRFC5389TransationId(id);

        std::auto_ptr<Checker> checker(new Checker(*this, channel, lcand, rcand, id, m_Owner.m_bControlling, m_Owner.m_TieBreaker));
        if (!checker.get() || !m_Checks.insert(std::make_pair(key, checker.get())).second)
        {
            LOG_ERROR("CheckSession", "Cannot Create Checker");
            return false;
        }

        checker.release();
        return true;
    }

    std::string Stream::CheckSession::MakeKey(const std::string & ip, uint16_t port)
    {
        try
        {
            return ip + boost::lexical_cast<std::string>(port);
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("CheckSession", "MakeKey exception %s", e.what());
            return std::string();
        }
    }

    Stream::CheckSession::Checker * Stream::CheckSession::FindChecker(const std::string & ip, uint16_t port)
    {
        try
        {
            auto itor = m_Checks.find(MakeKey(ip,port));
            return itor == m_Checks.end() ? nullptr : itor->second;
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("Find Checker exception %s", e.what());
            return nullptr;
        }

    }

    Stream::CheckSession::Checker::Checker(CheckSession &Owner, Channel& channel, const Candidate& lcand, const Candidate& rcand, STUN::TransIdConstRef id, bool bControlling, uint64_t tieBreaker) :
        m_Owner(Owner), m_Channel(channel), m_LCand(lcand),m_RCand(rcand),
        m_ReqMsg(lcand.m_Priority,id, bControlling, tieBreaker, Owner.m_LocalAuthInfo._ufrag, Owner.m_RemoteAuthInfo._pwd)
    {
    }

    Stream::UDPCheckSession::UDPCheckSession(Stream & Owner, UDPChannel & channel, const UTILITY::AuthInfo & lAuthInfo, const UTILITY::AuthInfo & rAuthInfo)
        : Stream::CheckSession(Owner, lAuthInfo, rAuthInfo),m_Channel(channel)
    {
    }

    Stream::UDPCheckSession::~UDPCheckSession()
    {
        if (m_RecvThrd.joinable())
            m_RecvThrd.join();
    }

    bool Stream::UDPCheckSession::Start()
    {
        m_RecvThrd = std::thread(RecvThread, this);
    }

    void Stream::UDPCheckSession::RecvThread(UDPCheckSession * pThis)
    {
        assert(pThis);

        do
        {
            STUN::PACKET::stun_packet packet;
            boost::asio::ip::udp::endpoint sender_ep;

            auto bytes = pThis->m_Channel.ReadFrom(&packet, sizeof(packet), sender_ep);

            if (STUN::MessagePacket::IsValidStunPacket(packet, bytes))
            {
            }
            std::lock_guard<decltype(pThis->m_Mutex)> locker(pThis->m_Mutex);
        } while (pThis->m_bQuit);
    }

    Stream::TCPPassCheckSession::TCPPassCheckSession(Stream & Owner, TCPPassiveChannel & channel, const UTILITY::AuthInfo & lAuthInfo, const UTILITY::AuthInfo & rAuthInfo)
       : Stream::CheckSession(Owner, lAuthInfo, rAuthInfo)
    {
    }

    Stream::TCPActCheckSession::TCPActCheckSession(Stream & Owner, TCPActiveChannel & channel, const UTILITY::AuthInfo & lAuthInfo, const UTILITY::AuthInfo & rAuthInfo)
        :Stream::CheckSession(Owner, lAuthInfo, rAuthInfo)
    {
    }

}