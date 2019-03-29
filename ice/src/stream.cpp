#include "stream.h"
#include "DataCarrier.h"
#include "Channel.h"
#include "config.h"
#include "stunmsg.h"
#include "session.h"
#include "media.h"

namespace {
    using namespace ICE;
    using TimeoutContainer = std::vector<uint32_t>;

    static TimeoutContainer sUDPTimeout = { 500, 1000, 2000, 4000, 8000, 16000, 8000 };
    static TimeoutContainer sTCPTimeout = { 395000 };
    static const uint16_t sNominatingTimeout = 10; // 10 seconds

    Candidate * CreateSvrCandidate(Protocol protocol,
        uint16_t compid,
        const std::string &stunserver,
        const std::string & connIP, uint16_t connPort,
        const std::string & baseIP, uint16_t basePort)
    {
        auto pri        = Candidate::ComputePriority(Candidate::CandType::svr_ref, Configuration::Instance().LocalPref(), compid);
        auto foundation = Candidate::ComputeFoundations(Candidate::CandType::svr_ref, baseIP, stunserver, protocol);

        switch (protocol)
        {
        case Protocol::tcp_pass:
            return new SvrPassiveCand(pri, foundation, connIP, connPort, baseIP, basePort);

        case Protocol::tcp_act:
            return new SvrActiveCand(pri, foundation, connIP, connPort, baseIP, basePort);

        case Protocol::udp:
            return new SvrCand(pri, foundation, connIP, connPort, baseIP, basePort);

        default:
            return nullptr;
        }
    }

    Candidate * CreateHostCandidate(Protocol protocol, uint16_t compid, const std::string & connIP, uint16_t connPort)
    {
        auto pri = Candidate::ComputePriority(Candidate::CandType::host, Configuration::Instance().LocalPref(), compid);
        auto foundation = Candidate::ComputeFoundations(Candidate::CandType::host, connIP, connIP, protocol);

        switch (protocol)
        {
        case Protocol::tcp_pass:
            return new PassiveCand(pri, foundation, connIP, connPort);

        case Protocol::tcp_act:
            return new ActiveCand(pri, foundation, connIP, connPort);

        case Protocol::udp:
            return new HostCand(pri, foundation, connIP, connPort);

        default:
            return nullptr;
        }
    }

    ///////////////////////////// class GatherSession //////////////////////////////////////
    class GatherSession {
    public:
        using ResultCallBack = std::function<void(bool, ICE::Channel& channel, const std::string &mapAddress, uint16_t port) >;

    private:
        enum class Status {
            init,
            waiting_resp,
            failed,
            passed,
        };

    public:
        GatherSession(STUN::TransIdConstRef id, ICE::Channel& channel)
            : m_Channel(channel), m_ReqMsg(id), m_RetCallBack(nullptr), m_Status(Status::init)
        {
        }

        virtual ~GatherSession()
        {
            if (m_SendThrd.joinable())
                m_SendThrd.join();

            if (m_RecvThrd.joinable())
                m_RecvThrd.join();
        }

        GatherSession(const GatherSession&) = delete;
        GatherSession& operator=(const GatherSession&) = delete;

    public:
        bool Start(ResultCallBack callback)
        {
            assert(callback && IsStatus(Status::init));

            std::lock_guard<decltype(m_StatusMutex)> locker(m_StatusMutex);

            m_Status = Status::waiting_resp;
            m_RetCallBack = callback;
            m_SendThrd = std::thread(&GatherSession::SendThread, this);
            m_RecvThrd = std::thread(&GatherSession::RecvThread, this);

            return true;
        }

    private:
        void OnStunMessage(const STUN::FirstBindRespMsg & msg)
        {
            LOG_INFO("GatherSession", "Received First Bind Response from[%s:%d]",
                m_Channel.PeerIP().c_str(), m_Channel.PeerPort());

            const STUN::ATTR::MappedAddress *pMappedAddr(nullptr);
            const STUN::ATTR::XorMappAddress *pXormapAddr(nullptr);
            const STUN::ATTR::XorMappedAddrSvr *pXormappedAddr(nullptr);

            bool bResult = true;
            std::string mapped;
            uint16_t port;

            if (msg.GetAttribute(pMappedAddr))
            {
                mapped = pMappedAddr->IP();
                port = pMappedAddr->Port();

            }
            else if (msg.GetAttribute(pXormapAddr))
            {
                mapped = pMappedAddr->IP();
                port = pMappedAddr->Port();
            }
            else if (msg.GetAttribute(pXormappedAddr))
            {
                mapped = pXormappedAddr->IP();
                port = pXormappedAddr->Port();
            }
            else
            {
                bResult = false;
                LOG_ERROR("GatherSession", "First Bind Response Message has no mapped address");
            }

            std::lock_guard<decltype(m_StatusMutex)> locker(m_StatusMutex);
            m_Status = bResult ? Status::passed : Status::failed;
            m_StatusCond.notify_all();

            m_RetCallBack(bResult, m_Channel, mapped, port);
        }
        void OnStunMessage(const STUN::FirstBindErrRespMsg & msg)
        {
            LOG_ERROR("GatherSession", "Received First Bind Error Response Message from [%s:%d]",
                m_Channel.PeerIP().c_str(), m_Channel.PeerPort());
            std::lock_guard<decltype(m_StatusMutex)> locker(m_StatusMutex);
            m_Status = Status::failed;
            m_StatusCond.notify_all();

            m_RetCallBack(false, m_Channel, "", 0);
        }
        bool IsStatus(GatherSession::Status eStatus)
        {
            std::lock_guard<decltype(m_StatusMutex)> locker(m_StatusMutex);
            return m_Status == eStatus;
        }

    private:
        static void SendThread(GatherSession * pThis)
        {
            assert(pThis);
            for (auto timer = sUDPTimeout.begin(); timer != sUDPTimeout.end(); ++timer)
            {
                pThis->m_Channel.Send(pThis->m_ReqMsg.GetData(), pThis->m_ReqMsg.GetLength());

                std::unique_lock<decltype(pThis->m_StatusMutex)> locker(pThis->m_StatusMutex);

                if (std::cv_status::no_timeout == pThis->m_StatusCond.wait_for(locker, std::chrono::milliseconds(*timer)))
                    break;
            }

            std::lock_guard<decltype(pThis->m_StatusMutex)> locker(pThis->m_StatusMutex);

            if (pThis->m_Status == Status::waiting_resp)
            {
                // we MUST invoke callback when timeout, otherwise no needed.
                LOG_ERROR("GatherSession", "timeout to receive response [%s:%d]=>[%s:%d]",
                    pThis->m_Channel.IP().c_str(), pThis->m_Channel.Port(),
                    pThis->m_Channel.PeerIP().c_str(), pThis->m_Channel.PeerPort());

                pThis->m_Status = Status::failed;
                pThis->m_RetCallBack(false, pThis->m_Channel, "", 0);
            }
        }
        static void RecvThread(GatherSession * pThis)
        {
            assert(pThis);
            while (pThis->IsStatus(Status::waiting_resp))
            {
                STUN::PACKET::stun_packet packet;
                auto bytes = pThis->m_Channel.Recv(&packet, sizeof(packet));

                if (STUN::MessagePacket::IsValidStunPacket(packet, bytes) && pThis->m_ReqMsg.IsTransIdEqual(packet))
                {
                    switch (packet.MsgId())
                    {
                    case STUN::MsgType::BindingResp:
                        pThis->OnStunMessage(STUN::FirstBindRespMsg(packet, bytes));
                        break;

                    case STUN::MsgType::BindingErrResp:
                        pThis->OnStunMessage(STUN::FirstBindErrRespMsg(packet, bytes));
                        break;

                    default:
                        LOG_WARNING("GatherSession", "RecvThread received unexcepted message [0x%X]", packet.MsgId());
                        break;
                    }
                }
            }
        }

    private:
        ICE::Channel          &m_Channel;
        STUN::FirstBindReqMsg  m_ReqMsg;
        ResultCallBack         m_RetCallBack;

        std::condition_variable m_StatusCond;
        std::mutex              m_StatusMutex;
        Status                  m_Status;

        std::thread            m_SendThrd;
        std::thread            m_RecvThrd;
    };

    //////////////////////////// class CheckSession ///////////////////////////////////////
    class CheckSession {
    public:
        enum class Status {
            failed,
            passed,
            nominated,
        };
    public:
        using Callback = std::function<void(Status, CheckSession&, const ICE::CandidatePeer &peer)>;

    public:
        CheckSession(ICE::Session &sess, ICE::Media &media, DataCarrier &dataCarrier, const ICE::CandidatePeer &peer, const TimeoutContainer &timer) :
            m_Carrier(dataCarrier), m_Timer(timer), m_Peer(peer),m_Session(sess), m_Media(media),m_pMsg(nullptr)
        {
            STUN::MessagePacket::GenerateRFC5389TransationId(m_Id);
        }
        virtual ~CheckSession()
        {
            m_bWaitResp = false;
            m_SendCond.notify_one();

            if (m_SendThrd.joinable())
                m_SendThrd.join();

            std::lock_guard<decltype(m_pMsgMutex)> locker(m_pMsgMutex);
            if (m_pMsg)
            {
                delete m_pMsg;
                m_pMsg = nullptr;
            }
        }

    public:
        void Start(bool bNominating, Callback callback)
        {
            assert(callback);

            if (m_SendThrd.joinable())
                m_SendThrd.join();

            std::lock_guard<decltype(m_pMsgMutex)> locker(m_pMsgMutex);

            m_Callback = callback;
            if (m_pMsg)
                delete m_pMsg;

            m_pMsg = new STUN::SubBindReqMsg(m_Peer.LCandidate().m_Priority,
                m_Id,
                m_Session.IsControlling(),
                m_Session.Tiebreaker(),
                m_Media.RIceUfrag() + ":" + m_Media.IceUfrag(),
                m_Media.RIcePwd());

            if (!this->m_pMsg)
            {
                m_Callback(Status::failed, *this, m_Peer);
                return;
            }

            if (bNominating)
                m_pMsg->AddAttribute(STUN::ATTR::UseCandidate());

            m_pMsg->Finalize();

            m_SendThrd = std::thread(&CheckSession::SendThread, this);
        }
        bool operator < (const CheckSession &other) const
        {
            if (this == &other)
                return false;

            if (m_Peer.Priority() == other.m_Peer.Priority())
                return this < &other;
            else
                return m_Peer.Priority() > other.m_Peer.Priority();
        }
        void OnDataCarrierRecved(const void *pData, int32_t bytes)
        {
            using namespace STUN;
            class DataGuard {
            public:
                DataGuard(const void *& pData) :
                    m_pData(pData)
                {

                }

                ~DataGuard()
                {
                    DataCarrier::Dealloc(m_pData);
                }
                const void *& m_pData;
            };

            if (pData == nullptr && bytes == 0)
            {
                OnConnectionLost();
                return;
            }

            DataGuard dataGuard(pData);
            auto packet = reinterpret_cast<const STUN::PACKET::stun_packet*>(pData);
            if (!MessagePacket::IsValidStunPacket(*packet, bytes))
                return;

            if (packet->MsgId() == STUN::MsgType::BindingRequest)
            {
                OnStunMessage(STUN::SubBindReqMsg(*packet, bytes));
                return;
            }

            if (0 != memcmp(m_Id, packet->TransId(), STUN::sTransationLength))
            {
                LOG_ERROR("CheckSession", "unmatched Transation id");
                return;
            }

            switch (packet->MsgId())
            {
            case MsgType::BindingErrResp:
                OnStunMessage(SubBindErrRespMsg(*packet, bytes));
                break;

            case MsgType::BindingResp:
                OnStunMessage(SubBindRespMsg(*packet, bytes));
                break;

            default:
                LOG_ERROR("CheckSession", "unexcepted message [0x%X] received", packet->MsgId());
                break;
            }
        }
        const ICE::CandidatePeer& GetCandPeer() const { return m_Peer; }

    private:
        static void SendThread(CheckSession *pThis)
        {
            assert(pThis);

            std::mutex send_mutex;
            auto & receiver = pThis->m_Peer.RCandidate().m_ConnIP;
            auto port       = pThis->m_Peer.RCandidate().m_ConnPort;
            bool bTimeout       = true;
            pThis->m_bWaitResp  = true;

            for (auto itor = pThis->m_Timer.begin(); itor != pThis->m_Timer.end(); ++itor)
            {
                {
                    std::lock_guard<decltype(pThis->m_pMsgMutex)> locker(pThis->m_pMsgMutex);
                    auto status = pThis->m_Carrier.Send(pThis->m_pMsg->GetData(), pThis->m_pMsg->GetLength(), receiver, port, *itor);
                    if (status == DataCarrier::send_status::failed)
                    {
                        LOG_ERROR("CheckSession", "Send Request failed");
                        break;
                    }
                    else if (status == DataCarrier::send_status::timeout)
                    {
                        LOG_ERROR("CheckSession","Send Request timeout [%s:%d] -> [%s:%d]",
                            pThis->m_Peer.LCandidate().m_BaseIP.c_str(), pThis->m_Peer.LCandidate().m_BasePort,
                            receiver.c_str(), port);
                        continue;
                    }
                    LOG_ERROR("CheckSession","Send Request OK [%s:%d] -> [%s:%d]",
                        pThis->m_Peer.LCandidate().m_BaseIP.c_str(),pThis->m_Peer.LCandidate().m_BasePort,
                        receiver.c_str(), port);
                }

                try
                {
                    std::unique_lock<decltype(send_mutex)> locker(send_mutex);
                    if(pThis->m_SendCond.wait_for(locker, std::chrono::milliseconds(*itor), [pThis]() {
                        return !pThis->m_bWaitResp;}))
                    {
                        bTimeout = false;
                        break;
                    }
                }
                catch (const std::exception& e)
                {
                    LOG_ERROR("CheckSession", "SendThread wait_for() exception [%s]", e.what());
                }
            }

            if (bTimeout)
            {
                LOG_ERROR("CheckSession", "Timeout to Receive Response Message [%s:%d]=>[%s:%d]",
                    pThis->m_Peer.LCandidate().m_BaseIP.c_str(), pThis->m_Peer.LCandidate().m_BasePort,
                    pThis->m_Peer.RCandidate().m_ConnIP.c_str(), pThis->m_Peer.RCandidate().m_BasePort);

                pThis->m_Callback(Status::failed, *pThis, pThis->m_Peer);
                return;
            }
        }

    private:
        void OnConnectionLost()
        {
            assert(m_Callback);
            LOG_ERROR("CheckSession", "OnConnectionLost %p", this);
            m_bWaitResp = false;
            m_SendCond.notify_one();
            m_Callback(Status::failed, *this, m_Peer);
        }
        void OnStunMessage(const STUN::SubBindReqMsg &msg)
        {
            using namespace STUN;
            assert(m_Callback);
            //RFC8445 [7.1.  STUN Extensions]
            const ATTR::Role *pRole(nullptr);
            const ATTR::Priority *pPriority(nullptr);
            const ATTR::UseCandidate *pUseCandidate(nullptr);

            LOG_ERROR("CheckSession","OnStunMessage->SubBindReqMsg [%s:%d] -> [%s:%d]",
                m_Peer.LCandidate().m_BaseIP.c_str(), m_Peer.LCandidate().m_BasePort,
                m_Peer.RCandidate().m_ConnIP.c_str(), m_Peer.RCandidate().m_ConnPort);

            if (!msg.GetAttribute(pRole) && !msg.GetAttribute(pPriority))
            {
                LOG_WARNING("CheckSession", "Reqeust Message has no role or priority attribute");
                m_Callback(Status::failed, *this, m_Peer);
                return;
            }

            if (m_Session.IsControlling() && msg.GetAttribute(pUseCandidate))
            {
                LOG_WARNING("CheckSession", "ice-controlling received use-candidate request");
                m_Callback(Status::failed, *this, m_Peer);
                return;
            }

            {// RFC5389 10.2.2. Receiving a Request
                const ATTR::MessageIntegrity *pMsgIntegrity(nullptr);
                const ATTR::UserName *pUsername(nullptr);

                auto & receiver = m_Peer.RCandidate().m_ConnIP;
                auto port = m_Peer.RCandidate().m_ConnPort;

                std::string username;
                if (msg.GetAttribute(pUsername))
                {
                    username = pUsername->Name();
                    auto pos = username.find('\0');
                    if (pos != std::string::npos)
                    {
                        username = username.substr(0, pos);
                    }

                }
                if (!msg.GetAttribute(pMsgIntegrity) || !pUsername)
                {
                    LOG_ERROR("CheckSession", "400 MessageIntegrity unmatched");
                    // 400 bad request
                    SubBindErrRespMsg errRespMsg(msg.TransationId(), 4, 0, "bad-request");
                    errRespMsg.Finalize();
                    m_Carrier.Send(errRespMsg.GetData(), errRespMsg.GetLength(),receiver, port);
                    m_Callback(Status::failed, *this, m_Peer);
                }
                else if ((m_Media.IceUfrag() + ":" + m_Media.RIceUfrag()) != username)
                {
                    // 401 Unauthorized
                    SubBindErrRespMsg errRespMsg(msg.TransationId(), 4, 1, "unmatched-username");
                    errRespMsg.Finalize();
                    //m_Carrier.Send(errRespMsg.GetData(), errRespMsg.GetLength(), receiver, port);
                    m_Callback(Status::failed, *this, m_Peer);
                }
                else if (!MessagePacket::VerifyMsgIntegrity(msg, m_Media.IcePwd()))
                {
                    // 401 Unauthorized
                    SubBindErrRespMsg errRespMsg(msg.TransationId(), 4, 1, "unmatched-MsgIntegrity");
                    errRespMsg.Finalize();
                    m_Carrier.Send(errRespMsg.GetData(), errRespMsg.GetLength(), receiver, port);
                    m_Callback(Status::failed, *this, m_Peer);
                }
                else if (msg.GetUnkonwnAttrs().size())
                {
                    SubBindErrRespMsg errRespMsg(msg.TransationId(), 4, 20, "Unknown-Attribute");
                    errRespMsg.AddUnknownAttributes(msg.GetUnkonwnAttrs());
                    errRespMsg.Finalize();
                    m_Carrier.Send(errRespMsg.GetData(), errRespMsg.GetLength(), receiver, port);
                    m_Callback(Status::failed, *this, m_Peer);
                }
                else if ((m_Session.IsControlling()) == (pRole->Type() == ATTR::Id::IceControlling))
                {
                    // RFC8445 [7.3.1.1.  Detecting and Repairing Role Conflicts]
                    if ((m_Session.IsControlling() && m_Session.Tiebreaker() >= pRole->TieBreaker()) ||
                        (!m_Session.IsControlling() && m_Session.Tiebreaker() < pRole->TieBreaker()))
                    {
                        LOG_ERROR("CheckSession", "Role Conflict!!!");
                        SubBindErrRespMsg errRespMsg(msg.TransationId(), 4, 87, "Role-Conflict");
                        errRespMsg.Finalize();
                        m_Carrier.Send(errRespMsg.GetData(), errRespMsg.GetLength(), receiver, port);
                    }
                    else
                    {
                        //TODO switch role
                    }
                }
                else
                {
                    ATTR::XorMappAddress xorMapAddr;
                    xorMapAddr.Port(port);
                    xorMapAddr.Address(boost::asio::ip::address::from_string(receiver).to_v4().to_uint());

                    SubBindRespMsg respMsg(msg.TransationId(), xorMapAddr, m_Media.IcePwd());
                    respMsg.Finalize();
                    m_Carrier.Send(respMsg.GetData(), respMsg.GetLength(), receiver, port);

                    const ATTR::UseCandidate *pUseCandidate(nullptr);
                    if (msg.GetAttribute(pUseCandidate))
                    {
                        /*
                         * invoke callback only when received use-candidate bind request
                         */
                        if (m_Session.IsControlling())
                            m_Callback(Status::failed, *this, m_Peer);
                        else
                            m_Callback(Status::nominated, *this, m_Peer);
                    }
                }
            }
        }
        void OnStunMessage(const STUN::SubBindRespMsg &msg)
        {
            using namespace STUN;
            assert(m_Callback);
            const ATTR::MessageIntegrity *pMsgIntegrity(nullptr);

            if (!msg.GetAttribute(pMsgIntegrity) || !MessagePacket::VerifyMsgIntegrity(msg, m_Media.RIcePwd()))
            {
                /*
                RFC5389 [10.1.3.  Receiving a Response]
                If the value does not match, or if
                MESSAGE-INTEGRITY was absent, the response MUST be discarded, as if
                it was never received
                */
                LOG_ERROR("CheckSession", "message-integrity unmatched");
                return;
            }

            const ATTR::XorMappAddress *pXorMapAddr(nullptr);
            if (msg.GetUnkonwnAttrs().size())
            {
                /*
                RFC5389 [7.3.3.  Processing a Success Response]
                If the success response contains unknown comprehension-required
                attributes, the response is discarded and the transaction is
                considered to have failed.
                */
                LOG_ERROR("CheckSession", "found unkonwn-attributs, set transaction as failed");
                m_bWaitResp = false;
                m_SendCond.notify_one();
                m_Callback(Status::failed, *this, m_Peer);
            }
            else if (!msg.GetAttribute(pXorMapAddr))
            {
                m_bWaitResp = false;
                m_SendCond.notify_one();
                m_Callback(Status::failed, *this, m_Peer);
            }
            else
            {
                m_bWaitResp = false;
                m_SendCond.notify_one();
                m_Callback(Status::passed, *this, m_Peer);
            }
        }
        void OnStunMessage(const STUN::SubBindErrRespMsg &msg)
        {
            using namespace STUN;
            assert(m_Callback);
            const ATTR::ErrorCode *pErrCode(nullptr);
            const ATTR::MessageIntegrity *pMsgIntegrity(nullptr);

            if (msg.GetAttribute(pMsgIntegrity) && !MessagePacket::VerifyMsgIntegrity(msg, m_Media.RIcePwd()))
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
                LOG_WARNING("CheckSession", "SubErrRespMsg cannot be authenticated");
                return;
            }

            if (!msg.GetAttribute(pErrCode))
            {
                /*
                there is no error code, invalid error resp message, set the status to failed
                */
                LOG_ERROR("CheckSession", "SubErrRespMsg has no error code");
                m_bWaitResp = false;
                m_SendCond.notify_one();
                m_Callback(Status::failed, *this, m_Peer);
                return;
            }

            auto errorCode = pErrCode->Code();

            if (errorCode == 487)
            {
                /*
                RFC8445 [7.2.5.1.  Role Conflict]
                */
                LOG_ERROR("CheckSession", "Role Conflict");
            }
            else if ((errorCode >= 300 && errorCode <= 399) ||
                (errorCode >= 400 && errorCode <= 499))
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
                LOG_ERROR("CheckSession", "SubErrRespMsg,error code [%d]", errorCode);
                m_bWaitResp = false;
                m_SendCond.notify_one();
                m_Callback(Status::failed, *this, m_Peer);
            }
            else if (errorCode >= 500 && errorCode <= 599)
            {
                /*
                o  If the error code is 500 through 599, the client MAY resend the
                request; clients that do so MUST limit the number of times they do
                pThis->
                */
            }
        }

    private:
        STUN::TransId m_Id;
        DataCarrier &m_Carrier;
        STUN::SubBindReqMsg *m_pMsg;
        std::mutex m_pMsgMutex;

        std::thread m_SendThrd;
        std::atomic_bool m_bWaitResp;
        std::condition_variable m_SendCond;

        ICE::Session &m_Session;
        ICE::Media &m_Media;
        Callback m_Callback;

        const TimeoutContainer &m_Timer;
        const ICE::CandidatePeer &m_Peer;
    };
}

namespace ICE {
    ////////////////////////////////////// class Stream //////////////////////////////////////
    Stream::Stream(Session& session, Media &media, uint16_t comp_id, Protocol protocol, const std::string& defaultIP, uint16_t defaultPort, OnRxCB rxCB)
        : m_Session(session), m_Media(media),m_Status(Status::init), m_ComponentId(comp_id), m_Protocol(protocol),m_DefaultIP(defaultIP),m_DefaultPort(defaultPort)
    {
        assert(rxCB != nullptr);
        m_ActiveChannel._rx_cb = rxCB;
    }

    Stream::~Stream()
    {
        LOG_ERROR("Stream","~Stream  enter %p", this);
        assert(!IsStatus(Status::checking));

        SetStatus(Status::quit);
        m_KeepAliveCond.notify_one();
        if (m_KeepAliveThrd.joinable())
            m_KeepAliveThrd.join();
        {
            std::lock_guard<decltype(m_CandChannelsMutex)> locker(m_CandChannelsMutex);
            for (auto itor = m_CandChannels.begin(); itor != m_CandChannels.end(); ++itor)
            {
                assert(itor->first);
                assert(itor->second);
                delete itor->first;
                delete itor->second;
            }
        }

        {
            std::lock_guard<decltype(m_ActiveMutex)> locker(m_ActiveMutex);
            if (m_ActiveChannel._bValid)
            {
                assert(m_ActiveChannel._channel && m_ActiveChannel._dataCarrier && m_ActiveChannel._lcand);
                m_ActiveChannel._channel->Close();
                m_ActiveChannel._dataCarrier->Stop();
                delete m_ActiveChannel._channel;
                delete m_ActiveChannel._dataCarrier;
                delete m_ActiveChannel._lcand;
            }
        }

        LOG_ERROR("Stream", "~Stream  leave %p", this);
    }

    bool Stream::GatherCandidates()
    {
        assert(IsStatus(Status::init) || IsStatus(Status::gatheringdone));

        struct GatherSessInfo
        {
            std::shared_ptr<GatherSession> sess;
            const Candidate                *cand;
        };

        using ChannelSessionMap = std::unordered_map<Channel*, GatherSessInfo >;

        auto& stunServers = Configuration::Instance().StunServer();
        auto& portRange   = Configuration::Instance().GetPortRange();

        ChannelSessionMap gatherSessions,failedSessions, passedSessions;

        // gather candidate from stun server
        for (auto itor = stunServers.begin(); itor != stunServers.end(); ++itor)
        {
            std::auto_ptr<Channel> channel(CreateChannel<UDPChannel>(m_DefaultIP, portRange.Min(), portRange.Max(), sAttempts));
            if (!channel.get() || !channel->Connect(itor->IP(), itor->Port()))
                continue;

            STUN::TransId id;
            STUN::MessagePacket::GenerateRFC5389TransationId(id);
            std::shared_ptr<GatherSession> session(new GatherSession(id, *channel.get()));

            if (!session || !gatherSessions.insert(std::make_pair(channel.get(), GatherSessInfo{session})).second)
                continue;

            channel.release();
        }

        struct Delegate{
            void OnGatherSession(bool bRet, ICE::Channel& channel, const std::string &mapAddress, uint16_t port)
            {
                std::auto_ptr<Candidate> cand(nullptr);
                if (bRet)
                {
                    Candidate::ComputeFoundations(Candidate::CandType::svr_ref, channel.IP(), channel.PeerIP(), m_Protocol);
                    Candidate::ComputePriority(Candidate::CandType::svr_ref, Configuration::Instance().LocalPref(), m_CompId);
                    cand.reset(CreateSvrCandidate(m_Protocol, m_CompId, channel.PeerIP(), mapAddress, port, channel.IP(), channel.Port()));
                }

                std::lock_guard<decltype(m_Mutex)> locker(m_Mutex);

                if (!cand.get())
                {
                    LOG_ERROR("Stream", "GatherCandidate failed to create candidate [%s:%d] => [%s:%d]",
                        channel.IP().c_str(), channel.Port(),
                        channel.PeerIP().c_str(), channel.PeerPort());

                    bRet = false;
                }

                auto itor = m_Sessions.find(&channel);
                assert(itor != m_Sessions.end());
                itor->second.cand = cand.release();

                auto& sessions = bRet ? m_Passed : m_Failed;
                sessions.insert(std::make_pair(&channel, itor->second));

                if (m_Sessions.size() == (m_Failed.size() + m_Passed.size()))
                    m_Cond.notify_one();
            }

            ChannelSessionMap       &m_Sessions;
            ChannelSessionMap       &m_Failed;
            ChannelSessionMap       &m_Passed;
            CandidateChannelMap     &m_CandChannels;
            std::mutex              &m_Mutex;
            std::condition_variable &m_Cond;
            const Protocol          &m_Protocol;
            const uint16_t          &m_CompId;
            Candidate               *m_Candidate;
        };

        std::mutex mutex;
        std::condition_variable cond;
        Delegate _delegate = { gatherSessions, failedSessions, passedSessions,
            m_CandChannels,
            mutex, cond, m_Protocol, m_ComponentId};

        for (auto itor = gatherSessions.begin(); itor != gatherSessions.end(); ++itor)
        {
            auto sess = itor->second.sess;

            assert(sess);

            if (!sess->Start(std::bind(&Delegate::OnGatherSession, &_delegate,
                std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4)))
            {
                std::lock_guard<decltype(mutex)> locker(mutex);
                failedSessions.insert(std::make_pair(itor->first, itor->second));
            }
        }

        // waiting for all session done
        std::unique_lock<decltype(mutex)> locker(mutex);
        cond.wait(locker, [&gatherSessions, &failedSessions, &passedSessions]() {
            return gatherSessions.size() == (failedSessions.size() + passedSessions.size());
        });

        while (passedSessions.size())
        {
            auto itor = passedSessions.begin();
            auto cand = itor->second.cand;
            delete itor->first;

            std::auto_ptr<Channel> channel(CreateChannel(m_Protocol, cand->m_BaseIP, cand->m_BasePort));
            if (!channel.get() || !m_CandChannels.insert(std::make_pair(cand, channel.get())).second)
            {
                LOG_ERROR("Stream", "GatherCandidate Create Candidate failed [%s:%d]",
                    cand->m_BaseIP.c_str(), cand->m_BasePort);

                delete cand;
                continue;
            }

            channel.release();

            passedSessions.erase(itor);
        }

        for (auto itor = failedSessions.begin(); itor != failedSessions.end(); ++itor)
        {
            delete itor->first;
            assert(!itor->second.cand);
            delete itor->second.cand;
        }

        // gather host cand
        std::auto_ptr<Channel> host_channel(CreateChannel(m_Protocol, m_DefaultIP, m_DefaultPort));
        if (host_channel.get())
        {
            std::auto_ptr<Candidate> host_cand(CreateHostCandidate(m_Protocol, m_ComponentId, m_DefaultIP, m_DefaultPort));
            if (!host_cand.get() || !m_CandChannels.insert(std::make_pair(host_cand.get(), host_channel.get())).second)
            {
                LOG_ERROR("Stream", "Gather Host Candidate Failed [%s:%d]",
                    m_DefaultIP.c_str(), m_DefaultPort);
            }
            else
            {
                host_channel.release();
                host_cand.release();
            }
        }

        SetStatus(Status::gatheringdone);
        std::lock_guard<decltype(m_CandChannelsMutex)> cand_locker(m_CandChannelsMutex);
        return m_CandChannels.size() > 0;
    }

    bool Stream::ConnectivityCheck(const CandPeerContainer & CandPeers)
    {
        assert(CandPeers.size() && IsStatus(Status::gatheringdone));
        SetStatus(Status::checking);
        LOG_INFO("Connectivity", "ConnectivityCheck->enter %p", this);
        struct CheckSessCmp
        {
            bool operator()(const CheckSession* s1, const CheckSession* s2) const
            {
                return *s1 < *s2;
            }
        };

        using DataCarrierMap = std::map<const Channel*, DataCarrier*>;
        using CheckSessions  = std::set<CheckSession*, CheckSessCmp>;

        struct Delegate {
            void OnCheckSessionDone(CheckSession::Status bRet, CheckSession& session, const CandidatePeer& peer)
            {
                std::lock_guard<decltype(m_checkMutex)> locker(m_checkMutex);

                LOG_ERROR("Stream", "OnCheckSessionDone [%s:%d]=>[%s:%d] %s",
                    peer.LCandidate().m_BaseIP.c_str(), peer.LCandidate().m_BasePort,
                    peer.RCandidate().m_ConnIP.c_str(), peer.RCandidate().m_ConnPort,
                    bRet == CheckSession::Status::failed ? "failed" : (bRet == CheckSession::Status::passed ? "passed" : "nominated"));

                if (bRet == CheckSession::Status::failed || bRet == CheckSession::Status::passed)
                {
                    auto & sessions = bRet == CheckSession::Status::failed ? m_FailedSessions : m_PassedSessions;
                    sessions.insert(&session);
                    if (m_CheckSessions.size() == (m_FailedSessions.size() + m_PassedSessions.size()))
                        m_SessionCond.notify_one();
                }
                else
                {
                    assert(!m_pNominatingSession || m_pNominatingSession != &session);
                    m_pNominatingSession = &session;
                    m_SessionCond.notify_one();
                }
            }

            void OnCheckSessionNominating(CheckSession::Status bRet, CheckSession& session, const CandidatePeer& peer)
            {
                std::lock_guard<decltype(m_checkMutex)> locker(m_checkMutex);
                assert(m_CheckSessions.find(&session) != m_CheckSessions.end());
                assert(bRet != CheckSession::Status::nominated);

                LOG_INFO("Stream", "[%s:%d] => [%s:%d] nominating %s",
                    peer.LCandidate().m_BaseIP.c_str(), peer.LCandidate().m_BasePort,
                    peer.RCandidate().m_ConnIP.c_str(), peer.RCandidate().m_ConnPort,
                    bRet == CheckSession::Status::failed ? "Failed" : "Passed");

                if (bRet == CheckSession::Status::failed)
                    m_pNominatingSession = nullptr;
                else
                    m_pNominatingSession = &session;
                m_SessionCond.notify_one();
            }

            std::mutex &m_checkMutex;
            std::condition_variable &m_SessionCond;
            CheckSessions &m_CheckSessions;
            CheckSessions &m_FailedSessions;
            CheckSessions &m_PassedSessions;
            CheckSession  *&m_pNominatingSession;
        };

        std::mutex  checkMutex;
        std::condition_variable checkCond;
        CheckSessions checkSessions, failedSessions, passedSessions;
        CheckSession *pNominatedSession(nullptr);

        DataCarrierMap Carriers;
        for (auto peer_itor = CandPeers.begin(); peer_itor != CandPeers.end(); ++peer_itor)
        {
            auto itor = m_CandChannels.find(&peer_itor->LCandidate());
            assert(itor != m_CandChannels.end() && itor->second);

            auto &rcand = peer_itor->RCandidate();
            auto &lcand = peer_itor->LCandidate();
            auto channel = itor->second;

            DataCarrier *carrier(nullptr);
            auto carrier_itor = Carriers.find(channel);

            if (carrier_itor == Carriers.end())
            {
                carrier = lcand.m_Protocol == Protocol::udp ?
                    new DataCarrier(*itor->second) : new ConnectedDataCarrier(*itor->second, rcand.m_ConnIP, rcand.m_ConnPort);
                if (!carrier || !Carriers.insert(std::make_pair(channel, carrier)).second)
                {
                    delete carrier;
                    LOG_ERROR("Stream", "Create DataCarrier error");
                    continue;
                }
            }
            else
            {
                carrier = carrier_itor->second;
            }

            assert(carrier);
            CheckSession *sess = new CheckSession(m_Session, m_Media, *carrier, *peer_itor, m_Protocol == Protocol::udp ? sUDPTimeout : sTCPTimeout);

            if (!sess)
            {
                LOG_ERROR("Stream", "ConnectivityCheck, Create CheckSession failed [%s:%d]=>[%s:%d]",
                    lcand.m_BaseIP.c_str(), lcand.m_BasePort,
                    rcand.m_ConnIP.c_str(), rcand.m_ConnPort);
                continue;
            }

            if (!carrier->Register(rcand.m_ConnIP, rcand.m_ConnPort,
                std::bind(&CheckSession::OnDataCarrierRecved, sess, std::placeholders::_1, std::placeholders::_2)))
            {
                LOG_ERROR("Stream", "ConnectivityCheck, register callback failed [%s:%d]=>[%s:%d]",
                    lcand.m_BaseIP.c_str(), lcand.m_BasePort,
                    rcand.m_ConnIP.c_str(), rcand.m_ConnPort);
                delete sess;
                continue;
            }

            if (!checkSessions.insert(sess).second)
            {
                LOG_ERROR("Stream", "ConnectivityCheck, insert [%s:%d]=>[%s:%d] to checkSession error",
                    lcand.m_BaseIP.c_str(), lcand.m_BasePort,
                    rcand.m_ConnIP.c_str(), rcand.m_ConnPort);

                carrier->Unregister(rcand.m_ConnIP, rcand.m_ConnPort);
                delete sess;
                continue;
            }
        }

        auto ClearResourceFunc = [&Carriers, &checkSessions, this]() {

            for (auto itor = this->m_CandChannels.begin(); itor != this->m_CandChannels.end(); ++itor)
            {
                assert(itor->first && itor->second);
                itor->second->Close(); // close channel
            }

            for (auto itor = Carriers.begin(); itor != Carriers.end(); ++itor)
            {
                delete itor->second;
            }

            for (auto itor = checkSessions.begin(); itor != checkSessions.end(); ++itor)
            {
                delete *itor;
            }

            LOG_ERROR("Stream","All session close");
            // now we could release all the invalid channels
            std::lock_guard<decltype(m_CandChannelsMutex)> locker(m_CandChannelsMutex);
            for (auto itor = this->m_CandChannels.begin(); itor != this->m_CandChannels.end(); ++itor)
            {
                assert(itor->first && itor->second);
                delete itor->first;
                delete itor->second;
            }

            this->m_CandChannels.clear();
        };

        if (Carriers.size() || checkSessions.size())
        {

            Delegate checkDelegate = {
                checkMutex,
                checkCond,
                checkSessions,
                failedSessions,
                passedSessions,
                pNominatedSession };

            for (auto itor = checkSessions.begin(); itor != checkSessions.end(); ++itor)
            {
                assert(*itor);
                (*itor)->Start(false, std::bind(&Delegate::OnCheckSessionDone, &checkDelegate,
                    std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
            }

            // start Carriers after session started
            std::for_each(Carriers.cbegin(), Carriers.cend(), [](auto &itor) {
                itor.second->Start();
            });

            LOG_INFO("Stream","Connectivity check check [%p] [%d] [%d]", this, checkSessions.size(),Carriers.size());
            // wait session check done
            {
                std::unique_lock<decltype(checkMutex)> locker(checkMutex);
                checkCond.wait(locker, [this, &checkSessions, &passedSessions, &failedSessions, &pNominatedSession]() {

                    LOG_INFO("Stream", "Connectivity check wake up [%p] [%d] [%d] [%d]", this, checkSessions.size(), passedSessions.size(), failedSessions.size());
                    return (checkSessions.size() == (passedSessions.size() + failedSessions.size())) || pNominatedSession;
                });
            }

            LOG_INFO("Stream", "Connectivity Check done total: [%d] passed [%d] failed [%d] ongoing [%d]",
                checkSessions.size(), passedSessions.size(), failedSessions.size(),
                checkSessions.size() - passedSessions.size() - failedSessions.size());

            if (checkSessions.size() != failedSessions.size())
            {
                if (m_Session.IsControlling())
                {
                    assert(!pNominatedSession && checkSessions.size() == (passedSessions.size() + failedSessions.size()));

                    if (passedSessions.size())
                    {
                        auto session = *passedSessions.begin();
                        passedSessions.erase(session);

                        session->Start(true, std::bind(&Delegate::OnCheckSessionNominating, &checkDelegate,
                            std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));

                        std::unique_lock<decltype(checkMutex)> locker(checkMutex);
                        checkCond.wait(locker);
                    }
                }
                else if (!pNominatedSession)
                {
                    LOG_INFO("Stream", "Connectivity Check has been done, wait for nominating (%ds) ", sNominatingTimeout);
                    std::unique_lock<decltype(checkMutex)> locker(checkMutex);
                    checkCond.wait_for(locker, std::chrono::seconds(sNominatingTimeout));
                }
                if (pNominatedSession)
                {
                    assert(checkSessions.find(pNominatedSession) != checkSessions.end());

                    auto peer = pNominatedSession->GetCandPeer();
                    auto cand_itor = m_CandChannels.find(&peer.LCandidate());

                    assert(cand_itor != m_CandChannels.end() && cand_itor->second);

                    LOG_INFO("Stream", "Actived Channel [%s:%d]=>[%s:%d]",
                        peer.LCandidate().m_BaseIP.c_str(), peer.LCandidate().m_BasePort,
                        peer.RCandidate().m_ConnIP.c_str(), peer.RCandidate().m_ConnPort);

                    std::lock_guard<decltype(m_ActiveMutex)> locker(m_ActiveMutex);
                    m_ActiveChannel._bValid = true;
                    m_ActiveChannel._lcand = &peer.LCandidate();
                    m_ActiveChannel._rcand_ip = peer.RCandidate().m_ConnIP;
                    m_ActiveChannel._rcand_port = peer.RCandidate().m_ConnPort;
                    m_ActiveChannel._channel = cand_itor->second;

                    auto carrier_itor = Carriers.find(m_ActiveChannel._channel);
                    assert(carrier_itor != Carriers.end() && carrier_itor->second);

                    carrier_itor->second->Unregister();

                    m_ActiveChannel._dataCarrier = carrier_itor->second;
                    m_ActiveChannel._dataCarrier->Register(peer.RCandidate().m_ConnIP, peer.RCandidate().m_ConnPort,
                        std::bind(&Stream::OnDataReceived, this, std::placeholders::_1, std::placeholders::_2));

                    m_KeepAliveThrd = std::thread(KeepAliveThread, this);

                    // remove from container
                    Carriers.erase(carrier_itor);
                    m_CandChannels.erase(cand_itor);
                }
            }
        }

        ClearResourceFunc();
        LOG_INFO("Connectivity", "ConnectivityCheck->leave %p", this);
        SetStatus(Status::checkingdone);
        std::lock_guard<decltype(m_ActiveMutex)> locker(m_ActiveMutex);
        return m_ActiveChannel._bValid;
    }

    void Stream::GetCandidates(CandContainer & Cands) const
    {
        assert(m_Status != Status::checkingdone);

        std::for_each(m_CandChannels.begin(), m_CandChannels.end(), [&Cands](auto &itor) {
            Cands.push_back(itor.first);
        });
    }

    bool Stream::SendData(const void * pData, uint32_t size)
    {
        assert(m_ActiveChannel._channel && m_ActiveChannel._dataCarrier);
        return DataCarrier::send_status::ok == m_ActiveChannel._dataCarrier->Send(pData, size, m_ActiveChannel._rcand_ip, m_ActiveChannel._rcand_port);
    }

    void Stream::Shutdown()
    {
        LOG_ERROR("Stream", "%p stream->close enter", this);
        {
            std::lock_guard<decltype(m_CandChannelsMutex)> locker(m_CandChannelsMutex);
            for (auto itor = m_CandChannels.begin(); itor != m_CandChannels.end(); ++itor)
            {
                assert(itor->first && itor->second);
                itor->second->Close();
            }
        }

        {
            std::lock_guard<decltype(m_ActiveMutex)> locker(m_ActiveMutex);
            if (m_ActiveChannel._bValid)
            {
                assert(m_ActiveChannel._channel);
                m_ActiveChannel._channel->Close();
            }
        }

        std::unique_lock<decltype(m_StatusMutex)> locker(m_StatusMutex);
        m_StatusCond.wait(locker, [this]() {
            return this->m_Status != Status::checking;
        });

        LOG_ERROR("Stream", "%p stream->close leave", this);
    }

    void Stream::CancleConnectivityCheck()
    {
        if (IsStatus(Status::checking))
        {
            std::lock_guard<decltype(m_CandChannelsMutex)> locker(m_CandChannelsMutex);
            for (auto itor = m_CandChannels.begin(); itor != m_CandChannels.end(); ++itor)
            {
                assert(itor->first && itor->second);
                itor->second->Close();
            }
        }
    }

    Channel * Stream::CreateChannel(Protocol protocol, const std::string & ip, uint16_t port)
    {
        switch (protocol)
        {
        case Protocol::udp:
            return CreateChannel<UDPChannel>(ip, port);

        case Protocol::tcp_act:
            return CreateChannel<TCPChannel>(ip, port, true);

        case Protocol::tcp_pass:
            return CreateChannel<TCPPassiveChannel>(ip, port, true);

        default:
            assert(0);
            return nullptr;
        }
    }

    Channel * Stream::CreateChannel(Protocol protocol, const std::string & ip, uint16_t lowport, uint16_t upperport, int16_t attempts)
    {
        switch (protocol)
        {
        case Protocol::udp:
            return CreateChannel<UDPChannel>(ip, lowport, upperport, attempts);

        case Protocol::tcp_act:
            return CreateChannel<TCPChannel>(ip, lowport, upperport, attempts, true);

        case Protocol::tcp_pass:
            return CreateChannel<TCPPassiveChannel>(ip, lowport, upperport, attempts, true);

        default:
            assert(0);
            return nullptr;
        }
    }

    void Stream::KeepAliveThread(Stream * pThis)
    {
        assert(pThis);
        assert(pThis->m_ActiveChannel._channel && pThis->m_ActiveChannel._dataCarrier);

        uint16_t tr = Configuration::Instance().Tr();
        std::mutex _mutex;

        while (pThis->m_Status != Status::quit)
        {
            STUN::TransId id;
            STUN::MessagePacket::GenerateRFC5389TransationId(id);
            STUN::IndicationMsg msg(id);
            msg.Finalize();
            pThis->m_ActiveChannel._dataCarrier->Send(msg.GetData(), msg.GetLength(),
                pThis->m_ActiveChannel._rcand_ip, pThis->m_ActiveChannel._rcand_port);

            std::unique_lock<decltype(_mutex)> locker(_mutex);
            pThis->m_KeepAliveCond.wait_for(locker, std::chrono::seconds(tr));
        }
    }

    void Stream::OnDataReceived(const void * pData, uint32_t size)
    {
        if (!pData || size == 0)
            return;

        auto packet = reinterpret_cast<const STUN::PACKET::stun_packet*>(pData);

        if (!STUN::MessagePacket::IsValidStunPacket(*packet, size))
        {
            assert(m_ActiveChannel._rx_cb);
            m_ActiveChannel._rx_cb(pData, size);
        }
        else
            DataCarrier::Dealloc(packet);
    }

    bool Stream::IsStatus(Status eStatus) const
    {
        std::lock_guard<decltype(m_StatusMutex)> locker(m_StatusMutex);
        return m_Status == eStatus;
    }

    void Stream::SetStatus(Status eStatus)
    {
        std::lock_guard<decltype(m_StatusMutex)> locker(m_StatusMutex);
        if (eStatus != m_Status)
        {
            m_Status = eStatus;
            m_StatusCond.notify_all();
        }
    }
}
