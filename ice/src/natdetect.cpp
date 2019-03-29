/*
 * reference: RFC3489 & RFC4787
 */
#include "natdetect.h"
#include "stunmsg.h"
#include "channel.h"
#include "pg_log.h"
#include "config.h"

#include <assert.h>

using namespace STUN;

namespace {
    const static std::vector<int16_t> sTimeout = { 100,300, 700,1500 };//{ 100,300, 700,1500,3100,4700,6300,7900,9500 };
}

bool NATDetect::Detecte(const std::string & serverIP, uint16_t port, std::function<void(NATBehavior)> cb)
{
    assert(cb);

    {
        std::lock_guard<decltype(m_DetectMutex)> locker(m_DetectMutex);
        assert(m_DetectStatus == DetectStatus::done);
        if (m_DetectThrd.joinable())
            m_DetectThrd.join();
        m_DetectStatus = DetectStatus::inprogress;
    }

    // create channle
    static const uint16_t tryTimes = 5;
    auto range = Configuration::Instance().GetPortRange();
    m_LocalIP = Configuration::Instance().DefaultIP();

    bool bCreated = false;
    for (uint16_t i = 0; i < tryTimes; ++i)
    {
        m_LocalPort = PG::GenerateRandom(range.Min(), range.Max());
        m_UDPChannel.Close();
        if (m_UDPChannel.Bind(m_LocalIP, m_LocalPort))
        {
            bCreated = true;
            break;
        }
    }

    if (!bCreated)
    {
        LOG_ERROR("NATDetect","Cannot Create Channle");
        return false;
    }

    try
    {
        assert(!m_RecvThrd.joinable() && !m_DetectThrd.joinable());
        m_RecvThrd   = std::thread(RecvThread,this);
        m_DetectThrd = std::thread(DetecteThread,this, serverIP, port, cb);
        return true;
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("NATDetect", "Exception [%s]",e.what());

        {
            std::lock_guard<decltype(m_DetectMutex)> locker(m_DetectMutex);
            assert(m_DetectStatus == DetectStatus::done);
            m_DetectStatus = DetectStatus::done;
        }

        m_UDPChannel.Close();
        {
            std::lock_guard<decltype(m_DetectMutex)> locker(m_DetectMutex);
            m_DetectStatus = DetectStatus::done;
        }

        if (m_RecvThrd.joinable())
            m_RecvThrd.join();

        if (m_DetectThrd.joinable())
            m_DetectThrd.join();

        return false;
    }
}

NATDetect::NATDetect() :
    m_DetectStatus(DetectStatus::done)
{
}

NATDetect::~NATDetect()
{
    assert(!m_SendThrd.joinable() && !m_RecvThrd.joinable());

    if (m_DetectThrd.joinable())
        m_DetectThrd.join();
}

void NATDetect::SendThread(NATDetect *pThis)
{
    assert(pThis->m_pFirstBindReq && pThis->m_Callback);
    {
        std::lock_guard<decltype(pThis->m_RespMutex)> locker(pThis->m_RespMutex);
        pThis->m_bRespRecved = false;
    }

    std::unique_lock<decltype(pThis->m_RespMutex)> locker(pThis->m_RespMutex);
    for (auto itor = sTimeout.begin(); itor != sTimeout.end(); ++itor)
    {
        pThis->m_UDPChannel.Send(pThis->m_pFirstBindReq->GetData(), pThis->m_pFirstBindReq->GetLength(), pThis->m_DestIP, pThis->m_DestPort, false);
        if (pThis->m_SendCond.wait_for(locker, std::chrono::milliseconds(*itor), [&pThis]() {return pThis->m_bRespRecved; }))
            return;
    }
    pThis->m_Callback(false, nullptr);
}

void NATDetect::RecvThread(NATDetect *pThis)
{
    assert(pThis);
    STUN::PACKET::stun_packet packet;
    std::string sender_ip;
    uint16_t sender_port;
    while (1)
    {
        auto bytes = pThis->m_UDPChannel.Recv(&packet, sizeof(packet), sender_ip, sender_port, false);
        {
            std::lock_guard<decltype(pThis->m_DetectMutex)> locker(pThis->m_DetectMutex);
            if (pThis->m_DetectStatus == DetectStatus::done)
                break;
        }

        if (-1 == bytes)
        {
            {
                std::lock_guard<decltype(pThis->m_RespMutex)> locker(pThis->m_RespMutex);
                pThis->m_bRespRecved = true;
                pThis->m_SendCond.notify_one();
            }
            {
                std::lock_guard<decltype(pThis->m_FirstBindMutex)> locker(pThis->m_FirstBindMutex);
                pThis->m_Callback(false, nullptr);
            }
        }
        else if(STUN::MessagePacket::IsValidStunPacket(packet,bytes))
        {
            std::lock_guard<decltype(pThis->m_FirstBindMutex)> locker(pThis->m_FirstBindMutex);
            if (pThis->m_pFirstBindReq && 
                pThis->m_pFirstBindReq->IsTransIdEqual(packet.TransId()) &&
                pThis->m_DestIP == sender_ip && pThis->m_DestPort == sender_port)
            {
                std::unique_lock<decltype(pThis->m_RespMutex)> locker(pThis->m_RespMutex);
                pThis->m_bRespRecved = true;
                pThis->m_SendCond.notify_one();
                pThis->m_Callback(true, &STUN::FirstBindRespMsg(packet,bytes));
            }
        }

        {
            std::lock_guard<decltype(pThis->m_DetectMutex)> locker(pThis->m_DetectMutex);
        }
    }
}

void NATDetect::DetecteThread(NATDetect *pThis,const std::string & serverIP, uint16_t port, std::function<void(NATBehavior)> cb)
{
    assert(pThis && pThis->m_RecvThrd.joinable());

    NATBehavior behavior(NATBehavior::blocked);

    auto testIRet = pThis->TestI(serverIP, port);

    if (testIRet == TestIRet::no_resp)
    {
        behavior = NATBehavior::blocked;
    }
    else if (testIRet == TestIRet::same)
    {
        if (pThis->TestII(serverIP, port))
        {
            behavior = NATBehavior::opened;
        }
        else
        {
            behavior = NATBehavior::symUDPFirewall;
        }
    }
    else if (!pThis->TestII(serverIP, port))
    {
        behavior = NATBehavior::Symmetric;
        if (pThis->TestI(pThis->m_ChangedIP, pThis->m_ChangedPort) == TestIRet::same)
        {
            if (pThis->TestIII(serverIP, port))
                behavior = NATBehavior::restrictedAddress;
            else
                behavior = NATBehavior::restrictedPort;
        }
    }
    else
    {
        behavior = NATBehavior::fullcone;
    }

    {
        std::lock_guard<decltype(pThis->m_DetectMutex)> locker(pThis->m_DetectMutex);
        pThis->m_DetectStatus = DetectStatus::done;
    }

    pThis->m_UDPChannel.Close();

    if (pThis->m_SendThrd.joinable())
        pThis->m_SendThrd.joinable();

    if (pThis->m_RecvThrd.joinable())
        pThis->m_RecvThrd.join();

    cb(behavior);
}

NATDetect::TestIRet NATDetect::TestI(const std::string &dest, uint16_t port)
{
    /*
    In test I, the client sends a
    STUN Binding Request to a server, without any flags set in the
    CHANGE-REQUEST attribute, and without the RESPONSE-ADDRESS attribute
     */

    assert(!m_SendThrd.joinable() && m_RecvThrd.joinable());

    LOG_ERROR("NATDetect", "TestI started");

    STUN::TransId id;
    STUN::MessagePacket::GenerateRFC5389TransationId(id);
    STUN::FirstBindReqMsg msg(id);
    msg.Finalize();

    std::condition_variable wait_resp_cond;

    TestIRet testIRet(TestIRet::no_resp);
    {
        std::lock_guard<decltype(m_FirstBindMutex)> locker(m_FirstBindMutex);
        m_Callback = [this, &testIRet, &wait_resp_cond](bool bRet, const STUN::FirstBindRespMsg *respMsg) {
            assert(respMsg || !bRet);
            LOG_ERROR("xxxx","xxxxxxxxxxxxx");
            if (bRet)
            {
                const STUN::ATTR::MappedAddress    *pMappedAddr(nullptr);
                const STUN::ATTR::XorMappAddress   *pXormapAddr(nullptr);
                const STUN::ATTR::XorMappedAddrSvr *pXormappedAddr(nullptr);
                const STUN::ATTR::ChangedAddress   *pChangedAddr(nullptr);

                std::string mapIP;
                uint16_t mapPort;

                bool hasMappedAddr = false;

                if (respMsg->GetAttribute(pMappedAddr))
                {
                    mapIP = pMappedAddr->IP();
                    mapPort = pMappedAddr->Port();
                    hasMappedAddr = true;
                }
                else if (respMsg->GetAttribute(pXormapAddr))
                {
                    mapIP = pXormapAddr->IP();
                    mapPort = pXormapAddr->Port();
                    hasMappedAddr = true;
                }
                else if (respMsg->GetAttribute(pXormappedAddr))
                {
                    mapIP = pXormappedAddr->IP();
                    mapPort = pXormappedAddr->Port();
                    hasMappedAddr = true;
                }

                if (hasMappedAddr)
                {
                    if (respMsg->GetAttribute(pChangedAddr))
                    {
                        this->m_ChangedIP    = pChangedAddr->IP();
                        this->m_ChangedPort  = pChangedAddr->Port();
                    }
                    if (mapIP == this->m_LocalIP && mapPort == this->m_LocalPort)
                        testIRet = TestIRet::same;
                    else
                        testIRet = TestIRet::different;
                }
                else
                {
                    testIRet = TestIRet::no_resp;
                }
            }

            else
            {
                LOG_ERROR("NATDetected","TestI no resp");
            }
            wait_resp_cond.notify_one();
        };
        m_DestIP = dest;
        m_DestPort = port;
        m_pFirstBindReq = &msg;
    }

    try
    {
        m_SendThrd = std::thread(SendThread, this);

        std::mutex mutex;
        std::unique_lock<decltype(mutex)> locker(mutex);
        wait_resp_cond.wait(locker);
        m_SendThrd.join();

        {
            std::lock_guard<decltype(m_FirstBindMutex)> locker(m_FirstBindMutex);
            m_pFirstBindReq = nullptr;
            LOG_ERROR("TestI","TestI out");
            return testIRet;
        }
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("NATDetect", "TestI cannot start send thread [%s]", e.what());

        if (m_SendThrd.joinable())
            m_SendThrd.join();

        std::lock_guard<decltype(m_FirstBindMutex)> locker(m_FirstBindMutex);
        m_pFirstBindReq = nullptr;
        return TestIRet::no_resp;
    }

}

bool NATDetect::TestII(const std::string &dest, uint16_t port)
{
    /*
    RFC3489
    In test II, the client sends a
    Binding Request with both the "change IP" and "change port" flags
    from the CHANGE-REQUEST attribute set
    */

    assert(!m_SendThrd.joinable() && m_RecvThrd.joinable());

    LOG_ERROR("NATDetect","TestII started");
    STUN::TransId id;
    STUN::MessagePacket::GenerateRFC5389TransationId(id);
    STUN::FirstBindReqMsg msg(id);
    STUN::ATTR::ChangeRequest cq(true, true);

    msg.AddAttribute(cq);
    msg.Finalize();

    bool bHasResp = false;
    std::condition_variable wait_resp_cond;

    {
        std::lock_guard<decltype(m_FirstBindMutex)> locker(m_FirstBindMutex);
        m_pFirstBindReq = &msg;
        m_DestIP = dest;
        m_DestPort = port;
        m_pFirstBindReq = &msg;
        m_Callback = [&bHasResp, &wait_resp_cond](bool bRet, const STUN::FirstBindRespMsg*) {
            bHasResp = bRet;
            wait_resp_cond.notify_one();
        };
    }

    try
    {
        assert(!m_SendThrd.joinable() && m_RecvThrd.joinable());
        m_SendThrd = std::thread(SendThread,this);

        std::mutex mutex;
        std::unique_lock<decltype(mutex)> locker(mutex);
        wait_resp_cond.wait(locker);
        m_SendThrd.join();
        {
            std::lock_guard<decltype(m_FirstBindMutex)> locker(m_FirstBindMutex);
            m_pFirstBindReq = nullptr;
        }
        return bHasResp;
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("NATDetect", "TestII cannot start send thread [%s]", e.what());
        if (m_SendThrd.joinable())
            m_SendThrd.join();
        std::lock_guard<decltype(m_FirstBindMutex)> locker(m_FirstBindMutex);
        m_pFirstBindReq = nullptr;
        return false;
    }
}

bool NATDetect::TestIII(const std::string &dest, uint16_t port)
{
    /*
    RFC3489
    In test III, the client sends
    a Binding Request with only the "change port" flag set
    */
    assert(!m_SendThrd.joinable() && m_RecvThrd.joinable());

    STUN::TransId id;
    STUN::MessagePacket::GenerateRFC5389TransationId(id);
    STUN::FirstBindReqMsg msg(id);
    STUN::ATTR::ChangeRequest cq(false, true);

    msg.AddAttribute(cq);
    msg.Finalize();

    bool bHasResp = false;
    std::condition_variable wait_resp_cond;

    {
        std::lock_guard<decltype(m_FirstBindMutex)> locker(m_FirstBindMutex);
        m_pFirstBindReq = &msg;
        m_DestIP = dest;
        m_DestPort = port;
        m_pFirstBindReq = &msg;
        m_Callback = [&bHasResp, &wait_resp_cond](bool bRet, const STUN::FirstBindRespMsg*) {
            bHasResp = bRet;
            wait_resp_cond.notify_one();
        };
    }

    try
    {
        m_SendThrd = std::thread(SendThread,this);

        std::mutex mutex;
        std::unique_lock<decltype(mutex)> locker(mutex);
        wait_resp_cond.wait(locker);
        m_SendThrd.join();
        {
            std::lock_guard<decltype(m_FirstBindMutex)> locker(m_FirstBindMutex);
            m_pFirstBindReq = nullptr;
        }
        return bHasResp;
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("NATDetect", "TestIII cannot start send thread [%s]", e.what());
        if (m_SendThrd.joinable())
            m_SendThrd.join();
        std::lock_guard<decltype(m_FirstBindMutex)> locker(m_FirstBindMutex);
        m_pFirstBindReq = nullptr;
        return false;
    }

}