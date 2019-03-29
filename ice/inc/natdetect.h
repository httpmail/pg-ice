#pragma once

#include "natdetect.h"
#include "channel.h"

#include <thread>

namespace STUN {
    class FirstBindReqMsg;
    class FirstBindRespMsg;
}

class NATDetect {

public:
    enum class NATBehavior{
        opened,
        blocked,
        symUDPFirewall,
        fullcone,
        Symmetric,
        restrictedAddress,
        restrictedPort,
    };

public:
    static NATDetect& Instance() { static NATDetect sInstance; return sInstance;}

private:
    NATDetect();
    ~NATDetect();

    NATDetect(const NATDetect&) = delete;
    NATDetect& operator= (const NATDetect&) = delete;

public:
    bool Detecte(const std::string & serverIP, uint16_t port, std::function<void(NATBehavior)> cb);

private:
    using RespCallback = std::function<void(bool bRet, const STUN::FirstBindRespMsg *msg)>;

private:
    static void SendThread(NATDetect *pThis);
    static void RecvThread(NATDetect *pThis);
    static void DetecteThread(NATDetect *pThis, const std::string &serverIP, uint16_t port, std::function<void(NATBehavior)> cb);

private:
    enum class TestIRet{
        no_resp,
        same,
        different,
    };

    enum class DetectStatus {
        done,
        inprogress,
    };

private:
    TestIRet TestI(const std::string &dest, uint16_t port);
    bool TestII (const std::string &dest, uint16_t port);
    bool TestIII(const std::string &dest, uint16_t port);

private:
    std::thread             m_SendThrd;
    std::condition_variable m_SendCond;

    std::thread             m_RecvThrd;
    std::condition_variable m_RecvCond;

    std::mutex              m_DetectMutex;
    DetectStatus            m_DetectStatus;
    std::thread             m_DetectThrd;

    std::mutex              m_RespMutex;
    bool                    m_bRespRecved;

    std::string             m_ServerIP;
    uint16_t                m_ServerPort;

    std::string             m_ChangedIP;
    uint16_t                m_ChangedPort;

    std::string             m_LocalIP;
    uint16_t                m_LocalPort;

    ICE::UDPChannel         m_UDPChannel;
    boost::asio::io_service m_IOService;

    std::mutex              m_FirstBindMutex;
    RespCallback            m_Callback;
    std::string             m_DestIP;
    uint16_t                m_DestPort;
    STUN::FirstBindReqMsg   *m_pFirstBindReq;
};