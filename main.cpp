
#include "agent.h"
#include "pg_log.h"
#include "sdp.h"
#include <boost/asio.hpp>
#include <thread>
#include <iostream>
#include "stunmsg.h"
#include "config.h"
#include "streamdef.h"
#include "natdetect.h"

#ifdef _DEBUG
#define DEBUG_CLIENTBLOCK new( _CLIENT_BLOCK, __FILE__, __LINE__)
#else
#define DEBUG_CLIENTBLOCK
#endif  // _DEBUG
#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#ifdef _DEBUG
#define new DEBUG_CLIENTBLOCK
#endif  // _DEBUG

static boost::asio::io_service sIOService;

class Endpoint {
public:
    Endpoint(const std::string& ip);
    virtual ~Endpoint();

    bool Create();

private:
    void OnSessionEvent(ICE::CAgent::SessionId, ICE::CAgent::SessionEvent e, ICE::CAgent::WPARAM wParam, ICE::CAgent::LPARAM lParam);
    void OnSessionCreated(bool bCreated);
    void OnSessionNegotiated(const std::string& answer);
    void OnComponet1Data(const void *pData, uint32_t size)
    {
        std::string info(reinterpret_cast<const char*>(pData), size);
        LOG_INFO("Endpoint", "Componet1 received info:\n[%s]", info.c_str());
    }

    void OnComponet2Data(const void *pData, uint32_t size)
    {
        std::string info(reinterpret_cast<const char*>(pData), size);
        LOG_INFO("Endpoint", "Componet2 received info:\n[%s]", info.c_str());
    }

private:
    static void SendOffer(Endpoint* pThis);
    static void RecvOffer(Endpoint* pthis);
    static void SendDataThread(Endpoint* pThis);

public:
    boost::asio::ip::udp::socket m_signal_socket;
    std::thread                  m_recv_thrd;
    std::thread                  m_send_thrd;
    ICE::CAgent::SessionId       m_sess_id;
    std::string                  m_offer;
    std::string                  m_remote_offer;
    std::condition_variable      m_send_cond;
    std::condition_variable      m_recv_cond;
    std::thread                  m_send_data_thrd;
    std::mutex m_roffer_mutex;
    bool m_broffer_recved;
    std::atomic_bool m_bNego;
    std::atomic_bool m_bQuit;
    std::mutex       m_channel_mutex;
};

#include "channel.h"

ICE::UDPChannel sChannel(sIOService);

void RecvThread()
{
    STUN::PACKET::stun_packet packet;
    std::string ip;
    uint16_t port;
    auto ret = sChannel.Recv(&packet, sizeof(packet), ip, port, false);

    std::cout << ret << std::endl;
    return;
}

void SendThread()
{

    sChannel.Bind(Configuration::Instance().DefaultIP(), 20000);

    STUN::TransId id;
    STUN::MessagePacket::GenerateRFC5389TransationId(id);
    STUN::FirstBindReqMsg msg(id);

    STUN::ATTR::ChangeRequest req(false, true);
    //msg.AddAttribute(req);

    msg.Finalize();

    if (-1 != sChannel.Send(msg.GetData(), msg.GetLength(), "192.168.110.52", 3478, false))
    {
        static auto thread = std::thread(RecvThread);
        thread.join();
    }
}

int main() 
{
    PG::log::Instance().SetLogFile("abc.log");
    bool b = false;
    std::condition_variable cond;
    NATDetect::Instance().Detecte("216.93.246.18", 3478, [&b, &cond](NATDetect::NATBehavior behavior) {
        switch (behavior)
        {
        case NATDetect::NATBehavior::blocked:
            std::cout << " blocked" << std::endl;
            break;

        case NATDetect::NATBehavior::fullcone:
            std::cout << " fullcone" << std::endl;
            break;

        case NATDetect::NATBehavior::opened:
            std::cout << " opened" << std::endl;
            break;

        case NATDetect::NATBehavior::restrictedAddress:
            std::cout << " restrictedAddress" << std::endl;
            break;

        case NATDetect::NATBehavior::restrictedPort:
            std::cout << " restrictedPort" << std::endl;
            break;

        case NATDetect::NATBehavior::Symmetric:
            std::cout << " Symmetric" << std::endl;
            break;

        case NATDetect::NATBehavior::symUDPFirewall:
            std::cout << " symUDPFirewall" << std::endl;
            break;

        default:
            break;
        }
        b = true;
        cond.notify_one();
    });

    std::mutex mutext;
    std::unique_lock<decltype(mutext)> locker(mutext);
    cond.wait(locker, [&b]() {
        return b;
    });
#if 0

    _CrtSetDbgFlag(_CrtSetDbgFlag(_CRTDBG_REPORT_FLAG) | _CRTDBG_LEAK_CHECK_DF);

    auto& config = Configuration::Instance();

    config.AddStunServer("64.235.150.11",3478);
    config.AddStunServer("216.93.246.18", 3478);
    config.AddStunServer("192.168.110.123", 3478);

    Endpoint ep(config.DefaultIP());
    ep.Create();
    //while (1);
    while (!ep.m_bNego);
    std::this_thread::sleep_for(std::chrono::seconds(3));

    LOG_INFO("Main", "Main Quit");
#endif
}

Endpoint::Endpoint(const std::string& ip) :
    m_signal_socket(sIOService), m_bNego(false), m_bQuit(false)
{
    try
    {
        boost::asio::ip::udp::endpoint ep(boost::asio::ip::address::from_string(ip), 32001);
        m_signal_socket.open(ep.protocol());
        m_signal_socket.set_option(boost::asio::socket_base::reuse_address(true));
        m_signal_socket.bind(ep);
        m_broffer_recved = false;
        m_send_thrd = std::thread(Endpoint::SendOffer, this);
        m_recv_thrd = std::thread(Endpoint::RecvOffer, this);
    }
    catch (const std::exception&e)
    {
        std::cout << e.what() << std::endl;
    }

}

Endpoint::~Endpoint()
{
    m_bQuit = true;
    std::this_thread::sleep_for(std::chrono::seconds(3));
    m_signal_socket.close();
    if (m_recv_thrd.joinable())
        m_recv_thrd.join();

    if (m_send_thrd.joinable())
        m_send_thrd.join();

    if (m_send_data_thrd.joinable())
        m_send_data_thrd.join();

    ICE::CAgent::Instance().ReleaseSession(m_sess_id);

    LOG_INFO("Endpoint", "Endpoint quit");
}

bool Endpoint::Create()
{
    using namespace ICE;
    static std::vector<MediaAttr> MediaAttrs = {
        {
#if 0
            "applicationsharing", true,
            {
                ICE::MediaAttr::StreamAttr{ ICE::Protocol::tcp_act,  1, 10000, Configuration::Instance().DefaultIP(), std::bind(&Endpoint::OnComponet1Data, this, std::placeholders::_1,std::placeholders::_2)},
                ICE::MediaAttr::StreamAttr{ ICE::Protocol::tcp_pass, 2, 10001, Configuration::Instance().DefaultIP(), std::bind(&Endpoint::OnComponet2Data, this, std::placeholders::_1,std::placeholders::_2) },
            }
        },
#else
        {
            "audio",false,
            {
                ICE::MediaAttr::StreamAttr{ ICE::Protocol::udp, 1, 10000, Configuration::Instance().DefaultIP(), std::bind(&Endpoint::OnComponet1Data, this, std::placeholders::_1,std::placeholders::_2) },
                ICE::MediaAttr::StreamAttr{ ICE::Protocol::udp, 2, 10001, Configuration::Instance().DefaultIP(), std::bind(&Endpoint::OnComponet2Data, this, std::placeholders::_1,std::placeholders::_2) },
            }
        }
#endif
        }
    };

    m_sess_id = CAgent::Instance().CreateSession(MediaAttrs,
        std::bind(&Endpoint::OnSessionEvent,this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3,std::placeholders::_4));
    return false;
}

void Endpoint::OnSessionEvent(ICE::CAgent::SessionId id, ICE::CAgent::SessionEvent e, ICE::CAgent::WPARAM wParam, ICE::CAgent::LPARAM lParam)
{
    assert(m_sess_id == id);

    switch (e)
    {
    case ICE::CAgent::SessionEvent::created:
        OnSessionCreated((uint32_t)wParam > 0);
       // m_bNego = true;
        break;

    case ICE::CAgent::SessionEvent::negotiated:
        m_bNego = true;
        OnSessionNegotiated(*reinterpret_cast<std::string*>(wParam));
        break;

    default:
        LOG_ERROR("EndPoint", "OnSessionEvent unexcepted event :[%d]", e);
        break;
    }
}

void Endpoint::OnSessionCreated(bool bCreated)
{
    LOG_INFO("EndPoint", "OnSessionCreated [%s]", bCreated ? "succeed" : "failed");
    if (bCreated)
    {
        ICE::CAgent::Instance().SetSessionRole(m_sess_id, false);
        ICE::CAgent::Instance().MakeOffer(m_sess_id, m_offer);
        LOG_INFO("Endpoint", "Offer:\n%s", m_offer.c_str());
        m_send_cond.notify_one();
    }
}

void Endpoint::OnSessionNegotiated(const std::string & answer)
{
    LOG_INFO("EndPoint", "OnSessionNegotiated:\n%s", answer.c_str());
    if (answer.length())
    {
        m_send_data_thrd = std::thread(SendDataThread, this);
    }
}

void Endpoint::SendOffer(Endpoint *pThis)
{
    assert(pThis);
    std::mutex mutex;
    std::unique_lock<decltype(mutex)> locker(mutex);
    pThis->m_send_cond.wait(locker);

    if (pThis->m_offer.length() == 0)
        return;

    try
    {
        boost::asio::ip::udp::endpoint remoteEp(pThis->m_signal_socket.local_endpoint().address(), 32000);
        while (!pThis->m_bQuit)
        {
            auto size = pThis->m_signal_socket.send_to(boost::asio::buffer(pThis->m_offer.data(), pThis->m_offer.length()), remoteEp);
            std::lock_guard<decltype(pThis->m_roffer_mutex)> recv_locker(pThis->m_roffer_mutex);
            if (true == pThis->m_send_cond.wait_for(locker, std::chrono::milliseconds(500), [pThis]() {return pThis->m_broffer_recved;}))
                break;
        }

        if(pThis->m_remote_offer.length())
            ICE::CAgent::Instance().MakeAnswer(pThis->m_sess_id, pThis->m_remote_offer);
    }
    catch (const std::exception&e)
    {
        LOG_ERROR("Exception", ":%s", e.what());
    }
}

void Endpoint::RecvOffer(Endpoint *pThis)
{
    boost::asio::ip::udp::endpoint remoteEp(pThis->m_signal_socket.local_endpoint().address(), 32000);
    char buffer[4096];
    while (!pThis->m_bQuit)
    {
        try
        {
            boost::system::error_code error;
            auto bytes = pThis->m_signal_socket.receive_from(boost::asio::buffer(buffer, sizeof(buffer)), remoteEp, 0, error);

            if (error)
                continue;

            std::lock_guard<decltype(pThis->m_roffer_mutex)> locker(pThis->m_roffer_mutex);
            pThis->m_remote_offer = std::string(buffer, bytes);
            pThis->m_broffer_recved = true;
            LOG_INFO("Endpoint", "Received:\n%s", pThis->m_remote_offer.c_str());
            break;
        }
        catch (const std::exception &e)
        {
            LOG_ERROR("Exception :", " %s", e.what());
        }
    }
}

void Endpoint::SendDataThread(Endpoint * pThis)
{
    assert(pThis);
    uint32_t cnt = 0;
    while (!pThis->m_bQuit)
    {
        cnt++;
        char buf[256];
        snprintf(buf, sizeof(buf), "send Info [%d]", cnt);
        if (PG::GenerateRandom32() & 1)
        {
            std::string info = "channel 1 ";
            info += buf;
            ICE::CAgent::Instance().SendData(pThis->m_sess_id, "audio", 1, info.data(), info.length());
        }
        else
        {
            std::string info = "channel 2 ";
            info += buf;
            ICE::CAgent::Instance().SendData(pThis->m_sess_id, "audio", 2, info.data(), info.length());
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

