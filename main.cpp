

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "agent.h"
#include "session.h"
#include "pg_log.h"
#include "sdp.h"
#include <boost/asio.hpp>
#include <thread>
#include <iostream>
#include< windows.h> 
#include <WS2tcpip.h>
#include "stunmsg.h"
#include "config.h"

class Endpoint {
public:
    Endpoint(const std::string& ip);
    virtual ~Endpoint();

    static void RecvThread(Endpoint *pThis);

public:
    boost::asio::ip::udp::socket m_signal_socket;
    std::thread                  m_recv_thrd;
};

static boost::asio::io_service sIOService;
static std::mutex sMutex;
static std::condition_variable sCond;
static bool bRecved = false;
static std::string sOffer;

int main() 
{
    auto& config = Configuration::Instance();

    config.AddStunServer("64.235.150.11",3478);
    //config.AddStunServer("216.93.246.18", 3478);
    //config.AddStunServer("192.168.110.123", 3478);

    Endpoint ep(config.DefaultIP());
    ICE::Session session;

    ICE::MediaAttr videoMedia = {
        "video",
        {
            ICE::MediaAttr::StreamAttr{ ICE::Protocol::udp, 1, 10000, config.DefaultIP() },
            ICE::MediaAttr::StreamAttr{ ICE::Protocol::udp, 2, 10001, config.DefaultIP() },
        }
    };

    ICE::MediaAttr audioMedia = {
        "audio",
        {
            ICE::MediaAttr::StreamAttr{ ICE::Protocol::udp, 1, 10010, config.DefaultIP() },
            ICE::MediaAttr::StreamAttr{ ICE::Protocol::udp, 2, 10011, config.DefaultIP() },
        }
    };

    std::string offer;
    session.SetControlling(false);
    if (session.CreateMedia(videoMedia))
    {

        if (session.MakeOffer(offer))
        {
            LOG_INFO("Main", "%s", offer.c_str());
        }

        CSDP sdp;
        if (sdp.Decode(offer))
        {
            LOG_INFO("Decode", "Done");
        }
        else
        {
            LOG_ERROR("Decode", "Error");
        }

        try
        {
            boost::asio::ip::udp::endpoint remoteEp(ep.m_signal_socket.local_endpoint().address(), 32000);
            while (1)
            {
                auto size = ep.m_signal_socket.send_to(boost::asio::buffer(offer.data(), offer.length()), remoteEp);
                std::unique_lock<decltype(sMutex)> locker(sMutex);
                auto ret = sCond.wait_for(locker, std::chrono::milliseconds(500), [] {
                    return bRecved;
                });

                if (ret)
                    break;
            }
        }
        catch (const std::exception&e)
        {
            LOG_ERROR("Exception", ":%s", e.what());
        }

        std::string answerOffer;
        session.MakeAnswer(sOffer, answerOffer);
        LOG_ERROR("answer", "%s", answerOffer.c_str());
    }
    else
    {
        assert(0);
    }
    while (1);
}

Endpoint::Endpoint(const std::string& ip) :
    m_signal_socket(sIOService)
{
    boost::asio::ip::udp::endpoint ep(boost::asio::ip::address::from_string(ip),32001);
    m_signal_socket.open(ep.protocol());
    m_signal_socket.bind(ep);

    m_recv_thrd = std::thread(Endpoint::RecvThread, this);
}

Endpoint::~Endpoint()
{
    if (m_recv_thrd.joinable())
        m_recv_thrd.join();
}

void Endpoint::RecvThread(Endpoint * pThis)
{
    boost::asio::ip::udp::endpoint remoteEp(pThis->m_signal_socket.local_endpoint().address(), 32000);
    char buffer[4096];
    while (1)
    {
        try
        {
            boost::system::error_code error;
            auto bytes = pThis->m_signal_socket.receive_from(boost::asio::buffer(buffer, sizeof(buffer)), remoteEp, 0, error);

            if (error)
                continue;

            std::lock_guard<decltype(sMutex)> locker(sMutex);
            bRecved = true;
            sOffer = std::string (buffer, bytes);
            sCond.notify_one();
        }
        catch (const std::exception &e)
        {
            LOG_ERROR("Exception :"," %s",e.what());
        }
    }
}

