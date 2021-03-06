#include "channel.h"
#include "pg_log.h"
#include "pg_util.h"
#include <boost/array.hpp>

#include <sstream>
#include<iomanip>
#include <memory>

namespace ICE {
    using namespace boost::asio::ip;

    boost::asio::io_service Channel::sIOService;
    const char* Channel::sInvalidIP = "Invalid IP";

    ///////////////////////////// UDPChannel class /////////////////////////////
    UDPChannel::UDPChannel(boost::asio::io_service &service /* = Channel::sIOService */) :
        m_Socket(service)
    {
    }

    UDPChannel::~UDPChannel()
    {
    }

    std::string UDPChannel::IP() const noexcept
    {
        boost::system::error_code error;
        auto ep = m_Socket.local_endpoint(error);

        if (error.value())
        {
            LOG_ERROR("UDPChannel", "get local address error :%d", error.value());
            return sInvalidIP;
        }
        return ep.address().to_string();
    }

    uint16_t UDPChannel::Port() const noexcept
    {
        boost::system::error_code error;

        auto ep = m_Socket.local_endpoint(error);
        if (error.value())
        {
            LOG_ERROR("UDPChannel", "get local port error :%d", error.value());
            return 0;
        }
        return ep.port();
    }

    std::string UDPChannel::PeerIP() const noexcept
    {
        boost::system::error_code error;
        auto ep = m_Socket.local_endpoint(error);
        if (error.value())
        {
            LOG_ERROR("UDPChannel", "get remote address error :%d", error.value());
            return sInvalidIP;
        }
        return ep.address().to_string();
    }

    uint16_t UDPChannel::PeerPort() const noexcept
    {
        boost::system::error_code error;
        auto ep = m_Socket.local_endpoint(error);
        if (error.value())
        {
            LOG_ERROR("UDPChannel", "get remote port error :%d", error.value());
            return 0;
        }
        return ep.port();
    }

    bool UDPChannel::Bind(const std::string& ip, uint16_t port, bool bReuse /*= false*/) noexcept
    {
        return Channel::Bind(m_Socket, udp::endpoint(address::from_string(ip), port), bReuse);
    }

    int32_t UDPChannel::Recv(void *buffer, int32_t size, bool /*framing*/) noexcept
    {
        boost::system::error_code error;

        auto bytes = m_Socket.receive(boost::asio::buffer(buffer, size), 0, error);

        if (error.value())
        {
            LOG_ERROR("UDPChannel", "Recv error :%d", error.value());
            return boost::asio::error::eof == error ? 0 : -1;
        }
        return bytes;
    }

    int32_t UDPChannel::Recv(void *buffer, int32_t size, std::string &sender_ip, uint16_t &sender_port, bool /*framing*/) noexcept
    {
        address addr;
        auto bytes = Recv(buffer, size, addr, sender_port, false);
        sender_ip = addr.to_string();
        return bytes;
    }

    int32_t UDPChannel::Recv(void *buffer, int32_t size, boost::asio::ip::address &sender, uint16_t &port, bool/*framing*/) noexcept
    {
        boost::system::error_code error;
        udp::endpoint ep;

        auto bytes = m_Socket.receive_from(boost::asio::buffer(buffer, size), ep, 0, error);

        if (error.value())
        {
            LOG_ERROR("UDPChannel", "Recv error :%d", error.value());
            return boost::asio::error::eof == error ? 0 : -1;
        }

        sender = ep.address();
        port = ep.port();
        return bytes;
    }

    int32_t UDPChannel::Send(const void *buffer, int32_t size, bool /*framing*/) noexcept
    {
        boost::system::error_code error;

        auto bytes = m_Socket.send(boost::asio::buffer(buffer, size), 0, error);

        if (error.value())
        {
            LOG_ERROR("UDPChannel", "Send error :%d", error.value());
            return boost::asio::error::eof == error ? 0 : -1;
        }
        return bytes;
    }

    int32_t UDPChannel::Send(const void *buffer, int32_t size, const std::string &recver_ip, uint16_t recver_port, bool /*framing*/) noexcept
    {
        return Send(buffer, size, address::from_string(recver_ip), recver_port,false);
    }

    int32_t UDPChannel::Send(const void *buffer, int32_t size, const boost::asio::ip::address &recver, uint16_t port, bool/*framing*/) noexcept
    {
        boost::system::error_code error;

        auto bytes = m_Socket.send_to(boost::asio::buffer(buffer, size), boost::asio::ip::udp::endpoint(recver, port),0,error);
        if (error.value())
        {
            LOG_ERROR("UDPChannel", "Send to [%s:%d] error :%d", recver.to_string().c_str(), port, error.value());
            return boost::asio::error::eof == error ? 0 : -1;
        }
        return bytes;
    }

    bool UDPChannel::Connect(const std::string& dest, uint16_t port) noexcept
    {
        boost::system::error_code error;
        udp::endpoint ep(address::from_string(dest), port);
        m_Socket.connect(ep, error);

        if (error.value())
        {
            LOG_ERROR("UDPChannel", "Connect to [%s, %d], error :%d", dest.c_str(), port, error.value());
            return false;
        }
        return true;
    }

    bool UDPChannel::Shutdown(ShutdownOption op) noexcept
    {
        return Channel::Shutdown(m_Socket, op);
    }

    void UDPChannel::Close() noexcept
    {
        Shutdown(Channel::ShutdownOption::Both);
        m_Socket.close();
    }

    ///////////////////////////// TCPChannel class /////////////////////////////
    TCPChannel::TCPChannel(boost::asio::io_service &service /*= Channel::sIOService*/)
        :m_Socket(service)
    {
    }

    TCPChannel::~TCPChannel()
    {
    }

    std::string TCPChannel::IP() const noexcept
    {
        boost::system::error_code error;
        auto ep = m_Socket.local_endpoint(error);
        if (error.value())
        {
            LOG_ERROR("TCPChannel", "get local address error :%d", error.value());
            return sInvalidIP;
        }
        return ep.address().to_string();
    }

    uint16_t TCPChannel::Port() const noexcept
    {
        boost::system::error_code error;
        auto ep = m_Socket.local_endpoint(error);
        if (error.value())
        {
            LOG_ERROR("TCPChannel", "get local port error :%d", error.value());
            return 0;
        }
        return ep.port();
    }

    std::string TCPChannel::PeerIP() const noexcept
    {
        boost::system::error_code error;
        auto ep = m_Socket.remote_endpoint(error);
        if (error.value())
        {
            LOG_ERROR("TCPChannel", "get remote address error :%d", error.value());
            return sInvalidIP;
        }
        return ep.address().to_string();
    }

    uint16_t TCPChannel::PeerPort() const noexcept
    {
        boost::system::error_code error;
        auto ep = m_Socket.remote_endpoint(error);
        if (error.value())
        {
            LOG_ERROR("TCPChannel", "get remote port error :%d", error.value());
            return 0;
        }
        return ep.port();
    }

    bool TCPChannel::Bind(const std::string& ip, uint16_t port, bool bReuse /*= false*/) noexcept
    {
        return Channel::Bind(m_Socket, tcp::endpoint(address::from_string(ip), port), bReuse);
    }

    int32_t TCPChannel::Recv(void *buffer, int32_t size, bool framing /*= false*/) noexcept
    {
        assert(buffer && size);

        boost::system::error_code error;

        int32_t bytes = 0;
        if (framing)
        {
            int16_t length;
            bytes = boost::asio::read(m_Socket, boost::asio::buffer(&length, sizeof(length)), boost::asio::transfer_at_least(sizeof(length)), error);
            if (error.value())
            {
                LOG_ERROR("TCPChannel", "recv error :%d",error.value());
                return boost::asio::error::eof == error ? 0 : -1;
            }

            length = boost::asio::detail::socket_ops::network_to_host_short(length);
            if (static_cast<int32_t>(length) > size)
            {
                LOG_ERROR("TCPChannel", "buffer size less than packet size");
                return -1;
            }

            bytes = boost::asio::read(m_Socket, boost::asio::buffer(buffer, length), boost::asio::transfer_all(), error);
            if (error)
            {
                LOG_ERROR("TCPChannel", "recv from error :%d",error.value());
                return boost::asio::error::eof == error ? 0 : -1;
            }
        }
        else
        {
            bytes = m_Socket.read_some(boost::asio::buffer(buffer, size), error);
            if (error.value())
            {
                LOG_ERROR("TCPChannel", "recv error :%d", error.value());
                return boost::asio::error::eof == error ? 0 : -1;
            }
        }
        return bytes;
    }

    int32_t TCPChannel::Recv(void *buffer, int32_t size, std::string& sender_ip, uint16_t& sender_port, bool framing /*= false*/) noexcept
    {
        assert(buffer && size);
        auto bytes = Recv(buffer, size, framing);
        if (bytes > 0)
        {
            boost::system::error_code error;
            auto ep = m_Socket.remote_endpoint(error);
            if (!error)
            {
                sender_ip = m_Socket.remote_endpoint().address().to_string();
                sender_port = m_Socket.remote_endpoint().port();
            }
            else
                return -1;
        }
        return bytes;
    }

    int32_t TCPChannel::Recv(void *buffer, int32_t size, boost::asio::ip::address &sender, uint16_t &port, bool framing) noexcept
    {
        auto bytes = Recv(buffer, size, framing);
        if (bytes > 0)
        {
            boost::system::error_code error;
            auto ep = m_Socket.remote_endpoint(error);
            if (!error)
            {
                sender = m_Socket.remote_endpoint().address();
                port = m_Socket.remote_endpoint().port();
            }
            else
                return -1;
        }
        return bytes;
    }

    int32_t TCPChannel::Send(const void *buffer, int32_t size, bool framing /*=false*/) noexcept
    {
        boost::system::error_code error;
        std::vector<boost::asio::const_buffer> v;

        if (framing)
        {
            uint16_t framing = PG::host_to_network<uint16_t>(size);
            v.push_back(boost::asio::buffer(&framing, sizeof(framing)));
        }

        v.push_back(boost::asio::buffer(buffer, size));

        auto bytes = boost::asio::write(m_Socket, v, boost::asio::transfer_all(), error);

        if (error)
        {
            LOG_ERROR("TCPChannel", "Send error :%d", error.value());
            return boost::asio::error::eof == error ? 0 : -1;
        }
        return bytes;
    }

    int32_t TCPChannel::Send(const void *buffer, int32_t size, const std::string &, uint16_t, bool framing /*=false*/) noexcept
    {
        assert(buffer && size);
        return Send(buffer, size, framing);
    }

    int32_t TCPChannel::Send(const void *buffer, int32_t size, const boost::asio::ip::address &recver, uint16_t port, bool framing) noexcept
    {
        return Send(buffer, size, framing);
    }

    bool TCPChannel::Connect(const std::string& dest, uint16_t port) noexcept
    {
        boost::system::error_code error;
        tcp::endpoint ep(address::from_string(dest), port);
        if (m_Socket.connect(ep, error))
        {
            LOG_ERROR("TCPChannel", "Connect to [%s, %d], error :%d", dest.c_str(), port, error.value());
            return false;
        }
        return true;
    }

    bool TCPChannel::Shutdown(ShutdownOption op) noexcept
    {
        return Channel::Shutdown(m_Socket, op);
    }

    void TCPChannel::Close() noexcept
    {
        Shutdown(ShutdownOption::Both);
        m_Socket.close();
    }

    ///////////////////////////// TCPPassiveChannel class ///////////////////////////// 
    TCPPassiveChannel::TCPPassiveChannel(boost::asio::io_service & service):
        m_Acceptor(service)
    {
    }

    bool TCPPassiveChannel::Bind(const std::string& ip, uint16_t port, bool bReuse /*=false*/) noexcept
    {
        tcp::endpoint ep(address::from_string(ip), port);

        boost::system::error_code error;

        if (m_Acceptor.open(ep.protocol(), error).value())
        {
            LOG_ERROR("TCPPassiveChannel", "Open Error %d", error.value());
            return false;
        }

        if (bReuse && m_Acceptor.set_option(boost::asio::socket_base::reuse_address(true), error).value())
        {
            LOG_ERROR("TCPPassiveChannel", "reuse Error %d", error.value());
            return false;
        }

        if (m_Acceptor.bind(ep, error).value())
        {
            LOG_ERROR("TCPPassiveChannel", "Bind Error %d", error.value());
            return false;
        }

        if (m_Acceptor.listen(sMaxBacklog, error).value())
        {
            LOG_ERROR("TCPPassiveChannel", "ListenError %d", error.value());
            return false;
        }
        return true;
    }

    bool TCPPassiveChannel::Connect(const std::string& ip, uint16_t port) noexcept
    {
        boost::system::error_code error;

        bool bRet = false;
        address target = address::from_string(ip);

        LOG_INFO("TCPPassiveChannel", "wait for [%s:%d] conntecting", ip.c_str(), port);

        while (1)
        {
            assert(!m_Socket.is_open());
            assert(m_Acceptor.is_open());
            if (m_Acceptor.accept(m_Socket, error))
            {
                LOG_ERROR("TCPPassiveChannel", "Connect, m_Acceptor.accept Error %d", error.value());
                bRet = false;
                break;
            }

            if (m_Socket.remote_endpoint().address() == target && port == m_Socket.remote_endpoint().port())
            {
                LOG_INFO("TCPPassiveChannel", "Connected [%s:%d] : [%s:%d]",
                    m_Socket.local_endpoint().address().to_string().c_str(), m_Socket.local_endpoint().port(),
                    ip.c_str(), port);
                bRet = true;
                break;
            }
            else
            {
                LOG_ERROR("TCPPassiveChannle", "unexcepted target");
                m_Socket.close(error);
            }
        }
        return bRet;
    }

    bool TCPPassiveChannel::Shutdown(ShutdownOption op) noexcept
    {
        boost::system::error_code error;
        if (m_Acceptor.close(error))
        {
            LOG_ERROR("TCPPassive", "Close acceptor error %d", error.value());
        }

        return Channel::Shutdown(m_Socket, op);
    }

    std::string TCPPassiveChannel::PeerIP() const noexcept
    {
        assert(m_Socket.is_open());

        return m_Socket.local_endpoint().address().to_string();
    }

    uint16_t TCPPassiveChannel::PeerPort() const noexcept
    {
        assert(m_Socket.is_open());
        return m_Socket.local_endpoint().port();
    }
}
