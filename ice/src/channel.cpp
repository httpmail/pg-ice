#include "channel.h"
#include "pg_log.h"
#include <boost/array.hpp>
#include <memory>

namespace ICE {

    boost::asio::io_service Channel::sIOService;

    //static boost::asio::io_service sIOService;

    Channel::~Channel()
    {
        //assert(0);
    }

    //////////////////////// UDPChannel //////////////////////////////
    UDPChannel::UDPChannel(boost::asio::io_service& service /*= sIOService*/) :
        m_Socket(service)
    {
    }

    UDPChannel::~UDPChannel()
    {
        if (m_Socket.is_open())
            Close();
    }

    bool UDPChannel::BindRemote(const std::string & ip, uint16_t port) noexcept
    {
        try
        {
            m_RemoteEp = boost::asio::ip::udp::endpoint(boost::asio::ip::address::from_string(ip), port);
            return true;
        }
        catch (const boost::system::system_error& e)
        {
            LOG_ERROR("UDPChannel", "BindRemote exception : %s", e.what());
            return false;
        }
    }

    bool UDPChannel::Shutdown(ShutdownType type) noexcept
    {
        try
        {
            boost::system::error_code errCode;
            m_Socket.shutdown(static_cast<boost::asio::socket_base::shutdown_type>(type), errCode);
            if (errCode)
            {
                LOG_ERROR("UDPChannel", "shutdown error %d", errCode);
                return false;
            }
            return true;
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("UDPChannel", "shutdown operator : %d, exception: %s", type, e.what());
            return false;
        }
    }

    std::string UDPChannel::PeerIP() const noexcept
    {
        return m_RemoteEp.address().to_string();
    }

    uint16_t UDPChannel::PeerPort() const noexcept
    {
        return m_RemoteEp.port();
    }

    bool UDPChannel::Bind(const std::string& ip, uint16_t port) noexcept
    {
        assert(!m_Socket.is_open());
        using namespace boost::asio::ip;
        try
        {
            udp::endpoint ep(address::from_string(ip), port);
            return BindSocket<true>(m_Socket, ep);
        }
        catch (const boost::system::system_error &e)
        {
            LOG_ERROR("UDPChannel", "Bind exception : %s", e.what());
            return false;
        }
    }

    int16_t UDPChannel::Write(const void* buffer, int16_t size) noexcept
    {
        assert(m_Socket.is_open());
        try
        {
            boost::system::error_code error;
            auto bytes = m_Socket.send_to(boost::asio::buffer(buffer, size), m_RemoteEp, 0, error);

            return boost::asio::error::eof == error ? 0 : static_cast<int16_t>(bytes);
        }
        catch (const boost::system::system_error& e)
        {
            LOG_ERROR("UDPChannel", "write exception : %s", e.what());
            return -1;
        }
    }

    int16_t UDPChannel::Read(void* buffer, int16_t size) noexcept
    {
        assert(m_Socket.is_open() && buffer && size);
        if (!m_Socket.is_open() || !buffer || !size)
        {
            LOG_ERROR("Read", "Error");
        }

        try
        {
            boost::system::error_code error;
            boost::asio::ip::udp::endpoint sender_ep;
            auto bytes = m_Socket.receive_from(boost::asio::buffer(buffer, size), sender_ep, 0, error);
            if (sender_ep != m_RemoteEp)
                return 0;
            return boost::asio::error::eof == error ? 0 : static_cast<int16_t>(bytes);
        }
        catch (const boost::system::system_error& e)
        {
            LOG_ERROR("UDPChannel", "write exception : %s", e.what());
            return -1;
        }
    }

    std::string UDPChannel::IP() const noexcept
    {
        try
        {
            return m_Socket.local_endpoint().address().to_string();
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("UDPChannel", "Get IP exception : %s", e.what());
            return "";
        }
    }

    uint16_t UDPChannel::Port() const noexcept
    {
        try
        {
            return m_Socket.local_endpoint().port();
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("UDPChannel", "Get Port exception : %s", e.what());
            return -1;
        }
    }

    bool UDPChannel::Close() noexcept
    {
        try
        {
            Shutdown(ShutdownType::both);
            m_Socket.close();
            return true;
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("UDPChannel", "Get Port exception : %s", e.what());
            return false;
        }
    }

    //////////////////////// TCPChannel //////////////////////////////
    TCPChannel::TCPChannel(boost::asio::io_service& service) :
        m_Socket(service)
    {
    }

    TCPChannel::~TCPChannel()
    {
        if (m_Socket.is_open())
            Close();
    }

    std::string TCPChannel::PeerIP() const noexcept
    {
        return m_Socket.remote_endpoint().address().to_string();
    }

    uint16_t TCPChannel::PeerPort() const noexcept
    {
        return m_Socket.remote_endpoint().port();
    }

    bool TCPChannel::Bind(const std::string& ip, uint16_t port) noexcept
    {
        assert(!m_Socket.is_open());

        using namespace boost::asio::ip;
        try
        {
            tcp::endpoint ep(address::from_string(ip), port);
            return BindSocket<false>(m_Socket, ep);
        }
        catch (const boost::system::system_error &e)
        {
            LOG_ERROR("UDPChannel", "Bind exception : %s", e.what());
            return false;
        }
    }

    int16_t TCPChannel::Write(const void* buffer, int16_t size) noexcept
    {
        assert(m_Socket.is_open() && buffer && size);
        try
        {
            boost::system::error_code error;
            uint16_t framing = boost::asio::detail::socket_ops::host_to_network_short(size);
            auto _buf0 = boost::asio::buffer(&framing, sizeof(framing));
            auto _buf1 = boost::asio::buffer(buffer, size);
            std::vector<boost::asio::const_buffer> v = { _buf0,_buf1 };
            auto bytes = boost::asio::write(m_Socket, boost::asio::buffer(buffer, size), boost::asio::transfer_all(), error);
            return boost::asio::error::eof == error ? 0 : static_cast<int16_t>(bytes);
        }
        catch (const boost::system::system_error &e)
        {
            LOG_ERROR("TCPChannel", "Write exception :%s", e.what());
            return -1;
        }
    }

    int16_t TCPChannel::Read(void* buffer, int16_t size) noexcept
    {
        assert(buffer && size);
        try
        {
            boost::system::error_code error;
            int16_t length;
            auto bytes = boost::asio::read(m_Socket, boost::asio::buffer(&length, sizeof(length)), boost::asio::transfer_at_least(sizeof(length)), error);
            if (boost::asio::error::eof == error)
                return 0;

            // get packet length
            *reinterpret_cast<int16_t*>(buffer) = length;

            length = boost::asio::detail::socket_ops::network_to_host_short(length);
            // read packet
            bytes = boost::asio::read(m_Socket, boost::asio::buffer(buffer, length), boost::asio::transfer_all(), error);

            return boost::asio::error::eof == error ? 0 : static_cast<int16_t>(bytes);

        }
        catch (const boost::system::system_error &e)
        {
            LOG_ERROR("TCPChannel", "Read exception : %s", e.what());
            return -1;
        }
    }

    std::string TCPChannel::IP() const noexcept
    {
        try
        {
            return m_Socket.local_endpoint().address().to_string();
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("TCPChannel", "Get IP exception : %s", e.what());
            return "";
        }
    }

    uint16_t TCPChannel::Port() const noexcept
    {
        try
        {
            return m_Socket.local_endpoint().port();
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("TCPChannel", "Get Port exception : %s", e.what());
            return -1;
        }
    }

    bool TCPChannel::Close() noexcept
    {
        try
        {
            Shutdown(ShutdownType::both);
            m_Socket.close();
            return true;
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("TCPChannel", "Close exception : %s", e.what());
            return false;
        }
    }

    bool TCPChannel::Shutdown(ShutdownType type) noexcept
    {
        try
        {
            boost::system::error_code errCode;
            m_Socket.shutdown(static_cast<boost::asio::socket_base::shutdown_type>(type), errCode);
            if (errCode)
            {
                LOG_ERROR("TCPChannel", "Shutdown error %d", errCode);
                return false;
            }
            return true;
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("TCPChannel", "Shutdown operator %d : exception: %s", type, e.what());
            return false;
        }
    }

    //////////////////////// TCPActiveChannel //////////////////////////////
    TCPActiveChannel::TCPActiveChannel(boost::asio::io_service& service /*= Channel::sIOService*/) :
        TCPChannel(service)
    {
    }

    TCPActiveChannel::~TCPActiveChannel()
    {
    }

    bool TCPActiveChannel::Connect(const boost::asio::ip::tcp::endpoint& ep) noexcept
    {
        ep.address().to_v4();
        assert(m_Socket.is_open());
        try
        {
            m_Socket.connect(ep);
            return true;
        }
        catch (const boost::system::system_error &e)
        {
            LOG_ERROR("TCPActive", "Connect exception :%s", e.what());
            return false;
        }
    }

    bool TCPActiveChannel::Connect(const std::string& ip, uint16_t port) noexcept
    {
        assert(m_Socket.is_open());

        try
        {
            auto ep = boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string(ip), port);
            return Connect(ep);
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("TCPActive", "Connect exception :%s", e.what());
            return false;
        }
    }

    //////////////////////// TCPPassiveChannel //////////////////////////////
    TCPPassiveChannel::TCPPassiveChannel(boost::asio::io_service& service /*= Channel::sIOService*/) :
        TCPChannel(service), m_Acceptor(service)
    {
    }

    TCPPassiveChannel::~TCPPassiveChannel()
    {
    }

    bool TCPPassiveChannel::Bind(const std::string& ip, uint16_t port) noexcept
    {
        try
        {
            m_Acceptor.bind(boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string(ip), port));
            m_Acceptor.listen();
            return true;
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("TCPPassiveChannel", "Bind exception: %s", e.what());
            return false;
        }
    }

    bool TCPPassiveChannel::Accept(boost::asio::ip::tcp::socket& socket, const std::string& ip, uint16_t port) noexcept
    {
        assert(m_Acceptor.is_open());

        try
        {
            return Accept(socket, boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string(ip), port));
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("TCPPassiveChannel", "Accept exception: %s", e.what());
            return false;
        }
    }

    bool TCPPassiveChannel::Accept(boost::asio::ip::tcp::socket& socket, boost::asio::ip::tcp::endpoint &ep) noexcept
    {
        assert(m_Acceptor.is_open());
        try
        {
            m_Acceptor.accept(socket, ep);
            return true;
        }
        catch (const std::exception&e)
        {
            LOG_ERROR("TCPPassiveChannel", "Accept exception: %s", e.what());
            return false;
        }
    }
}