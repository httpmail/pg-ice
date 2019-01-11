#include "channel.h"
#include "pg_log.h"
#include <boost/array.hpp>

#include <sstream>
#include<iomanip>
#include <memory>

#if PG_LOG_ENABLE
#define dump_packet(sender, recver, packet, size) dump(sender, recver, packet, size)
#endif

namespace {
    template<class T>
    void dump(const T& sender, const T& recver, const void *packet, uint32_t size)
    {
        static_assert(!std::is_pointer<T>::value, "cannot be pointer");
        static_assert(std::is_base_of<boost::asio::ip::udp::endpoint, T>::value||
                      std::is_base_of<boost::asio::ip::tcp::endpoint, T>::value,
            "Must udp::endpoint or tcp::endpoint");

        std::ostringstream info;
        info.setf(std::ostringstream::hex);

        for (decltype(size) i = 0; i < size; ++i)
        {
            info << std::hex << std::setw(2) << std::setfill('0') << (uint16_t)((uint8_t*)packet)[i] << " ";
            if ((i + 1) % 32 == 0)
                info << std::endl;
        }

        LOG_INFO("channel", "%s:%d => %s:%d :\n%s",
            sender.address().to_string().c_str(), sender.port(),
            recver.address().to_string().c_str(), recver.port(),
            info.str().c_str());
    }
}

#if 0
namespace ICE {

    boost::asio::io_service Channel::sIOService;
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
            LOG_INFO("UDPChannel", "bind :[%s:%d]", ip.c_str(), port);
            m_RemoteEp = boost::asio::ip::udp::endpoint(boost::asio::ip::address::from_string(ip), port);
            m_Socket.connect(m_RemoteEp);
            return true;
        }
        catch (const boost::system::system_error& e)
        {
            LOG_ERROR("UDPChannel", "BindRemote exception : %s", e.what());
            return false;
        }
    }

    int16_t UDPChannel::WriteTo(const void * buffer, int16_t size, const std::string & ip, uint16_t port)
    {
        using namespace boost::asio::ip;
        assert(m_Socket.is_open());

        return WriteTo(buffer, size, udp::endpoint(address::from_string(ip), port));
    }

    int16_t UDPChannel::WriteTo(const void * buffer, int16_t size, const boost::asio::ip::udp::endpoint & ep)
    {
        assert(m_Socket.is_open());

        boost::system::error_code err;
        auto bytes = m_Socket.send_to(boost::asio::buffer(buffer, size), ep, 0, err);
        if (err.value())
            return -1;
        return static_cast<int16_t>(bytes);
    }

    int16_t UDPChannel::ReadFrom(void * buffer, int16_t size, std::string & ip, uint16_t port)
    {
        using namespace boost::asio::ip;
        assert(m_Socket.is_open());

        udp::endpoint ep;
        auto ret = ReadFrom(buffer, size, ep);

        ip   = ep.address().to_string();
        port = ep.port();

        return ret;
    }

    int16_t UDPChannel::ReadFrom(void * buffer, int16_t size, boost::asio::ip::udp::endpoint & ep)
    {
        using namespace boost::asio::ip;

        assert(m_Socket.is_open());

        boost::system::error_code error;
        auto bytes = m_Socket.receive_from(boost::asio::buffer(buffer, size), ep, 0);
        if (error.value())
            return -1;
        return static_cast<int16_t>(bytes);
    }

    bool UDPChannel::Shutdown(ShutdownType type) noexcept
    {
        return true;
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
            if (error.value())
            {
                LOG_ERROR("UDPChannel", "Write error %d", error.value());
                return -1;
            }
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
            auto bytes = m_Socket.receive_from(boost::asio::buffer(buffer, size),m_RemoteEp, 0, error);
            if (error.value())
            {
                assert(m_Socket.is_open());
                LOG_ERROR("UDPChannel", "receive_from error %d", error.value());
            }

            dump_packet(m_RemoteEp, m_Socket.local_endpoint(), buffer, bytes);

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

#endif

namespace ICE1 {
    using namespace boost::asio::ip;


    ///////////////////////////// UDPChannel class /////////////////////////////
    UDPChannel::UDPChannel(boost::asio::io_service &service /* = Channel::sIOService */) :
        m_Socket(service)
    {
    }

    UDPChannel::~UDPChannel()
    {
    }

    uint32_t UDPChannel::Recv(void *buffer, uint32_t size) noexcept
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

    uint32_t UDPChannel::Recv(void *buffer, uint32_t size, std::string &sender_ip, uint16_t &sender_port) noexcept
    {
        boost::system::error_code error;
        udp::endpoint ep(address::from_string(sender_ip), sender_port);

        auto bytes = m_Socket.receive_from(boost::asio::buffer(buffer, size), ep, 0, error);

        if (error.value())
        {
            LOG_ERROR("UDPChannel", "Recv error :%d", error.value());
            return boost::asio::error::eof == error ? 0 : -1;
        }
        return bytes;
    }

    uint32_t UDPChannel::Send(const void *buffer, uint32_t size) noexcept
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

    uint32_t UDPChannel::Send(const void *buffer, uint32_t size, const std::string &recver_ip, uint16_t recver_port) noexcept
    {
        boost::system::error_code error;
        udp::endpoint ep(address::from_string(recver_ip), recver_port);

        auto bytes = m_Socket.send_to(boost::asio::buffer(buffer, size), ep, 0, error);

        if (error.value())
        {
            LOG_ERROR("UDPChannel", "Send to [%s:%d] error :%d", recver_ip.c_str(), recver_port, error.value());
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

    bool UDPChannel::Accept() noexcept
    {
        return true;
    }

    bool UDPChannel::Shutdown(ShutdownOption op) noexcept
    {
        return Channel::Shutdown(m_Socket, op);
    }


    ///////////////////////////// TCPChannel class /////////////////////////////

    TCPChannel::TCPChannel(boost::asio::io_service &service /*= Channel::sIOService*/)
        :m_Socket(service)
    {
    }

    TCPChannel::~TCPChannel()
    {
    }

    uint32_t TCPChannel::Recv(void *buffer, uint32_t size) noexcept
    {
        assert(buffer && size);

        boost::system::error_code error;

        // read packet length

        int16_t length;
        auto bytes = boost::asio::read(m_Socket, boost::asio::buffer(&length, sizeof(length)), boost::asio::transfer_at_least(sizeof(length)), error);
        if (error.value())
            return boost::asio::error::eof == error ? 0 : error.value();

        length = boost::asio::detail::socket_ops::network_to_host_short(length);
        if (length > size)
        {
            LOG_ERROR("TCPChannel", "buffer size less than packet size");
            return -1;
        }

        bytes = boost::asio::read(m_Socket, boost::asio::buffer(buffer, length), boost::asio::transfer_all(), error);
        if (error.value())
        {
            LOG_ERROR("TCPChannel", "recv from [%s, %d], error :%d",
                m_Socket.remote_endpoint().address().to_string().c_str(), m_Socket.remote_endpoint().port(),
                error.value());
            return boost::asio::error::eof == error ? 0 : error.value();
        }
        return bytes;
    }

    uint32_t TCPChannel::Recv(void *buffer, uint32_t size, std::string&, uint16_t& ) noexcept
    {
        assert(buffer && size);
        Recv(buffer, size);
    }

    uint32_t TCPChannel::Send(const void *buffer, uint32_t size) noexcept
    {
        boost::system::error_code error;
        uint16_t framing = boost::asio::detail::socket_ops::host_to_network_short(size);

        std::vector<boost::asio::const_buffer> v = { 
            boost::asio::buffer(&framing, sizeof(framing)),
            boost::asio::buffer(buffer, size) 
        };

        auto bytes = boost::asio::write(m_Socket, boost::asio::buffer(buffer, size), boost::asio::transfer_all(), error);

        if (error.value())
        {
            LOG_ERROR("TCPChannel", "Send to [%s, %d], error :%d",
                m_Socket.remote_endpoint().address().to_string().c_str(), m_Socket.remote_endpoint().port(),
                error.value());
            return boost::asio::error::eof == error ? 0 : -1;
        }
        return bytes;
    }

    uint32_t TCPChannel::Send(const void *buffer, uint32_t size, const std::string &, uint16_t) noexcept
    {
        assert(buffer && size);
        return Send(buffer, size);
    }

    bool TCPChannel::Connect(const std::string& dest, uint16_t port) noexcept
    {
        boost::system::error_code error;
        tcp::endpoint ep(address::from_string(dest), port);

        m_Socket.connect(ep, error);

        if (error.value())
        {
            LOG_ERROR("TCPChannel", "Connect to [%s, %d], error :%d", dest.c_str(), port, error.value());
            return false;
        }

        return true;
    }

    bool TCPChannel::Accept() noexcept
    {
        return true;
    }

    bool TCPChannel::Shutdown(ShutdownOption op) noexcept
    {
        return Channel::Shutdown(m_Socket, op);
    }
}