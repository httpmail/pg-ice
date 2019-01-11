#pragma once

#include <stdint.h>
#include <string>
#include <boost/asio.hpp>
#include <type_traits>

#include "pg_log.h"

#if 0
namespace ICE {

    template<bool is_upd>
    struct channel_type { 
        using endpoint = boost::asio::ip::tcp::endpoint;
        using socket = boost::asio::ip::tcp::socket;
    };

    template<>
    struct channel_type<true> {
        using endpoint = boost::asio::ip::udp::endpoint;
        using socket = boost::asio::ip::udp::socket;
    };

    class Channel {
    public:
        enum class ShutdownType {
            both = boost::asio::socket_base::shutdown_both,
            read = boost::asio::socket_base::shutdown_receive,
            write = boost::asio::socket_base::shutdown_send,
        };
    public:
        Channel() {}
        virtual ~Channel() = 0;

    public:
        template<bool is_upd>
        bool BindSocket(typename channel_type<is_upd>::socket &socket, const typename channel_type<is_upd>::endpoint &ep) noexcept
        {
            try
            {
                socket.open(ep.protocol());
                socket.bind(ep);
                return true;
            }
            catch (const boost::system::system_error& e)
            {
                LOG_ERROR("Channel", "Bind exception : %s", e.what());
                return false;
            }
        }

        template<class T>
        bool BindSocket(T& socket, const typename channel_type<std::is_base_of<boost::asio::ip::udp::socket, T>::value>::endpoint &ep)
        {
            using namespace boost::asio::ip;
            static_assert(std::is_base_of<udp::socket, T>::value || std::is_base_of<tcp::socket, T>::value,
             "the base class of T must be udp::socket or tcp::socket");

            socket.open(ep.protocol());
            socket.bind(ep);
            return true;
        }

        template<bool is_upd, class Option>
        bool BindSocket(typename channel_type<is_upd>::socket &socket, const typename channel_type<is_upd>::endpoint &ep, const Option option) noexcept
        {
            try
            {
                socket.open(ep.protocol());
                socket.set_option(option);
                socket.bind(ep);
                return true;
            }
            catch (const boost::system::system_error& e)
            {
                LOG_ERROR("Channel", "Bind exception : %s", e.what());
                return false;
            }
        }

        template<class socket_type, class SettableSocketOption>
        bool SetOption(socket_type &socket, const SettableSocketOption& option)
        {
            try
            {
                socket.set_option(option);
                return true;
            }
            catch (const boost::system::system_error& e)
            {
                LOG_ERROR("Channel", "SetOption exception : %s", e.what());
                return false;
            }
        }

    public:
        virtual bool Bind(const std::string& ip, uint16_t port) noexcept = 0;
        virtual int16_t Write(const void* buffer, int16_t size) noexcept = 0;
        virtual int16_t Read(void* buffer, int16_t size) noexcept = 0;
        virtual std::string IP() const noexcept = 0;
        virtual uint16_t Port() const noexcept = 0;
        virtual bool Close() noexcept = 0;
        virtual bool Shutdown(ShutdownType type) noexcept = 0;
        virtual std::string PeerIP() const noexcept = 0;
        virtual uint16_t PeerPort() const noexcept = 0;

    protected:
        static boost::asio::io_service sIOService;
    };

    class UDPChannel : public Channel {
    public:
        UDPChannel(boost::asio::io_service& service = Channel::sIOService);
        virtual ~UDPChannel();

    public:
        bool BindRemote(const std::string &ip, uint16_t port) noexcept;
        boost::asio::ip::udp::socket& Socket() { return m_Socket; }
        int16_t WriteTo(const void* buffer, int16_t size, const std::string& ip, uint16_t port);
        int16_t WriteTo(const void* buffer, int16_t size, const boost::asio::ip::udp::endpoint &ep);
        int16_t ReadFrom(void* buffer, int16_t size, std::string& ip, uint16_t port);
        int16_t ReadFrom(void* buffer, int16_t size, boost::asio::ip::udp::endpoint &ep);

    public:
        virtual bool Bind(const std::string& ip, uint16_t port) noexcept override;
        virtual int16_t Write(const void* buffer, int16_t size) noexcept override;
        virtual int16_t Read(void* buffer, int16_t size) noexcept override;
        virtual std::string IP() const noexcept override;
        virtual uint16_t Port() const noexcept override;
        virtual bool Close() noexcept override;
        virtual bool Shutdown(ShutdownType type) noexcept override;
        virtual std::string PeerIP() const noexcept;
        virtual uint16_t PeerPort() const noexcept;

    private:
        boost::asio::ip::udp::socket    m_Socket;
        boost::asio::ip::udp::endpoint  m_RemoteEp;
    };

    class TCPChannel : public Channel {
    public:
        TCPChannel(boost::asio::io_service& service = Channel::sIOService);
        virtual ~TCPChannel();

    public:
        boost::asio::ip::tcp::socket& Socket() { return m_Socket; }

    public:
        virtual bool Bind(const std::string& ip, uint16_t port) noexcept override;
        virtual int16_t Write(const void* buffer, int16_t size) noexcept override final;
        virtual int16_t Read(void* buffer, int16_t size) noexcept override final;
        virtual std::string IP() const noexcept override;
        virtual uint16_t Port() const noexcept override;
        virtual bool Close() noexcept override;
        virtual bool Shutdown(ShutdownType type) noexcept override;
        virtual std::string PeerIP() const noexcept;
        virtual uint16_t PeerPort() const noexcept;
        bool Connect(const boost::asio::ip::tcp::endpoint& ep) noexcept { return true; }
        bool Connect(const std::string& ip, uint16_t port) noexcept { return true; }

    protected:
        boost::asio::ip::tcp::socket m_Socket;
    };

    class TCPActiveChannel : public TCPChannel {
    public:
        TCPActiveChannel(boost::asio::io_service& service = Channel::sIOService);
        virtual ~TCPActiveChannel();

    public:
        bool Connect(const boost::asio::ip::tcp::endpoint& ep) noexcept;
        bool Connect(const std::string& ip, uint16_t port) noexcept;

    };

    class TCPPassiveChannel : public TCPChannel {
    public:
        TCPPassiveChannel(boost::asio::io_service& service = Channel::sIOService);
        virtual ~TCPPassiveChannel();

    public:
        virtual bool Bind(const std::string& ip, uint16_t port) noexcept override final;

    public:
        bool Accept(boost::asio::ip::tcp::socket& socket, boost::asio::ip::tcp::endpoint &ep) noexcept;
        bool Accept(boost::asio::ip::tcp::socket& socket, const std::string& ip, uint16_t port) noexcept;

    private:
        boost::asio::ip::tcp::acceptor m_Acceptor;
    };
}

#endif

namespace ICE1{

    template<bool is_upd>
    struct channel_type {
        using endpoint = boost::asio::ip::tcp::endpoint;
        using socket = boost::asio::ip::tcp::socket;
    };

    template<>
    struct channel_type<true> {
        using endpoint = boost::asio::ip::udp::endpoint;
        using socket = boost::asio::ip::udp::socket;
    };

    class Channel {
    public:
        enum class ShutdownOption : uint8_t {
            Recvice,
            Send,
            Both,
        };

    public:
        Channel();
        virtual ~Channel() = 0 {}

        virtual uint32_t Recv(void *buffer, uint32_t size) noexcept;
        virtual uint32_t Recv(void *buffer, uint32_t size, std::string &sender_ip, uint16_t &sender_port) noexcept;

        virtual uint32_t Send(const void *buffer, uint32_t size) noexcept;
        virtual uint32_t Send(const void *buffer, uint32_t size, const std::string &recver_ip, uint16_t recver_port) noexcept;

        virtual bool Connect(const std::string& ip, uint16_t port) noexcept;
        virtual bool Accept() noexcept;
        virtual bool Shutdown(ShutdownOption op) noexcept;

    public:
        template<class T>
        bool Shutdown(T &s, ShutdownOption op) noexcept;

        template<class T>
        bool Bind(T &s, typename const channel_type<std::is_base_of<boost::asio::ip::udp::socket, T>::value>::endpoint *ep);

    protected:
        static boost::asio::io_service sIOService;
    };

    class UDPChannel : public Channel {
    public:
        UDPChannel(boost::asio::io_service &service = Channel::sIOService);
        UDPChannel(const UDPChannel&) = delete;
        UDPChannel& operator=(const UDPChannel&) = delete;

        virtual ~UDPChannel();

    public:
        virtual uint32_t Recv(void *buffer, uint32_t size) noexcept override;
        virtual uint32_t Recv(void *buffer, uint32_t size, std::string &sender_ip, uint16_t &sender_port) noexcept override;

        virtual uint32_t Send(const void *buffer, uint32_t size) noexcept override;
        virtual uint32_t Send(const void *buffer, uint32_t size, const std::string &recver_ip, uint16_t recver_port) noexcept override;

        virtual bool Connect(const std::string& ip, uint16_t port) noexcept override;
        virtual bool Accept() noexcept override;
        virtual bool Shutdown(ShutdownOption op) noexcept override;

    private:
        boost::asio::ip::udp::socket m_Socket;
    };

    class TCPChannel : public Channel {
    public:
        TCPChannel(boost::asio::io_service &service = Channel::sIOService);
        TCPChannel(const TCPChannel&) = delete;
        TCPChannel& operator=(const TCPChannel&) = delete;

        virtual ~TCPChannel();

    public:
        virtual uint32_t Recv(void *buffer, uint32_t size) noexcept override;
        virtual uint32_t Recv(void *buffer, uint32_t size, std::string &sender_ip, uint16_t &sender_port) noexcept override;

        virtual uint32_t Send(const void *buffer, uint32_t size) noexcept override;
        virtual uint32_t Send(const void *buffer, uint32_t size, const std::string &recver_ip, uint16_t recver_port) noexcept override;

        virtual bool Connect(const std::string& ip, uint16_t port) noexcept override;
        virtual bool Accept() noexcept override;
        virtual bool Shutdown(ShutdownOption op) noexcept override;

    private:
        boost::asio::ip::tcp::socket m_Socket;
    };

    template<class T>
    inline bool Channel::Shutdown(T & s, ShutdownOption op) noexcept
    {
        using namespace boost::asio::ip;

        static_assert(!std::is_pointer<T>, "T cannot be pointer");
        static_assert(std::is_base_of <udp::socket, T>::value || std::is_base_of<tcp::socket, T>::value,
            "the base of socket must be boost::asio::ip::udp or boost::asio::ip::tcp");

        boost::system::error_code error;

        switch (op)
        {
        case Channel::ShutdownOption::Recvice:
            s.shutdown(boost::asio::socket_base::shutdown_receive, error);
            break;

        case Channel::ShutdownOption::Send:
            s.shutdown(boost::asio::socket_base::shutdown_send, error);
            break;

        case Channel::ShutdownOption::Both:
            s.shutdown(boost::asio::socket_base::shutdown_send, error);
            break;
        default:
            break;
        }

        if (error.value())
        {
            LOG_ERROR("Channel", "Shutdown error [%d]", error.value());
            return false;
        }

        return true;
    }

    template<class T>
    inline bool Channel::Bind(T & s, typename const channel_type<std::is_base_of<boost::asio::ip::udp::socket, T>::value>::endpoint * ep)
    {
        using namespace boost::asio::ip;

        static_assert(!std::is_pointer<T>, "T cannot be pointer");
        static_assert(std::is_base_of <udp::socket, T>::value || std::is_base_of<tcp::socket, T>::value,
            "the base of socket must be boost::asio::ip::udp or boost::asio::ip::tcp");

        boost::system::error_code error;

        socket.open(ep.protocol(), error);
        if (error.value())
        {
            LOG_ERROR("Channel", "open error : [%d]", error.value());
            return false;
        }

        socket.bind(ep, error);
        if (error.value())
        {
            LOG_ERROR("Channel", "Bind error : [%d]", error.value());
            return false;
        }

        return true;
    }
}