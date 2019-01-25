#pragma once

#include <stdint.h>
#include <string>
#include <boost/asio.hpp>
#include <type_traits>

#include "pg_log.h"

namespace ICE{

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
            Receive,
            Send,
            Both,
        };

    public:
        Channel() {};
        virtual ~Channel() = 0 {}

        virtual bool Bind(const std::string& ip, uint16_t port) noexcept = 0;

        virtual int32_t Recv(void *buffer, int32_t size, bool framing = false) noexcept = 0;
        virtual int32_t Recv(void *buffer, int32_t size, std::string &sender_ip, uint16_t &sender_port, bool framing = false) noexcept = 0;

        virtual int32_t Send(const void *buffer, int32_t size, bool framing = false) noexcept = 0;
        virtual int32_t Send(const void *buffer, int32_t size, const std::string &recver_ip, uint16_t recver_port, bool framing = false) noexcept = 0;

        virtual bool Connect(const std::string& destip, uint16_t port) noexcept = 0;
        virtual bool Shutdown(ShutdownOption op) noexcept = 0;
        virtual void Close() noexcept = 0;

        virtual std::string IP() const noexcept = 0;
        virtual uint16_t Port() const noexcept = 0;

        virtual std::string PeerIP() const noexcept = 0;
        virtual uint16_t PeerPort() const noexcept = 0;

    public:
        template<class T>
        static bool Shutdown(T &s, ShutdownOption op) noexcept;

        template<class T>
        static bool Bind(T &s, typename const channel_type<std::is_base_of<boost::asio::ip::udp::socket, T>::value>::endpoint &ep);

    protected:
        static boost::asio::io_service sIOService;
        static const char* sInvalidIP;
    };

    class UDPChannel : public Channel {
    public:
        UDPChannel(boost::asio::io_service &service = Channel::sIOService);
        UDPChannel(const UDPChannel&) = delete;
        UDPChannel& operator=(const UDPChannel&) = delete;

        virtual ~UDPChannel();

    public:
        virtual bool Bind(const std::string& ip, uint16_t port) noexcept override;

        virtual int32_t Recv(void *buffer, int32_t size, bool framing) noexcept override;
        virtual int32_t Recv(void *buffer, int32_t size, std::string &sender_ip, uint16_t &sender_port, bool framing) noexcept override;

        virtual int32_t Send(const void *buffer, int32_t size, bool framing) noexcept override;
        virtual int32_t Send(const void *buffer, int32_t size, const std::string &recver_ip, uint16_t recver_port, bool framing) noexcept override;

        virtual bool Connect(const std::string& ip, uint16_t port) noexcept override;
        virtual bool Shutdown(ShutdownOption op) noexcept override;
        virtual void Close() noexcept override;

        virtual std::string IP() const noexcept;
        virtual uint16_t    Port() const noexcept;
        virtual std::string PeerIP() const noexcept;
        virtual uint16_t    PeerPort() const noexcept;

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
        virtual bool Bind(const std::string& ip, uint16_t port) noexcept override;

        virtual int32_t Recv(void *buffer, int32_t size, bool framing) noexcept override;
        virtual int32_t Recv(void *buffer, int32_t size, std::string &sender_ip, uint16_t &sender_port, bool framing) noexcept override;

        virtual int32_t Send(const void *buffer, int32_t size, bool framing) noexcept override;
        virtual int32_t Send(const void *buffer, int32_t size, const std::string &recver_ip, uint16_t recver_port, bool framing) noexcept override;

        virtual bool Connect(const std::string& destip, uint16_t port) noexcept override;
        virtual bool Shutdown(ShutdownOption op) noexcept override;
        virtual void Close() noexcept override;

        virtual std::string IP() const noexcept;
        virtual uint16_t    Port() const noexcept;

        virtual std::string PeerIP() const noexcept;
        virtual uint16_t    PeerPort() const noexcept;

    protected:
        boost::asio::ip::tcp::socket m_Socket;
    };

    class TCPPassiveChannel : public TCPChannel {
    public:
        TCPPassiveChannel(boost::asio::io_service &service = Channel::sIOService);
        TCPPassiveChannel(const TCPPassiveChannel&) = delete;
        TCPPassiveChannel& operator=(const TCPPassiveChannel&) = delete;
        ~TCPPassiveChannel() {}

    public:
        virtual bool Bind(const std::string& ip, uint16_t port) noexcept override;
        virtual bool Connect(const std::string& ip, uint16_t port) noexcept override;

        virtual bool Shutdown(ShutdownOption op) noexcept override;
        virtual std::string PeerIP() const noexcept;
        virtual uint16_t    PeerPort() const noexcept;

    private:
        boost::asio::ip::tcp::acceptor m_Acceptor;

    private:
        static const uint16_t sMaxBacklog = 32;
    };

    template<class T>
    inline bool Channel::Shutdown(T & s, ShutdownOption op) noexcept
    {
        using namespace boost::asio::ip;

        static_assert(!std::is_pointer<T>::value, "T cannot be pointer");
        static_assert(std::is_base_of <udp::socket, T>::value || std::is_base_of<tcp::socket, T>::value,
            "the base of socket must be boost::asio::ip::udp or boost::asio::ip::tcp");

        boost::system::error_code error;

        switch (op)
        {
        case Channel::ShutdownOption::Receive:
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
    inline bool Channel::Bind(T & s, typename const channel_type<std::is_base_of<boost::asio::ip::udp::socket, T>::value>::endpoint& ep)
    {
        using namespace boost::asio::ip;

        static_assert(!std::is_pointer<T>::value, "T cannot be pointer");
        static_assert(std::is_base_of <udp::socket, T>::value || std::is_base_of<tcp::socket, T>::value,
            "the base of socket must be boost::asio::ip::udp or boost::asio::ip::tcp");

        boost::system::error_code error;

        s.open(ep.protocol(), error);
        if (error.value())
        {
            LOG_ERROR("Channel", "open error : [%d]", error.value());
            return false;
        }

        s.bind(ep, error);
        if (error.value())
        {
            LOG_ERROR("Channel", "Bind error : [%d]", error.value());
            return false;
        }

        return true;
    }
}