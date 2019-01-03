#pragma once

#include <string>
#include <boost/asio.hpp>
#include <type_traits>

#include "pg_log.h"

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
        bool BindSocket( typename channel_type<is_upd>::socket &socket, const typename channel_type<is_upd>::endpoint &ep) noexcept
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