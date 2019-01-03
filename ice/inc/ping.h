#pragma once

#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <thread>
#include <mutex>
#include <future>
#include <condition_variable>

namespace ICE {

    class CPing {
    private:
        using icmp           = boost::asio::ip::icmp;
        using deadline_timer = boost::asio::deadline_timer;
        enum State {
            sent = 0,
            received,
            quit,
        };

    public:
        CPing(const std::string& dest_address, uint16_t timeoutMS, boost::asio::io_context& io);
        virtual ~CPing();

        bool Run();

    private:
        unsigned int GetIdentifier() const {
            return m_identifier;
        }

    private:
        static void SendThread(CPing* pOwn);
        static void RecvThread(CPing* pOwn);

    private:
        icmp::socket   m_socket;
        uint16_t       m_seq_number;
        int16_t        m_retrytimes;
        uint16_t       m_identifier;
        const uint16_t m_timout;
        const std::string m_destination;
        icmp::endpoint m_dest_ep;
        State          m_state;
        boost::asio::streambuf   m_reply_buffer;

        std::thread    m_send_thread;
        std::thread    m_recv_thread;

        std::mutex     m_mutex;
        std::condition_variable m_send_condition;
        std::condition_variable m_recv_condition;

    private:
        static boost::asio::io_context sIOService;
    };
}