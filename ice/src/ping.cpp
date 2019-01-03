#include "ping.h"
#include "icmp_header.h"
#include "ipv4_header.h"
#include <iostream>

namespace ICE{
    boost::asio::io_service CPing::sIOService;

    CPing::CPing(const std::string& dest_address, uint16_t timeoutMS, boost::asio::io_context& io) :
        m_destination(dest_address), m_socket(io, icmp::v4()),m_timout(timeoutMS), m_retrytimes(3)
    {
    }

    CPing::~CPing()
    {
        if (m_send_thread.joinable())
            m_send_thread.join();

        if (m_recv_thread.joinable())
            m_recv_thread.join();
    }

    bool CPing::Run()
    {
        try
        {
            icmp::resolver resolver(sIOService);
            m_dest_ep = *resolver.resolve(icmp::v4(), m_destination, "").begin();
            std::cout << m_dest_ep.address().to_string() << std::endl;
            std::cout << m_dest_ep.port() << std::endl;

            m_send_thread = std::thread(SendThread, this);
            std::this_thread::sleep_for(std::chrono::seconds(2));
            m_recv_thread = std::thread(RecvThread, this);

            return true;
        }
        catch (const std::exception&)
        {
            return false;
        }
    }

    void CPing::SendThread(CPing* pOwn)
    {
        boost::asio::io_service io_service;

        uint16_t sequence_number = 0;
        const std::string body("\"Hello!\"");

        std::ostringstream oss;
        oss << std::this_thread::get_id();
        pOwn->m_identifier = static_cast<uint16_t>(std::stoul(oss.str()));

        // Create an ICMP header for an echo request.
        icmp_header echo_request;
        echo_request.type(icmp_header::echo_request);
        echo_request.code(0);

        echo_request.identifier(pOwn->GetIdentifier());
        boost::asio::deadline_timer timer(io_service);

        std::unique_lock<std::mutex> locker(pOwn->m_mutex);
        while (pOwn->m_retrytimes--)
        {
            echo_request.sequence_number(++sequence_number);
            compute_checksum(echo_request, body.begin(), body.end());
            boost::asio::streambuf request_buffer;
            std::ostream os(&request_buffer);
            os << echo_request << body;

            auto time_sent = boost::posix_time::microsec_clock::universal_time();

            // send data
            try
            {
                auto ret1 = pOwn->m_socket.send_to(request_buffer.data(), pOwn->m_dest_ep);
                pOwn->m_state = State::sent;
                auto ret = pOwn->m_send_condition.wait_for(locker, std::chrono::milliseconds(pOwn->m_timout), [&pOwn] {
                    return pOwn->m_state == CPing::State::received || pOwn->m_state == CPing::State::quit;
                });
                if (pOwn->m_state == CPing::State::quit)
                    break;

                auto time_received = boost::posix_time::microsec_clock::universal_time();
                auto time_elapse = time_received - time_sent;
                std::cout << "elapse : " << time_elapse.total_milliseconds() << std::endl;
            }
            catch (const std::exception&e)
            {
                std::cout << "send exception: " << e.what() << std::endl;
            }
        }

        pOwn->m_socket.close();
        pOwn->m_state = CPing::State::quit;
    }

    void CPing::RecvThread(CPing* pOwn)
    {
        while (1)
        {
            boost::asio::streambuf reply_buffer;
            size_t recv_bytes = 0;
            try
            {
                recv_bytes = pOwn->m_socket.receive_from(reply_buffer.prepare(1024),pOwn->m_dest_ep);
            }
            catch (const std::exception& e)
            {
                std::cout << "recv exception: " << e.what() << std::endl; 
                break;
            }

            reply_buffer.commit(recv_bytes);

            // Decode the reply packet.
            std::istream is(&reply_buffer);

            ipv4_header ipv4_hdr;
            icmp_header icmp_hdr;
            is >> ipv4_hdr >> icmp_hdr;

            // We can receive all ICMP packets received by the host, so we need to
            // filter out only the echo replies that match the our identifier and
            // expected sequence number.
            std::lock_guard<std::mutex> locker(pOwn->m_mutex);

            if (is && icmp_hdr.type() == icmp_header::echo_reply
                && icmp_hdr.identifier() == pOwn->GetIdentifier()
                && icmp_hdr.sequence_number() == pOwn->m_seq_number)
            {
                // wake up send thread
                pOwn->m_state = CPing::State::received;
                pOwn->m_send_condition.notify_one();
            }
        }
        pOwn->m_state = CPing::State::quit;
    }
}