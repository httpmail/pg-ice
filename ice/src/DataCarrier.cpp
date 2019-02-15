#include "DataCarrier.h"
#include "Channel.h"
#include "pg_log.h"
#include "stunmsg.h"

namespace ICE {

    std::condition_variable DataCarrier::sFreePacketsCond;
    std::mutex              DataCarrier::sFreePacketsMutex;
    DataCarrier::Buffer     DataCarrier::sFreePackets;
    DataCarrier::Packet     DataCarrier::sPacketCache[DataCarrier::sPacketCacheSize];

    bool DataCarrier::sbInited = DataCarrier::Initilize();

    DataCarrier::DataCarrier(ICE::Channel & channel)
        :m_Channel(channel), m_bStarted(false)
    {
    }

    DataCarrier::~DataCarrier()
    {
        LOG_WARNING("DataCarrier", "Unregisterred listerner [%d] [%p] [%p]", m_RecvListener.size(), this, &m_Channel);

        m_bQuit = true;

         m_SendCond.notify_one();
        if (m_SendThrd.joinable())
            m_SendThrd.join();

        m_RecvCond.notify_all();
        if (m_RecvThrd.joinable())
            m_RecvThrd.join();

        m_RecvCond.notify_all();
        if (m_HandThrd.joinable())
            m_HandThrd.join();

        {
            std::lock_guard<decltype(m_SendMutex)> locker(m_SendMutex);
            while (!m_SendPackets.empty())
            {
                Dealloc(m_SendPackets.front());
                m_SendPackets.pop();
            }
        }

        {
            std::lock_guard<decltype(m_RecvMutex)> locker(m_RecvMutex);
            while (!m_RecvPackets.empty())
            {
                Dealloc(m_RecvPackets.front());
                m_RecvPackets.pop();
            }
        }

        LOG_INFO("DataCarrier", "sFreePackets [%d], total [%d]", sFreePackets.size(), DataCarrier::sPacketCacheSize);
    }

    void DataCarrier::Start()
    {
        {
            std::lock_guard<decltype(m_StartedMutex)> locker(m_StartedMutex);
            if (m_bStarted)
            {
                LOG_WARNING("DataCarrier", "Already Started");
                return;
            }
        }

        m_bStarted = true;
        m_SendThrd = std::thread(SendThread, this);
        m_RecvThrd = std::thread(RecvThread, this);
        m_HandThrd = std::thread(HandleRecvPacketsThread, this);
        return;
    }

    bool DataCarrier::Send(const void * data, uint32_t size, const std::string & dest, uint16_t port)
    {
        assert(data && size);

        auto packet = AllocPacket();

        // copy data
        assert(size <= sizeof(packet->m_packet));

        memcpy(&packet->m_packet, data, size);
        packet->m_Address.address = boost::asio::ip::address::from_string(dest);
        packet->m_Address.port = port;
        packet->m_size = size;

        {
            std::lock_guard<decltype(m_SendMutex)> sendLocker(m_SendMutex);
            m_SendPackets.push(packet);
        }
         m_SendCond.notify_one();

        return true;
    }

    bool DataCarrier::Register(const std::string& target, uint16_t port, RecvCallBack recvCallback)
    {
        using namespace boost::asio::ip;
        TransportAddress address = { address::from_string(target), port };

        std::lock_guard<decltype(m_ListenerMutex)> locker(m_ListenerMutex);
        auto itor = m_RecvListener.find(address);
        if (itor != m_RecvListener.end())
        {
            LOG_WARNING("DataCarrier", "Register, already registered [%s:%d]", target.c_str(), port);
            return false;
        }

        return m_RecvListener.insert(std::make_pair(address, recvCallback)).second;
    }

    bool DataCarrier::Unregister(const std::string & target, uint16_t port)
    {
        using namespace boost::asio::ip;
        TransportAddress address = { address::from_string(target), port };

        std::lock_guard<decltype(m_ListenerMutex)> locker(m_ListenerMutex);
        m_RecvListener.erase(address);
        return true;
    }

    void DataCarrier::Unregister()
    {
        std::lock_guard<decltype(m_ListenerMutex)> locker(m_ListenerMutex);
        m_RecvListener.clear();
    }

    bool DataCarrier::Initilize()
    {
        std::lock_guard<decltype(sFreePacketsMutex)> locker(sFreePacketsMutex);
        if (sbInited)
            return true;

        for (uint16_t i = 0; i < sPacketCacheSize; ++i)
            sFreePackets.push(&sPacketCache[i]);

        sbInited = true;
        return sbInited;
    }

    void DataCarrier::SendThread(DataCarrier * pThis)
    {
        assert(pThis);

        while (!pThis->m_bQuit)
        {
            Packet *packet(nullptr);
            {
                std::unique_lock<decltype(pThis->m_SendMutex)> locker(pThis->m_SendMutex);
                pThis->m_SendCond.wait(locker, [pThis]() {
                    return pThis->m_SendPackets.size() > 0 || pThis->m_bQuit;
                });

                // send the front packet
                if (pThis->m_bQuit)
                    break;

                packet = pThis->m_SendPackets.front();
                pThis->m_SendPackets.pop();
            }

            pThis->m_Channel.Send(&packet->m_packet, packet->m_size, packet->m_Address.address, packet->m_Address.port, true);
            Dealloc(packet);
        }
    }

    void DataCarrier::RecvThread(DataCarrier * pThis)
    {
        assert(pThis);

        while (!pThis->m_bQuit)
        {
            auto packet = AllocPacket();
            auto bytes = pThis->m_Channel.Recv(&packet->m_packet, sizeof(packet->m_packet),
                packet->m_Address.address,
                packet->m_Address.port, true);

            if (bytes > 0)
            {
                packet->m_size = bytes;
                std::lock_guard<decltype(pThis->m_RecvMutex)> recvLocker(pThis->m_RecvMutex);
                pThis->m_RecvPackets.push(packet);
                pThis->m_RecvCond.notify_one();
            }
            else
            {
                Dealloc(packet);
            }
        }
    }

    void DataCarrier::HandleRecvPacketsThread(DataCarrier * pThis)
    {
        assert(pThis);

        while (!pThis->m_bQuit)
        {
            Packet *packet(nullptr);

            {
                std::unique_lock<decltype(pThis->m_RecvMutex)> locker(pThis->m_RecvMutex);

                pThis->m_RecvCond.wait(locker, [pThis]() {
                    return pThis->m_RecvPackets.size() > 0 || pThis->m_bQuit;
                });

                if (pThis->m_bQuit)
                    break;

                packet = pThis->m_RecvPackets.front();
                pThis->m_RecvPackets.pop();
            }

            {
                std::lock_guard<decltype(pThis->m_ListenerMutex)> locker(pThis->m_ListenerMutex);
                auto listerner_itor = pThis->m_RecvListener.find(packet->m_Address);
                if (listerner_itor != pThis->m_RecvListener.end())
                {
                    assert(listerner_itor->second);
                    listerner_itor->second(&packet->m_packet, packet->m_size);
                }
                else
                {
                    LOG_WARNING("DataCarrier","unexcepted sender [%s:%d]",
                        boost::asio::ip::address(packet->m_Address.address).to_string().c_str(),
                        packet->m_Address.port);
                }
            }
            Dealloc(packet);
        }
    }

    DataCarrier::Packet * DataCarrier::AllocPacket()
    {
        std::unique_lock<decltype(sFreePacketsMutex)> locker(sFreePacketsMutex);
        sFreePacketsCond.wait(locker, []() {
            return sFreePackets.size() > 0;
        });

        auto packet = sFreePackets.front();
        sFreePackets.pop();

        return packet;
    }

    void DataCarrier::Dealloc(Packet * packet)
    {
        assert(packet >= &sPacketCache[0] && packet <= &sPacketCache[sPacketCacheSize - 1]);

        std::lock_guard<decltype(sFreePacketsMutex)> locker(sFreePacketsMutex);
        sFreePackets.push(packet);
        sFreePacketsCond.notify_all();
    }
}