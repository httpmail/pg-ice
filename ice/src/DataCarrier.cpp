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
        LOG_WARNING("DataCarrier", "Unregisterred listerner [%d]", m_RecvListerners.size());

        m_bQuit = true;

        m_SendCond.notify_one();
        if (m_SendThrd.joinable())
            m_SendThrd.join();

        m_RecvCond.notify_all();
        if (m_RecvThrd.joinable())
            m_RecvThrd.join();

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

        auto itor = m_RecvListerners.find(address);
        if (itor != m_RecvListerners.end())
        {
            LOG_WARNING("DataCarrier", "Register, already registered [%s:%d]", target.c_str(), port);
            return false;
        }
        return m_RecvListerners.insert(std::make_pair(address, recvCallback)).second;
    }

    bool DataCarrier::Unregister(const std::string & target, uint16_t port)
    {
        using namespace boost::asio::ip;
        TransportAddress address = { address::from_string(target), port };

        m_RecvListerners.erase(address);
        return true;
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
                {
                    while (pThis->m_SendPackets.size())
                    {
                        Dealloc(pThis->m_SendPackets.front());
                        pThis->m_SendPackets.pop();
                    }
                    break;
                }
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
                if (STUN::MessagePacket::IsValidStunPacket(packet->m_packet, bytes))
                {
                        LOG_INFO("DataCarrier", "%d, %x", packet->m_Address.port, packet->m_packet.MsgId());
                }
                {
                    packet->m_size = bytes;
                    std::lock_guard<decltype(pThis->m_RecvMutex)> recvLocker(pThis->m_RecvMutex);
                    pThis->m_RecvPackets.push(packet);
                }
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
                {
                    while (pThis->m_RecvPackets.size())
                    {
                        Dealloc(pThis->m_RecvPackets.front());
                        pThis->m_RecvPackets.pop();
                    }
                    break;
                }
                packet = pThis->m_RecvPackets.front();
                pThis->m_RecvPackets.pop();
            }

            auto listerner_itor = pThis->m_RecvListerners.find(packet->m_Address);
            assert(listerner_itor->second);
            LOG_INFO("DataCarrier", "%p ", listerner_itor);
            listerner_itor->second(&packet->m_packet, packet->m_size);

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