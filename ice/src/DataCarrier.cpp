#include "DataCarrier.h"
#include "Channel.h"
#include "pg_log.h"
#include "stunmsg.h"

#ifdef _DEBUG
#define DEBUG_CLIENTBLOCK new( _CLIENT_BLOCK, __FILE__, __LINE__)
#define new DEBUG_CLIENTBLOCK
#else
#define DEBUG_CLIENTBLOCK
#endif  // _DEBUG
#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>
#ifdef _DEBUG
#define new DEBUG_CLIENTBLOCK
#endif  // _DEBUG

namespace ICE {

    std::condition_variable DataCarrier::sFreePacketsCond;
    std::mutex              DataCarrier::sFreePacketsMutex;
    DataCarrier::Buffer     DataCarrier::sFreePackets;
    DataCarrier::Packet     DataCarrier::sPacketCache[DataCarrier::sPacketCacheSize];

    bool DataCarrier::sbInited = DataCarrier::Initilize();

    DataCarrier::DataCarrier(ICE::Channel & channel)
        :m_Channel(channel),m_Status(Status::init)
    {
    }

    DataCarrier::~DataCarrier()
    {
        LOG_WARNING("DataCarrier", "Unregisterred listerner [%d] [%p] [%p]", m_RecvListener.size(), this, &m_Channel);

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
                DataCarrier::Packet* packet = m_SendPackets.front();
                Dealloc(packet);
                m_SendPackets.pop();
            }
        }

        {
            std::lock_guard<decltype(m_RecvMutex)> locker(m_RecvMutex);
            while (!m_RecvPackets.empty())
            {
                DataCarrier::Packet* packet = m_RecvPackets.front();
                Dealloc(packet);
                m_RecvPackets.pop();
            }
        }

        LOG_INFO("DataCarrier", "sFreePackets [%d], total [%d]", sFreePackets.size(), DataCarrier::sPacketCacheSize);
    }

    void DataCarrier::Start()
    {
        assert(!IsStatus(Status::quit));

        if (IsStatus(Status::started))
        {
            LOG_ERROR("DataCarrier", "Start, Already Started");
            return;
        }

        if (StartThread())
            SetStatus(Status::started);
        else
            SetStatus(Status::quit);
    }

    void DataCarrier::Stop()
    {
        if(!IsStatus(Status::quit))
            SetStatus(Status::quit);

        std::lock_guard<decltype(m_ListenerMutex)> locker(m_ListenerMutex);

        for (auto itor = m_RecvListener.begin(); itor != m_RecvListener.end(); ++itor)
        {
            assert(itor->second);
            itor->second(nullptr, 0);
        }
    }

    DataCarrier::send_status DataCarrier::Send(const void * data, uint32_t size, const std::string & dest, uint16_t port, uint32_t msecTimeout /* = 500*/)
    {
        assert(data && size);
        {
            std::unique_lock<decltype(m_StatusMutex)> locker(m_SendMutex);
            if (!m_StatusCond.wait_for(locker, std::chrono::milliseconds(msecTimeout), [this]() {
                return this->m_Status == Status::quit || this->m_Status == Status::started;
            }))
            {
                LOG_ERROR("DataCarrier", "Send out, time out");
                return send_status::timeout;
            }

            if (m_Status == Status::quit)
            {
                LOG_ERROR("DataCarrier", "Send error, already quit");
                return send_status::failed;
            }
        }

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

        return send_status::ok;
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

    bool DataCarrier::StartThread()
    {
        assert(!m_SendThrd.joinable() && !m_RecvThrd.joinable() && !m_HandThrd.joinable());
        try
        {
            m_SendThrd = std::thread(SendThread, this);
            m_RecvThrd = std::thread(RecvThread, this);
            m_HandThrd = std::thread(HandleRecvPacketsThread, this);
            return true;
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("DataCarrier", "StartThread failed %s",e.what());
            return false;
        }
    }

    void DataCarrier::SetStatus(Status eStatus)
    {
        std::lock_guard<decltype(m_StatusMutex)> locker(m_StatusMutex);
        if (m_Status != eStatus)
        {
            m_Status = eStatus;
            m_StatusCond.notify_all();
            m_SendCond.notify_all();
            m_RecvCond.notify_all();
        }
    }

    bool DataCarrier::IsStatus(Status eStatus)
    {
        std::lock_guard<decltype(m_StatusMutex)> locker(m_StatusMutex);
        return m_Status == eStatus;
    }

    void DataCarrier::Dealloc(const void * data)
    {
        if(data)
            Dealloc(const_cast<Packet*>(reinterpret_cast<const Packet*>(data)));
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

        while (1)
        {
            Packet *packet(nullptr);

            {
                std::unique_lock<decltype(pThis->m_SendMutex)> locker(pThis->m_SendMutex);
                pThis->m_SendCond.wait(locker, [pThis]() {
                    return pThis->m_SendPackets.size() > 0 || pThis->IsStatus(Status::quit);
                });

                // send the front packet
                if (pThis->IsStatus(Status::quit))
                    break;

                packet = pThis->m_SendPackets.front();
                pThis->m_SendPackets.pop();
            }

            assert(packet);

            auto ret = pThis->m_Channel.Send(&packet->m_packet, packet->m_size, packet->m_Address.address, packet->m_Address.port, true);
            Dealloc(packet);

            if (ret == -1)
            {
                LOG_ERROR("DataCarrier","SendThread channel error");
                pThis->Stop();
                break;
            }
        }
    }

    void DataCarrier::RecvThread(DataCarrier * pThis)
    {
        assert(pThis);

        while (1)
        {
            auto packet = AllocPacket();
            auto bytes = pThis->m_Channel.Recv(&packet->m_packet, sizeof(packet->m_packet),
                packet->m_Address.address,
                packet->m_Address.port, true);

            if (pThis->IsStatus(Status::quit))
            {
                Dealloc(packet);
                break;
            }

            packet->m_size = bytes;
            std::lock_guard<decltype(pThis->m_RecvMutex)> recvLocker(pThis->m_RecvMutex);
            pThis->m_RecvPackets.push(packet);
            pThis->m_RecvCond.notify_one();

            if (bytes == -1)
            {
                LOG_ERROR("DataCarrier", "RecvThread channel error");
                pThis->Stop();
                break;
            }
        }
    }

    void DataCarrier::HandleRecvPacketsThread(DataCarrier * pThis)
    {
        assert(pThis);

        while (1)
        {
            Packet *packet(nullptr);
            {
                std::unique_lock<decltype(pThis->m_RecvMutex)> locker(pThis->m_RecvMutex);

                pThis->m_RecvCond.wait(locker, [pThis]() {
                    return pThis->m_RecvPackets.size() > 0 || pThis->IsStatus(Status::quit);
                });

                if (pThis->IsStatus(Status::quit))
                {
                    pThis->Stop();
                    break;
                }

                packet = pThis->m_RecvPackets.front();
                pThis->m_RecvPackets.pop();
            }

            {
                assert(packet);
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
                    Dealloc(packet);
                }
            }
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

    void DataCarrier::Dealloc(Packet *packet)
    {
        assert(packet >= &sPacketCache[0] && packet <= &sPacketCache[sPacketCacheSize - 1]);

        std::lock_guard<decltype(sFreePacketsMutex)> locker(sFreePacketsMutex);
        sFreePackets.push(packet);
        sFreePacketsCond.notify_all();
    }

    ConnectedDataCarrier::ConnectedDataCarrier(ICE::Channel & channel, const std::string & dest, uint16_t port)
        : DataCarrier(channel),m_dest(dest), m_port(port)
    {
    }

    ConnectedDataCarrier::~ConnectedDataCarrier()
    {
        if (m_ConnectedThrd.joinable())
            m_ConnectedThrd.join();
    }

    void ConnectedDataCarrier::Start()
    {
        assert(!IsStatus(Status::quit));
        if (IsStatus(Status::started) || IsStatus(Status::starting))
        {
            LOG_ERROR("ConnectedDataCarrier","Start, already started");
            return;
        }

        SetStatus(Status::starting);
        m_ConnectedThrd = std::thread(ConnectThread, this);
    }

    bool ConnectedDataCarrier::Register(const std::string & target, uint16_t port, RecvCallBack recvCallback)
    {
        using namespace boost::asio::ip;
        TransportAddress address = { address::from_string(target), port };

        std::lock_guard<decltype(m_ListenerMutex)> locker(m_ListenerMutex);
        assert(m_RecvListener.size() == 0 && target == m_dest && port == m_port);
        return m_RecvListener.insert(std::make_pair(address, recvCallback)).second;
    }

    void ConnectedDataCarrier::ConnectThread(ConnectedDataCarrier *pThis)
    {
        auto ret = pThis->m_Channel.Connect(pThis->m_dest, pThis->m_port);
        if (ret && pThis->StartThread())
            pThis->SetStatus(Status::started);
        else
        {
            LOG_ERROR("ConnectedDataCarrier","ConnectThread, connecting failed");
            pThis->Stop();
        }
    }
}