#include "stunpacket.h"
#include "channel.h"

PacketCarrier::~PacketCarrier()
{
}

bool PacketCarrier::RegisterListener(Session * pListener)
{
    return false;
}

bool PacketCarrier::SendPacket(const STUN::MessagePacket & packet, const std::string & receiver, uint16_t port)
{
    return true;
}

bool PacketCarrier::SendPacket(const STUN::MessagePacket & packet)
{
    return true;
}

void PacketCarrier::SendThread(PacketCarrier * pThis)
{
    assert(pThis);

    while (1)
    {
        std::unique_lock<decltype(pThis->m_SendPacketMutex)> locker(pThis->m_SendPacketMutex);
        pThis->m_SendPacketCond.wait(locker, [pThis]() {
            return pThis->m_SendPackets.size();
        });

        auto packet = pThis->m_SendPackets.front();

        assert(packet);

        pThis->m_SendPackets.pop();
        locker.release();

    }
}

void PacketCarrier::RecvThread(PacketCarrier * pThis)
{
    assert(pThis);

    while (1)
    {
        std::unique_lock<decltype(sFreePacketMutex)> locker(sFreePacketMutex);
        sFreePacketCond.wait(locker, []() {
            return sFreePackets.size();
        });

        auto packet = sFreePackets.front();
        sFreePackets.pop();
        locker.release();


    }
}

void PacketCarrier::DispatchThread(PacketCarrier * pThis)
{
    assert(pThis);

    while (true)
    {
        std::unique_lock<decltype(pThis->m_RecvPacketMutex)> locker(pThis->m_RecvPacketMutex);
        pThis->m_RecvPacketCond.wait(locker, [pThis]() {
            return pThis->m_RecvPackets.size();
        });

        auto packet = pThis->m_RecvPackets.front();
        pThis->m_RecvPackets.pop();
        locker.release();
    }
}

void PacketCarrier::ConnectThread(PacketCarrier * pThis, const std::string& peer, uint16_t port)
{
    assert(pThis);

    auto ret = pThis->m_Channel.Connect(peer, port);

    if (ret)
    {
        pThis->m_DispThrd = std::thread(DispatchThread, pThis);
        pThis->m_SendThrd = std::thread(SendThread, pThis);
        pThis->m_RecvThrd = std::thread(RecvThread, pThis);
    }
}
