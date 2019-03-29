
#include "media.h"

#include "stundef.h"
#include "session.h"
#include "stream.h"
#include "DataCarrier.h"
#include "pg_log.h"

namespace {
    static const std::string BASE64 =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789"
        "+/";

    static const uint16_t BASE64_CNT = static_cast<uint16_t>(BASE64.length());

    std::string GenerateUserFrag()
    {
        std::string frag;
        for (uint16_t i = 0; i < STUN::sIceUfragLength; ++i)
            frag += BASE64[PG::GenerateRandom(0, BASE64_CNT - 1)];
        return frag;
    }

    std::string GenerateUserPwd()
    {
        std::string pwd;
        for (uint16_t i = 0; i < STUN::sIcePWDLength; ++i)
            pwd += BASE64[PG::GenerateRandom(0, BASE64_CNT - 1)];
        return pwd;
    }

    uint16_t DecodePacketCompId(const uint8_t *data, uint32_t size)
    {
        assert(data && size >= 2);

        if (((data[0] & 0xc0) == 0x80))
        {
            // rtp
            if ((data[1] & 0x40) == 0x00)
                return static_cast<uint16_t>(ICE::Media::ClassicID::RTP);

            /*
            0xC8(200) - SR(Sender Report)
            0xC9(201) - RR(Reciever Report)
            0xCA(202) - SDES(Source Description)
            0xCB(203) - BYE(goodbye)
            0xCC(204) - APP(application-defined)
            0xCD(205) - RTPFB(Generic RTP Feedback)
            0xCE(206) - PSFB(Payload-specific)
            0xCF(207) - XR(extended report)
            0xD0(208) - AVB(AVB RTCP packet)
            0xD1(209) - RSI(Receiver Summary Information)
            0xD2(210) - TOKEN(Port Mapping)

            REF:
            http://www.iana.org/assignments/rtp-parameters/rtp-parameters.xml
            http://freesoft.org/CIE/RFC/1889/47.htm
            */
            else if (data[1] == 0xC8
                || data[1] == 0xC9
                || data[1] == 0xCA
                || data[1] == 0xCB
                || data[1] == 0xCC
                || data[1] == 0xCD
                || data[1] == 0xCE
                || data[1] == 0xCF
                || data[1] == 0xD0
                || data[1] == 0xD1
                || data[1] == 0xD2
                )
            {
                // rtcp
                return static_cast<uint16_t>(ICE::Media::ClassicID::RTCP);
            }
        }

        return 0;
    }
}

namespace ICE {
    ICE::Media::Media(Session &session) :
        m_Session(session), m_icepwd(GenerateUserPwd()), m_iceufrag(GenerateUserFrag()),m_ConnStatus(ConnStatus::init)
    {
    }

    ICE::Media::~Media()
    {
        if(m_ConnCheckThrd.joinable())
            m_ConnCheckThrd.join();

        Shutdown();

        for (auto itor = m_Streams.begin(); itor != m_Streams.end(); ++itor)
        {
            assert(itor->second);
            delete itor->second;
        }
    }

    const std::string & Media::GetDefaultIP(uint16_t id) const
    {
        auto itor = m_DefaultMap.find(id);
        assert(itor != m_DefaultMap.end());
        return itor->second.m_ip;
    }

    uint16_t Media::GetDefaultPort(uint16_t id) const
    {
        auto itor = m_DefaultMap.find(id);
        assert(itor != m_DefaultMap.end());
        return itor->second.m_port;
    }

    bool Media::CreateStream(uint16_t compId, Protocol protocol, const std::string& hostIP, uint16_t hostPort,
        std::function<void(const void*, uint32_t)> cb)
    {
        uint32_t key = (compId << 16) | static_cast<uint16_t>(protocol);

        assert(m_Streams.find(key) == m_Streams.end());

        SaveDefaultInfo(compId, hostIP, hostPort);
        std::auto_ptr<Stream> stream(new Stream(m_Session, *this, compId, protocol, hostIP, hostPort,
            std::bind(&Media::OnDataReceived, this, std::placeholders::_1, std::placeholders::_2, cb)));
        if (!stream.get())
        {
            LOG_ERROR("Media", "CreateStream ID [%d ] failed", compId);
            return false;
        }

        if(!stream->GatherCandidates())
        {
            LOG_ERROR("Media", "Create Stream Failed to gather candidates");
            return false;
        }

        if (!m_Streams.insert(std::make_pair(key, stream.get())).second)
        {
            LOG_ERROR("Media", "Create Stream Failed to insert stream");
            return false;
        }

        stream.release();
        return true;
    }

    void Media::SaveDefaultInfo(uint16_t compId, const std::string & ip, uint16_t port)
    {
        auto itor = m_DefaultMap.find(compId);
        assert(itor == m_DefaultMap.end());

        m_DefaultMap.insert(std::make_pair(compId, DefaultInfo{ip, port}));
    }

    void Media::Shutdown()
    {
        for (auto itor = m_ValidStreams.begin(); itor != m_ValidStreams.end(); ++itor)
            itor->second->Shutdown();
    }

    bool Media::SendData(uint16_t compId, const void * pData, uint32_t size)
    {
        assert(m_ValidStreams.find(compId) != m_ValidStreams.end());
        return m_ValidStreams[compId]->SendData(pData, size);
    }

    void Media::ConnectivityCheck(const std::map<Stream*, CandPeerContainer*>& checkList, std::function<void(Media*, bool)> callback)
    {
        assert(callback);

        std::lock_guard<decltype(m_ConnMutex)> locker(m_ConnMutex);
        assert(m_ConnStatus == ConnStatus::init);

        try
        {
            m_ConnStatus = ConnStatus::ongoing;
            m_ConnCheckThrd = std::thread(ConnectivityCheckThread, this, checkList,callback);
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("Media", "ConnectivityCheck failed to create thread [%s]", e.what());
            m_ConnStatus = ConnStatus::failed;
            callback(this, false);
        }
    }

    bool Media::IsConnectivityCheckCompleted(Stream * stream, bool bResult)
    {

        assert(stream);
        std::lock_guard<decltype(m_ConnMutex)> locker(m_ConnMutex);

        assert(m_Streams.find((stream->ComponentId() << 16) | (static_cast<uint16_t>(stream->GetProtocol()))) != m_Streams.end());

        if (!bResult || !m_ValidStreams.insert(std::make_pair(stream->ComponentId(), stream)).second)
        {
            LOG_ERROR("Media","ConnectivityCheckCompleted failed [%d]", stream->ComponentId());
            return true;
        }

        if (m_ValidStreams.size() == m_Streams.size())
            return true;
        else
            return false;
#if 0
        assert(stream && cond);

        {
            std::lock_guard<decltype(m_ConnMutex)> locker(m_ConnMutex);
            assert(m_ConnStatus == ConnStatus::ongoing);
        }

        uint32_t key = (stream->ComponentId() << 16) | (static_cast<uint16_t>(stream->GetProtocol()));

        std::lock_guard<decltype(m_ConnMutex)> locker(m_ConnMutex);
        auto itor = m_Streams.find(key);
        assert(itor != m_Streams.end() && m_ValidStreams.find(stream->ComponentId()) == m_ValidStreams.end());

        m_Streams.erase(itor);
        if (bResult && m_ValidStreams.insert(std::make_pair(stream->ComponentId(), stream)).second)
        {
            LOG_ERROR("Media", "IsConnectivityCheckCompleted => Succeed");
            m_ConnStatus = ConnStatus::done;
            cond->notify_all();
        }
        else
        {
        }
#endif
        return false;
    }

    void Media::OnDataReceived(const void * pData, uint32_t size, std::function<void(const void*, uint32_t)> cb)
    {
        assert(cb);
        cb(pData, size);
        DataCarrier::Dealloc(pData);
    }

    void Media::ConnectivityCheckThread(Media * pThis, const std::map<Stream*, CandPeerContainer*> &checkList, std::function<void(Media*, bool)> callback)
    {
        using CheckList = std::map<Stream*, CandPeerContainer*>;

        class CheckHelper {
        public:
            CheckHelper(std::function<bool(Stream*, bool)> callback) :
                m_cb(callback), m_Status(Status::waiting), m_bStarted(false)
            {
                assert(callback);
            }

            ~CheckHelper()
            {
                for (auto itor = m_Jobs.begin(); itor != m_Jobs.end(); ++itor)
                {
                    assert(itor->second && !itor->second->joinable());
                    delete itor->second;
                }
            }

            bool AddJob(Stream *stream, CandPeerContainer *list)
            {
                assert(stream && list);
                try
                {
                    assert(m_Jobs.find(stream) == m_Jobs.end());

                    std::thread *pThrd = new std::thread(JobThread, this, stream, list);
                    if (!pThrd)
                        return false;

                    return m_Jobs.insert(std::make_pair(stream, pThrd)).second;
                }
                catch (const std::exception& e)
                {
                    LOG_ERROR("Stream", "ConnectivityCheckThread cannot create job [%]", e.what());
                    return false;
                }
            }

            void Start()
            {
                assert(m_Jobs.size());
                std::lock_guard<decltype(m_StartedMutex)> locker(m_StartedMutex);
                m_bStarted = true;
                m_StartCond.notify_all();
            }

            bool WaitJobsDone()
            {
                {
                    std::unique_lock<decltype(m_StatusMutex)> locker(m_StatusMutex);
                    m_CompletedCond.wait(locker, [this]() {
                        return this->m_Status != Status::waiting;
                    });
                }

                for (auto itor = m_Jobs.begin(); itor != m_Jobs.end(); ++itor)
                {
                    assert(itor->first && itor->second);
                    if(itor->second->joinable())
                        itor->first->CancleConnectivityCheck();
                    itor->second->join();
                }

                assert(m_Status != Status::waiting);
                return m_Status == Status::failed ? false : true;
            }

            static void JobThread(CheckHelper *pThis, Stream *stream, CandPeerContainer *list)
            {
                assert(pThis && stream && list);
                {
                    std::mutex mutex;
                    std::unique_lock<decltype(pThis->m_StartedMutex)> locker(pThis->m_StartedMutex);
                    pThis->m_StartCond.wait(locker, [pThis]() {
                        return pThis->m_bStarted;
                    });
                }

                auto bRet = stream->ConnectivityCheck(*list);

                {
                    std::lock_guard<decltype(pThis->m_StatusMutex)> locker(pThis->m_StatusMutex);
                    assert(pThis->m_DoneStreams.find(stream) == pThis->m_DoneStreams.end());
                    pThis->m_DoneStreams.insert(stream);

                    if (pThis->m_Status == Status::succeed)
                    {
                        LOG_INFO("Stream","ConnectivityCheck already completed");
                        return;
                    }
                }

                auto bCompleted = pThis->m_cb(stream, bRet);
                if (bCompleted)
                {
                    std::lock_guard<decltype(pThis->m_StatusMutex)> locker(pThis->m_StatusMutex);
                    pThis->m_Status = Status::succeed;
                    pThis->m_CompletedCond.notify_one();
                }
                else if (pThis->m_DoneStreams.size() == pThis->m_Jobs.size())
                {
                    pThis->m_Status = Status::failed;
                    pThis->m_CompletedCond.notify_one();
                }
            }

        private:
            enum class Status {
                waiting,
                failed,
                succeed
            };
        private:
            std::condition_variable             m_StartCond;
            std::condition_variable             m_CompletedCond;
            std::map<Stream*, std::thread*>     m_Jobs;
            std::set<Stream*>                   m_DoneStreams;
            std::function<bool(Stream*, bool)>  m_cb;
            std::mutex m_StatusMutex;
            Status m_Status;

            std::mutex m_StartedMutex;
            bool m_bStarted;
        };

        CheckHelper helper(std::bind(&Media::IsConnectivityCheckCompleted, pThis, std::placeholders::_1, std::placeholders::_2));

        for (auto list_itor = checkList.begin(); list_itor != checkList.end(); ++list_itor)
        {
            assert(list_itor->first && list_itor->second);

            uint32_t key = (list_itor->first->ComponentId() << 16) | static_cast<uint16_t>(list_itor->first->GetProtocol());
            std::unique_lock<decltype(pThis->m_ConnMutex)> locker(pThis->m_ConnMutex);
            auto stream_itor = pThis->m_Streams.find(key);

            assert(stream_itor != pThis->m_Streams.end() && stream_itor->second);

            helper.AddJob(list_itor->first, list_itor->second);
        }

        helper.Start();
        bool bRet = helper.WaitJobsDone();
        callback(pThis, bRet);
    }

    MultiplexStream::~MultiplexStream()
    {
        LOG_ERROR("MultiplexStream", "~MultiplexStream %p", this);

        m_bQuit = true;
        Shutdown();
        for (auto itor = m_Multiplex.begin(); itor != m_Multiplex.end(); ++itor)
        {
            itor->second->_cond.notify_one();
            if (itor->second->_thread.joinable())
                itor->second->_thread.join();

            while (!itor->second->_packets.empty())
            {
                auto packet = itor->second->_packets.front();
                DataCarrier::Dealloc(&packet);
                itor->second->_packets.pop();
            }
            delete itor->second;
        }
    }

    bool MultiplexStream::CreateStream(uint16_t compId, Protocol protocol, const std::string & hostIP, uint16_t hostPort, std::function<void(const void*, uint32_t)> cb)
    {
        assert(protocol == Protocol::tcp_act || protocol == Protocol::tcp_pass);

        uint32_t act_key = (compId << 16) | static_cast<uint16_t>(Protocol::tcp_act);
        uint32_t pass_key = (compId << 16) | static_cast<uint16_t>(Protocol::tcp_pass);

        assert(m_Streams.find(act_key) == m_Streams.end() && m_Streams.find(pass_key) == m_Streams.end() &&
               m_Multiplex.find(compId) == m_Multiplex.end());

        SaveDefaultInfo(compId, hostIP, hostPort);

        std::auto_ptr<MultiplexHelper> multipHelper(new MultiplexHelper);
        multipHelper->_cb = cb;
        if (!multipHelper.get() || !m_Multiplex.insert(std::make_pair(compId, multipHelper.get())).second)
        {
            LOG_ERROR("MultiplexStream", "CreateStream failed to create MultiplexHelper");
            return false;
        }

        std::auto_ptr<Stream> act_stream(new Stream(m_Session, *this, compId, Protocol::tcp_act, hostIP, hostPort,
            std::bind(&MultiplexStream::OnDataReceived, this, std::placeholders::_1, std::placeholders::_2, nullptr)));

        if (!act_stream.get())
        {
            LOG_ERROR("MultiplexStream", "CreateStream failed to create tcp_act stream");
            return false;
        }

        std::auto_ptr<Stream> pass_stream(new Stream(m_Session, *this, compId, Protocol::tcp_pass, hostIP, hostPort,
            std::bind(&MultiplexStream::OnDataReceived, this, std::placeholders::_1, std::placeholders::_2, nullptr)));

        if (!pass_stream.get())
        {
            LOG_ERROR("MultiplexStream", "CreateStream failed to create tcp_pass stream");
            return false;
        }

        if (!act_stream->GatherCandidates() || !pass_stream->GatherCandidates())
        {
            LOG_ERROR("MultiplexStream", "CreateStream failed to gather candidates");
            return false;
        }

        if (!m_Streams.insert(std::make_pair(act_key, act_stream.get())).second ||
            !m_Streams.insert(std::make_pair(pass_key, pass_stream.get())).second)
        {
            LOG_ERROR("MultiplexStream", "CreateStream failed to insert");
            return false;
        }

        multipHelper.release();
        act_stream.release();
        pass_stream.release();
        return true;
    }

    bool MultiplexStream::SendData(uint16_t compId, const void * pData, uint32_t size)
    {
        assert(m_ValidStreams.size() == 1 && m_ValidStreams.begin()->second);
        return m_ValidStreams.begin()->second->SendData(pData, size);
    }

    void MultiplexStream::OnDataReceived(const void * pData, uint32_t size, std::function<void(const void*, uint32_t)>)
    {
        assert(pData && size);

        const uint8_t* buffer = reinterpret_cast<const uint8_t*>(pData);
        uint16_t compId = DecodePacketCompId(reinterpret_cast<const uint8_t*>(pData),size);

        auto &itor = m_Multiplex.find(compId);
        if (itor == m_Multiplex.end())
        {
            LOG_WARNING("MultiplexStream", "OnDataReceived, cannot handle component [%d]", compId);
            DataCarrier::Dealloc(pData);
            return;
        }

        std::lock_guard<decltype(itor->second->_mutex)> locker(itor->second->_mutex);
        itor->second->_packets.push(Packet{ pData, size });
        itor->second->_cond.notify_one();
    }

    bool MultiplexStream::IsConnectivityCheckCompleted(Stream * stream, bool bResult)
    {
        assert(stream);

        if (!bResult)
            return false;

        std::lock_guard<decltype(m_ConnMutex)> locker(m_ConnMutex);
        assert(m_ValidStreams.find(stream->ComponentId()) == m_ValidStreams.end() && 
               m_Streams.find((stream->ComponentId() << 16) | (static_cast<uint16_t>(stream->GetProtocol()))) != m_Streams.end());

        LOG_INFO("MultiplexStream","IsConnectivityCheckCompleted => [%p] [%s]", stream, bResult ? "Succeed" : "Failed");

        if (bResult && m_ValidStreams.insert(std::make_pair(stream->ComponentId(), stream)).second)
            return true;
        else
            return false;
    }

    void MultiplexStream::HandleData(MultiplexStream & This, MultiplexHelper & helper)
    {
        while (1)
        {
            std::unique_lock<decltype(helper._mutex)> locker(helper._mutex);
            helper._cond.wait(locker, [&helper, &This](){
                return helper._packets.size() > 0 || !This.m_bQuit;
            });

            if (!This.m_bQuit)
                break;

            auto &packet = helper._packets.front();
            helper._packets.pop();
            locker.release();

            helper._cb(packet.data, packet.size);
            DataCarrier::Dealloc(packet.data);
        }
    }
}