#include "media.h"

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
}

namespace ICE {
    ICE::Media::Media() :
        m_icepwd(GenerateUserPwd()), m_iceufrag(GenerateUserFrag())
    {
    }

    ICE::Media::~Media()
    {
    }

    const Stream* Media::GetStreamById(uint8_t id) const
    {
        assert(id >= static_cast<uint16_t>(ClassicID::RTP));

        auto itor = m_Streams.find(id);
        return itor != m_Streams.end() ? itor->second : nullptr;
    }

    bool Media::CreateStream(uint8_t compId, Protocol protocol, const std::string & hostIP, uint16_t port, const CAgentConfig& config)
    {
        class EventHelper : public PG::CListener {
        public:
            EventHelper(Media* pOwner, Stream* pStream) :
                m_pOwner(pOwner), m_pStream(pStream)
            {
                assert(pOwner && pStream);
            }

            virtual ~EventHelper()
            {
            }

            void OnEventFired(PG::MsgEntity * pSender, PG::MsgEntity::MSG_ID msg_id, PG::MsgEntity::WPARAM wParam, PG::MsgEntity::LPARAM lParam) override
            {
                assert(static_cast<Stream::Message>(msg_id) == Stream::Message::Gathering && wParam == (PG::MsgEntity::WPARAM)m_pStream);
                m_bResult = lParam > 0;
                std::unique_lock<decltype(m_Mutex)> locker(m_Mutex);
                m_Cond.notify_one();
            }

            bool WaitResult()
            {
                std::unique_lock<decltype(m_Mutex)> locker(m_Mutex);
                m_Cond.wait(locker);
                return m_bResult;
            }

        private:
            Media   *m_pOwner;
            Stream  *m_pStream;
            bool     m_bResult;
            std::condition_variable m_Cond;
            std::mutex              m_Mutex;
        };

        std::auto_ptr<Stream> stream(new Stream(compId, protocol, 0xFFFF, hostIP, port));
        if (!stream.get())
        {
            LOG_ERROR("Media", "Not enough to Create Stream failed");
            return false;
        }

        EventHelper helper(this, stream.get());
        if (!stream->RegisterEventListener(static_cast<uint16_t>(Stream::Message::Gathering), &helper) ||
            !stream->GatheringCandidate(config))
        {
            LOG_ERROR("Media", "Create Stream Failed");
            return false;
        }

        if (!helper.WaitResult() || !m_Streams.insert(std::make_pair(compId, stream.get())).second)
        {
            LOG_ERROR("Media", "Create Stream Failed 1");
            return false;
        }

        stream->UnregisterEventListenner(static_cast<uint16_t>(Stream::Message::Gathering), &helper);
        stream.release();
        return true;
    }
}