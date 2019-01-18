
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

    bool Media::CreateStream(uint8_t compId, Protocol protocol, const std::string& hostIP, uint16_t hostPort)
    {

        std::auto_ptr<Stream> stream(new Stream(compId, protocol, hostIP, hostPort));
        if (!stream.get())
        {
            LOG_ERROR("Media", "Not enough to Create Stream failed");
            return false;
        }

        if(!stream->GatherCandidate())
        {
            LOG_ERROR("Media", "Create Stream Failed to gather candidates");
            return false;
        }

        if (!m_Streams.insert(std::make_pair(compId, stream.get())).second)
        {
            LOG_ERROR("Media", "Create Stream Failed");
            return false;
        }

        stream.release();
        return true;
    }
}