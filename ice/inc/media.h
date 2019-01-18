#pragma once

#include <set>
#include "stream.h"

namespace ICE {

    class CAgentConfig;
    class Stream;

    class Media{
    public:
        enum class ClassicID : uint8_t{
            RTP = 1,
            RTCP,
        };

    public:
        using StreamContainer = std::map<uint16_t, Stream*>; /*key = component id*/

    public:
        Media();
        virtual ~Media();

        const StreamContainer& GetStreams() const { return m_Streams; }
        const Stream* GetStreamById(uint8_t id) const;
        const std::string& IcePwd() const { return m_icepwd; }
        const std::string& IceUfrag() const { return m_iceufrag; }
        bool CreateStream(uint8_t compId, Protocol protocol, const std::string& hostIP, uint16_t hostPort);

    private:
        StreamContainer     m_Streams;
        const std::string   m_icepwd;
        const std::string   m_iceufrag;

    };
}