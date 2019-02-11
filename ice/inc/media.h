#pragma once

#include <map>
#include "streamdef.h"

namespace ICE {

    class CAgentConfig;
    class Stream;
    class Session;

    class Media{
    public:
        enum class ClassicID : uint8_t{
            RTP = 1,
            RTCP,
        };

    public:
        using StreamContainer = std::map<uint16_t, Stream*>; /*key = component id*/

    public:
        Media(Session &session);
        virtual ~Media();

        const StreamContainer& GetStreams() const { return m_Streams; }
        const Stream* GetStreamById(uint8_t id) const;
        const std::string& IcePwd() const { return m_icepwd; }
        const std::string& IceUfrag() const { return m_iceufrag; }

        const std::string& RIcePwd() const   { return m_RIcepwd; }
        void SetRIcePwd(const std::string& pwd) { m_RIcepwd = pwd; }

        const std::string& RIceUfrag() const { return m_RIcefrag; }
        void SetRIceUfrag(const std::string& ufrag) { m_RIcefrag = ufrag; }
        bool CreateStream(uint8_t compId, Protocol protocol, const std::string& hostIP, uint16_t hostPort);

    private:
        Session            &m_Session;
        StreamContainer     m_Streams;
        const std::string   m_icepwd;
        const std::string   m_iceufrag;

        std::string m_RIcepwd;
        std::string m_RIcefrag;
    };
}