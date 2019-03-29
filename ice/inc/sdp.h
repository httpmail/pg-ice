#pragma once

#include <stdint.h>
#include <unordered_set>
#include <unordered_map>
#include <string>

#include "candidate.h"

namespace ICE {
    class Session;
}
class CSDP {
public:
    class RemoteMedia {
    public:
        using CandContainer     = std::unordered_set<ICE::Candidate*>;
        using ComponentCands    = std::unordered_map<uint16_t, CandContainer*>;

    public:
        RemoteMedia(const std::string& type, const std::string& pwd, const std::string& ufrag) :
            m_type(type), m_icepwd(pwd), m_iceufrag(ufrag)
        {
        }

        virtual ~RemoteMedia();

        const std::string& Type() const { return m_type; }
        const ComponentCands& Candidates() const { return m_Cands; }

        bool AddHostCandidate(ICE::Protocol protocol,uint8_t compId, uint32_t pri, const std::string& foundation, const std::string& connIP, uint16_t connPort);

        bool AddSrflxCandidate(ICE::Protocol protocol, uint8_t compId, uint32_t pri, const std::string& foundation,
            const std::string& connIP, uint16_t connPort,
            const std::string& baseIP, uint16_t basePort);

        bool AddPrflxCandidate(ICE::Protocol protocol, uint8_t compId, uint32_t pri, const std::string& foundation,
            const std::string& connIP, uint16_t connPort,
            const std::string& baseIP, uint16_t basePort);

        bool AddRelayCandidate(ICE::Protocol protocol, uint8_t compId, uint32_t pri, const std::string& foundation,
            const std::string& connIP, uint16_t connPort,
            const std::string& baseIP, uint16_t basePort);

        const std::string& IcePassword() const { return m_icepwd; }
        const std::string& IceUfrag() const { return m_iceufrag; }
    private:
        bool AddCandidate(uint8_t compId, ICE::Candidate* can);

    private:
        const std::string   m_icepwd;
        const std::string   m_iceufrag;
        const std::string   m_type;
        ComponentCands      m_Cands;
    };

public:
    using RemoteMediaContainer = std::unordered_map<std::string, RemoteMedia*>;
    using ConnectContainer     = std::unordered_map<std::string, bool>; /* IPV*/

public:
    CSDP();
    virtual ~CSDP();

public:
    bool Decode(const std::string& offer);
    bool EncodeOffer(const ICE::Session & session, std::string& offer);
    bool EncodeAnswer(const ICE::Session &session, const std::string &offer, std::string& answer);
    const RemoteMediaContainer& GetRemoteMedia() const { return m_RemoteMedias; }

private:
    RemoteMedia* DecodeMediaLine(const std::string& mediaLine, bool bSesUfragPwdExisted);
    bool DecodeCLine(const std::string& cline);

private:
    RemoteMediaContainer m_RemoteMedias;
    std::string          m_IcePwd;
    std::string          m_IceUfrag;
    ConnectContainer     m_Cline;
};