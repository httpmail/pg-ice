#pragma once

#include <stdint.h>
#include <string>
#include <set>
#include <assert.h>

#include "streamdef.h"

namespace ICE {
    class Candidate {
    public:
        /*RFC8445 5.1.2.2.  Guidelines for Choosing Type and Local Preferences*/
        enum class CandType : uint16_t{
            svr_ref     = 100,
            relayed     = 0,
            host        = 126,
            peer_ref    = 110,
        };

        Candidate(Protocol protocol, CandType type, uint32_t pri, const std::string& foundation,
            const std::string& connIP, uint16_t connPort,
            const std::string& baseIP, uint16_t basePort) :
            m_Protocol(protocol), m_CandType(type),m_Priority(pri),m_Foundation(foundation),
            m_ConnIP(connIP),m_BaseIP(baseIP),m_ConnPort(connPort),m_BasePort(basePort)
        {
            assert(baseIP.length() && connIP.length() && connPort && basePort);
        }

        static uint32_t ComputePriority(CandType type, uint32_t localPref, uint16_t comp_id)
        {
            return ((static_cast<uint8_t>(type) & 0xFF) << 24) + ((localPref & 0xFFFF) << 8) + (((256 - comp_id) & 0xFF) << 0);
        }

        static std::string ComputeFoundations(CandType type, const std::string& baseIP, const std::string& serverIP, ICE::Protocol protocol);

    public:
        const Protocol m_Protocol;
        CandType       m_CandType;
        const uint32_t m_Priority;
        const uint16_t m_ConnPort;
        const uint16_t m_BasePort;
        const std::string m_Foundation;
        const std::string m_ConnIP;
        const std::string m_BaseIP;
    };

    class HostCand : public Candidate {
    public:
        HostCand(uint32_t pri, const std::string& foundation, const std::string& connIP, uint16_t connPort) :
            Candidate(Protocol::udp, CandType::host, pri, foundation, connIP, connPort, connIP, connPort)
        {}
    };

    class ActiveCand : public Candidate {
    public:
        ActiveCand(uint32_t pri, const std::string& foundation,const std::string& connIP, uint16_t connPort) :
            Candidate(Protocol::tcp_act, CandType::host, pri, foundation, connIP, connPort, connIP, connPort)
        {}
    };

    class PassiveCand : public Candidate {
    public:
        PassiveCand(uint32_t pri, const std::string& foundation,const std::string& connIP, uint16_t connPort):
            Candidate(Protocol::tcp_pass, CandType::host, pri, foundation, connIP, connPort, connIP, connPort)
        {}
    };

    class SvrCand : public Candidate {
    public:
        SvrCand(uint32_t pri, const std::string& foundation,
            const std::string& connIP, uint16_t connPort,
            const std::string& baseIP, uint16_t basePort) :
            Candidate(Protocol::udp, CandType::svr_ref, pri, foundation, connIP, connPort, baseIP, basePort)
        {}
    };

    class SvrPassiveCand : public Candidate {
    public:
        SvrPassiveCand(uint32_t pri, const std::string& foundation,
            const std::string& connIP, uint16_t connPort,
            const std::string& baseIP, uint16_t basePort) :
            Candidate(Protocol::tcp_pass, CandType::svr_ref, pri, foundation, connIP, connPort, baseIP, basePort)
        {}
    };

    class SvrActiveCand : public Candidate {
    public:
        SvrActiveCand(uint32_t pri, const std::string& foundation,
            const std::string& connIP, uint16_t connPort,
            const std::string& baseIP, uint16_t basePort) :
            Candidate(Protocol::tcp_act, CandType::svr_ref, pri, foundation, connIP, connPort, baseIP, basePort)
        {}
    };

    class PeerCand : public Candidate {
    public:
        PeerCand(uint32_t pri, const std::string& foundation,
            const std::string& connIP, uint16_t connPort,
            const std::string& baseIP, uint16_t basePort) :
            Candidate(Protocol::udp, CandType::peer_ref, pri, foundation, connIP, connPort, baseIP, basePort)
        {}
    };

    class RelayedCand : public Candidate {
    public:
        RelayedCand(uint32_t pri, const std::string& foundation,
            const std::string& connIP, uint16_t connPort,
            const std::string& baseIP, uint16_t basePort) :
            Candidate(Protocol::udp, CandType::relayed, pri, foundation, connIP, connPort, baseIP, basePort)
        {}
    };

    class CandidatePeer {
    public:
        CandidatePeer::CandidatePeer(uint64_t PRI, const ICE::Candidate& lcand, const ICE::Candidate &rcand) :
            m_PRI(PRI), m_LCand(lcand), m_RCand(rcand)
        {
            assert(&lcand != &rcand);
            assert((lcand.m_Protocol == rcand.m_Protocol && lcand.m_Protocol == Protocol::udp) ||
                (lcand.m_Protocol != rcand.m_Protocol && lcand.m_Protocol != Protocol::udp && rcand.m_Protocol != Protocol::udp));
        }

        virtual CandidatePeer::~CandidatePeer()
        {
        }

        void Priority(uint64_t pri) { m_PRI = pri; }
        uint64_t Priority() const { return m_PRI; }

        const Candidate& LCandidate() const { return m_LCand; }
        const Candidate& RCandidate() const { return m_RCand; }

        bool operator< (const CandidatePeer &other) const
        {
            if (this == &other || 
                ((&other.m_LCand == &m_LCand) && (&other.m_RCand == &m_RCand)))
                return false;

            if (other.m_PRI != m_PRI)
                return other.m_PRI < m_PRI;

            if (&other.m_LCand != &m_LCand)
                return &other.m_LCand < &m_LCand;

            return &other.m_RCand < &m_RCand;
        }

    private:
        uint64_t m_PRI;
        const Candidate &m_LCand;
        const Candidate &m_RCand;
    };

    using CandPeerContainer = std::set<CandidatePeer>;
    using CandContainer     = std::vector<const Candidate*>;
}