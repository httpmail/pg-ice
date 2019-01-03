#pragma once

#include <string>
#include <map>
#include <assert.h>

#include "stundef.h"
#include "pg_msg.h"

namespace ICE {
    class CSession;

    class CAgentConfig {
    public:
        class PortRange {
        public:
            PortRange(uint16_t lower, uint16_t upper) :
                m_lower(lower), m_upper(upper)
            {
                assert(lower < upper);
            }

            void Set(uint16_t lower, uint16_t upper)
            {
                assert(lower < upper);
                m_lower = lower;
                m_upper = upper;
            }

            uint16_t Lower() const { return m_lower; }
            uint16_t Upper() const { return m_upper; }

            ~PortRange() {}

        private:
            uint16_t m_lower;
            uint16_t m_upper;
        };
        using ServerContainer = std::map<std::string, int16_t>; // @std::string: ip address, @int : port

    public:
        CAgentConfig();
        CAgentConfig(const CAgentConfig& config);
        virtual ~CAgentConfig() {}

    public:
        bool LoadConfigFile(const std::string& config_file);

        uint16_t RTO() const { return m_RTO; }
        uint16_t Ta()  const { return m_Ta; }
        uint16_t Rm()  const { return m_Rm; }
        uint16_t Ti()  const { return m_Ti; }
        uint16_t Rc()  const { return m_Rc; }
        uint16_t CandPairsLimits() const { return m_cand_pairs_limits; }
        bool     IPv4Supported()   const { return m_ipv4_supported; }

        const std::string& DefaultIP() const { return m_default_address; }
        const ServerContainer& StunServer() const { return m_stun_servers; }
        const ServerContainer& TurnServer() const { return m_turn_servers; }

        bool AddStunServer(const std::string& stun, int port = 3478);
        bool AddTurnServer(const std::string& turn, int port = 3478);

        STUN::AgentRole Role() const { return m_role; }
        void Role(const STUN::AgentRole &role)
        {
            if (role != m_role)
                m_role = role;
        }

        const PortRange& GetPortRange() const { return m_PortRange; }

    private:
        static bool AddServer(ServerContainer &serverContainer, const std::string& server, int port);

    private:
        uint16_t m_RTO; /* initial value recommended 500ms - 3s */
        uint16_t m_Ta;  /* default value 50ms */
        uint16_t m_Rm;  /* default value 16   */
        uint16_t m_Ti;  /* default value 39500ms(39.5s) */
        uint16_t m_Rc;  /* default value 7 */
        uint16_t m_cand_pairs_limits; /* defualt value 100*/
        bool     m_ipv4_supported;    /* default value true */
        std::string m_default_address;/* default ip for candidate gathering */

        STUN::AgentRole m_role;
        PortRange       m_PortRange;
        ServerContainer m_stun_servers;
        ServerContainer m_turn_servers;

    private:
        static const uint16_t sDefaultRTO = 500;
        static const uint16_t sDefaultTa = 50;
        static const uint16_t sDefaultRm = 16;
        static const uint16_t sDefaultTi = 39500;
        static const uint16_t sDefaultRc = 7;
        static const uint16_t sCandPairsLimits = 100;
        static const uint16_t sIPv4Supported = 1;
        static const uint16_t sLowerPort = 30000;
        static const uint16_t sUpperPort = 32000;
    };

    class CAgent {
    public:
        CAgent() {}
        virtual ~CAgent() {}
        const CAgentConfig& AgentConfig() const { return m_config; }

    private:
        CAgentConfig m_config;
    };
}