#pragma once

#include <stdint.h>
#include <string>
#include <vector>

namespace ICE {

    static const uint8_t RTP_ID = 1;
    static const uint8_t RTCP_ID = 2;

    enum class Protocol : uint8_t{
        udp,
        tcp_act,
        tcp_pass
    };

    struct MediaAttr{
        struct StreamAttr {
            Protocol    m_Protocol;
            uint8_t     m_CompId;
            uint16_t    m_HostPort;
            std::string m_HostIP;
        };

        std::string             m_Name;
        std::vector<StreamAttr> m_StreamAttrs;
    };
}