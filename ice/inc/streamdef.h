#pragma once

#include <stdint.h>
#include <vector>
#include <string>
#include <functional>

namespace ICE {

    static const uint8_t RTP_ID = 1;
    static const uint8_t RTCP_ID = 2;

    enum class Protocol : uint8_t{
        udp,
        tcp_act,
        tcp_pass
    };

    struct MediaAttr{
        using OnRxCallBack = std::function<void(const void *pData, uint32_t size)>;
        struct StreamAttr {
            Protocol    m_Protocol;
            uint8_t     m_CompId;
            uint16_t    m_HostPort;
            std::string m_HostIP;
            OnRxCallBack m_RxCB;
        };
        std::string             m_Name;
        bool                    m_Multiplexed;
        std::vector<StreamAttr> m_StreamAttrs;
    };
}