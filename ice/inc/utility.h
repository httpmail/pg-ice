#pragma once

#include <set>
#include <string>
#include <stdint.h>
#include <assert.h>

namespace UTILITY {

    struct Server {
        Server(const std::string& ip, uint16_t port) :
            _ip(ip), _port(port) {}

        bool operator < (const Server& other) const
        {
            if (&other == this || other._ip == _ip && other._port == _port)
                return false;

            if (other._ip == _ip)
                return other._port < _port;
            else
                return other._ip < _ip;
        }

        const std::string _ip;
        const uint16_t    _port;
    };

    struct PortRange {
        PortRange(uint16_t min, uint16_t max) : _min(min), _max(max) { assert(min < max); }
        const uint16_t _min;
        const uint16_t _max;
    };

    struct AuthInfo {
        AuthInfo(const std::string& pwd, const std::string& ufrag) : _pwd(pwd), _ufrag(ufrag) {}
        const std::string _pwd;
        const std::string _ufrag;
    };
    using Servers = std::set<Server>;
}