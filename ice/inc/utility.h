#pragma once

#include <set>
#include <string>
#include <stdint.h>
#include <assert.h>

namespace UTILITY {

    class Server {
    public:
        Server() {}
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

        void IP(const std::string& ip) { _ip = ip; }
        const std::string& IP() const { return _ip; }

        void Port(uint16_t port) { _port = port; }
        uint16_t Port() const { return _port; }

    private:
        std::string _ip;
        uint16_t    _port;
    };

    struct PortRange {
    public:
        PortRange() {};
        PortRange(uint16_t min, uint16_t max) : _min(min), _max(max) { assert(min < max); }

        void Set(uint16_t min, uint16_t max) { assert(min < max); _min = min; _max = max; }

        uint16_t Min() const { return _min; }
        uint16_t Max() const { return _max; }

    public:
        uint16_t _min;
        uint16_t _max;
    };

    struct AuthInfo {
        AuthInfo() {};
        AuthInfo(const std::string& pwd, const std::string& ufrag) : _pwd(pwd), _ufrag(ufrag) {}

        std::string _pwd;
        std::string _ufrag;
    };

    using Servers = std::set<Server>;
}