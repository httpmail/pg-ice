#include "config.h"

#include <boost/asio.hpp>
#include <boost/filesystem.hpp>
#include <boost/asio.hpp>

namespace {
    std::string GetDefaultIPAddress(bool bSupportIPv4)
    {
        using boost::asio::ip::tcp;

        boost::asio::io_service io_service;
        tcp::resolver resolver(io_service);
        tcp::resolver::query query(boost::asio::ip::host_name(), "");
        tcp::resolver::iterator itor = resolver.resolve(query);
        tcp::resolver::iterator end;

        while (itor != end)
        {
            auto ep = *itor++;
            auto ep_address = ep.endpoint().address();

            /*
            Addresses from a loopback interface MUST NOT be included in the
            candidate addresses
            */
            if (ep_address.is_loopback())
                continue;

            if (ep_address.is_v6())
            {
                /*
                Deprecated IPv4-compatible IPv6 addresses [RFC4291] and IPv6 sitelocal
                unicast addresses [RFC3879] MUST NOT be included in the
                address candidates


                IPv4-mapped IPv6 addresses SHOULD NOT be included in the address
                candidates unless the application using ICE does not support IPv4
                (i.e., it is an IPv6-only application [RFC4038]).
                */

                auto ipv6 = ep_address.to_v6();
                if (ipv6.is_v4_compatible() || ipv6.is_site_local() || ipv6.is_link_local() || (bSupportIPv4 && ipv6.is_v4_mapped()))
                    continue;
            }
            else if (0 == ep_address.to_string().find("169.254"))  // ipv4 lock-link
                continue;

            return ep.endpoint().address().to_string();
        }
        return std::string();
    }
}

Configuration::Configuration() :
    m_LocalPref(0xFFFF),
    m_RTO(sDefaultRTO),
    m_Ta(sDefaultTa),
    m_Rm(sDefaultRm),
    m_Ti(sDefaultTi),
    m_Rc(sDefaultRc),
    m_cand_pairs_limits(sCandPairsLimits),
    m_ipv4_supported(sIPv4Supported),
    m_PortRange(sLowerPort, sUpperPort)
{
    m_default_address = GetDefaultIPAddress(sIPv4Supported);
}

bool Configuration::LoadConfigFile(const std::string & config_file)
{
    if (boost::filesystem::exists(config_file))
    {
        std::ifstream file(config_file);
        assert(file.is_open());
    }

    if (!m_default_address.length())
        m_default_address = GetDefaultIPAddress(m_ipv4_supported);

    assert(m_default_address.length());

    return true;
}

bool Configuration::AddStunServer(const std::string & stun, int port /*= 3478*/)
{
    return AddServer(m_stun_servers, stun, port);
}

bool Configuration::AddTurnServer(const std::string & turn, int port /*= 3478*/)
{
    return AddServer(m_turn_servers, turn, port);
}

bool Configuration::AddServer(UTILITY::Servers & serverContainer, const std::string & server, int port)
{
    return serverContainer.insert(UTILITY::Server(server, port)).second;
}