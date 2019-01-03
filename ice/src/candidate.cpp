
#include "candidate.h"
#include <functional>
#include <boost/function.hpp>
#include <boost/lexical_cast.hpp>

namespace ICE {
    std::string Candidate::ComputeFoundations(CandType type, const std::string & baseIP, const std::string & serverIP, ICE::Protocol protocol)
    {
        char buf[4]; /* the max_value of type is 256 */
        std::string hashStr(baseIP + serverIP);
        sprintf_s(buf, sizeof(buf), "%d", type);
        hashStr += buf;
        sprintf_s(buf, sizeof(buf), "%d", protocol);
        hashStr += buf;

        try
        {
            return boost::lexical_cast<std::string>(std::hash<std::string>{}(hashStr));
        }
        catch (const std::exception&)
        {
            return "0000";
        }
    }
}