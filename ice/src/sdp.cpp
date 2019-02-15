#include "sdp.h"
#include "candidate.h"
#include "session.h"
#include "media.h"
#include "stream.h"
#include "pg_log.h"
#include "config.h"

#include <boost/tokenizer.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/asio.hpp>

#include <sstream>
#include <assert.h>

namespace SDPDEF {
    static const std::string nettype = "IN";
    static const std::string candtype = "typ";
    static const std::string reladdr = "raddr";
    static const std::string relport = "rport";
    static const std::string v_line = "v=";
    static const std::string o_line = "o=";
    static const std::string m_line = "m=";
    static const std::string c_line = "c=";
    static const std::string s_line = "s=";
    static const std::string t_line = "t=";
    static const std::string candidate_line = "a=candidate:";
    static const std::string remotecand_line = "a=remote-candidates:";
    static const std::string icepwd_line = "a=ice-pwd:";
    static const std::string iceufrag_line = "a=ice-ufrag:";
    static const std::string rtcp_line = "a=rtcp:";
    static const std::string CRLF = "\r\n";
    static const std::string host_cand_type = "host";
    static const std::string srflx_cand_type = "srflx";
    static const std::string prflx_cand_type = "prflx";
    static const std::string relay_cand_type = "relay";
    static const std::string typ = "typ";
    static const std::string ipv4 = "IP4";
    static const std::string ipv6 = "IP6";
    static const std::string UDP = "UDP";
    static const std::string TCP_ACT = "tcp-act";
    static const std::string TCP_PASS = "tcp-pass";

    static const uint16_t min_cand_content_num = 8;
    static const uint16_t nonhost_cand_content_num = 12;
    static const uint16_t media_content_num = 4;
    static const uint16_t remote_cands_num = 3; // at least 
    static const uint16_t cline_content_num = 3;

    /*
    RFC5245 [15.1.  "candidate" Attribute]
    candidate-attribute   = "candidate" ":" foundation SP component-id SP
    transport SP
    priority SP
    connection-address SP     ;from RFC 4566
    port         ;port from RFC 4566
    SP cand-type
    [SP rel-addr]
    [SP rel-port]
    *(SP extension-att-name SP
    extension-att-value)
    */
    enum class CandAttrIndex : uint8_t {
        foundation = 0,
        compId,
        transport, /*UDP TCP*/
        priority,
        conn_addr,
        conn_port,
        typ,      /* 'typ' */
        candtype, /*"host" "srflx" "prflx" "relay"*/
        raddr,    /* 'raddr'*/
        conn_raddr,
        rport,    /*'rport'*/
        conn_rport,
        max_support_attr
    };

    enum class MediaAttrIndex : uint8_t {
        media = 0,
        port,
        proto,
        fmt,
    };

    enum class RemoteCandsIndex : uint8_t {
        compId = 0,
        connAddr,
        connPort,
    };

    enum class CLineIndex : uint8_t {
        nettype,
        addrtype,
        connaddr,
    };

    static const boost::char_separator<char> whitespace_separator(" ");
    static const boost::char_separator<char> slash_separator("/");

    using CharToken = boost::tokenizer<boost::char_separator<char>>;

    const std::string& addrtype(const std::string& ip)
    {
        return boost::asio::ip::address::from_string(ip).is_v4() ? ipv4 : ipv6;
    }

    const std::string& addrtype(bool isIPv4)
    {
        return isIPv4 ? ipv4 : ipv6;
    }

    const char* GetProtocolName(ICE::Protocol protocol)
    {
        if (ICE::Protocol::tcp_pass == protocol)
            return  TCP_PASS.c_str();
        else if (ICE::Protocol::tcp_act == protocol)
            return TCP_ACT.c_str();
        else
            return UDP.c_str();
    }

    bool IsValidAttrPos(std::string::size_type pos)
    {
        return pos != std::string::npos;
    }

    bool IsValidCandType(const std::string& candtype)
    {
        return candtype == host_cand_type ||
            candtype == srflx_cand_type ||
            candtype == prflx_cand_type ||
            candtype == relay_cand_type;
    }

    bool IsValidAddrType(const std::string& addr)
    {
        return addr == ipv4 || addr == ipv6;
    }

    const char* GetCandidateTypeName(ICE::Candidate::CandType eType)
    {
        using namespace ICE;
        if (Candidate::CandType::peer_ref == eType)
            return prflx_cand_type.c_str();
        else if (Candidate::CandType::svr_ref == eType)
            return srflx_cand_type.c_str();
        else if (Candidate::CandType::relayed == eType)
            return relay_cand_type.c_str();
        else
            return host_cand_type.c_str();
    }
}

CSDP::CSDP()
{
}

CSDP::~CSDP()
{
}

/*
    v=0
    o=jdoe 2890844526 2890842807 IN IP4 $L-PRIV-1.IP
    s=
    c=IN IP4 $NAT-PUB-1.IP
    t=0 0
    a=ice-pwd:asd88fgpdd777uzjYhagZg
    a=ice-ufrag:8hhY
    m=audio $NAT-PUB-1.PORT RTP/AVP 0
    b=RS:0
    b=RR:0
    a=rtpmap:0 PCMU/8000
    a=candidate:1 1 UDP 2130706431 $L-PRIV-1.IP $L-PRIV-1.PORT typ
    host
    a=candidate:2 1 UDP 1694498815 $NAT-PUB-1.IP $NAT-PUB-1.PORT typ
    srflx raddr $L-PRIV-1.IP rport $L-PRIV-1.PORT
*/

bool CSDP::Decode(const std::string & offer)
{
    // decode c-line
    auto pos = offer.find(SDPDEF::c_line);
    if (!SDPDEF::IsValidAttrPos(pos) || !DecodeCLine(offer.substr(pos, offer.find(SDPDEF::CRLF, pos))))
    {
        LOG_ERROR("CSDP", "Invalid c-line %s", offer.substr(pos, offer.find(SDPDEF::CRLF, pos)).c_str());
        return false;
    }

    auto mline_pos = offer.find(SDPDEF::m_line);
    if (!SDPDEF::IsValidAttrPos(mline_pos))
    {
        LOG_ERROR("SDP", "Invlaid m-line");
        return false;
    }

    // check if ice-pwd and ice-ufrag existed in session section
    bool bUfragPwdExisted = false;
    auto session_section = offer.substr(0, mline_pos);
    auto ice_pwd_pos = session_section.find(SDPDEF::icepwd_line);
    auto ice_ufrag_pos = session_section.find(SDPDEF::iceufrag_line);

    if (SDPDEF::IsValidAttrPos(ice_pwd_pos) != SDPDEF::IsValidAttrPos(ice_ufrag_pos))
    {
        LOG_ERROR("SDP", "invalid ice-pwd, ice-ufrag attribute");
        return false;
    }

    if (SDPDEF::IsValidAttrPos(ice_pwd_pos))
    {
        bUfragPwdExisted = true;
        auto pwd_end = session_section.find(SDPDEF::CRLF, ice_pwd_pos + SDPDEF::icepwd_line.length());
        m_IcePwd = session_section.substr(ice_pwd_pos + SDPDEF::icepwd_line.length(), pwd_end - ice_pwd_pos - SDPDEF::icepwd_line.length());

        auto ufrag_end = session_section.find(SDPDEF::CRLF, ice_ufrag_pos + SDPDEF::iceufrag_line.length());
        m_IceUfrag = session_section.substr(ice_ufrag_pos + SDPDEF::iceufrag_line.length(),ufrag_end - ice_ufrag_pos - SDPDEF::iceufrag_line.length());
    }

    do
    {
        auto next_mline_pos = offer.find(SDPDEF::m_line, mline_pos + SDPDEF::m_line.length());
        auto media_line = offer.substr(mline_pos, next_mline_pos == std::string::npos ? next_mline_pos :  next_mline_pos - mline_pos);
        std::auto_ptr<RemoteMedia> media(DecodeMediaLine(media_line, bUfragPwdExisted));
        if (!media.get() || !m_RemoteMedias.insert(std::make_pair(media->Type(), media.get())).second)
        {
            LOG_ERROR("SDP", "Decode Media Line Error");
            return false;
        }
        media.release();
        mline_pos = next_mline_pos;
    } while (SDPDEF::IsValidAttrPos(mline_pos));

    return true;
}

bool CSDP::EncodeOffer(const ICE::Session & session, std::string& offer)
{
    auto Medias = session.GetMedias();
    assert(Medias.size());

    bool isIPv4 = boost::asio::ip::address::from_string(session.DefaultIP()).is_v4();

    std::ostringstream offer_stream;

    // encode "v" line
    offer_stream << SDPDEF::v_line
        << "0" << SDPDEF::CRLF;

    // encode "o" line
    offer_stream << SDPDEF::o_line
        << session.Username() << " "
        << std::chrono::steady_clock::now().time_since_epoch().count() << " "
        << std::chrono::steady_clock::now().time_since_epoch().count() << " "
        << SDPDEF::nettype << " "
        << SDPDEF::addrtype(isIPv4) << " "
        << session.DefaultIP() << SDPDEF::CRLF;

    // encode "s" line
    offer_stream << SDPDEF::s_line
        << session.SessionName() << SDPDEF::CRLF;

    // encode "c" line
    offer_stream << SDPDEF::c_line
        << SDPDEF::nettype << " "
        << SDPDEF::addrtype(isIPv4) << " "
        << session.DefaultIP() << SDPDEF::CRLF;

    // encode "t" line
    offer_stream << SDPDEF::t_line
        << 0 << " "
        << 0 << SDPDEF::CRLF;


    //encode "a=candidate"
    for (auto media_itor = Medias.begin(); media_itor != Medias.end(); ++media_itor)
    {
        auto *rtp = media_itor->second->GetStreamById(static_cast<uint16_t>(ICE::Media::ClassicID::RTP));

        // encode "m" line
        offer_stream << SDPDEF::m_line
            << media_itor->first << " "
            << rtp->GetDefaultPort() << " "
            << rtp->GetTransportProtocol() << " "
            << 0 << SDPDEF::CRLF;

        // encode "rtcp" line
        auto *rtcp = media_itor->second->GetStreamById(static_cast<uint16_t>(ICE::Media::ClassicID::RTCP));
        assert(rtcp);
        offer_stream << SDPDEF::rtcp_line
            << rtcp->GetDefaultPort() << SDPDEF::CRLF;

        // encode "a=ice-pwd"
        offer_stream << SDPDEF::icepwd_line
            << media_itor->second->IcePwd() << SDPDEF::CRLF;

        //encode "a=ice-ufrag"
        offer_stream << SDPDEF::iceufrag_line
            << media_itor->second->IceUfrag() << SDPDEF::CRLF;

        auto Streams = media_itor->second->GetStreams();
        assert(Streams.size());
        for (auto stream_itor = Streams.begin(); stream_itor != Streams.end(); ++stream_itor)
        {
            ICE::CandContainer cands;
            stream_itor->second->GetCandidates(cands);
            auto compId = stream_itor->first;

            const char* transport = SDPDEF::GetProtocolName(stream_itor->second->GetProtocol());
            for (auto& cand_itor = cands.begin(); cand_itor != cands.end(); ++cand_itor)
            {
                auto cand = *cand_itor;
                /*
                rfc5245
                15.1.  "candidate" Attribute
                */
                offer_stream << SDPDEF::candidate_line
                    << cand->m_Foundation << " "
                    << compId << " "
                    << transport << " "
                    << cand->m_Priority << " "
                    << cand->m_ConnIP << " "
                    << cand->m_ConnPort << " "
                    << SDPDEF::candtype << " "
                    << SDPDEF::GetCandidateTypeName(cand->m_CandType);

                if (ICE::Candidate::CandType::host != cand->m_CandType)
                {
                    offer_stream << " "
                        << SDPDEF::reladdr << " "
                        << cand->m_BaseIP << " "
                        << SDPDEF::relport << " "
                        << cand->m_BasePort;
                }
                offer_stream << SDPDEF::CRLF;
            }
        }
    }


    offer = offer_stream.str();
    return offer.length() > 0;
}

bool CSDP::EncodeAnswer(const ICE::Session & session, const std::string & offer, std::string & answer)
{
    answer = offer;

    for (auto media_itor = session.GetMedias().begin(); media_itor != session.GetMedias().end(); ++media_itor)
    {
        assert(media_itor->second);
        auto media = media_itor->second;

        std::ostringstream remote_line;

        remote_line << SDPDEF::remotecand_line;

        for (auto stream_itor = media->GetStreams().begin(); stream_itor != media->GetStreams().end(); ++stream_itor)
        {
            assert(stream_itor->second);
            auto stream = stream_itor->second;
            auto ip = stream->GetRemoteCandidateIP();
            auto port = stream->GetRemoteCandidatePort();

            remote_line << stream_itor->first << " ";
            remote_line << ip << " ";
            remote_line << port << " ";
        }

        std::string remote = remote_line.str();
        // trim space from the end
        remote.pop_back();

        auto pos = offer.find(media_itor->first);
        assert(pos != std::string::npos);

        auto nxt_media = offer.find(SDPDEF::m_line, pos);
        if (std::string::npos == nxt_media)
            answer.append(remote);
        else
        {
            remote += SDPDEF::CRLF;
            answer.insert(nxt_media, remote);
        }
    }

    return true;
}

CSDP::RemoteMedia* CSDP::DecodeMediaLine(const std::string & mediaLine, bool bSesUfragPwdExisted)
{
    assert(SDPDEF::IsValidAttrPos(mediaLine.find(SDPDEF::m_line)));

    using Content = std::vector<std::string>;

    // decode "m="
    std::string info(mediaLine.substr(SDPDEF::m_line.length(), mediaLine.find(SDPDEF::CRLF) - SDPDEF::m_line.length()));

    SDPDEF::CharToken token(info, SDPDEF::whitespace_separator);

    Content media_content;
    for (auto itor = token.begin(); itor != token.end(); ++itor)
    {
        media_content.push_back(*itor);
    }

    /*
    rfc4566
    m=<media> <port>/<number of ports> <proto> <fmt>
    */
    if (media_content.size() < SDPDEF::media_content_num)
    {
        LOG_ERROR("SDP", "Decode SDP, illegal m= %s", info.c_str());
        return nullptr;
    }

    /*
    decode a=rtcp:
    */
    auto rtcp_pos = mediaLine.find(SDPDEF::rtcp_line);
    if (SDPDEF::IsValidAttrPos(rtcp_pos))
    {
        auto rtcp_content = mediaLine.substr(rtcp_pos + SDPDEF::rtcp_line.length(),
            mediaLine.find(SDPDEF::CRLF, rtcp_pos) - rtcp_pos - SDPDEF::rtcp_line.length());
        try
        {
            boost::lexical_cast<uint16_t>(rtcp_content);
        }
        catch (const std::exception&)
        {
            LOG_WARNING("SDP", "Decode SDP, illegal rtcp content a=rtcp:%s", rtcp_content);
            return nullptr;
        }
    }

    /*
    RFC5245[15.4.]
    decode ice-ufrag and ice-pwd
    */
    auto ice_ufrag_pos = mediaLine.find(SDPDEF::iceufrag_line);
    auto ice_pwd_pos = mediaLine.find(SDPDEF::icepwd_line);

    bool bUfragExisted = SDPDEF::IsValidAttrPos(ice_ufrag_pos);
    bool bPwdExisted = SDPDEF::IsValidAttrPos(ice_pwd_pos);

    if ((bUfragExisted != bPwdExisted) || (!bSesUfragPwdExisted && !bUfragExisted))
    {
        LOG_ERROR("Session", "Decode SDP, illegal ufrag or pwd");
        return nullptr;
    }

    std::string ice_ufrag = "";
    std::string ice_pwd = "";

    if (bUfragExisted)
    {
        assert(bPwdExisted);
        ice_ufrag = mediaLine.substr(ice_ufrag_pos + SDPDEF::iceufrag_line.length(), mediaLine.find(SDPDEF::CRLF, ice_ufrag_pos) - ice_ufrag_pos - SDPDEF::iceufrag_line.length());
        ice_pwd = mediaLine.substr(ice_pwd_pos + SDPDEF::icepwd_line.length(), mediaLine.find(SDPDEF::CRLF, ice_pwd_pos) - ice_pwd_pos - SDPDEF::icepwd_line.length());
    }

    /*
    RFC5245[15.1.  "candidate" Attribute]
    Decode a=candidate
    */

    std::auto_ptr<RemoteMedia> remoteMedia(new RemoteMedia(media_content[static_cast<uint16_t>(SDPDEF::MediaAttrIndex::media)],ice_pwd, ice_ufrag));

    for (auto cand_finder = mediaLine.find(SDPDEF::candidate_line); SDPDEF::IsValidAttrPos(cand_finder);
        cand_finder = mediaLine.find(SDPDEF::candidate_line, cand_finder + SDPDEF::candidate_line.length()))
    {
        assert(SDPDEF::IsValidAttrPos(cand_finder));
        auto cand_end_pos = mediaLine.find(SDPDEF::CRLF, cand_finder);
        auto info_len = cand_end_pos == std::string::npos ? cand_end_pos : cand_end_pos - cand_finder - SDPDEF::candidate_line.length();

        Content cand_content;
        auto info = mediaLine.substr(cand_finder + SDPDEF::candidate_line.length(), info_len);

        SDPDEF::CharToken token(info, SDPDEF::whitespace_separator);

        for (auto itor = token.begin(); itor != token.end(); ++itor)
            cand_content.push_back(*itor);

        // check content number
        if (cand_content.size() < SDPDEF::min_cand_content_num)
        {
            LOG_ERROR("Session", "Decode SDP, invalid candidate[host size invalid]: %s", mediaLine.substr(cand_finder, cand_end_pos).c_str());
            return nullptr;
        }

        // check 'typ'
        if (cand_content[static_cast<uint16_t>(SDPDEF::CandAttrIndex::typ)] != SDPDEF::typ)
        {
            LOG_ERROR("Session", "Decode SDP, candidate typ Must be \'typ\' :%s", mediaLine.substr(cand_finder, cand_end_pos).c_str());
            return nullptr;
        }

        // check 'candidate_type' must be 'host, srflx,prflx,relay'
        auto candtype = cand_content[static_cast<uint16_t>(SDPDEF::CandAttrIndex::candtype)];
        if (!SDPDEF::IsValidCandType(candtype))
        {
            LOG_ERROR("Session", "Decode SDP, invalid candidate type :%s", candtype.c_str());
            return nullptr;
        }

        // if is non-host-candidate, check content number
        bool isHostCand = (candtype == SDPDEF::host_cand_type);
        if (!isHostCand && cand_content.size() < SDPDEF::nonhost_cand_content_num)
        {
            LOG_ERROR("Session", "Decode SDP, invalid candidate[non-host size invalid]: %s", mediaLine.substr(cand_finder, cand_end_pos).c_str());
            return nullptr;
        }

        // check 'raddr' and 'rport '
        if (!isHostCand &&
            (cand_content[static_cast<uint16_t>(SDPDEF::CandAttrIndex::raddr)] != SDPDEF::reladdr) &&
            (cand_content[static_cast<uint16_t>(SDPDEF::CandAttrIndex::rport)] != SDPDEF::relport))
        {
            LOG_ERROR("Session", "Decode SDP, invalid raddr or rport: %s", mediaLine.substr(cand_finder, cand_end_pos).c_str());
            return nullptr;
        }

        cand_content[static_cast<uint16_t>(SDPDEF::CandAttrIndex::transport)];

        uint32_t compId, priority;
        uint16_t conn_port(0), conn_rport(0);
        try
        {
            priority = boost::lexical_cast<uint32_t>(cand_content[static_cast<uint16_t>(SDPDEF::CandAttrIndex::priority)]);
            compId = boost::lexical_cast<uint16_t>(cand_content[static_cast<uint8_t>(SDPDEF::CandAttrIndex::compId)]);
            conn_port = boost::lexical_cast<uint16_t>(cand_content[static_cast<uint16_t>(SDPDEF::CandAttrIndex::conn_port)]);
            if (!isHostCand)
                conn_rport = boost::lexical_cast<uint16_t>(cand_content[static_cast<uint16_t>(SDPDEF::CandAttrIndex::conn_rport)]);
        }
        catch (const std::exception&)
        {
            LOG_ERROR("Session", "Decode SDP, invalid priority, component, or port");
            return nullptr;
        }

        if (candtype == SDPDEF::host_cand_type)
        {
            if (!remoteMedia->AddHostCandidate(compId, priority,
                cand_content[static_cast<uint8_t>(SDPDEF::CandAttrIndex::foundation)],
                cand_content[static_cast<uint8_t>(SDPDEF::CandAttrIndex::conn_addr)],
                conn_port))
            {
                LOG_ERROR("SDP", "add host candidate failed");
                return nullptr;
            }
        }
        else if (candtype == SDPDEF::srflx_cand_type)
        {
            if (!remoteMedia->AddSrflxCandidate(compId, priority,
                cand_content[static_cast<uint8_t>(SDPDEF::CandAttrIndex::foundation)],
                cand_content[static_cast<uint8_t>(SDPDEF::CandAttrIndex::conn_addr)],conn_port,
                cand_content[static_cast<uint8_t>(SDPDEF::CandAttrIndex::conn_raddr)], conn_rport))
            {
                LOG_ERROR("SDP", "add srflx candidate failed");
                return nullptr;
            }
        }
        else if (candtype == SDPDEF::relay_cand_type)
        {
            if (!remoteMedia->AddRelayCandidate(compId, priority,
                cand_content[static_cast<uint8_t>(SDPDEF::CandAttrIndex::foundation)],
                cand_content[static_cast<uint8_t>(SDPDEF::CandAttrIndex::conn_addr)], conn_port,
                cand_content[static_cast<uint8_t>(SDPDEF::CandAttrIndex::conn_raddr)], conn_rport))
            {
                LOG_ERROR("SDP", "add relay candidate failed");
                return nullptr;
            }
        }
    }


    /*
        RFC5245 [15.2.  "remote-candidates" Attribute]
     */
    for (auto r_cand_finer = mediaLine.find(SDPDEF::remotecand_line); SDPDEF::IsValidAttrPos(r_cand_finer);
        r_cand_finer = mediaLine.find(SDPDEF::remotecand_line, r_cand_finer + SDPDEF::remotecand_line.length()))
    {
        auto end_pos    = mediaLine.find(SDPDEF::CRLF, r_cand_finer);
        auto info_len   = end_pos == std::string::npos ? end_pos : end_pos - r_cand_finer - SDPDEF::remotecand_line.length();
        Content r_cand_content;
        auto info = mediaLine.substr(end_pos + SDPDEF::remotecand_line.length(), info_len);
        SDPDEF::CharToken token(info, SDPDEF::whitespace_separator);

        for (auto itor = token.begin(); itor != token.end(); ++itor)
            r_cand_content.push_back(*itor);

        if (r_cand_content.size() % SDPDEF::remote_cands_num)
        {
            LOG_ERROR("SDP", "remote-candidates content invalid: %s",
                mediaLine.substr(end_pos + SDPDEF::remotecand_line.length(), end_pos).c_str());
            return nullptr;
        }

        
        r_cand_finer = end_pos;
    }
    return remoteMedia.release();
}

bool CSDP::DecodeCLine(const std::string & cline)
{
    /*
      rfc4566[5.7.  Connection Data ("c=")]
     */

    assert(cline.find(SDPDEF::c_line) == 0);

    auto end_pos = cline.find(SDPDEF::CRLF);
    auto info = cline.substr(SDPDEF::c_line.length(), end_pos - SDPDEF::c_line.length());
    SDPDEF::CharToken token(info, SDPDEF::whitespace_separator);

    std::vector<std::string> content;
    for (auto itor = token.begin(); itor != token.end(); ++itor)
    {
        content.push_back(*itor);
    }


    if (content.size() != SDPDEF::cline_content_num)
        return false;

    if (content[static_cast<uint16_t>(SDPDEF::CLineIndex::nettype)] != SDPDEF::nettype)
    {
        LOG_ERROR("SDP", "Invalid nettype %s", content[static_cast<uint16_t>(SDPDEF::CLineIndex::nettype)].c_str());
        return false;
    }

    auto addrtype = content[static_cast<uint16_t>(SDPDEF::CLineIndex::addrtype)];
    if (!SDPDEF::IsValidAddrType(addrtype))
    {
        LOG_ERROR("SDP", "Invalid addrtype :%s", addrtype.c_str());
        return false;
    }

    SDPDEF::CharToken connaaddr_token(content[static_cast<uint16_t>(SDPDEF::CLineIndex::connaddr)], SDPDEF::slash_separator);

    std::vector<std::string> connaddr_content;
    for (auto itor = connaaddr_token.begin(); itor != connaaddr_token.end(); ++itor)
    {
        connaddr_content.push_back(*itor);
    }


    if (SDPDEF::ipv4 == addrtype)
    {
        if (connaddr_content.size() <= 3)
        {
            if (!m_Cline.insert(std::make_pair(connaddr_content[0], true)).second)
            {
                LOG_ERROR("SDP", "save CLine error");
                return false;
            }
            if (connaddr_content.size() > 1)
            {
                try
                {
                    auto ttl = boost::lexical_cast<uint16_t>(connaddr_content[1]); // TTL

                    // mulitcast
                    if (connaddr_content.size() > 2)
                    {
                        auto number_of_addr = boost::lexical_cast<uint16_t>(connaddr_content[2]); // number of number of addresses

                        uint16_t last_number = boost::lexical_cast<uint16_t>(*connaddr_content[0].rbegin());
                        std::string ip = connaddr_content[0].substr(0, connaddr_content[0].length() - 1);
                        for (decltype(number_of_addr)i = 0; i < number_of_addr - 1; ++i)
                        {
                            if (!m_Cline.insert(std::make_pair(ip + boost::lexical_cast<char>(++last_number), true)).second)
                            {
                                LOG_ERROR("SDP", "save CLine error");
                                return false;
                            }
                        }
                    }
                }
                catch (const std::exception&)
                {
                    LOG_ERROR("SDP", "Invalid CLine");
                    return false;
                }
            }
        }
        else
        {
            LOG_ERROR("SDP", "Invalid CLine");
            return false;
        }
    }
    else
    {
        if (connaddr_content.size() > 2)
        {
            LOG_ERROR("SDP", "invlaid CLine with IPv6 addrtype");
            return false;
        }

        if (!m_Cline.insert(std::make_pair(connaddr_content[0], false)).second)
        {
            LOG_ERROR("SDP", "Cannot Save CLine");
            return false;
        }

        if (connaddr_content.size() == 2)
        {
            //TTL
        }
    }

    return true;
}


CSDP::RemoteMedia::~RemoteMedia()
{
    for (auto itor = m_Cands.begin(); itor != m_Cands.end(); ++itor)
    {
        assert(itor->second);

        for (auto cand_itor = itor->second->begin(); cand_itor != itor->second->end(); ++cand_itor)
            delete *cand_itor;

        delete itor->second;
    }
}

bool CSDP::RemoteMedia::AddHostCandidate(uint8_t compId, uint32_t pri, const std::string& foundation, const std::string & baseIP, uint16_t basePort)
{
    std::auto_ptr<ICE::HostCand> cand(new ICE::HostCand(pri, foundation, baseIP, basePort));

    if (cand.get() && AddCandidate(compId, cand.get()))
    {
        cand.release();
        return true;
    }
    return false;
}

bool CSDP::RemoteMedia::AddSrflxCandidate(uint8_t compId, uint32_t pri, const std::string& foundation,
    const std::string& connIP, uint16_t connPort,
    const std::string& baseIP, uint16_t basePort)
{
    std::auto_ptr<ICE::SvrCand> cand(new ICE::SvrCand(pri, foundation, connIP, connPort, baseIP, basePort));

    if (cand.get() && AddCandidate(compId, cand.get()))
    {
        cand.release();
        return true;
    }
    return false;
}

bool CSDP::RemoteMedia::AddPrflxCandidate(uint8_t compId, uint32_t pri, const std::string& foundation,
    const std::string& connIP, uint16_t connPort,
    const std::string& baseIP, uint16_t basePort)
{
    std::auto_ptr<ICE::PeerCand> cand(new ICE::PeerCand(pri, foundation, connIP, connPort, baseIP, basePort));

    if (cand.get() && AddCandidate(compId, cand.get()))
    {
        cand.release();
        return true;
    }

    return false;
}

bool CSDP::RemoteMedia::AddRelayCandidate(uint8_t compId, uint32_t pri, const std::string& foundation, const std::string & connIP, uint16_t connPort, const std::string & baseIP, uint16_t basePort)
{
    std::auto_ptr<ICE::RelayedCand> cand(new ICE::RelayedCand(pri, foundation, connIP, connPort, baseIP, basePort));

    if (cand.get() && AddCandidate(compId, cand.get()))
    {
        cand.release();
        return true;
    }

    return false;
}

bool CSDP::RemoteMedia::AddCandidate(uint8_t compId, ICE::Candidate *can)
{
    assert(can);
    auto itor = m_Cands.find(compId);

    CandContainer *container = nullptr;

    if (itor == m_Cands.end())
    {
        container = new CandContainer;
        if (!container || !m_Cands.insert(std::make_pair(compId, container)).second)
        {
            LOG_ERROR("Session", "Not enough memory to create Candidate");
            delete container;
            return false;
        }
    }
    else
    {
        assert(itor->second);
        container = itor->second;
    }

    assert(container);

    if (!container->insert(can).second)
    {
        LOG_ERROR("Session", "Add Candidate Failed");
        return false;
    }

    return true;
}
