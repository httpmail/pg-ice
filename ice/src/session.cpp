#include "session.h"
#include "agent.h"
#include "media.h"
#include "stream.h"
#include "sdp.h"
#include "candidate.h"

#include "pg_log.h"

#include <boost/asio.hpp>

#include <assert.h>

namespace {
    using namespace ICE;
    void FormingCandidatePairs(Session::CandPeerContainer& candPeers, const ICE::Stream::CandsContainer& lcandscontainer, const CSDP::RemoteMedia::CandContainer &rcandscontainer, bool bControlling)
    {
        for (auto lcands_itor = lcandscontainer.begin(); lcands_itor != lcandscontainer.end(); ++lcands_itor)
        {
            auto lcand = lcands_itor->first;
            assert(lcand);
            for (auto rcands_itor = rcandscontainer.begin(); rcands_itor != rcandscontainer.end(); ++rcands_itor)
            {
                auto rcand = *rcands_itor;
                assert(rcand);

                auto lcand_family = boost::asio::ip::address::from_string(lcand->m_ConnIP).is_v4();
                auto rcand_family = boost::asio::ip::address::from_string(rcand->m_ConnIP).is_v4();
                if ((lcand_family == rcand_family) &&
                    (lcand->m_Protocol == rcand->m_Protocol && lcand->m_Protocol == Protocol::udp) ||
                    (lcand->m_Protocol != rcand->m_Protocol && lcand->m_Protocol != Protocol::udp && rcand->m_Protocol != Protocol::udp))
                {
                    /*
                    RFC8445[6.1.2.3.  Computing Pair Priority and Ordering Pairs]
                    Let G be the priority for the candidate provided by the controlling agent.
                    Let D be the priority for the candidate provided by the controlled agent
                    pair priority = 2^32*MIN(G,D) + 2*MAX(G,D) + (G>D?1:0)
                    */
                    auto G = bControlling ? lcand->m_Priority : rcand->m_Priority;
                    auto D = bControlling ? rcand->m_Priority : lcand->m_Priority;

                    uint64_t priority = ((uint64_t)1 << 32) * std::min(G, D) + 2 * std::max(G, D) + (G > D ? 1 : 0);

                    CandidatePeer peer(priority, *lcand, *rcand);

                    bool bAddPeer(true);
                    for (auto peer_itor = candPeers.begin(); peer_itor != candPeers.end(); ++peer_itor)
                    {
                        /*
                        RFC8445 [6.1.2.4.  Pruning the Pairs]
                        two candidate pairs are redundant if
                        their local candidates have the same base and their remote candidates
                        are identical
                         */
                        auto peer_lcand = peer_itor->LCandidate();
                        auto peer_rcand = peer_itor->RCandidate();
                        if ((lcand->m_BaseIP == peer_lcand.m_BaseIP && lcand->m_BasePort == peer_lcand.m_BasePort) &&
                            (rcand->m_ConnIP == peer_rcand.m_ConnIP && rcand->m_ConnPort == peer_rcand.m_ConnPort))
                        {
                            bAddPeer = false;
                            break;
                        }
                    }

                    if (bAddPeer && !candPeers.insert(peer).second)
                    {
                        LOG_ERROR("Session", "Insert peer failed");
                        return;
                    }
                }
            }
        }
    }
}

namespace ICE {
    Session::Session(const std::string& defaultIP) :
        m_Config(PG::GenerateRandom64(), defaultIP)
    {
    }

    Session::~Session()
    {
    }

    bool Session::CreateMedia(const MediaAttr& mediaAttr, const CAgentConfig& config)
    {
        if (m_Medias.end() != m_Medias.find(mediaAttr.m_Name))
        {
            LOG_WARNING("Session", "Media %s already existed", mediaAttr.m_Name);
            return false;
        }

        std::auto_ptr<Media> media(new Media);
        if (!media.get())
        {
            LOG_ERROR("Session", "Not Enough memory to create Media");
            return false;
        }


        for (auto itor = mediaAttr.m_StreamAttrs.begin(); itor != mediaAttr.m_StreamAttrs.end(); ++itor)
        {
            if (!media->CreateStream(itor->m_CompId, itor->m_Protocol, itor->m_HostIP, itor->m_HostPort, config))
            {
                LOG_ERROR("Session", "Media [%s] Create Stream failed [%d] [%s:%d]", mediaAttr.m_Name, itor->m_CompId, itor->m_HostIP.c_str(), itor->m_HostPort);
                return false;
            }
        }

        if (!m_Medias.insert(std::make_pair(mediaAttr.m_Name, media.get())).second)
        {
            LOG_ERROR("Session", "Create Media Failed");
            return false;
        }

        media.release();
        return true;
    }

    bool Session::ConnectivityCheck(const std::string & offer, const CAgentConfig& config)
    {
        CSDP sdp;

        LOG_INFO("Session", "remote offer :%s", offer.c_str());

        // decode remote endpoint sdp
        if (!sdp.Decode(offer))
        {
            LOG_ERROR("Session", "Invalid Offer");
            return false;
        }

        // make check list
        auto remoteMedias = sdp.GetRemoteMedia();
        int16_t total_cand_pairs = 0;
        for (auto lmedia_itor = m_Medias.begin(); lmedia_itor != m_Medias.end(); ++lmedia_itor)
        {
            auto rmedia_itor = remoteMedias.find(lmedia_itor->first);
            if (rmedia_itor == remoteMedias.end())
            {
                LOG_ERROR("Session", "remote media has no [%s]", lmedia_itor->first.c_str());
                return false;
            }
            auto lmedia = lmedia_itor->second;

            assert(lmedia);

            auto & lstreams_container = lmedia->GetStreams();
            auto rmedia = rmedia_itor->second;
            for (auto lstream_itor = lstreams_container.begin(); lstream_itor != lstreams_container.end(); ++lstream_itor)
            {
                auto lstream = lstream_itor->second;
                auto rcand_container = rmedia->Candidates();
                auto rcand_itor = rcand_container.find(lstream->ComponentId());
                if (rcand_itor == rcand_container.end())
                {
                    LOG_ERROR("Session", "remote [%s] media has no [%d] component", lstream->ComponentId(), lmedia_itor->first.c_str());
                    return false;
                }
                std::auto_ptr<CandPeerContainer> candPeerContainer(new CandPeerContainer);

                if (!candPeerContainer.get())
                {
                    LOG_ERROR("Session", "Not enough memory to create candidate peer container");
                    return false;
                }

                assert(rcand_itor->second);
                FormingCandidatePairs(*candPeerContainer.get(), lstream->GetCandidates(), *rcand_itor->second, m_Config.IsControlling());
                if (candPeerContainer->empty())
                {
                    LOG_ERROR("Session", "[%s] media has no candidate peers", lmedia_itor->first.c_str());
                    return false;
                }
                else if (!m_CheckList.insert(std::make_pair(StreamInfo(lstream,lmedia->IcePwd(), rmedia->IcePassword(),lmedia->IceUfrag(),rmedia->IceUfrag()), candPeerContainer.get())).second)
                {
                    LOG_ERROR("Session", "[%s] media cannot create Check List", lmedia_itor->first.c_str());
                    return false;
                }

                total_cand_pairs += static_cast<int16_t>(candPeerContainer->size());
                for (auto itor = candPeerContainer->begin(); itor != candPeerContainer->end(); ++itor)
                {
                    auto rcand = itor->RCandidate();
                    auto lcand = itor->LCandidate();
                    LOG_ERROR("Session","lcand: [%d] => [%s:%d], [%s:%d] \n rcand: [%d] => [%s:%d], [%s:%d]",
                        lcand.m_CandType,
                        lcand.m_BaseIP.c_str(), lcand.m_BasePort,
                        lcand.m_ConnIP.c_str(), lcand.m_ConnPort,
                        rcand.m_CandType,
                        rcand.m_BaseIP.c_str(), rcand.m_BasePort,
                        rcand.m_ConnIP.c_str(), rcand.m_ConnPort);
                }
                candPeerContainer.release();
            }
        }

        if (total_cand_pairs == 0 || total_cand_pairs > config.CandPairsLimits())
        {
            LOG_ERROR("Session", "too much candidate pairs [%d]", total_cand_pairs);
            std::for_each(m_CheckList.begin(), m_CheckList.end(), [](auto &elem) {
                delete elem.second;
            });
            return false;
        }

        // connectivity check
        for (auto check_itor = m_CheckList.begin(); check_itor != m_CheckList.end(); ++check_itor)
        {
            auto stream = check_itor->first.m_pStream;
            assert(stream && check_itor->second);

            for (auto cand_peer_itor = check_itor->second->begin(); cand_peer_itor != check_itor->second->end(); ++cand_peer_itor)
            {
                auto lcand = cand_peer_itor->LCandidate();
                auto rcand = cand_peer_itor->RCandidate();

                if (!stream->ConnectivityCheck(&lcand, &rcand, m_Config.TieBreaker(), m_Config.IsControlling(),
                    check_itor->first.m_LPwd, check_itor->first.m_RPwd, check_itor->first.m_LUfrag, check_itor->first.m_RUfrag))
                    continue;
                std::this_thread::sleep_for(std::chrono::milliseconds(config.Ta()));
            }
        }
    }

    bool Session::MakeOffer(std::string & offer)
    {
        CSDP sdp;
        return sdp.Encode(*this, offer);
    }

    bool Session::MakeAnswer(const std::string & remoteOffer, std::string & answer)
    {
        return true;
    }
}