#include "session.h"
#include "agent.h"
#include "media.h"
#include "stream.h"
#include "sdp.h"
#include "candidate.h"
#include "config.h"

#include "pg_log.h"
#include "pg_util.h"

#include <boost/asio.hpp>

#include <assert.h>

namespace {
    using namespace ICE;

     void FormingCandidatePairs(CandPeerContainer& candPeers, const CandContainer &lcandscontainer, const CandContainer &rcandscontainer, bool bControlling)
    {
        for (auto lcands_itor = lcandscontainer.begin(); lcands_itor != lcandscontainer.end(); ++lcands_itor)
        {
            auto lcand = *lcands_itor;
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
                        auto& peer_lcand = (peer_itor)->LCandidate();
                        auto& peer_rcand = (peer_itor)->RCandidate();
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
    Session::Session(const std::string& sessionName, const std::string& userName) :
        m_Tiebreaker(PG::GenerateRandom64()),
        m_DefaultIP(Configuration::Instance().DefaultIP()),
        m_Username(userName), m_SessionName(sessionName),
        m_bControlling(true),
        m_CheckStatus(CheckStatus::init)
    {
    }

    Session::~Session()
    {
        for (auto itor = m_Medias.begin(); itor != m_Medias.end(); ++itor)
            delete itor->second;
    }

    void Session::SetControlling(bool bControlling)
    {
        std::lock_guard<decltype(m_ControllingMutex)> locker(m_ControllingMutex);
        m_bControlling = bControlling;
    }

    bool Session::IsControlling() const
    {
        std::lock_guard<decltype(m_ControllingMutex)> locker(m_ControllingMutex);
        return m_bControlling;
    }

    bool Session::CreateMedia(const MediaAttr& mediaAttr)
    {
        if (m_Medias.end() != m_Medias.find(mediaAttr.m_Name))
        {
            LOG_WARNING("Session", "Media [%s] already existed", mediaAttr.m_Name.c_str());
            return false;
        }

        std::auto_ptr<Media> media(mediaAttr.m_Multiplexed ? new MultiplexStream(*this) : new Media(*this));
        if (!media.get())
        {
            LOG_ERROR("Session", "Failed to Media [%s]", mediaAttr.m_Name.c_str());
            return false;
        }

        for (auto itor = mediaAttr.m_StreamAttrs.begin(); itor != mediaAttr.m_StreamAttrs.end(); ++itor)
        {
            if (!media->CreateStream(itor->m_CompId, itor->m_Protocol, itor->m_HostIP, itor->m_HostPort, itor->m_RxCB))
            {
                LOG_ERROR("Session", "Media [%s] failed to Create Stream [%d] [%s:%d]", mediaAttr.m_Name.c_str(), itor->m_CompId, itor->m_HostIP.c_str(), itor->m_HostPort);
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

    bool Session::SendData(const std::string & mediaName, uint16_t compId, const void * pData, uint32_t size)
    {
        std::unique_lock<decltype(m_MediaMutex)> locker(m_MediaMutex);
        auto itor = m_Medias.find(mediaName);
        assert(itor != m_Medias.end());
        return itor->second->SendData(compId, pData, size);
    }

    bool Session::ConnectivityCheck(const std::string & offer)
    {
        CSDP sdp;

        {
            std::lock_guard<decltype(m_MediaMutex)> locker(m_MediaMutex);
            assert(m_CheckStatus == CheckStatus::init);
            m_CheckStatus = CheckStatus::ongoing;
        }

        LOG_INFO("Session", "remote offer :%s", offer.c_str());

        // decode remote endpoint sdp
        if (!sdp.Decode(offer))
        {
            LOG_ERROR("Session", "Invalid Offer");
            return false;
        }

        // make check list
        using CheckContainer      = std::map<Stream*, CandPeerContainer*>;
        using MediaCheckContainer = std::map<Media*,   CheckContainer*>;

        auto remoteMedias = sdp.GetRemoteMedia();
        int16_t total_cand_pairs = 0;

        MediaCheckContainer mediaCheckList;
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

            std::auto_ptr<CheckContainer> checkContainer(new CheckContainer);
            
            if (!checkContainer.get() || !mediaCheckList.insert(std::make_pair(lmedia, checkContainer.get())).second)
            {
                LOG_ERROR("Session", "Create Media CheckList failed [%s]", rmedia_itor->first.c_str());
                return false;
            }

            auto & lstreams = lmedia->GetStreams();
            auto rmedia = rmedia_itor->second;
            for (auto lstreams_itor = lstreams.begin(); lstreams_itor != lstreams.end(); ++lstreams_itor)
            {
                assert(lstreams_itor->second);
                auto lstream = lstreams_itor->second;
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

                CandContainer lcands, rcands;
                lstream->GetCandidates(lcands);
                rcands.assign(rcand_itor->second->begin(), rcand_itor->second->end());

                FormingCandidatePairs(*candPeerContainer.get(), lcands, rcands, m_bControlling);
                if (candPeerContainer->empty())
                {
                    LOG_ERROR("Session", "[%s] media has no candidate peers", lmedia_itor->first.c_str());
                    continue;
                }
                else if (!checkContainer->insert(std::make_pair(lstream, candPeerContainer.get())).second)
                {
                    LOG_ERROR("Session", "[%s] media cannot create Check List", lmedia_itor->first.c_str());
                    return false;
                }

                total_cand_pairs += static_cast<int16_t>(candPeerContainer->size());
                for (auto itor = candPeerContainer->begin(); itor != candPeerContainer->end(); ++itor)
                {
                    auto rcand = itor->RCandidate();
                    auto lcand = itor->LCandidate();
                    LOG_ERROR("Session", "lcand: [%d] => [%s:%d], [%s:%d] \n rcand: [%d] => [%s:%d], [%s:%d]",
                        lcand.m_CandType,
                        lcand.m_BaseIP.c_str(), lcand.m_BasePort,
                        lcand.m_ConnIP.c_str(), lcand.m_ConnPort,
                        rcand.m_CandType,
                        rcand.m_BaseIP.c_str(), rcand.m_BasePort,
                        rcand.m_ConnIP.c_str(), rcand.m_ConnPort);
                }
                candPeerContainer.release();
            }

            checkContainer.release();
            lmedia->SetRIcePwd(rmedia->IcePassword());
            lmedia->SetRIceUfrag(rmedia->IceUfrag());
        }

        MediaContainer medias(m_Medias.begin(), m_Medias.end());
        for (auto itor = m_Medias.begin(); itor != m_Medias.end(); ++itor)
        {
            assert(itor->second);
            auto media = itor->second;
            auto media_itor = mediaCheckList.find(media);
            assert(media_itor != mediaCheckList.end() && media_itor->second);

            media->ConnectivityCheck(*media_itor->second,
                std::bind(&Session::OnMediaConnectivityCheck, this, std::placeholders::_1, std::placeholders::_2, &medias));
        }

        std::unique_lock<decltype(m_MediaMutex)> locker(m_MediaMutex);
        m_ConnCheckCond.wait(locker, [this]() {
            return this->m_CheckStatus == CheckStatus::done || this->m_CheckStatus == CheckStatus::failed;
        });

        for (auto media_itor = mediaCheckList.begin(); media_itor != mediaCheckList.end(); ++media_itor)
        {
            auto check_container = media_itor->second;
            assert(check_container);
            for (auto check_itor = check_container->begin(); check_itor != check_container->end(); ++check_itor)
                delete check_itor->second;

            delete check_container;
        }

        assert(m_CheckStatus == CheckStatus::done || m_CheckStatus == CheckStatus::failed);

        return m_CheckStatus == CheckStatus::done;
    }

    void Session::OnMediaConnectivityCheck(Media *media, bool bRet, MediaContainer *medias)
    {
        assert(medias);

        std::lock_guard<decltype(m_MediaMutex)> locker(m_MediaMutex);
        bool bFound = false;
        auto itor = medias->begin();
        for (; itor != medias->end(); ++itor)
        {
            if (itor->second == media)
            {
                bFound = true;
                break;
            }
        }

        assert(bFound);

        if (!bRet)
        {
            LOG_ERROR("Session", "Connectivity check failed : %s", itor->first.c_str());
            m_CheckStatus = CheckStatus::failed;
        }

        medias->erase(itor);
        if (medias->empty())
        {
            if (m_CheckStatus != CheckStatus::failed)
                m_CheckStatus = CheckStatus::done;
            m_ConnCheckCond.notify_one();
        }
    }

    const std::string& Session::MakeOffer()
    {
        CSDP sdp;
        sdp.EncodeOffer(*this, m_Offer);
        return m_Offer;
    }

    const std::string& Session::MakeAnswer(const std::string & remoteOffer)
    {
        auto ret = ConnectivityCheck(remoteOffer);
        if (!ret)
            return m_Answer;

        CSDP sdp;
        sdp.EncodeAnswer(*this, m_Offer, m_Answer);
        return m_Answer;
    }
}