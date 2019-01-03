#pragma once

#include <set>
#include <map>
#include <assert.h>

#include "streamdef.h"

namespace ICE {
    class CAgentConfig;
    class Media;
    class Stream;
    class Candidate;

    class Session
    {
    public:
        class SessionConfig {
        public:
            SessionConfig(uint64_t tiebreak, const std::string& defaultIP) :
                m_Tiebreaker(tiebreak),
                m_DefaultIP(defaultIP),
                m_Username("-"),
                m_SessionName("-")
            {
            }

            ~SessionConfig()
            {
            }

        public:
            const std::string GetConnectivityCheckUsername() const
            {
                return m_RemoteUserFrag + ":";
            }

            const std::string GetConnectivityCheckPassword() const
            {
                return m_RemoteUserPwd;
            }

            void RemoteUserFrag(const std::string& remoteUserFrag)
            {
                m_RemoteUserFrag = remoteUserFrag;
            }

            const std::string& RemoteUserFrag() const
            {
                return m_RemoteUserFrag;
            }

            void RemoteUserPassword(const std::string& remoteUserPwd)
            {
                m_RemoteUserPwd = remoteUserPwd;
            }

            const std::string& RemoteUserPassword() const
            {
                return m_RemoteUserPwd;
            }

            const std::string& UserName() const
            {
                return m_Username;
            }

            const std::string& SessionName() const
            {
                return m_SessionName;
            }

            const std::string& DefaultIP() const
            {
                return m_DefaultIP;
            }

            uint64_t TieBreaker() const { return m_Tiebreaker; }
            bool IsControlling() const { return m_bControlling; }

        private:
            /* rfc5245 15.4 */
            std::string m_RemoteUserFrag;
            std::string m_RemoteUserPwd;

            const std::string m_Username;    /*for SDP*/
            const std::string m_SessionName; /*for SDP*/
            const std::string m_DefaultIP;

            bool m_bControlling;
            const uint64_t m_Tiebreaker; /* rfc8445 16.1 */
        };

    public:
        class CandidatePeer {
        public:
            CandidatePeer(uint64_t PRI, const Candidate* lcand, const Candidate* rcand);
            virtual ~CandidatePeer();

            void Priority(uint64_t pri) { m_PRI = pri; }
            uint64_t Priority() const { return m_PRI; }

            const Candidate* LCandidate() const { return m_LCand; }
            const Candidate* RCandidate() const { return m_RCand; }

            bool operator< (const CandidatePeer &other) const
            {
                if (other.m_LCand == m_LCand && other.m_RCand == m_RCand)
                    return false;

                if (other.m_PRI != m_PRI)
                    return other.m_PRI < m_PRI;

                if (other.m_LCand != m_LCand)
                    return other.m_LCand < m_LCand;

                return other.m_RCand < m_RCand;
            }

        private:
            uint64_t m_PRI;
            const Candidate *m_LCand;
            const Candidate *m_RCand;
        };

        struct StreamInfo {
        public:
            StreamInfo(Stream* stream, const std::string& key, const std::string& username) :
                m_pStream(stream), m_Key(key), m_Username(username)
            {
                assert(stream);
            }
            bool operator< (const StreamInfo &other) const
            {
                if (m_pStream == other.m_pStream)
                    return false;
                return m_pStream < other.m_pStream;
            }

        public:
            Stream          *m_pStream;
            std::string      m_Key;
            std::string      m_Username;
        };
    public:
        using CandPeerContainer = std::set<CandidatePeer>;
        using MediaContainer    = std::map<std::string, const Media*>;
        using CheckContainer    = std::map<StreamInfo, CandPeerContainer*>; /*key[@uint16_t component id]*/

    public:
        Session(const std::string& defaultIP);
        virtual ~Session();

        bool CreateMedia(const MediaAttr& mediaAttr, const CAgentConfig& config);
        bool ConnectivityCheck(const std::string& offer, const CAgentConfig& config);
        bool MakeOffer(std::string& offer);
        bool MakeAnswer(const std::string& remoteOffer, std::string& answer);
        const MediaContainer& GetMedias() const { return m_Medias; }
        const SessionConfig& Config() const { return m_Config; }

    private:
        SessionConfig           m_Config;
        MediaContainer          m_Medias;
        CandPeerContainer       m_CandPeers;
        CheckContainer          m_CheckList;
    };
}