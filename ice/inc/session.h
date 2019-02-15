#pragma once

#include "streamdef.h"
#include "candidate.h"

#include <map>
#include <thread>
#include <mutex>
#include <assert.h>

namespace ICE {

    class Stream;
    class Media;

    class Session {
    public:
        struct StreamInfo {
        public:
            StreamInfo(Stream* stream, const std::string & lpwd, const std::string & rpwd, const std::string& lufrag, const std::string& rufrag) :
                m_pStream(stream), m_LPwd(lpwd), m_RPwd(rpwd), m_LUfrag(lufrag), m_RUfrag(rufrag)
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
            Stream              *m_pStream;
            const std::string   &m_LPwd;
            const std::string   &m_RPwd;
            const std::string   &m_LUfrag;
            const std::string   &m_RUfrag;
        };

    public:
        using MediaContainer    = std::map<std::string, Media*>;
        using CheckContainer    = std::map<StreamInfo, CandPeerContainer*>; /*key[@uint16_t component id]*/

    public:
        explicit Session(const std::string& sessionName = "-", const std::string& userName = "-");
        virtual ~Session();

        void SetControlling(bool bControlling = true);
        bool IsControlling() const;
        bool CreateMedia(const MediaAttr& mediaAttr);
        bool ConnectivityCheck(const std::string& offer);
        bool MakeOffer(std::string& offer);
        bool MakeAnswer(const std::string& remoteOffer, std::string& answer);

        const MediaContainer& GetMedias() const { return m_Medias; }

        const std::string& Username()  const  { return m_Username;  }
        const std::string& DefaultIP() const  { return m_DefaultIP; }
        const std::string& SessionName() const { return m_SessionName; }

        uint64_t Tiebreaker() const { return m_Tiebreaker; }

    private:
        static void ConnectivityCheckThread(Session * pThis, const StreamInfo* streamInfo, CandPeerContainer * peers);

    private:
        std::condition_variable m_ConnCheckCond;

        std::string m_Offer;
        std::string m_Answer;
        MediaContainer m_Medias;
        CheckContainer m_CheckList;

        /* rfc5245 15.4 */
        std::string m_RemoteUserFrag;
        std::string m_RemoteUserPwd;

        const std::string m_Username;    /*for SDP*/
        const std::string m_SessionName; /*for SDP*/
        const uint64_t m_Tiebreaker;     /* rfc8445 16.1 */
        const std::string m_DefaultIP;

        mutable std::mutex m_ControllingMutex;
        bool m_bControlling;
    };
}