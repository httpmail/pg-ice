#pragma once

#include "streamdef.h"
#include "candidate.h"

#include <map>
#include <thread>
#include <mutex>
#include <atomic>
#include <assert.h>

namespace ICE {

    class Stream;
    class Media;

    class Session {
    public:
        using MediaContainer    = std::map<std::string, Media*>;

    public:
        explicit Session(const std::string& sessionName = "-", const std::string& userName = "-");
        virtual ~Session();

        void SetControlling(bool bControlling = true);
        bool IsControlling() const;
        bool CreateMedia(const MediaAttr& mediaAttr);
        const std::string& MakeOffer();
        const std::string& MakeAnswer(const std::string& remoteOffer);

        const MediaContainer& GetMedias() const { return m_Medias; }

        const std::string& Username()  const  { return m_Username;  }
        const std::string& DefaultIP() const  { return m_DefaultIP; }
        const std::string& SessionName() const { return m_SessionName; }

        bool SendData(const std::string& mediaName, uint16_t compId, const void *pData, uint32_t size);
        uint64_t Tiebreaker() const { return m_Tiebreaker; }

    private:
        bool ConnectivityCheck(const std::string& offer);
        void OnMediaConnectivityCheck(Media* media, bool bRet, MediaContainer *medias);

    private:
        enum class CheckStatus {
            init,
            ongoing,
            done,
            failed,
        };

    private:
        CheckStatus m_CheckStatus;
        std::condition_variable m_ConnCheckCond;
        std::mutex  m_MediaMutex;
        MediaContainer m_Medias;


        std::string m_Offer;
        std::string m_Answer;

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