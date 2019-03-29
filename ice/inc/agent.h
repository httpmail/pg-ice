#pragma once

#include <stdint.h>
#include <string>
#include <thread>
#include <mutex>
#include <unordered_map>

namespace ICE {
    class Session;
    struct MediaAttr;

    class CAgent {
        template<bool _32bit>
        struct UINT_PTR {
            using WPARAM = uint32_t;
            using LPARAM = uint32_t;
        };

        template<>
        struct UINT_PTR<false> {
            using WPARAM = uint64_t;
            using LPARAM = uint64_t;
        };

    public:
        enum class SessionEvent {
            created,        /* WPARAM : true, false */
            negotiated,     /* WPARAM : */
        };

        using SessionId = uint32_t;
        using WPARAM = UINT_PTR<sizeof(void*) == 4>::WPARAM*;
        using LPARAM = UINT_PTR<sizeof(void*) == 4>::LPARAM*;
        using SessionEventCallBack = std::function<void(SessionId, SessionEvent, WPARAM, LPARAM)>;

    private:
        struct SessionInfo {
            enum class status {
                init,
                creating,
                failed,
                created,
                negotiating,
            };
            std::mutex  _mutex;
            SessionEventCallBack _callback = nullptr;
            Session*    _sess = nullptr;
            status      _status = status::init;
            SessionId   _id = 0;
        };

        using Sessions = std::unordered_map<SessionId, SessionInfo*>;

    private:
        CAgent() {}
        CAgent(const CAgent&) = delete;
        CAgent& operator=(const CAgent&) = delete;
        virtual ~CAgent() {}

    public:
        static CAgent& Instance() { static CAgent sInstance; return sInstance; }

    public:
        SessionId CreateSession(const std::vector<MediaAttr> &mediaAttrs, SessionEventCallBack callback);
        void ReleaseSession(SessionId id);

        std::string& MakeOffer(SessionId id, std::string& offer);
        bool MakeAnswer(SessionId id, const std::string& remoteOffer);
        void SetSessionRole(SessionId id, bool bControlling);
        bool SendData(SessionId id, const std::string& mediaName, uint16_t compId, const void *pData, uint32_t size);
    private:
        static void CreateSessionThread(CAgent *pThis, SessionId id, const std::vector<MediaAttr> &mediaAttrs);
        static void MakeAnswerThread(CAgent *pThis, SessionId id, std::string remoteOffer);

    private:
        std::mutex  m_SessMutex;
        Sessions    m_Sessions;

    private:
        static std::mutex sIdMutex;
        static SessionId  sId;
    };
}