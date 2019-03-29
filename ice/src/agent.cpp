#include "agent.h"
#include "session.h"
#include "pg_log.h"

namespace ICE {

    CAgent::SessionId CAgent::sId = 1;
    CAgent::SessionId CAgent::CreateSession(const std::vector<MediaAttr> &mediaAttrs, SessionEventCallBack callback)
    {
        assert(callback != nullptr);

        std::auto_ptr<SessionInfo> sessInfo(new SessionInfo);

        if (!sessInfo.get())
        {
            LOG_ERROR("CAgent", "CreateSession Failed to create info");
            return 0;
        }

        std::auto_ptr<Session> session(new Session);
        if (!session.get())
        {
            LOG_ERROR("CAgent", "CreateSession Failed");
            return 0;
        }

        std::lock_guard<decltype(m_SessMutex)> locker(m_SessMutex);
        if (!m_Sessions.insert(std::make_pair(sId, sessInfo.get())).second)
        {
            LOG_ERROR("CAgent", "CraeteSession Failed to insert session");
            return 0;
        }

        sessInfo->_callback = callback;
        sessInfo->_sess = session.release();
        sessInfo->_id = sId;

        sessInfo->_status = SessionInfo::status::creating;
        auto thread = std::thread(&CAgent::CreateSessionThread, this, sessInfo->_id, mediaAttrs);
        thread.detach();

        sessInfo.release();
        return sId++;
    }

    void CAgent::ReleaseSession(SessionId id)
    {
        SessionInfo *sessInfo(nullptr);
        {
            std::lock_guard<decltype(m_SessMutex)> locker(m_SessMutex);
            auto itor = m_Sessions.find(id);
            if (itor == m_Sessions.end())
            {
                LOG_ERROR("Agent", "ReleaseSession, cannot find session [%d]", id);
                return;
            }
            sessInfo = itor->second;
        }

        {
            assert(sessInfo);
            std::lock_guard<decltype(sessInfo->_mutex)> locker(sessInfo->_mutex);
            if (sessInfo->_status == SessionInfo::status::creating ||
                sessInfo->_status == SessionInfo::status::negotiating)
            {
                LOG_WARNING("Agent", "Session is in [%s] status",
                    sessInfo->_status == SessionInfo::status::creating ? "creating" : "negotiating");
                return;
            }

            delete sessInfo->_sess;
        }

        {
            std::lock_guard<decltype(m_SessMutex)> locker(m_SessMutex);
            auto itor = m_Sessions.find(id);
            assert(itor != m_Sessions.end());

            delete itor->second;
            m_Sessions.erase(itor);
        }
    }

    std::string& CAgent::MakeOffer(SessionId id, std::string& offer)
    {
        SessionInfo *sessInfo(nullptr);
        {
            std::lock_guard<decltype(m_SessMutex)> locker(m_SessMutex);
            auto itor = m_Sessions.find(id);
            if (itor == m_Sessions.end())
            {
                LOG_ERROR("Agent", "MakeOffer cannto find session [%d]", id);
                return offer;
            }
            sessInfo = itor->second;
        }

        {
            std::lock_guard<decltype(sessInfo->_mutex)> locker(sessInfo->_mutex);
            if (sessInfo->_status != SessionInfo::status::created)
            {
                LOG_ERROR("Agent", "MakeOffer, session is not ready [%d]", sessInfo->_status);
                return offer;
            }

            offer = sessInfo->_sess->MakeOffer();
            return offer;
        }
    }

    bool CAgent::MakeAnswer(SessionId id, const std::string & remoteOffer)
    {
        SessionInfo *sessInfo(nullptr);
        {
            std::lock_guard<decltype(m_SessMutex)> locker(m_SessMutex);
            auto itor = m_Sessions.find(id);
            if (itor == m_Sessions.end())
            {
                LOG_ERROR("Agent", "MakeAnswer cannto find session [%d]", id);
                return false;
            }
            sessInfo = itor->second;
        }

        {
            std::lock_guard<decltype(sessInfo->_mutex)> locker(sessInfo->_mutex);
            if (sessInfo->_status != SessionInfo::status::created)
            {
                LOG_ERROR("Agent", "MakeAnswer, session is not ready [%d]", sessInfo->_status);
                return false;
            }
            sessInfo->_status = SessionInfo::status::negotiating;
            auto thread = std::thread(CAgent::MakeAnswerThread, this, id, remoteOffer);
            thread.detach();
        }

        return true;
    }

    void CAgent::SetSessionRole(SessionId id, bool bControlling)
    {
        std::lock_guard<decltype(m_SessMutex)> locker(m_SessMutex);
        auto itor = m_Sessions.find(id);
        if (itor == m_Sessions.end())
        {
            LOG_ERROR("Agent", "SetSessionRole cannot find session [%d]", id);
            return;
        }

        assert(itor->second && itor->second->_sess);
        itor->second->_sess->SetControlling(bControlling);
    }

    bool CAgent::SendData(SessionId id, const std::string & mediaName, uint16_t compId, const void *pData, uint32_t size)
    {
        std::lock_guard<decltype(m_SessMutex)> locker(m_SessMutex);
        auto itor = m_Sessions.find(id);
        if (itor == m_Sessions.end())
        {
            LOG_ERROR("Agent", "SendData cannot find session [%d]", id);
            return false;
        }

        assert(itor->second && itor->second->_sess);
        return itor->second->_sess->SendData(mediaName, compId, pData, size);
    }

    void CAgent::CreateSessionThread(CAgent * pThis, SessionId id, const std::vector<MediaAttr> &mediaAttrs)
    {
        assert(pThis && id);

        SessionInfo *sessInfo(nullptr);
        {
            std::lock_guard<decltype(pThis->m_SessMutex)> locker(pThis->m_SessMutex);
            auto itor = pThis->m_Sessions.find(id);
            assert(itor != pThis->m_Sessions.end());
            sessInfo = itor->second;
        }

        assert(sessInfo && sessInfo->_sess);
        std::unique_lock<decltype(sessInfo->_mutex)> locker(sessInfo->_mutex);
        sessInfo->_status = SessionInfo::status::creating;

        bool bCreated = true;
        for (auto itor = mediaAttrs.begin(); itor != mediaAttrs.end(); ++itor)
        {
            if (!sessInfo->_sess->CreateMedia(*itor))
            {
                LOG_ERROR("Agent", "Session [%d ] Create Media [%s] failed", id, itor->m_Name.c_str());
                bCreated = false;
                break;
            }
        }

        assert(sessInfo->_callback);
        sessInfo->_status = bCreated ? SessionInfo::status::created : SessionInfo::status::failed;
        locker.unlock();
        sessInfo->_callback(sessInfo->_id, SessionEvent::created, (WPARAM)(bCreated), nullptr);
    }

    void CAgent::MakeAnswerThread(CAgent * pThis, SessionId id, std::string remoteOffer)
    {
        assert(pThis && id);

        SessionInfo *sessInfo(nullptr);
        {
            std::lock_guard<decltype(pThis->m_SessMutex)> locker(pThis->m_SessMutex);
            auto itor = pThis->m_Sessions.find(id);
            assert(itor != pThis->m_Sessions.end());
            sessInfo = itor->second;
        }

        assert(sessInfo && sessInfo->_sess);
        std::lock_guard<decltype(sessInfo->_mutex)> locker(sessInfo->_mutex);
        auto &answer = sessInfo->_sess->MakeAnswer(remoteOffer);
        sessInfo->_status = SessionInfo::status::created;
        assert(sessInfo->_callback);
        sessInfo->_callback(sessInfo->_id, SessionEvent::negotiated, (WPARAM)(&answer), nullptr);
    }
}