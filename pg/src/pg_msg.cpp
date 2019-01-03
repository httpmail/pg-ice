#include "pg_msg.h"
#include "pg_log.h"
#include "pg_listener.h"

#include <assert.h>
#include <memory>
#include <functional>
#include <algorithm>
#include "pg_buffer.h"

PG::CircularBuffer<char, 12, 12> b;

namespace PG {

    MsgEntity::MsgEntityContainer MsgEntity::m_msg_entities;

    MsgEntity::MsgEntity():
        m_quit(false)
    {
        assert(m_msg_entities.find(this) == m_msg_entities.end());
        m_msg_entities.insert(this);
        m_thread = std::thread(MsgDispitcherThread, this);
    }

    MsgEntity::~MsgEntity()
    {
        Close();
        std::lock_guard<decltype(m_listeners_mutex)> locker(m_listeners_mutex);
        for (auto itor = m_listeners.begin(); itor != m_listeners.end(); ++itor)
        {
            if (itor->second != nullptr)
            {
                assert(0 == itor->second->size());
                delete itor->second;
            }
        }
    }

    void MsgEntity::Close()
    {
        if (!m_quit)
        {
            m_quit = true;
            m_queue_condition.notify_one();
        }

        if (m_thread.joinable())
            m_thread.join();
    }

    bool MsgEntity::SendMessage(MSG_ID msgId, WPARAM wParam, LPARAM lParam)
    {
        OnMsgReceived(msgId, wParam, lParam);
        return true;
    }

    bool MsgEntity::PostMessage(MSG_ID msgId, WPARAM wParam, LPARAM lParam)
    {
        std::lock_guard<decltype(m_queue_mutex)> locker(m_queue_mutex);
        CMsgWrapper msg(msgId, wParam, lParam);
        m_msg_queue.push_back(msg);
        m_queue_condition.notify_one();
        return true;
    }

    bool MsgEntity::RegisterEventListener(MSG_ID msgId, CListener * listener)
    {
        return RegisterListener(msgId, listener);
    }

    bool MsgEntity::UnregisterEventListenner(MSG_ID msgId, CListener * listener)
    {
        return UnregisterListener(msgId, listener);
    }

    bool MsgEntity::RegisterListener(MSG_ID msgId, CListener * listener)
    {
        std::lock_guard<decltype(m_listeners_mutex)> locker(m_listeners_mutex);
        auto itor = m_listeners.find(msgId);
        if (itor == m_listeners.end())
        {
            LOG_ERROR("MSG", "RegisterListener : nonexistence Message[id :%d]", msgId);
            return false;
        }
        else
        {
            auto listener_container = itor->second;
            assert(listener_container);
            listener_container->insert(listener);
            return true;
        }
    }

    bool MsgEntity::UnregisterListener(MSG_ID msgId, CListener * listener)
    {
        std::lock_guard<decltype(m_listeners_mutex)> locker(m_listeners_mutex);
        auto itor = m_listeners.find(msgId);
        if (itor == m_listeners.end())
        {
            LOG_ERROR("MSG", "UnregisterListener : nonexistence Message[id :%d]", msgId);
            return false;
        }
        else
        {
            auto listener_container = itor->second;
            assert(listener_container);
            listener_container->erase(listener);
            return true;
        }
    }

    bool MsgEntity::RegisterEvent(MSG_ID msgId)
    {
        std::lock_guard<decltype(m_listeners_mutex)> locker(m_listeners_mutex);
        auto itor = m_listeners.find(msgId);
        if (itor != m_listeners.end())
            return true;
        try
        {
            std::auto_ptr<ListenerContainer> listenerContainer(new ListenerContainer);
            if (listenerContainer.get())
            {
                m_listeners[msgId] = listenerContainer.release();
                return true;
            }
            return false;
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("MSG", "RegisterEvent exception :%s", e.what());
            return false;
        }
    }

    void MsgEntity::NotifyListener(MSG_ID msgId, WPARAM wParam, LPARAM lParam)
    {
        std::lock_guard<decltype(m_listeners_mutex)> locker(m_listeners_mutex);
        auto itor = m_listeners.find(msgId);
        if (itor != m_listeners.end())
        {
            std::for_each(itor->second->begin(), itor->second->end(), [this, msgId, wParam, lParam](auto &listener) {
                listener->OnEventFired(this, msgId, wParam, lParam);
            });
        }
    }

    void MsgEntity::MsgDispitcherThread(MsgEntity * pOwn)
    {
        assert(pOwn);

        while (pOwn->m_quit)
        {
            std::unique_lock<decltype(pOwn->m_queue_mutex)> locker(pOwn->m_queue_mutex);
            pOwn->m_queue_condition.wait(locker, [&pOwn] {
                return !pOwn->m_msg_queue.empty() || pOwn->m_quit;
            });

            if (pOwn->m_quit)
                break;

            MsgQueue tempQueue(pOwn->m_msg_queue);
            pOwn->m_msg_entities.clear();
            locker.unlock();

            for (auto msg : tempQueue)
            {
                pOwn->OnMsgReceived(msg.MsgId(), msg.WParam(), msg.LParam());
                if (pOwn->m_quit)
                    return;
            }
        }
    }

    //////////////////////////// Publisher ////////////////////////////////////
    Publisher::~Publisher()
    {
        while (!m_Msg.empty())
        {
            auto itor = m_Msg.begin();
            assert(itor->second->empty());
            delete itor->second;
            m_Msg.erase(itor);
        }
    }

    bool Publisher::Subscribe(Subscriber * subscriber, MsgEntity::MSG_ID msgId)
    {
        assert(subscriber);

        std::lock_guard<decltype(m_Mutex)> locker(m_Mutex);

        auto itor = m_Msg.find(msgId);
        if (itor == m_Msg.end())
        {
            LOG_ERROR("Publisher", "Subscribe Msg [%d] unregistered", msgId);
            return false;
        }

        assert(itor->second);
        return itor->second->insert(subscriber).second;
    }

    bool Publisher::Unsubscribe(Subscriber * subscriber, MsgEntity::MSG_ID msgId)
    {
        assert(subscriber);

        std::lock_guard<decltype(m_Mutex)> locker(m_Mutex);
        auto itor = m_Msg.find(msgId);
        if (itor == m_Msg.end())
        {
            LOG_ERROR("Publisher", "Unsubscribe Msg [%d] unregistered", msgId);
            return false;
        }

        assert(itor->second);
        itor->second->erase(subscriber);

        return true;
    }

    bool Publisher::Unsubscribe(Subscriber * subscriber)
    {
        assert(subscriber);

        std::lock_guard<decltype(m_Mutex)> locker(m_Mutex);
        std::for_each(m_Msg.begin(), m_Msg.end(), [subscriber](auto& itor){
            itor.second->erase(subscriber);
        });
        return true;
    }

    bool Publisher::RegisterMsg(MsgEntity::MSG_ID msgId)
    {
        std::lock_guard<decltype(m_Mutex)> locker(m_Mutex);
        if (m_Msg.end() != m_Msg.find(msgId))
        {
            LOG_WARNING("Publisher", "msg :[%d] has been registered", msgId);
            return true;
        }

        std::auto_ptr<SubscribersContainer> container(new SubscribersContainer);
        if (container.get() && m_Msg.insert(std::make_pair(msgId, container.get())).second)
        {
            container.release();
            return true;
        }
        return false;
    }

    void Publisher::Publish(MsgEntity::MSG_ID msgId, MsgEntity::WPARAM wParam, MsgEntity::LPARAM lParam)
    {
        std::lock_guard<decltype(m_Mutex)> locker(m_Mutex);
        auto msg = m_Msg.find(msgId);

        if (msg == m_Msg.end())
        {
            LOG_WARNING("Publisher", "Publish msg [%d] Unregistered", msgId);
            return;
        }

        assert(msg->second);

        std::for_each(msg->second->begin(), msg->second->end(), [this, msgId, wParam, lParam](auto& itor) {
            itor->OnPublished(this, msgId, wParam, lParam);
        });
    }
}
