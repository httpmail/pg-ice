#include "pg_log.h"

#include <assert.h>
#include <stdarg.h>
#include <iostream>
#include <boost/filesystem.hpp>
#include "pg_buffer.h"

namespace PG {
    log::log() :
        m_WriteThrd(log::WriterThread, this), m_bQuit(false)
    {
    }

    log::~log()
    {
        std::unique_lock<decltype(m_LogMutex)> locker(m_LogMutex);
        m_LogCond.wait(locker, [this] {
            return this->m_Logs.empty();
        });

        m_bQuit = true;
        m_LogCond.notify_one();

        if (m_FileStream.is_open())
        {
            m_FileStream.close();
            m_FileStream.flush();
        }
    }

    log & log::Instance()
    {
        static log sInstance;
        return sInstance;
    }

    bool log::SetLogFile(const std::string & file_path)
    {
        if (m_FileStream.is_open())
            return true;

        m_FileStream.open(file_path, std::ios::app);
        return m_FileStream.is_open();
    }

    void log::Output(const char *pModule, const char *file_path, int line, const char* levelInfo, const char *pFormat, ...)
    {
        assert(file_path && pFormat && levelInfo);
        try
        {
            thread_local std::shared_ptr<TLSContainer> Buffer(new TLSContainer);

            auto& buffer = Buffer->Lock4Write();

            boost::filesystem::path full_path(file_path, boost::filesystem::native);
            assert(boost::filesystem::is_regular_file(full_path) && boost::filesystem::exists(full_path));

            auto head_len = sprintf_s(buffer.data(), Buffer->DataLength(), "[%s]: %s(%d) : ",levelInfo, full_path.filename().string().c_str(), line);
            assert(head_len < Buffer->DataLength());

            auto remain_buffer_bytes = Buffer->DataLength() - head_len;

            va_list argp;

            va_start(argp, pFormat);
            auto real_bytes = vsnprintf(&buffer[head_len], remain_buffer_bytes, pFormat, argp);
            assert(real_bytes < remain_buffer_bytes);
            Buffer->Unlock(buffer);

            std::lock_guard<decltype(m_LogMutex)> locker(m_LogMutex);
            m_Logs.push_back(Buffer);
            va_end(argp);

            m_LogCond.notify_one();
        }
        catch (const std::exception &)
        {
            return;
        }
    }

    void log::WriterThread(log *pInstance)
    {
        assert(pInstance == &log::Instance());

        while (!pInstance->m_bQuit)
        {
            std::unique_lock<decltype(pInstance->m_LogMutex)> locker(pInstance->m_LogMutex);
            pInstance->m_LogCond.wait(locker, [pInstance] {
                return !pInstance->m_Logs.empty() || pInstance->m_bQuit;
            });

            auto& stream = (pInstance->m_FileStream.is_open() ? pInstance->m_FileStream : std::cout);
            while (!pInstance->m_Logs.empty())
            {
                auto log = *pInstance->m_Logs.begin();
                locker.unlock();

                assert(log->Size());

                auto& content = log->Lock4Read();
                stream << content.data() << std::endl;
                log->Unlock(content);

                locker.lock();
                pInstance->m_Logs.erase(pInstance->m_Logs.begin());
            }
            stream.flush();
        }
    }
}