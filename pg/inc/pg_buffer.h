#pragma once

#include <vector>
#include <array>
#include <condition_variable>
#include <mutex>
#include <atomic>
#include <exception>
#include <assert.h>

namespace PG {
    template<class T, uint16_t TSize, uint16_t TNumber>
    class CircularBuffer {
    public:
        using Elem = std::array<T, TSize>;

    private:
        enum class flag : uint8_t {
            free    = 0,
            writing = 1,
            wrote   = 2,
            reading = 3,
        };

        struct ElemWrapper {
            ElemWrapper() :
                _flag(flag::free)
            {
            }
            Elem _elem;
            flag _flag;
        };
        using Container = std::array<ElemWrapper, TNumber>;

    public:
        CircularBuffer() :
            m_Size(0), m_WriterIndex(0), m_ReaderIndex(0)
        {
        }

        virtual ~CircularBuffer()
        {
        }

        Elem& Lock4Write()
        {
            std::unique_lock<decltype(m_Wait4FreeMutex)> locker(m_Wait4FreeMutex);
            m_Wait4Free.wait(locker, [this]{
                return this->m_Size < TNumber;
            });

            if (this->m_Size == TNumber)
                throw std::out_of_range("CircularBuffer destruct!!");

            auto index = m_WriterIndex;

            assert(m_Buffer[index]._flag == flag::free);

            m_Buffer[index]._flag = flag::writing;
            return m_Buffer[index]._elem;
        }

        Elem& Lock4Read()
        {
            std::unique_lock<decltype(m_Wait4ReadyMutex)> locker(m_Wait4ReadyMutex);
            m_Wait4Ready.wait(locker, [this] {
                return this->m_Size;
            });

            if (m_Size == 0)
                throw std::out_of_range("CircularBuffer destruct!!");

            auto index = m_ReaderIndex;

            assert(m_Buffer[index]._flag == flag::wrote);

            m_Buffer[index]._flag = flag::reading;
            return m_Buffer[index]._elem;
        }

        uint16_t Size() const
        {
            return m_Size;
        }

        uint16_t DataLength() const
        {
            return TSize;
        }

        void Unlock(const Elem& elem, bool bCanceled = false)
        {
            auto wIndex = m_WriterIndex;
            auto rIndex = m_ReaderIndex;

            assert(&elem == &m_Buffer[wIndex]._elem || &elem == &m_Buffer[rIndex]._elem);

            if (&elem == &m_Buffer[wIndex]._elem && m_Buffer[wIndex]._flag == flag::writing)
            {

                if (bCanceled)
                {
                    m_Buffer[wIndex]._flag = flag::free;
                    return;
                }

                m_Buffer[wIndex]._flag = flag::wrote;

                wIndex++;
                if (wIndex == TNumber)
                    wIndex = 0;
                m_WriterIndex = wIndex;
                m_Size++;
                m_Wait4Ready.notify_one();
            }
            else if (&elem == &m_Buffer[rIndex]._elem && m_Buffer[rIndex]._flag == flag::reading)
            {
                if (bCanceled)
                {
                    m_Buffer[rIndex]._flag = flag::wrote;
                    return;
                }

                m_Buffer[rIndex]._flag = flag::free;

                rIndex++;
                if (rIndex == TNumber)
                    rIndex = 0;

                m_ReaderIndex = rIndex;
                m_Size--;
                m_Wait4Free.notify_one();
            }
            else
            {
                assert(0);
            }
        }

    private:
        std::array<ElemWrapper, TNumber> m_Buffer;
        std::mutex m_Wait4FreeMutex;
        std::mutex m_Wait4ReadyMutex;
        std::condition_variable m_Wait4Free;
        std::condition_variable m_Wait4Ready;
        std::uint16_t m_Size;
        std::uint16_t m_WriterIndex;
        std::uint16_t m_ReaderIndex;
    };

    template<class _Elem, uint16_t _Size>
    class FIFOBuffer {
    public:
        FIFOBuffer() :
            m_ReleaseFlag(false),
            m_write(0),
            m_WriterIndex(0),m_ReaderIndex(0),
            m_WriterLocked(false),m_ReaderLocked(false)
        {
            static_assert(_Size, "Size Must > 0");
        }

        ~FIFOBuffer()
        {
            m_ReaderCond.notify_all();
            m_WriterCond.notify_all();
        }

        _Elem* LockWriter()
        {
            std::unique_lock<decltype(m_WriterMutex)> locker(m_WriterMutex);
            if (m_ReleaseFlag)
                return nullptr;

            m_WriterCond.wait(locker, [this] {
                return (!this->m_WriterLocked && this->m_write < _Size) || this->m_ReleaseFlag;
            });

            assert(!m_WriterLocked && this->m_write < _Size);

            if (m_ReleaseFlag)
                return nullptr;

            m_WriterLocked = true;
            return &m_Elems[m_WriterIndex];
        }

        void UnlockWriter(bool bCanceled = false)
        {

            assert(m_WriterLocked);

            std::unique_lock<decltype(m_WriterMutex)> locker(m_WriterMutex);
            m_WriterLocked = false;
            if (bCanceled)
                return;

            m_write++;
            assert(m_write <= _Size);

            m_WriterIndex++;
            if (m_WriterIndex == _Size)
                m_WriterIndex = 0;

            m_ReaderCond.notify_one();
            m_WriterCond.notify_one();
        }

        _Elem* LockReader()
        {
            std::unique_lock<decltype(m_ReaderMutex)> locker(m_ReaderMutex);

            assert(!m_ReaderLocked);
            m_ReaderCond.wait(locker, [this] {
                return (this->m_write && !this->m_ReaderLocked) || this->m_ReleaseFlag;
            });

            if (m_ReleaseFlag)
                return nullptr;

            m_ReaderLocked = true;
            return &m_Elems[m_ReaderIndex];
        }

        void UnlockReader(bool bCanceled)
        {
            std::unique_lock<decltype(m_ReaderMutex)> locker(m_ReaderMutex);
            assert(m_ReaderLocked);

            m_ReaderLocked = false;
            if (bCanceled)
                return;

            m_write--;
            m_ReaderIndex++;
            if (m_ReaderIndex == _Size)
                m_ReaderIndex = 0;

            m_WriterCond.notify_all();
        }

        void ReleaseLocker()
        {
            m_ReleaseFlag = true;
            m_ReaderCond.notify_all();
            m_WriterCond.notify_all();
        }

    private:
        _Elem    m_Elems[_Size];
        std::atomic_bool     m_ReleaseFlag;
        std::atomic_uint16_t m_write;

        bool     m_WriterLocked;
        uint16_t m_WriterIndex;
        std::mutex        m_WriterMutex;
        std::condition_variable m_WriterCond;

        bool m_ReaderLocked;
        uint16_t m_ReaderIndex;
        std::mutex m_ReaderMutex;
        std::condition_variable m_ReaderCond;
    };
}
