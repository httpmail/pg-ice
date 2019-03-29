#pragma once

#include <map>
#include <set>
#include <queue>
#include <mutex>
#include <thread>
#include <atomic>
#include "streamdef.h"
#include "candidate.h"

namespace ICE {

    class CAgentConfig;
    class Stream;
    class Session;

    class Media{
    public:
        enum class ClassicID : uint16_t {
            RTP = 1,
            RTCP,
        };

        using StreamContainer = std::map<uint32_t, Stream*>;  /* high 16 bits = comp_id, low 16 bits = protocol */
        using VailidStreams   = std::map<uint16_t, Stream*>;  /* uint16_t comp_id */

    public:
        virtual bool CreateStream(uint16_t compId, Protocol protocol, const std::string& hostIP, uint16_t hostPort,
            std::function<void(const void*, uint32_t)> cb);

    public:
        Media(Session &session);
        virtual ~Media();

        const StreamContainer& GetStreams()    const { return m_Streams; }
        const VailidStreams& GetValidStreams() const { return m_ValidStreams; }

        const std::string& IcePwd() const { return m_icepwd; }
        const std::string& IceUfrag() const { return m_iceufrag; }

        const std::string& RIcePwd() const   { return m_RIcepwd; }
        void SetRIcePwd(const std::string& pwd) { m_RIcepwd = pwd; }

        const std::string& RIceUfrag() const { return m_RIcefrag; }
        void SetRIceUfrag(const std::string& ufrag) { m_RIcefrag = ufrag; }

        const std::string& GetDefaultIP(uint16_t id) const;
        uint16_t GetDefaultPort(uint16_t id) const;

        void ConnectivityCheck(const std::map<Stream*, CandPeerContainer*> &checkList, std::function<void(Media*, bool)> callback);

    public:
        virtual bool SendData(uint16_t compId, const void *pData, uint32_t size);

    protected:
        virtual bool IsConnectivityCheckCompleted(Stream* stream, bool bResult);
        virtual void OnDataReceived(const void *pData, uint32_t size, std::function<void(const void*, uint32_t)> cb);

    protected:
        void SaveDefaultInfo(uint16_t compId, const std::string &ip, uint16_t port);
        void Shutdown();

    private:
        static void ConnectivityCheckThread(Media *pThis, const std::map<Stream*, CandPeerContainer*> &checkList, std::function<void(Media*, bool)> callback);

    protected:
        enum class ConnStatus : uint8_t{
            init,
            ongoing,
            failed,
            done
        };

    protected:
        Session                 &m_Session;
        std::mutex              m_ConnMutex;
        StreamContainer         m_Streams;
        VailidStreams           m_ValidStreams;
        ConnStatus              m_ConnStatus;

        std::thread             m_ConnCheckThrd;
        const std::string       m_icepwd;
        const std::string       m_iceufrag;

        std::string             m_RIcepwd;
        std::string             m_RIcefrag;

    private:
        struct DefaultInfo {
            std::string m_ip;
            uint16_t    m_port;
            Protocol    m_protocol;
        };

        using DefaultMap = std::map<uint16_t, DefaultInfo>;

        DefaultMap m_DefaultMap;
    };

    class MultiplexStream : public Media {
    public:
        MultiplexStream(Session &session) : Media(session), m_bQuit(false)
        {
        }

        virtual ~MultiplexStream();

    public:
        virtual bool CreateStream(uint16_t compId, Protocol protocol, const std::string& hostIP, uint16_t hostPort,
            std::function<void(const void*, uint32_t)> cb) override;
        virtual bool SendData(uint16_t compId, const void *pData, uint32_t size) override;

    protected:
        virtual void OnDataReceived(const void *pData, uint32_t size, std::function<void(const void*, uint32_t)> cb) override;
        virtual bool IsConnectivityCheckCompleted(Stream* stream, bool bResult) override;

    private:
        struct Packet{
            const void *data;
            uint32_t size;
        };

        struct MultiplexHelper{
            std::mutex                                 _mutex;
            std::thread                                _thread;
            std::condition_variable                    _cond;
            std::function<void(const void*, uint32_t)> _cb;
            std::queue<Packet>                         _packets;
        };

    private:
        static void HandleData(MultiplexStream &This, MultiplexHelper &helper);

    private:
        std::map<uint16_t, MultiplexHelper*> m_Multiplex;
        std::atomic_bool                     m_bQuit;
    };
}