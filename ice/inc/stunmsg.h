#pragma once

#include "pg_log.h"
#include "stundef.h"

#include <type_traits>
#include <unordered_map>
#include <set>

#include <assert.h>


namespace ICE {
    class Channel;
}

namespace STUN {
    class MessagePacket {

        MessagePacket(const MessagePacket&) = delete;
        MessagePacket& operator=(const MessagePacket&) = delete;

    public:
        using UnkonwnAttrContainer = std::set<ATTR::Id>;

    public:
        MessagePacket(MsgType msgId, TransIdConstRef transId):
            m_StunPacket(msgId, transId), m_AttrLength(0)
        {
        }

        MessagePacket(const PACKET::stun_packet& packet, uint16_t packet_size);

        ~MessagePacket()
        {
        }

        bool IsTransIdEqual(TransIdConstRef transId) const
        {
            return 0 == memcmp(transId, m_StunPacket.TransId(), sizeof(transId));
        }

        bool IsTransIdEqual(const MessagePacket& other) const
        {
            return 0 == memcmp(other.m_StunPacket.TransId(), m_StunPacket.TransId(), sizeof(m_StunPacket.TransId()));
        }

        TransIdConstRef TransationId() const
        {
            return m_StunPacket.TransId();
        }

        const uint8_t* GetData() const
        {
            return reinterpret_cast<const uint8_t*>(&m_StunPacket);
        }

        uint16_t GetLength() const
        {
            return m_AttrLength + sStunHeaderLength;
        }

        bool HasAttribute(ATTR::Id id) const
        {
            return m_Attributes.find(id) != m_Attributes.end();
        }
        bool HasUnknownAttributes() const
        {
            return m_UnsupportedAttrs.size() > 0;
        }

        virtual void Finalize() = 0 {}
        bool SendData(ICE::Channel& channel);

        const ATTR::MappedAddress*    GetAttribute(const ATTR::MappedAddress*& mapAddr) const;
        const ATTR::ChangeRequest*    GetAttribute(const ATTR::ChangeRequest*& changeReq) const;
        const ATTR::XorMappedAddress* GetAttribute(const ATTR::XorMappedAddress*& xorMap) const;
        const ATTR::Role*             GetAttribute(const ATTR::Role*& role) const;
        const ATTR::Priority*         GetAttribute(const ATTR::Priority*& pri) const;
        const ATTR::UseCandidate*     GetAttribute(const ATTR::UseCandidate*& useCan) const;
        const ATTR::Software*         GetAttribute(const ATTR::Software*& software) const;
        const ATTR::Realm*            GetAttribute(const ATTR::Realm*& realm) const;
        const ATTR::Nonce*            GetAttribute(const ATTR::Nonce*& nonce) const;
        const ATTR::Password*         GetAttribute(const ATTR::Password*& pwd) const;
        const ATTR::UserName*         GetAttribute(const ATTR::UserName*& username) const;
        const ATTR::MessageIntegrity* GetAttribute(const ATTR::MessageIntegrity*& msgIntegrity) const;
        const ATTR::Fingerprint*      GetAttribute(const ATTR::Fingerprint*& figerprint) const;
        const ATTR::UnknownAttributes* GetAttribute(const ATTR::UnknownAttributes*& unknowAttrs) const;
        const ATTR::ErrorCode*        GetAttribute(const ATTR::ErrorCode*& errCode) const;

        const UnkonwnAttrContainer& GetUnkonwnAttrs() const { return m_UnkonwnAttrs; }

        void AddAttribute(const ATTR::MappedAddress &attr);
        void AddAttribute(const ATTR::ChangeRequest &attr);
        void AddAttribute(const ATTR::XorMappedAddress &attr);
        void AddAttribute(const ATTR::Role &attr);
        void AddAttribute(const ATTR::Priority &attr);
        void AddPriority(uint32_t pri)
        {
            AddAttribute(ATTR::Priority(pri));
        }

        void AddAttribute(const ATTR::UseCandidate &attr);
        void AddSoftware(const std::string& desc);
        void AddRealm(const std::string& realm);
        void AddErrorCode(uint16_t clsCode, uint16_t number, const std::string& reason);
        void AddNonce(const std::string& nonce);
        void AddPassword(const std::string& password);
        void AddUsername(const std::string& username);
        void AddUnknownAttributes(const UnkonwnAttrContainer& unknownattributes);

        static void GenerateRFC5389TransationId(TransIdRef id);
        static void GenerateRFC3489TransationId(TransIdRef id);
        static void ComputeSHA1(const MessagePacket &packet, const std::string& key, SHA1Ref sha1);
        static bool VerifyMsgIntegrity(const MessagePacket &packet, const std::string& key);
        static bool IsValidStunPacket(const PACKET::stun_packet& packet, uint16_t packet_size);

    protected:
        using Attributes = std::unordered_map<ATTR::Id, int16_t>; /*key = attribute id,  value = index in StunPacket::m_Attrs */

    protected:
        uint16_t CalcAttrEncodeSize(uint16_t contentSize, uint16_t& paddingSize, uint16_t header_size = 4) const;
        uint8_t* AllocAttribute(ATTR::Id id, uint16_t size);
        void     AddTextAttribute(ATTR::Id id, const void* data, uint16_t size);

    protected:
        uint16_t                m_AttrLength;
        PACKET::stun_packet     m_StunPacket;
        Attributes              m_Attributes;
        UnkonwnAttrContainer    m_UnkonwnAttrs;
        Attributes              m_UnsupportedAttrs;
    };

    ////////////////////////////// first message //////////////////////////////
    class FirstBindReqMsg : public MessagePacket {
    public:
        FirstBindReqMsg(const TransId& transId) : MessagePacket(MsgType::BindingRequest, transId) {}
        FirstBindReqMsg(const PACKET::stun_packet& packet, uint16_t packet_size);
        virtual void Finalize() {}
    };

    class FirstBindRespMsg : public MessagePacket {
    public:
        FirstBindRespMsg(const TransId& transId) : MessagePacket(MsgType::BindingResp, transId) {}
        FirstBindRespMsg(const PACKET::stun_packet& packet, uint16_t packet_size);
        virtual void Finalize() {}
    };

    class FirstBindErrRespMsg : public MessagePacket {
    public:
        FirstBindErrRespMsg(const TransId& transId) : MessagePacket(MsgType::BindingErrResp, transId) {}
        FirstBindErrRespMsg(const PACKET::stun_packet& packet, uint16_t packet_size);
        virtual void Finalize() {}
    };

    ////////////////////////////// subsequent message //////////////////////////////
    class SubBindReqMsg : public MessagePacket  {
    public:
        SubBindReqMsg(uint32_t pri, const TransId& transId, bool bControlling, uint64_t tieBreaker);
        SubBindReqMsg(const PACKET::stun_packet& packet, uint16_t packet_size);
        virtual void Finalize() {}
    };

    class SubBindResqMsg : public MessagePacket {
    public:
        SubBindResqMsg(const TransId& transId, const ATTR::XorMappedAddress& xormapAddr);
        SubBindResqMsg(const PACKET::stun_packet& packet, uint16_t packet_size);
        virtual void Finalize() {}
    };

    class SubBindErrRespMsg : public MessagePacket {
    public:
        SubBindErrRespMsg(TransIdConstRef id, uint8_t classCode, uint8_t number, const std::string& reason);
        SubBindErrRespMsg(TransIdConstRef id, const UnkonwnAttrContainer unknownAttr);
        SubBindErrRespMsg(const PACKET::stun_packet& packet, uint16_t packet_size);
        virtual void Finalize() {}
    };
}