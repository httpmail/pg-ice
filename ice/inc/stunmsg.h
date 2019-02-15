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
        MessagePacket() {}

        MessagePacket(MsgType msgId, TransIdConstRef transId) :
            m_StunPacket(msgId, transId), m_AttrLength(0)
        {
        }

        MessagePacket(const PACKET::stun_packet& packet, uint16_t packet_size);

        virtual ~MessagePacket() = 0 {}

        bool IsTransIdEqual(TransIdConstRef transId) const
        {
            return 0 == memcmp(transId, m_StunPacket.TransId(), sizeof(transId));
        }

        bool IsTransIdEqual(const MessagePacket& other) const
        {
            return 0 == memcmp(other.m_StunPacket.TransId(), m_StunPacket.TransId(), sizeof(m_StunPacket.TransId()));
        }

        bool IsTransIdEqual(const PACKET::stun_packet& other) const
        {
            return 0 == memcmp(other.TransId(), m_StunPacket.TransId(), sizeof(m_StunPacket.TransId()));
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

        virtual void Finalize() = 0;

        int32_t SendData(ICE::Channel& channel);
        int32_t SendData(ICE::Channel& channel, const std::string& dest, uint16_t port);

        const ATTR::MappedAddress*    GetAttribute(const ATTR::MappedAddress*& mapAddr) const;
        const ATTR::XorMappAddress*    GetAttribute(const ATTR::XorMappAddress *& mapAddr) const;
        const ATTR::ChangeRequest*    GetAttribute(const ATTR::ChangeRequest*& changeReq) const;
        const ATTR::XorMappedAddrSvr* GetAttribute(const ATTR::XorMappedAddrSvr*& xorMap) const;
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

        void AddAttribute(const ATTR::AddressIPv4 &attr);
        void AddAttribute(const ATTR::XorMappedIPv4 &attr);
        void AddAttribute(const ATTR::ChangeRequest &attr);
        void AddAttribute(const ATTR::Role &attr);
        void AddAttribute(const ATTR::Priority &attr);
        void AddAttribute(const ATTR::UseCandidate &attr);

        void AddPriority(uint32_t pri)
        {
            AddAttribute(ATTR::Priority(pri));
        }

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

        /*
         * @ATTR::Id
         * @uint16_t size - attribute total size include header
         */
        uint8_t* AllocAttribute(ATTR::Id id, uint16_t size);
        void     AddTextAttribute(ATTR::Id id, const void* data, uint16_t size);

    protected:
        static void Finalize(MessagePacket &packet, const std::string& pwd);

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
        virtual void Finalize() override;
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
        SubBindReqMsg(uint32_t pri, const TransId& transId, bool bControlling, uint64_t tieBreaker, const std::string& username, const std::string& pwd);
        SubBindReqMsg(const PACKET::stun_packet& packet, uint16_t packet_size);
        virtual ~SubBindReqMsg();
        virtual void Finalize() override;

    private:
        std::string m_IcePwd;
    };

    class SubBindRespMsg : public MessagePacket {
    public:
        SubBindRespMsg(const TransId& transId, const ATTR::XorMappAddress& xormapAddr, const std::string& pwd);
        SubBindRespMsg(const PACKET::stun_packet& packet, uint16_t packet_size);
        virtual void Finalize() override;

    private:
        std::string m_pwd;
    };

    class SubBindErrRespMsg : public MessagePacket {
    public:
        SubBindErrRespMsg(TransIdConstRef id, uint8_t classCode, uint8_t number, const std::string& reason);
        SubBindErrRespMsg(TransIdConstRef id, const UnkonwnAttrContainer unknownAttr);
        SubBindErrRespMsg(const PACKET::stun_packet& packet, uint16_t packet_size);
        virtual void Finalize() override;
    };

    class IndicationMsg : public MessagePacket {
    public:
        IndicationMsg(TransIdConstRef id) :
            MessagePacket(MsgType::BindingIndicate,id)
        {
        }

        virtual void Finalize() override;
    };
}