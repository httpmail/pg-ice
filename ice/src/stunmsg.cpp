#include "stunmsg.h"
#include "channel.h"

#include <openssl/hmac.h>
#include <boost/crc.hpp>

#pragma comment(lib, "libcrypto")
#pragma comment(lib, "libssl")

namespace {
    uint16_t CalcPaddingSize(uint16_t length, int16_t N = 4)
    {
        assert((!(N &(N - 1))) && N); // n MUST be 2^n
        return (length + N - 1) & (~(N - 1));
    }

    STUN::SHA1Ref CalcHmacSha1(const std::string& key, const uint8_t* block, int16_t block_size, STUN::SHA1Ref sha1)
    {
        unsigned int size;
        HMAC(EVP_sha1(), key.data(), static_cast<int>(key.length()), block, block_size, sha1, &size);
        return sha1;
    }
}

namespace STUN {
    uint8_t * MessagePacket::AllocAttribute(ATTR::Id id, uint16_t size)
    {
        if (m_AttrLength + size > sizeof(m_StunPacket.Attributes()))
            return nullptr;

        assert(m_Attributes.find(id) == m_Attributes.end());
        m_Attributes[id] = m_AttrLength;
        auto pBuf = &m_StunPacket.Attributes()[m_AttrLength];
        m_AttrLength += size;
        return pBuf;
    }

    uint16_t MessagePacket::CalcAttrEncodeSize(uint16_t contentSize, uint16_t& paddingSize, uint16_t header_size /*= 4*/) const
    {
        paddingSize = CalcPaddingSize(contentSize);
        return paddingSize + contentSize + header_size;
    }

    void MessagePacket::AddTextAttribute(ATTR::Id id, const void* data, uint16_t size)
    {
        uint16_t padding_size = 0;
        auto total_size = CalcAttrEncodeSize(size, padding_size);
        auto pBuf =  AllocAttribute(id, total_size);
        if (!pBuf)
        {
            LOG_ERROR("STUN-MSG", "Not Enough Memory for TextAttribute [%d]", id);
            return ;
        }

        reinterpret_cast<uint16_t*>(pBuf)[0] = PG::host_to_network(static_cast<uint16_t>(id));
        reinterpret_cast<uint16_t*>(pBuf)[1] = PG::host_to_network(size);
        pBuf += 4;

        memcpy(pBuf, data, size);
        if (padding_size)
        {
            memset(pBuf + size, 0, padding_size);
        }
    }

    void MessagePacket::AddAttribute(const ATTR::Priority &attr)
    {
        if (HasAttribute(attr.Type()))
        {
            LOG_WARNING("STUN-MSG", "Priority attribute already existed");
            return;
        }

        static_assert(sizeof(ATTR::Priority) == 8, "Priority Must be 8 bytes");

        auto pBuf = AllocAttribute(attr.Type(), sizeof(attr));

        assert(pBuf);

        reinterpret_cast<uint64_t*>(pBuf)[0] = reinterpret_cast<const uint64_t*>(&attr)[0];
    }

    void MessagePacket::AddAttribute(const ATTR::UseCandidate & attr)
    {
        if (HasAttribute(attr.Type()))
        {
            LOG_WARNING("STUN-MSG", "UseCandidate attribute already existed");
            return;
        }

        // UseCandidate has no content
        static_assert(sizeof(ATTR::UseCandidate) == sizeof(ATTR::Header), "UseCandidate has no content");

        auto pBuf = AllocAttribute(attr.Type(), sizeof(ATTR::UseCandidate));
        assert(pBuf);
        m_Attributes[attr.Type()] = m_AttrLength;
        reinterpret_cast<uint32_t*>(pBuf)[0] = reinterpret_cast<const uint32_t*>(&attr)[0];
    }

    MessagePacket::MessagePacket(const PACKET::stun_packet & packet, uint16_t packet_size) :
        m_StunPacket(packet)
    {
        assert(IsValidStunPacket(packet, packet_size));

        m_AttrLength = packet.Length();
        try
        {
            auto attr         = packet.Attributes();
            auto content_len  = packet.Length();
            uint16_t attr_len = 0;

            for(decltype(content_len) i = 0 ; i < content_len;  i += attr_len + sizeof(ATTR::Header))
            {
                ATTR::Id id = static_cast<ATTR::Id>(PG::network_to_host(reinterpret_cast<const uint16_t*>(&attr[i])[0]));
                attr_len    = CalcPaddingSize(PG::network_to_host(reinterpret_cast<const uint16_t*>(&attr[i])[1]));
                switch (id)
                {
                case STUN::ATTR::Id::MappedAddress:
                case STUN::ATTR::Id::RespAddress:
                case STUN::ATTR::Id::ChangeRequest:
                case STUN::ATTR::Id::SourceAddress:
                case STUN::ATTR::Id::ChangedAddress:
                case STUN::ATTR::Id::Username:
                case STUN::ATTR::Id::Password:
                case STUN::ATTR::Id::MessageIntegrity:
                case STUN::ATTR::Id::ErrorCode:
                case STUN::ATTR::Id::UnknownAttributes:
                case STUN::ATTR::Id::ReflectedFrom:
                case STUN::ATTR::Id::Realm:
                case STUN::ATTR::Id::Nonce:
                case STUN::ATTR::Id::XorMappedAddress:
                case STUN::ATTR::Id::Software:
                case STUN::ATTR::Id::AlternateServer:
                case STUN::ATTR::Id::Priority:
                case STUN::ATTR::Id::UseCandidate:
                case STUN::ATTR::Id::Fingerprint:
                case STUN::ATTR::Id::IceControlled:
                case STUN::ATTR::Id::IceControlling:
                    m_Attributes[id] = i;
                    break;

                default:
                    m_UnkonwnAttrs.insert(id);
                    LOG_WARNING("STUN-MSG", "Unsupported attribute [0x%X]", id);
                    break;
                }
            }
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("STUN-MSG", "Decode StunPacket exception :%s", e.what());
        }
    }

    void MessagePacket::AddAttribute(const ATTR::MappedAddress &attr)
    {
        if (HasAttribute(attr.Type()))
        {
            LOG_WARNING("STUN-MSG", "MappedAddress[%d] attribute already existed!", attr.Type());
            return;
        }

        static_assert(sizeof(ATTR::MappedAddress) == 12, "MappedAddress MUST be 12 bytes");

        auto pBuf = AllocAttribute(attr.Type(), sizeof(ATTR::MappedAddress));
        if (!pBuf)
        {
            LOG_ERROR("STUN-MSG", "Not enough memory for Attribute [%d]", attr.Type());
            return;
        }

        const uint8_t* source = reinterpret_cast<const uint8_t*>(&attr);

        reinterpret_cast<uint64_t*>(pBuf)[0]     = reinterpret_cast<const uint64_t*>(source)[0];
        reinterpret_cast<uint32_t*>(&pBuf[4])[0] = reinterpret_cast<const uint32_t*>(&source[4])[0];
    }

    void MessagePacket::AddAttribute(const ATTR::ChangeRequest & attr)
    {
        static_assert(sizeof(ATTR::ChangeRequest) == 8, "sizeof(ChangeRequest) Must Be 8 bytes");

        if (HasAttribute(attr.Type()))
        {
            LOG_WARNING("STUN-MSG", "ChangeRequest already existed");
            return;
        }

        auto pBuf = AllocAttribute(attr.Type(), sizeof(ATTR::ChangeRequest));
        if (!pBuf)
        {
            LOG_ERROR("STUN-MSG", "Not Enough Memory for ChangeRequest");
            return;
        }

        reinterpret_cast<uint64_t*>(pBuf)[0] = reinterpret_cast<const uint64_t*>(&attr)[0];
    }

    void MessagePacket::AddAttribute(const ATTR::XorMappedAddress &attr)
    {
        static_assert(sizeof(ATTR::XorMappedAddress) == 12, "XorMappedAddress Must Be 12 Bytes");

        if (HasAttribute(attr.Type()))
        {
            LOG_WARNING("STUN-MSG", "XorMappedAddress attributes already existed!");
            return;
        }

        auto pBuf = AllocAttribute(attr.Type(), sizeof(ATTR::XorMappedAddress));

        if (!pBuf)
        {
            LOG_ERROR("STUN-MSG", "Not enough memory for XorMappedAddress");
            return;
        }

        const uint8_t* source = reinterpret_cast<const uint8_t*>(&attr);
        reinterpret_cast<uint64_t*>(pBuf)[0] = reinterpret_cast<const uint64_t*>(source)[0];
        reinterpret_cast<uint32_t*>(&pBuf[4])[0] = reinterpret_cast<const uint32_t*>(&source[4])[0];
    }

    void MessagePacket::AddAttribute(const ATTR::Role &attr)
    {
        if (HasAttribute(attr.Type()))
        {
            LOG_WARNING("STUN-MSG", "Role attribute already existed!");
            return;
        }

        static_assert(sizeof(ATTR::Role) == 12, "Role Attribute Must Be 12 Bytes");

        auto pBuf = AllocAttribute(attr.Type(), sizeof(ATTR::Role));
        if (!pBuf)
        {
            LOG_ERROR("STUN-MSG", "Not enough memory for Role");
            return;
        }

        const uint8_t* source = reinterpret_cast<const uint8_t*>(&attr);
        reinterpret_cast<uint64_t*>(pBuf)[0] = reinterpret_cast<const uint64_t*>(source)[0];
        reinterpret_cast<uint32_t*>(&pBuf[4])[0] = reinterpret_cast<const uint32_t*>(&source[4])[0];
    }

    void MessagePacket::AddSoftware(const std::string& desc)
    {
        assert(desc.length() < ATTR::sTextLimite);
        AddTextAttribute(ATTR::Id::Software, desc.data(), static_cast<uint16_t>(desc.length()));
    }

    void MessagePacket::AddRealm(const std::string& realm)
    {
        assert(realm.length() < ATTR::sTextLimite);

        //AddTextAttribute(ATTR::Id::Realm, realm.data(), realm.length());
    }

    void MessagePacket::AddErrorCode(uint16_t clsCode, uint16_t number, const std::string& reason)
    {
        assert(reason.length() < ATTR::sTextLimite);
        uint16_t reason_length = static_cast<uint16_t>(reason.length());
        auto size = CalcPaddingSize(reason_length);
        uint16_t padding_size = size - reason_length;

        // ErrorCode attribute size = HEADER + 4 bytes + reason
        auto pBuf = AllocAttribute(ATTR::Id::ErrorCode, size + sizeof(ATTR::Header) + 4);
        if (!pBuf)
        {
            LOG_ERROR("STUN-MSG", "Not Enough memory for ErrorCode");
            return;
        }

        reinterpret_cast<uint16_t*>(pBuf)[0] = PG::host_to_network(static_cast<uint16_t>(ATTR::Id::ErrorCode));
        // error code length = reason length + 4 bytes
        reinterpret_cast<uint16_t*>(pBuf)[0] = PG::host_to_network(static_cast<uint16_t>(reason_length + 4));

        ATTR::ErrorCode *pErrorCode = reinterpret_cast<ATTR::ErrorCode*>(pBuf);
        pErrorCode->Class(clsCode);
        pErrorCode->Number(number);
        pErrorCode->Reason(reason);
        if(padding_size)
            memset(pBuf + 4 + reason_length, 0, padding_size);
    }

    void MessagePacket::AddNonce(const std::string& nonce)
    {
        assert(nonce.length() < ATTR::sTextLimite);

        //AddTextAttribute(ATTR::Id::Nonce, nonce.data(), nonce.length());
    }

    void MessagePacket::AddPassword(const std::string& password)
    {
        assert(password.length() < ATTR::sTextLimite);

        AddTextAttribute(ATTR::Id::Password, password.data(), static_cast<uint16_t>(password.length()));
    }

    void MessagePacket::AddUsername(const std::string& username)
    {
        assert(username.length() < ATTR::sUsernameLimite);

        AddTextAttribute(ATTR::Id::Username, username.data(), static_cast<uint16_t>(username.length()));
    }

    void MessagePacket::AddUnknownAttributes(const UnkonwnAttrContainer& unknownattributes)
    {
        if (HasAttribute(ATTR::Id::UnknownAttributes))
        {
            LOG_WARNING("STUN-MSG", "unknownAttribute already existed!");
            return;
        }

        uint16_t content_size = static_cast<uint16_t>(unknownattributes.size()) * sizeof(ATTR::Id);
        auto size = CalcPaddingSize(content_size);

        auto pBuf = AllocAttribute(STUN::ATTR::Id::UnknownAttributes, size + content_size + 4);
        if (!pBuf)
        {
            LOG_ERROR("STUN-MSG", "Not Enough for unknownattribute");
            return;
        }

        reinterpret_cast<uint16_t*>(pBuf)[0] = PG::host_to_network(static_cast<uint16_t>(ATTR::Id::UnknownAttributes));
        reinterpret_cast<uint16_t*>(pBuf)[1] = PG::host_to_network(content_size);

        pBuf += 4;
        uint16_t *pAttrBuf = reinterpret_cast<uint16_t*>(pBuf);
        for (auto itor = unknownattributes.begin(); itor != unknownattributes.end(); ++itor)
        {
            *(pAttrBuf++) = PG::host_to_network(static_cast<uint16_t>(*itor));
        }
    }

    void MessagePacket::GenerateRFC5389TransationId(TransIdRef id)
    {
        static_assert(sizeof(id) == sTransationLength, "the length of Transation Id is ");

        reinterpret_cast<uint32_t*>(id)[0] = PG::host_to_network(sMagicCookie);
        reinterpret_cast<uint32_t*>(&id[4])[0] = PG::host_to_network(PG::GenerateRandom32());
        reinterpret_cast<uint64_t*>(&id[8])[0] = PG::host_to_network(PG::GenerateRandom64());
    }

    void MessagePacket::GenerateRFC3489TransationId(TransIdRef id)
    {
        static_assert(sizeof(id) == sTransationLength, "the length of Transation Id is ");
        reinterpret_cast<uint64_t*>(&id)[0] = PG::host_to_network(PG::GenerateRandom64());
        reinterpret_cast<uint64_t*>(&id)[1] = PG::host_to_network(PG::GenerateRandom64());
    }

    bool MessagePacket::SendData(ICE::Channel & channel)
    {
        Finalize();
        return channel.Write(&m_StunPacket, m_AttrLength + sStunHeaderLength) > 0;
    }

    const ATTR::MappedAddress* MessagePacket::GetAttribute(const ATTR::MappedAddress *& mapAddr) const
    {
        auto itor = m_Attributes.find(ATTR::Id::MappedAddress);
        mapAddr = (itor == m_Attributes.end()) ?
            nullptr : reinterpret_cast<const ATTR::MappedAddress*>(&m_StunPacket.Attributes()[itor->second]);

        return mapAddr;
    }

    const ATTR::ChangeRequest* MessagePacket::GetAttribute(const ATTR::ChangeRequest *& changeReq) const
    {
        auto itor = m_Attributes.find(ATTR::Id::ChangeRequest);
        changeReq = (itor == m_Attributes.end()) ?
            nullptr : reinterpret_cast<const ATTR::ChangeRequest*>(&m_StunPacket.Attributes()[itor->second]);

        return changeReq;
    }

    const ATTR::XorMappedAddress* MessagePacket::GetAttribute(const ATTR::XorMappedAddress *& xorMap) const
    {
        auto itor = m_Attributes.find(ATTR::Id::XorMappedAddress);
        xorMap = (itor == m_Attributes.end()) ?
            nullptr : reinterpret_cast<const ATTR::XorMappedAddress*>(&m_StunPacket.Attributes()[itor->second]);

        return xorMap;
    }

    const ATTR::Role* MessagePacket::GetAttribute(const ATTR::Role *& role) const
    {
        auto itor = m_Attributes.find(ATTR::Id::IceControlled);
        if (itor == m_Attributes.end())
            itor = m_Attributes.find(ATTR::Id::IceControlling);

        role = (itor == m_Attributes.end()) ?
            nullptr : reinterpret_cast<const ATTR::Role*>(&m_StunPacket.Attributes()[itor->second]);

        return role;
    }

    const ATTR::Priority* MessagePacket::GetAttribute(const ATTR::Priority *& pri) const
    {
        auto itor = m_Attributes.find(ATTR::Id::Priority);
        pri = (itor == m_Attributes.end()) ?
            nullptr : reinterpret_cast<const ATTR::Priority*>(&m_StunPacket.Attributes()[itor->second]);

        return pri;
    }

    const ATTR::UseCandidate* MessagePacket::GetAttribute(const ATTR::UseCandidate *& useCan) const
    {
        auto itor = m_Attributes.find(ATTR::Id::UseCandidate);
        useCan = (itor == m_Attributes.end()) ?
            nullptr : reinterpret_cast<const ATTR::UseCandidate*>(&m_StunPacket.Attributes()[itor->second]);

        return useCan;
    }

    const ATTR::Software* MessagePacket::GetAttribute(const ATTR::Software *& software) const
    {
        auto itor = m_Attributes.find(ATTR::Id::Software);
        software = (itor == m_Attributes.end()) ?
            nullptr : reinterpret_cast<const ATTR::Software*>(&m_StunPacket.Attributes()[itor->second]);

        return software;
    }

    const ATTR::Realm* MessagePacket::GetAttribute(const ATTR::Realm *& realm) const
    {
        auto itor = m_Attributes.find(ATTR::Id::Realm);
        realm = (itor == m_Attributes.end()) ?
            nullptr : reinterpret_cast<const ATTR::Realm*>(&m_StunPacket.Attributes()[itor->second]);

        return realm;
    }

    const ATTR::Nonce* MessagePacket::GetAttribute(const ATTR::Nonce *& nonce) const
    {
        auto itor = m_Attributes.find(ATTR::Id::Nonce);
        nonce = (itor == m_Attributes.end()) ?
            nullptr : reinterpret_cast<const ATTR::Nonce*>(&m_StunPacket.Attributes()[itor->second]);

        return nonce;
    }

    const ATTR::Password* MessagePacket::GetAttribute(const ATTR::Password *& pwd) const
    {
        auto itor = m_Attributes.find(ATTR::Id::Password);
        pwd = (itor == m_Attributes.end()) ?
            nullptr : reinterpret_cast<const ATTR::Password*>(&m_StunPacket.Attributes()[itor->second]);

        return pwd;
    }

    const ATTR::UserName* MessagePacket::GetAttribute(const ATTR::UserName *& username) const
    {
        auto itor = m_Attributes.find(ATTR::Id::Username);
        username = (itor == m_Attributes.end()) ?
            nullptr : reinterpret_cast<const ATTR::UserName*>(&m_StunPacket.Attributes()[itor->second]);

        return username;
    }

    const ATTR::MessageIntegrity * MessagePacket::GetAttribute(const ATTR::MessageIntegrity *& msgIntegrity) const
    {
        auto itor = m_Attributes.find(ATTR::Id::MessageIntegrity);
        msgIntegrity = (itor == m_Attributes.end()) ?
            nullptr : reinterpret_cast<const ATTR::MessageIntegrity*>(&m_StunPacket.Attributes()[itor->second]);

        return msgIntegrity;
    }

    const ATTR::Fingerprint * MessagePacket::GetAttribute(const ATTR::Fingerprint *& figerprint) const
    {
        auto itor = m_Attributes.find(ATTR::Id::Fingerprint);
        figerprint = (itor == m_Attributes.end()) ?
            nullptr : reinterpret_cast<const ATTR::Fingerprint*>(&m_StunPacket.Attributes()[itor->second]);

        return figerprint;
    }

    const ATTR::UnknownAttributes* MessagePacket::GetAttribute(const ATTR::UnknownAttributes *& unknowAttrs) const
    {
        auto itor = m_Attributes.find(ATTR::Id::UnknownAttributes);
        unknowAttrs = (itor == m_Attributes.end()) ?
            nullptr : reinterpret_cast<const ATTR::UnknownAttributes*>(&m_StunPacket.Attributes()[itor->second]);

        return unknowAttrs;
    }

    const ATTR::ErrorCode * MessagePacket::GetAttribute(const ATTR::ErrorCode *& errCode) const
    {
        auto itor = m_Attributes.find(ATTR::Id::ErrorCode);
        errCode = (itor == m_Attributes.end()) ?
            nullptr : reinterpret_cast<const ATTR::ErrorCode*>(&m_StunPacket.Attributes()[itor->second]);
        return errCode;
    }

    void MessagePacket::ComputeSHA1(const MessagePacket & packet, const std::string & key,SHA1Ref sha1)
    {
    }

    bool MessagePacket::VerifyMsgIntegrity(const MessagePacket & packet, const std::string & key)
    {
        const ATTR::MessageIntegrity *pMsgIntegrity = nullptr;

        if (!packet.GetAttribute(pMsgIntegrity))
            return false;
        /*
         RFC8445 [15.4]
         Based on the rules above, the hash used to construct MESSAGE-
         INTEGRITY includes the length field from the STUN message header.
         Prior to performing the hash, the MESSAGE-INTEGRITY attribute MUST be
         inserted into the message (with dummy content).  The length MUST then
         be set to point to the length of the message up to, and including,
         the MESSAGE-INTEGRITY attribute itself, but excluding any attributes
         after it.  Once the computation is performed, the value of the
         MESSAGE-INTEGRITY attribute can be filled in, and the value of the
         length in the STUN header can be set to its correct value -- the
         length of the entire message.  Similarly, when validating the
         MESSAGE-INTEGRITY, the length field should be adjusted to point to
         the end of the MESSAGE-INTEGRITY attribute prior to calculating the
         HMAC.  Such adjustment is necessary when attributes, such as
         FINGERPRINT, appear after MESSAGE-INTEGRITY
         */

        STUN::PACKET::stun_packet *rawPacket = (STUN::PACKET::stun_packet*)(const_cast<uint8_t*>(packet.GetData()));
        auto body_len = rawPacket->Length();
        auto sha1_text_len = body_len;
        const ATTR::Fingerprint *pFingerprint = nullptr;
        if (packet.GetAttribute(pFingerprint))
        {
            sha1_text_len -= pFingerprint->ContentLength() + sizeof(ATTR::Header);
            rawPacket->Length(sha1_text_len);
        }
        SHA1 sha1;
        CalcHmacSha1(key.data(), (const uint8_t*)rawPacket, sha1_text_len,sha1);
        rawPacket->Length(body_len);
        return 0 == memcmp(sha1, pMsgIntegrity->SHA1(), sizeof(sha1));
    }

    bool MessagePacket::IsValidStunPacket(const PACKET::stun_packet& packet, uint16_t packet_size)
    {
        if (packet_size < sStunHeaderLength)
            return false;

        const uint8_t* rawData = reinterpret_cast<const uint8_t*>(&packet);

        if (rawData[0] != 0x00 && rawData[0] != 0x01)
            return false;

        auto content_length = packet.Length();

        // content length always padding to 4 bytes
        if ( 0 != (content_length & 0x03) || (content_length + sStunHeaderLength != packet_size))
            return false;

        // packet has magicCookie
        if (reinterpret_cast<const uint32_t*>(packet.TransId())[0] == PG::host_to_network(sMagicCookie))
        {
        }
        return true;
    }

    ////////////////////////////// FirstBindReqMsg //////////////////////////////
    FirstBindReqMsg::FirstBindReqMsg(const PACKET::stun_packet & packet, uint16_t packet_size) :
        MessagePacket(packet, packet_size)
    {
        assert(packet.MsgId() == MsgType::BindingRequest);
    }

    ////////////////////////////// FirstBindRespMsg //////////////////////////////
    FirstBindRespMsg::FirstBindRespMsg(const PACKET::stun_packet & packet, uint16_t packet_size) :
        MessagePacket(packet, packet_size)
    {
        assert(packet.MsgId() == MsgType::BindingResp);
    }

    ////////////////////////////// FirstBindErrRespMsg //////////////////////////////
    FirstBindErrRespMsg::FirstBindErrRespMsg(const PACKET::stun_packet & packet, uint16_t packet_size) :
        MessagePacket(packet, packet_size)
    {
        assert(packet.MsgId() == MsgType::BindingErrResp);
    }

    ////////////////////////////// SubBindReqMsg //////////////////////////////
    SubBindReqMsg::SubBindReqMsg(uint32_t pri, const TransId & transId, bool bControlling, uint64_t tieBreaker):
        MessagePacket(STUN::MsgType::BindingRequest, transId)
    {
        AddAttribute(ATTR::Role(bControlling, tieBreaker));
        AddAttribute(ATTR::Priority(pri));
    }

    SubBindReqMsg::SubBindReqMsg(const PACKET::stun_packet & packet, uint16_t packet_size):
        MessagePacket(packet,packet_size)
    {
        assert(packet.MsgId() == MsgType::BindingRequest);
    }

    SubBindResqMsg::SubBindResqMsg(const TransId & transId, const ATTR::XorMappedAddress& xormapAddr) :
        MessagePacket(STUN::MsgType::BindingResp, transId)
    {
        AddAttribute(xormapAddr);
    }

    SubBindResqMsg::SubBindResqMsg(const PACKET::stun_packet & packet, uint16_t packet_size):
        MessagePacket(packet, packet_size)
    {
        assert(packet.MsgId() == MsgType::BindingResp);
    }

    SubBindErrRespMsg::SubBindErrRespMsg(TransIdConstRef id, uint8_t classCode, uint8_t number, const std::string & reason) :
        MessagePacket(STUN::MsgType::BindingErrResp, id)
    {
        AddErrorCode(classCode, number, reason);
    }

    SubBindErrRespMsg::SubBindErrRespMsg(TransIdConstRef id, const UnkonwnAttrContainer unknownAttr) :
        MessagePacket(STUN::MsgType::BindingErrResp, id)
    {
        AddUnknownAttributes(unknownAttr);
    }

    SubBindErrRespMsg::SubBindErrRespMsg(const PACKET::stun_packet & packet, uint16_t packet_size) :
        MessagePacket(packet, packet_size)
    {
        AddErrorCode(4, 87, "unknown-attributes");
        assert(packet.MsgId() == MsgType::BindingErrResp);
    }

}
