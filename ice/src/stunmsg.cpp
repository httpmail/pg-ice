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

    static const uint16_t sRFC3489_MULTIPLE_BYTES = 64;
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
        m_StunPacket.Length(m_AttrLength);
        return pBuf;
    }

    uint16_t MessagePacket::CalcAttrEncodeSize(uint16_t contentSize, uint16_t& paddingSize, uint16_t header_size /*= 4*/) const
    {
        auto size_after_padding = CalcPaddingSize(contentSize);
        paddingSize = size_after_padding - contentSize;
        return size_after_padding;
    }

    void MessagePacket::AddTextAttribute(ATTR::Id id, const void* data, uint16_t size)
    {
        uint16_t padding_size = 0;
        auto total_size = CalcAttrEncodeSize(size + sizeof(ATTR::Header), padding_size);
        auto pBuf = AllocAttribute(id, total_size);
        if (!pBuf)
        {
            LOG_ERROR("STUN-MSG", "Not Enough Memory for TextAttribute [%d]", id);
            return;
        }

        reinterpret_cast<uint16_t*>(pBuf)[0] = PG::host_to_network(static_cast<uint16_t>(id));
        reinterpret_cast<uint16_t*>(pBuf)[1] = PG::host_to_network<uint16_t>(size + padding_size);
        pBuf += 4;

        memcpy(pBuf, data, size);
        if (padding_size)
        {
            memset(pBuf + size, 0, padding_size);
        }
    }

    void MessagePacket::Finalize(MessagePacket & packet, const std::string & pwd)
    {
        auto& attributes = packet.m_Attributes;

        assert(attributes.find(ATTR::Id::MessageIntegrity) == attributes.end());

        /*
        https://tools.ietf.org/html/draft-ietf-behave-rfc3489bis-02#section-10.2.8
        1.calculate stun packet length, it should include 'msg-integrity' and 'fingerprint' length
        2.calculate sha1 text length, exclude 'msg-integrity' and 'fingerprint' length and multip with 64 bytes.
        */

        auto size_before_auth = packet.GetLength();
        auto pMsgInegrityBuf = packet.AllocAttribute(STUN::ATTR::Id::MessageIntegrity, sizeof(ATTR::MessageIntegrity));
        auto pFingerprintBuf = packet.AllocAttribute(STUN::ATTR::Id::Fingerprint, sizeof(ATTR::Fingerprint));

        if (!pMsgInegrityBuf || !pFingerprintBuf)
        {
            LOG_ERROR("MessagePacket", "Finalize cannot allocate attribute MessageIntegrity [%p], Fingerprint [%p]",
                pMsgInegrityBuf, pFingerprintBuf);
            return;
        }

        // Add MessageIntegrity
        SHA1 sha1;
        auto sha1_length = CalcPaddingSize(size_before_auth, sRFC3489_MULTIPLE_BYTES);
        memset(&(reinterpret_cast<uint8_t*>(&packet.m_StunPacket)[size_before_auth]), 0, sha1_length - size_before_auth);
        CalcHmacSha1(pwd, reinterpret_cast<const uint8_t*>(&packet.m_StunPacket), sha1_length, sha1);
        auto pMsgIntegrity = reinterpret_cast<ATTR::MessageIntegrity*>(pMsgInegrityBuf);
        reinterpret_cast<uint16_t*>(pMsgIntegrity)[0] = PG::host_to_network(static_cast<uint16_t>(ATTR::Id::MessageIntegrity));
        reinterpret_cast<uint16_t*>(pMsgIntegrity)[1] = PG::host_to_network(static_cast<uint16_t>(STUN::sSHA1Size));
        pMsgIntegrity->SHA1(sha1);

        // Add Fingerprint
        reinterpret_cast<uint16_t*>(pFingerprintBuf)[0] = PG::host_to_network(static_cast<uint16_t>(ATTR::Id::Fingerprint));
        reinterpret_cast<uint16_t*>(pFingerprintBuf)[1] = PG::host_to_network(static_cast<uint16_t>(sizeof(ATTR::Fingerprint) - sizeof(ATTR::Header)));
        auto pFigerprint = reinterpret_cast<ATTR::Fingerprint*>(pFingerprintBuf);

        boost::crc_32_type crc32_result;
        crc32_result.process_bytes(&packet.m_StunPacket, packet.GetLength() - sizeof(ATTR::Fingerprint));
        uint32_t crc32 = crc32_result.checksum() ^ sStunXorFingerprint;

        pFigerprint->CRC32(crc32);
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
            auto attr = packet.Attributes();
            auto content_len = packet.Length();
            uint16_t attr_len = 0;

            for (decltype(content_len) i = 0; i < content_len; i += attr_len + sizeof(ATTR::Header))
            {
                ATTR::Id id = static_cast<ATTR::Id>(PG::network_to_host(reinterpret_cast<const uint16_t*>(&attr[i])[0]));
                attr_len = CalcPaddingSize(PG::network_to_host(reinterpret_cast<const uint16_t*>(&attr[i])[1]));

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
                case STUN::ATTR::Id::XorMapped:
                case STUN::ATTR::Id::XorMappedSvr:
                case STUN::ATTR::Id::Software:
                case STUN::ATTR::Id::AlternateServer:
                case STUN::ATTR::Id::Priority:
                case STUN::ATTR::Id::UseCandidate:
                case STUN::ATTR::Id::Fingerprint:
                case STUN::ATTR::Id::IceControlled:
                case STUN::ATTR::Id::IceControlling:
                case STUN::ATTR::Id::MsCandInd:
                case STUN::ATTR::Id::MsIce2:
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

    void MessagePacket::AddAttribute(const ATTR::AddressIPv4 & attr)
    {
        if (HasAttribute(attr.Type()))
        {
            LOG_WARNING("STUN-MSG", "Address [%d] attribute already existed!", attr.Type());
            return;
        }

        static_assert(sizeof(ATTR::AddressIPv4) == 12, "address attribute MUST be 12 bytes");

        auto pBuf = AllocAttribute(attr.Type(), sizeof(ATTR::AddressIPv4));
        if (!pBuf)
        {
            LOG_ERROR("STUN-MSG", "Not enough memory for Attribute [%d]", attr.Type());
            return;
        }

        const uint8_t* source = reinterpret_cast<const uint8_t*>(&attr);
        reinterpret_cast<uint64_t*>(pBuf)[0] = reinterpret_cast<const uint64_t*>(source)[0];
        reinterpret_cast<uint32_t*>(&pBuf[8])[0] = reinterpret_cast<const uint32_t*>(&source[8])[0];
    }

    void MessagePacket::AddAttribute(const ATTR::XorMappedIPv4 & attr)
    {
        if (HasAttribute(attr.Type()))
        {
            LOG_WARNING("STUN-MSG", "XorMappedIPv4 [%d] attribute already existed!", attr.Type());
            return;
        }

        static_assert(sizeof(ATTR::AddressIPv4) == 12, "XorMappedIPv4 attribute MUST be 12 bytes");

        auto pBuf = AllocAttribute(attr.Type(), sizeof(ATTR::AddressIPv4));
        if (!pBuf)
        {
            LOG_ERROR("STUN-MSG", "Not enough memory for Attribute [%d]", attr.Type());
            return;
        }

        const uint8_t* source = reinterpret_cast<const uint8_t*>(&attr);
        reinterpret_cast<uint64_t*>(pBuf)[0] = reinterpret_cast<const uint64_t*>(source)[0];
        reinterpret_cast<uint32_t*>(&pBuf[8])[0] = reinterpret_cast<const uint32_t*>(&source[8])[0];
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
        pBuf += 8;
        source += 8;
        reinterpret_cast<uint32_t*>(pBuf)[0] = reinterpret_cast<const uint32_t*>(source)[0];
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
        reinterpret_cast<uint16_t*>(pBuf)[1] = PG::host_to_network(static_cast<uint16_t>(reason_length + 4));

        ATTR::ErrorCode *pErrorCode = reinterpret_cast<ATTR::ErrorCode*>(pBuf);
        pErrorCode->Class(clsCode);
        pErrorCode->Number(number);
        pErrorCode->Reason(reason);
        if (padding_size)
            memset(pBuf + 8 + reason_length, 0, padding_size);
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

    int32_t MessagePacket::SendData(ICE::Channel & channel)
    {
        Finalize();
        return channel.Send(&m_StunPacket, m_AttrLength + sStunHeaderLength);
    }

    int32_t MessagePacket::SendData(ICE::Channel & channel, const std::string & dest, uint16_t port)
    {
        Finalize();
        return channel.Send(&m_StunPacket, m_AttrLength + sStunHeaderLength, dest, port);
    }

    const ATTR::MappedAddress* MessagePacket::GetAttribute(const ATTR::MappedAddress *& mapAddr) const
    {
        auto itor = m_Attributes.find(ATTR::Id::MappedAddress);
        mapAddr = (itor == m_Attributes.end()) ?
            nullptr : reinterpret_cast<const ATTR::MappedAddress*>(&m_StunPacket.Attributes()[itor->second]);

        return mapAddr;
    }

    const ATTR::XorMappAddress* MessagePacket::GetAttribute(const ATTR::XorMappAddress *& mapAddr) const
    {
        auto itor = m_Attributes.find(ATTR::Id::XorMapped);
        mapAddr = (itor == m_Attributes.end()) ?
            nullptr : reinterpret_cast<const ATTR::XorMappAddress*>(&m_StunPacket.Attributes()[itor->second]);

        return mapAddr;
    }

    const ATTR::ChangeRequest* MessagePacket::GetAttribute(const ATTR::ChangeRequest *& changeReq) const
    {
        auto itor = m_Attributes.find(ATTR::Id::ChangeRequest);
        changeReq = (itor == m_Attributes.end()) ?
            nullptr : reinterpret_cast<const ATTR::ChangeRequest*>(&m_StunPacket.Attributes()[itor->second]);

        return changeReq;
    }

    const ATTR::XorMappedAddrSvr* MessagePacket::GetAttribute(const ATTR::XorMappedAddrSvr *& xorMap) const
    {
        auto itor = m_Attributes.find(ATTR::Id::XorMappedSvr);
        xorMap = (itor == m_Attributes.end()) ?
            nullptr : reinterpret_cast<const ATTR::XorMappedAddrSvr*>(&m_StunPacket.Attributes()[itor->second]);

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

    const ATTR::ChangedAddress * MessagePacket::GetAttribute(const ATTR::ChangedAddress *& changedAddr) const
    {

        auto itor = m_Attributes.find(ATTR::Id::ChangedAddress);
        changedAddr = (itor == m_Attributes.end()) ?
            nullptr : reinterpret_cast<const ATTR::ChangedAddress*>(&m_StunPacket.Attributes()[itor->second]);
        return changedAddr;
    }

    void MessagePacket::ComputeSHA1(const MessagePacket & packet, const std::string & key, SHA1Ref sha1)
    {
    }

    bool MessagePacket::VerifyMsgIntegrity(const MessagePacket & packet, const std::string & key)
    {
        const ATTR::MessageIntegrity *pMsgIntegrity = nullptr;

        if (!packet.GetAttribute(pMsgIntegrity))
            return false;
        /*
        https://datatracker.ietf.org/doc/rfc5389/?include_text=1
        15.4
        */
        ;
        STUN::PACKET::stun_packet temp;
        auto sha1_text_length = packet.GetLength() - sizeof(ATTR::MessageIntegrity);
        if (packet.HasAttribute(ATTR::Id::Fingerprint))
        {
            sha1_text_length -= sizeof(ATTR::Fingerprint);
        }
        sha1_text_length = CalcPaddingSize(sha1_text_length, sRFC3489_MULTIPLE_BYTES);
        memset(&temp, 0, sha1_text_length);
        memcpy(&temp, &packet.m_StunPacket, packet.GetLength() - sizeof(ATTR::MessageIntegrity) - sizeof(ATTR::Fingerprint));

        SHA1 sha1;
        CalcHmacSha1(key, reinterpret_cast<const uint8_t*>(&temp), sha1_text_length, sha1);
        return 0 == memcmp(sha1, pMsgIntegrity->SHA1(), STUN::sSHA1Size);
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
        if (0 != (content_length & 0x03) || (content_length + sStunHeaderLength != packet_size))
            return false;

        // packet has magicCookie
        if (reinterpret_cast<const uint32_t*>(packet.TransId())[0] == PG::host_to_network(sMagicCookie))
        {
            const ATTR::Fingerprint *pFingerprint = reinterpret_cast<const ATTR::Fingerprint *>(&rawData[content_length + STUN::sStunHeaderLength - sizeof(ATTR::Fingerprint)]);
            if (pFingerprint->Type() == ATTR::Id::Fingerprint)
            {
                if (pFingerprint->ContentLength() != 4)
                    return false;
                boost::crc_32_type crc32_result;
                crc32_result.process_bytes(&packet, packet.Length() - sizeof(ATTR::Fingerprint) + STUN::sStunHeaderLength);
                uint32_t crc32 = crc32_result.checksum() ^ sStunXorFingerprint;
                if (crc32 == pFingerprint->CRC32())
                    return true;
                return false;
            }
        }
        return true;
    }

    ////////////////////////////// FirstBindReqMsg //////////////////////////////
    FirstBindReqMsg::FirstBindReqMsg(const PACKET::stun_packet & packet, uint16_t packet_size) :
        MessagePacket(packet, packet_size)
    {
        assert(packet.MsgId() == MsgType::BindingRequest);
    }

    void FirstBindReqMsg::Finalize()
    {
        m_StunPacket.Length(m_AttrLength);
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
    SubBindReqMsg::SubBindReqMsg(uint32_t pri, const TransId & transId, bool bControlling, uint64_t tieBreaker, const std::string& username, const std::string& pwd) :
        MessagePacket(STUN::MsgType::BindingRequest, transId), m_IcePwd(pwd)
    {
        AddAttribute(ATTR::Role(bControlling, tieBreaker));
        AddAttribute(ATTR::Priority(pri));
        AddUsername(username);
    }

    SubBindReqMsg::SubBindReqMsg(const PACKET::stun_packet & packet, uint16_t packet_size) :
        MessagePacket(packet, packet_size)
    {
        assert(packet.MsgId() == MsgType::BindingRequest);
    }

    SubBindReqMsg::~SubBindReqMsg()
    {
    }

    void SubBindReqMsg::Finalize()
    {
        MessagePacket::Finalize(*this, m_IcePwd);
    }


    SubBindRespMsg::SubBindRespMsg(const TransId & transId, const ATTR::XorMappAddress& xormapAddr, const std::string& pwd) :
        MessagePacket(STUN::MsgType::BindingResp, transId), m_pwd(pwd)
    {
        AddAttribute(xormapAddr);
    }

    SubBindRespMsg::SubBindRespMsg(const PACKET::stun_packet & packet, uint16_t packet_size) :
        MessagePacket(packet, packet_size)
    {
        assert(packet.MsgId() == MsgType::BindingResp);
    }

    void SubBindRespMsg::Finalize()
    {
        MessagePacket::Finalize(*this, m_pwd);
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
        assert(packet.MsgId() == MsgType::BindingErrResp);
    }

    void SubBindErrRespMsg::Finalize()
    {
        // add fingerprint to packet
        auto pBuf = AllocAttribute(STUN::ATTR::Id::Fingerprint, sizeof(ATTR::Fingerprint));
        assert(pBuf);
        reinterpret_cast<uint16_t*>(pBuf)[0] = PG::host_to_network(static_cast<uint16_t>(ATTR::Id::Fingerprint));
        reinterpret_cast<uint16_t*>(pBuf)[1] = PG::host_to_network(static_cast<uint16_t>(sizeof(ATTR::Fingerprint) - sizeof(ATTR::Header)));

        auto pFigerprint = reinterpret_cast<ATTR::Fingerprint*>(pBuf);
        boost::crc_32_type crc32_result;
        crc32_result.process_bytes(&m_StunPacket, m_StunPacket.Length() - sizeof(ATTR::Fingerprint));
        uint32_t crc32 = crc32_result.checksum() ^ sStunXorFingerprint;
        pFigerprint->CRC32(crc32);
    }

    void IndicationMsg::Finalize()
    {
        // add fingerprint to packet
        auto pBuf = AllocAttribute(STUN::ATTR::Id::Fingerprint, sizeof(ATTR::Fingerprint));
        assert(pBuf);
        reinterpret_cast<uint16_t*>(pBuf)[0] = PG::host_to_network(static_cast<uint16_t>(ATTR::Id::Fingerprint));
        reinterpret_cast<uint16_t*>(pBuf)[1] = PG::host_to_network(static_cast<uint16_t>(sizeof(ATTR::Fingerprint) - sizeof(ATTR::Header)));

        auto pFigerprint = reinterpret_cast<ATTR::Fingerprint*>(pBuf);
        boost::crc_32_type crc32_result;
        crc32_result.process_bytes(&m_StunPacket, m_StunPacket.Length() - sizeof(ATTR::Fingerprint));
        uint32_t crc32 = crc32_result.checksum() ^ sStunXorFingerprint;
        pFigerprint->CRC32(crc32);
    }
}
