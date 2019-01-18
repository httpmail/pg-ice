#pragma once

#include <stdint.h>
#include <boost/asio.hpp>

#include "pg_util.h"

#pragma warning (disable:4200)
#pragma pack(4)

namespace STUN {
    static const char* sSoftWareInfo = "Software 1.0.0";
    static const uint32_t sIcePWDLength = 22;  /*RFC5245 15.4*/
    static const uint32_t sIceUfragLength = 4; /*RFC5245 15.4*/
    static const uint32_t sSHA1Size = 20;
    static const uint32_t sMagicCookie = 0x2112A442;
    static const uint32_t sStunXorFingerprint = 0x5354554e;
    static const uint16_t sIPv4PathMTU = 548;
    static const uint16_t sIPv6PathMTU = 1280;
    static const uint16_t sTransationLength = 16;
    static const uint16_t sStunHeaderLength = 20;
    static const uint16_t sStunAttrHeaderLength = 4;
    static const uint16_t sStunPacketLength = sIPv4PathMTU; /* NOTICE just set stun packet length as the MTU of ipv4*/

    using TransId = uint8_t[sTransationLength];
    using TransIdRef = uint8_t(&)[sTransationLength];
    using TransIdConstRef = const uint8_t(&)[sTransationLength];

    using AttrContent           = uint8_t[sStunPacketLength];
    using AttrContentRef        = uint8_t(&)[sStunPacketLength];
    using AttrContentConstRef   = const uint8_t(&)[sStunPacketLength];

    using SHA1 = uint8_t[sSHA1Size];
    using SHA1Ref = uint8_t(&)[sSHA1Size];
    using SHA1ConstRef = const uint8_t(&)[sSHA1Size];

    enum class AgentRole : uint8_t {
        Controlling = 0,
        Controlled = 1
    };

    enum class ErrorCode : uint16_t {
        BadRequest = 404,
        Unauthorized = 401,
        UnknownAttribute = 420,
        StaleCredentials = 430,
        IntegrityCheckFailure = 431,
        MissingUsername = 432,
        UseTLS = 433,
        ServerError = 500,
        GlobalFailure = 600,
    };

    enum class MsgType : uint16_t {
        InvalidMsg      = 0x0000,
        BindingRequest  = 0x0001,
        BindingResp     = 0x0101,
        BindingErrResp  = 0x0111,
        SSRequest       = 0x0002,
        SSResponse      = 0x0102,
        SSErrResp       = 0x1102,
    };

    enum class AddressFamily : uint8_t {
        IPv4 = 0x01,
        IPv6 = 0x02,
    };

    enum class MTU {
        IPv4 = 548,
        IPv6 = 1280
    };

    namespace ATTR {

        static const uint16_t sUsernameLimite = 517;
        static const uint16_t sTextLimite = 127;

        /*RFC5245 15.4.*/
        enum class  UFRAGLimit : uint16_t /* in character */ {
            Upper = 256,
            Lower = 4,
        };

        enum class PasswordLimit : uint16_t /* in character */ {
            Upper = 256,
            Lower = 22,
        };

        enum class Id {
            MappedAddress = 0x0001,
            RespAddress = 0x0002,
            ChangeRequest = 0x0003,
            SourceAddress = 0x0004,
            ChangedAddress = 0x0005,
            Username = 0x0006,
            Password = 0x0007,

            MessageIntegrity = 0x0008,
            ErrorCode = 0x0009,

            UnknownAttributes = 0x000A,
            ReflectedFrom = 0x000B,

            Realm = 0x0014,
            Nonce = 0x0015,

            XorMappedAddress = 0x0020,

            XorMappedAdd = 0x8020, /* stun server used 8020 instead of 0x0020 which defined in RFC5389 */
            Software = 0x8022,
            AlternateServer = 0x8023,
            Priority = 0x0024, /* RFC8445 16.1 */
            UseCandidate = 0x0025, /* RFC8445 16.1 */
            Fingerprint = 0x8028,
            IceControlled = 0x8029, /* RFC8445 16.1 */
            IceControlling = 0x802A, /* RFC8445 16.1 */
        };

        ////////////////////// attribute ////////////////////////////////
        /*
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |         Type                  |            Length             |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                             Value                             ....
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        */
        class Header {
        public:
            explicit Header(Id type, uint16_t length) :
                m_type(PG::host_to_network(static_cast<uint16_t>(type))), m_length(PG::host_to_network(length))
            {
            }

            uint16_t ContentLength() const
            {
                return PG::network_to_host(m_length);
            }

            void ContentLength(uint16_t length)
            {
                m_length = PG::network_to_host(m_length);
            }

            Id Type() const
            {
                return static_cast<Id>(PG::network_to_host(m_type));
            }

        protected:
            uint16_t m_type;
            uint16_t m_length;
        };

        /*
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |0 0 0 0 0 0 0 0|    Family     |           Port                |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                                                               |
        |                 Address (32 bits or 128 bits)                 |
        |                                                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        */
        class MappedAddress : public Header {
        public:
            MappedAddress(Id id = Id::MappedAddress) :
                Header(id, 8)
            {}

            uint16_t Port() const
            {
                return PG::network_to_host<uint16_t>(m_Port);
            }

            void Port(uint16_t port)
            {
                m_Port = PG::host_to_network<uint16_t>(port);
            }

            uint32_t Address() const
            {
                return PG::network_to_host(m_Address);
            }

            std::string IP() const
            {
                boost::asio::ip::address_v4 address(Address());
                return address.to_string();
            }

            void Address(uint32_t address)
            {
                m_Address = PG::host_to_network(m_Address);
            }

            AddressFamily Family() const
            {
                return  static_cast<AddressFamily>(m_Family);
            }

        private:
            unsigned : 8;
            unsigned m_Family : 8;
            unsigned m_Port :   16;
            unsigned m_Address : 32;
        };

        class ResponseAddress : public MappedAddress {
        public:
            ResponseAddress() :
                MappedAddress(Id::RespAddress)
            {}
        };

        /*
            The CHANGE-REQUEST attribute is used by the client to request that
            the server use a different address and/or port when sending the
            response.  The attribute is 32 bits long, although only two bits (A
            and B) are used:

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 A B 0|
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            The meaning of the flags is:

            A: This is the "change IP" flag.  If true, it requests the server
            to send the Binding Response with a different IP address than the
            one the Binding Request was received on.

            B: This is the "change port" flag.  If true, it requests the
            server to send the Binding Response with a different port than the
            one the Binding Request was received on.
         */
        class ChangeRequest : public Header {
        public:
            ChangeRequest(bool changeIP) :
                Header(Id::ChangeRequest, 4)
            {}

        private:
            unsigned : 16;
            unsigned : 8;
            unsigned : 1;
            unsigned m_ChangeIP     :1;
            unsigned m_ChangePort   :1;
            unsigned : 1;
            unsigned : 4;
        };

        class SourceAddress : public MappedAddress {
        public:
            SourceAddress() :
                MappedAddress(Id::SourceAddress)
            {}
        };

        class ChangedAddress : public MappedAddress {
        public:
            ChangedAddress() :
                MappedAddress(Id::ChangedAddress)
            {}
        };

        class UserName : public Header {
        public:
            UserName() :
                Header(Id::Username, 0)
            {}

            void Name(const std::string& name)
            {
                auto len = static_cast<uint16_t>(name.length());
                assert(len < sUsernameLimite);
                ContentLength(len);
                memcpy(m_Name, name.data(), len);
            }

            std::string Name() const
            {
                assert(ContentLength());
                return std::string(reinterpret_cast<const char*>(m_Name), ContentLength());
            }
        private:
            uint8_t m_Name[0];
        };

        class Password : public Header {
        public:
            Password() :
                Header(Id::Password, 0)
            {}

            void SetPassword(const std::string& name)
            {
                auto len = static_cast<uint16_t>(name.length());
                assert(len < sTextLimite);
                ContentLength(len);
                memcpy(m_Password, name.data(), len);
            }

            std::string GetPassword() const
            {
                assert(ContentLength());
                return std::string(reinterpret_cast<const char*>(m_Password), ContentLength());
            }
        private:
            uint8_t m_Password[0];
        };

        class MessageIntegrity : public Header {
        public:
            MessageIntegrity(SHA1ConstRef sha1) :
                Header(Id::MessageIntegrity, sSHA1Size)
            {
                memcpy(m_SHA1, sha1, sSHA1Size);
            }

            SHA1ConstRef SHA1() const { return m_SHA1; }

            void SHA1(SHA1ConstRef sha1) { memcpy(m_SHA1, sha1, sSHA1Size); }

        private:
            STUN::SHA1 m_SHA1;
        };

        /*
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |           Reserved, should be 0         |Class|     Number    |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |      Reason Phrase (variable)                                ..
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         */
        class ErrorCode : public Header {
        public:
            ErrorCode() :
                Header(Id::ErrorCode, 0)
            {}

            void Class(uint16_t classCode)
            {
                assert(classCode >= 3 && classCode <= 6);

                m_Class = classCode;
            }

            void Number(uint16_t number)
            {
                assert(number >= 0 && number <= 99);
                m_Number = number;
            }

            uint16_t Code() const { return m_Class * 100 + m_Number; }

            void Reason(const std::string& reason)
            {
                auto len = static_cast<uint16_t>(reason.length());
                assert(len < sTextLimite);

                ContentLength(len + 4);
                memcpy(m_Reason, reason.data(), len);
            }

            std::string& Reason() const
            {
                assert(ContentLength() - 4);
                return std::string(reinterpret_cast<const char*>(m_Reason), ContentLength() - 4);
            }

        private:
            unsigned int : 16;
            unsigned int m_Class : 3;
            unsigned int : 5;
            unsigned int m_Number: 8;
            uint8_t  m_Reason[0];
        };

        class UnknownAttributes : public Header {
        public:
            UnknownAttributes() :
                Header(Id::UnknownAttributes, 0)
            {}

        private:
            uint16_t m_Attrs[0];
        };

        class ReflectedFrom : public MappedAddress {
        public:
            ReflectedFrom() :
                MappedAddress(Id::ReflectedFrom)
            {}
        };

        class Realm : public Header {
        public:
            Realm() :
                Header(Id::Realm,0)
            {}

            void SetRealm(const std::string& realm)
            {
                auto len = static_cast<uint16_t>(realm.length());

                assert(len < sTextLimite);

                ContentLength(len);
                memcpy(m_Realm, realm.data(), len);
            }

            std::string& GetRealm() const
            {
                assert(ContentLength());
                return std::string(reinterpret_cast<const char*>(m_Realm), ContentLength());
            }

        private:
            char* m_Realm[0];
        };

        class Nonce : public Header {
        public:
            Nonce() :
                Header(Id::Nonce, 0)
            {}

            void SetNonce(const std::string& realm)
            {
                auto len = static_cast<uint16_t>(realm.length());

                ContentLength(len);
                memcpy(m_Nonce, realm.data(), len);
            }

            std::string& GetNonce() const
            {
                assert(ContentLength());
                return std::string(reinterpret_cast<const char*>(m_Nonce), ContentLength());
            }
        private:
            uint8_t m_Nonce[0];
        };

        class XorMappedAddr : public Header{
        public:
            XorMappedAddr() :
                Header(Id::XorMappedAdd, 4)
            {}

            uint16_t Port() const
            {
                return static_cast<uint16_t>((sMagicCookie >> 16) ^ PG::network_to_host(static_cast<uint16_t>(m_Port)));
            }

            void Port(int16_t port)
            {
                m_Port = PG::host_to_network(static_cast<uint16_t>(port ^ (sMagicCookie >> 16)));
            }

            uint32_t Address() const
            {
                return static_cast<int32_t>(sMagicCookie ^ PG::network_to_host(static_cast<uint32_t>(m_Address)));
            }

            std::string IP() const
            {
                boost::asio::ip::address_v4 address(Address());
                return address.to_string();
            }

            void Address(uint32_t address)
            {
                m_Address = PG::host_to_network(address ^ sMagicCookie);
            }

            AddressFamily Family() const
            {
                return  static_cast<AddressFamily>(m_Family);
            }

            const uint8_t* RawData() const
            {
                return reinterpret_cast<const uint8_t*>(this);
            }

        private:
            unsigned : 8;
            unsigned m_Family : 8;
            unsigned m_Port : 16;
            unsigned m_Address : 32;
        };

        class XorMappedAddress : public Header {
        public:
            XorMappedAddress() :
                Header(Id::XorMappedAddress, 4)
            {}

            uint16_t Port() const
            {
                return static_cast<uint16_t>((sMagicCookie >> 16) ^ PG::network_to_host(static_cast<uint16_t>(m_Port)));
            }

            void Port(int16_t port)
            {
                m_Port = PG::host_to_network(static_cast<uint16_t>(port ^ (sMagicCookie >> 16)));
            }

            uint32_t Address() const
            {
                return static_cast<int32_t>(sMagicCookie ^ PG::network_to_host(static_cast<uint32_t>(m_Address)));
            }

            std::string IP() const
            {
                boost::asio::ip::address_v4 address(Address());
                return address.to_string();
            }

            void Address(uint32_t address)
            {
                m_Address = PG::host_to_network(address ^ sMagicCookie);
            }

            AddressFamily Family() const
            {
                return  static_cast<AddressFamily>(m_Family);
            }

            const uint8_t* RawData() const
            {
                return reinterpret_cast<const uint8_t*>(this);
            }

        private:
            unsigned :8;
            unsigned m_Family : 8;
            unsigned m_Port   : 16;
            unsigned m_Address: 32;
        };

        class Software : public Header {
        public:
            Software() :
                Header(Id::Software, 0)
            {}

            void Describe(const std::string& desc)
            {
                auto len = static_cast<uint16_t>(desc.length());
                ContentLength(len);
                memcpy(m_describe, desc.data(), len);
            }

            std::string Describe() const
            {
                assert(ContentLength());
                return std::string(reinterpret_cast<const char*>(m_describe), ContentLength());
            }
        private:
            uint8_t m_describe[0];
        };

        class AlternateServer : public MappedAddress {
        public:
            AlternateServer() :
                MappedAddress(Id::AlternateServer)
            {}
        };

        class Fingerprint : public Header {
        public:
            Fingerprint() :
                Header(Id::Fingerprint, 4)
            {}

            uint32_t CRC32() const { return PG::network_to_host(m_CRC32); }
            void CRC32(uint32_t crc32) { m_CRC32 = PG::host_to_network(crc32); }

        private:
            uint32_t m_CRC32;
        };

        class Priority : public Header {
        public:
            Priority(uint32_t pri) :
                Header(Id::Priority, 4),m_Pri(PG::host_to_network(pri))
            {}

            uint32_t Pri() const
            {
                return PG::network_to_host(m_Pri);
            }

        private:
            uint32_t m_Pri;
        };

        class UseCandidate : public Header {
        public:
            UseCandidate() :
                Header(Id::UseCandidate, 0)
            {}
        };

        class Role : public Header {
        public:
            Role(bool bControlling, uint64_t tiebreaker) :
                Header(bControlling ? Id::IceControlling : Id::IceControlled, 8),
                m_Tiebreaker(PG::host_to_network(tiebreaker))
            {}

            uint64_t TieBreaker() const
            {
                return PG::network_to_host(m_Tiebreaker);
            }

        private:
            uint64_t m_Tiebreaker;
        };

    }

    namespace PACKET {
        class stun_packet {
        public:
            stun_packet() :
                stun_packet(MsgType::InvalidMsg)
            {
            }

            stun_packet(MsgType eMsg) :
                _msgId(PG::host_to_network(static_cast<uint16_t>(eMsg))),
                _length(0)
            {
            }

            stun_packet(MsgType eMsg, TransIdConstRef id) :
                _msgId(PG::host_to_network(static_cast<uint16_t>(eMsg))),
                _length(0)
            {
                static_assert(sizeof(id) == sTransationLength, "Id Must be 16 bytes");
                memcpy(_transId, id,sizeof(id));
            }

            stun_packet& operator=(const stun_packet& other)
            {
                assert(other.MsgId() != MsgType::InvalidMsg);

                if(&other != this)
                    memcpy(this, &other, other.Length() + 20);
            }

            MsgType MsgId() const
            {
                return static_cast<MsgType>(PG::network_to_host(_msgId));
            }

            void MsgId(MsgType eMsg)
            {
                _msgId = PG::host_to_network(static_cast<uint16_t>(eMsg));
            }

            uint16_t Length() const
            {
                return PG::network_to_host(_length);
            }

            void Length(uint16_t length)
            {
                _length = PG::host_to_network(length);
            }

            void TransId(TransIdConstRef id)
            {
                memcpy(_transId, id, sizeof(_transId));
            }

            auto TransId() -> TransIdRef
            {
                return _transId;
            }

            auto TransId() const -> TransIdConstRef
            {
                return _transId;
            }

            auto Attributes() const -> AttrContentConstRef
            {
                return _attr;
            }

            auto Attributes() -> AttrContentRef
            {
                return _attr;
            }

        private:
            uint16_t            _msgId;
            uint16_t            _length;
            STUN::TransId       _transId;
            STUN::AttrContent   _attr;
        };
    }
}

#pragma pack()