#pragma once

#include "stundef.h"

namespace STUN{
    namespace PROTOCOL {
        template<class protocol_version>
        class STUN_PROTOCOL {
        public:
            static uint16_t Encode(const ATTR::MappedAddress& attr, uint8_t* buf)
            {
                auto header_size = EncodeHeader(attr, buf);
                buf += header_size;

                // reserved
                buf[0] = 0;

                // family
                buf[1] = static_cast<uint8_t>(attr.Family());

                // port 
                reinterpret_cast<uint16_t*>(&buf[2])[0] = attr.Port();

                // address
                reinterpret_cast<uint32_t*>(&buf[3])[0] = attr.Address();

                return attr.ContentLength() + header_size;
            }

            static uint16_t Encode(const ATTR::ChangeRequest& attr, uint8_t *buf)
            {
                auto header_size = EncodeHeader(attr, buf);
                buf += header_size;

                //reinterpret_cast<uint32_t*>(buf)[0] = attr.Value();
                return attr.ContentLength() + header_size;
            }

            static uint16_t Encode(const ATTR::UserName& attr, uint8_t *buf)
            {
            }

            static uint16_t Encode(const ATTR::Password& attr, uint8_t *buf)
            {
                return protocol_version::Encode(attr, buf);
            }

            static uint16_t Encode(const ATTR::MessageIntegrity& attr, uint8_t *buf)
            {
                return protocol_version::Encode(attr, buf);
            }

            static uint16_t Encode(const ATTR::ErrorCode &attr, uint8_t* buf)
            {
                return protocol_version::Encode(attr, buf);
            }

            static uint16_t Encode(const ATTR::UnknownAttributes& attr, uint8_t *buf)
            {
                return protocol_version::Encode(attr, buf);
            }

            static uint16_t Encode(const ATTR::ReflectedFrom& attr, uint8_t* buf)
            {
                return protocol_version::Encode(attr, buf);
            }

            static uint16_t Encode(const ATTR::Realm& attr, uint8_t *buf)
            {
                return protocol_version::Encode(attr, buf);
            }

            static uint16_t Encode(const ATTR::Nonce& attr, uint8_t* buf)
            {
                return protocol_version::Encode(attr, buf);
            }

            static uint16_t Encode(const ATTR::XorMappedAddress& attr, uint8_t* buf)
            {
                return protocol_version::Encode(attr, buf);
            }

            static uint16_t Encode(const ATTR::Software& attr, uint8_t* buf)
            {
                return protocol_version::Encode(attr, buf);
            }

            static uint16_t Encode(const ATTR::AlternateServer& attr, uint8_t* buf)
            {
                return protocol_version::Encode(attr, buf);
            }

            static uint16_t Encode(const ATTR::Priority& attr, uint8_t* buf)
            {
                auto header_size = EncodeHeader(attr, buf);
                buf += header_size;

                reinterpret_cast<uint32_t*>(buf)[0] = attr.Pri();
                return attr.ContentLength() + header_size; // content + header length
            }

            static uint16_t Encode(const ATTR::UseCandidate& attr, uint8_t* buf)
            {
                auto header_size = EncodeHeader(attr, buf);
                buf += header_size;

                return attr.ContentLength() + header_size;
            }

            static uint16_t Encode(const ATTR::Fingerprint& attr, uint8_t* buf)
            {
                return protocol_version::Encode(attr, buf);
            }

            static uint16_t Encode(const ATTR::Role& attr, uint8_t* buf)
            {
                auto header_size = EncodeHeader(attr, buf);
                buf += header_size;

                reinterpret_cast<uint64_t*>(buf)[0] = attr.TieBreaker();
                return attr.ContentLength() + header_size;
            }

            static void GenerateTransationId(STUN::TransId id)
            {
                reinterpret_cast<uint64_t*>(id)[0] = PG::GenerateRandom64();
                reinterpret_cast<uint64_t*>(id)[1] = PG::GenerateRandom64();
            }

        protected:
            static uint16_t EncodeHeader(const ATTR::Header& header, uint8_t* buf)
            {
                reinterpret_cast<uint16_t*>(buf)[0] = static_cast<uint16_t>(header.Type());
                reinterpret_cast<uint16_t*>(buf)[1] = header.ContentLength();

                return sizeof(header);
            }
        };

        class RFC3489 : private STUN_PROTOCOL<RFC3489> {
        public:
            static uint16_t Encode(const ATTR::ChangeRequest& attr, uint8_t* buf)
            {
                return STUN_PROTOCOL::Encode(attr, buf);
            }
        };

        class RFC5389 : private STUN_PROTOCOL<RFC5389> {
        public:
            static uint16_t Encode(const ATTR::Priority& attr, uint8_t* buf);
            static uint16_t Encode(const ATTR::Role& attr, uint8_t* buf);
            static uint16_t Encode(const ATTR::UseCandidate& attr, uint8_t* buf);
            static void GenerateTransationId(STUN::TransId id);
        };
    }
}