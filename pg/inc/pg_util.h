#pragma once

#include <stdint.h>
#include <ctime>
#include <boost/asio.hpp>
#include <boost/random/uniform_int.hpp>
#include <boost/random/uniform_real.hpp>
#include <boost/random/variate_generator.hpp>
#include <boost/random/mersenne_twister.hpp>

namespace PG {
    using random_generator = boost::mt19937;

    static random_generator sRandomGenerator(static_cast<uint32_t>(std::time(nullptr)));

    template<bool, class T>
    struct is_integer_random { using type = boost::uniform_real<T>; };

    template<class T>
    struct is_integer_random<true, T> { using type = boost::uniform_int<T>; };

    template<class T>
    T GenerateRandom(T min, T max)
    {
        static_assert(std::is_integral<T>::value || std::is_floating_point<T>::value, "Must be integral or Float");

        using dist_type = is_integer_random<std::is_integral<T>::value, T>::type;

        assert(min < max);

        dist_type degen_dist(min, max);
        boost::variate_generator<random_generator&, dist_type> deg(sRandomGenerator, degen_dist);
        return deg();
    }

    static uint32_t GenerateRandom32()
    {
        return GenerateRandom(static_cast<uint32_t>(0), UINT32_MAX);
    }

    static uint64_t GenerateRandom64()
    {
        return GenerateRandom(static_cast<uint64_t>(0), UINT64_MAX);
    }

    template<class T, int, bool b = true>
    struct to_big_endian {
        using transform = T;
    };

    template<class T>
    struct to_big_endian<T, sizeof(uint16_t), false> {
        static T transform(T value)
        {
            static_assert(std::is_integral<T>::value, "Must be integral");

            uint8_t * value_p = reinterpret_cast<uint8_t*>(&value);
            return static_cast<uint16_t>(value_p[0]) << 8 | static_cast<uint16_t>(value_p[1]);
        }
    };

    template<class T>
    struct to_big_endian<T, sizeof(uint32_t), false> {
        static T transform(T value)
        {
            static_assert(std::is_integral<T>::value, "Must be integral");

            uint8_t *value_p = reinterpret_cast<uint8_t*>(&value);

            return static_cast<uint32_t>(value_p[0]) << 24 |
                static_cast<uint32_t>(value_p[1]) << 16 |
                static_cast<uint32_t>(value_p[2]) << 8 |
                static_cast<uint32_t>(value_p[3]);
        }
    };

    template<class T>
    struct to_big_endian<T, sizeof(uint64_t), false> {
        static T transform(T value)
        {
            static_assert(std::is_integral<T>::value, "Must be integral");

            uint8_t *value_p = reinterpret_cast<uint8_t*>(&value);

            return static_cast<uint64_t>(value_p[0]) << 56 |
                static_cast<uint64_t>(value_p[1]) << 48 |
                static_cast<uint64_t>(value_p[2]) << 40 |
                static_cast<uint64_t>(value_p[3]) << 32 |
                static_cast<uint64_t>(value_p[4]) << 24 |
                static_cast<uint64_t>(value_p[5]) << 16 |
                static_cast<uint64_t>(value_p[6]) << 8 |
                static_cast<uint64_t>(value_p[7]);
        }
    };

    template<class T, int, bool b = true>
    struct to_little_endian {
        using transform = T;
    };

    template<class T>
    struct to_little_endian<T, sizeof(uint16_t), false> {
        static T transform(T value)
        {
            static_assert(std::is_integral<T>::value, "Must be integral");

            uint16_t  result;
            uint8_t* result_p = reinterpret_cast<uint8_t*>(&result);
            result_p[0] = static_cast<uint8_t>((value >> 8) & 0xFF);
            result_p[1] = static_cast<uint8_t>((value) & 0xFF);

            return static_cast<T>(result);
        }
    };

    template<class T>
    struct to_little_endian<T, sizeof(uint32_t), false> {
        static T transform(T value)
        {
            static_assert(std::is_integral<T>::value, "Must be integral");

            uint32_t result;
            uint8_t* result_p = reinterpret_cast<uint8_t*>(&result);

            result_p[0] = static_cast<uint8_t>((value >> 24) & 0xFF);
            result_p[1] = static_cast<uint8_t>((value >> 16) & 0xFF);
            result_p[2] = static_cast<uint8_t>((value >> 8) & 0xFF);
            result_p[3] = static_cast<uint8_t>(value & 0xFF);

            return static_cast<T>(result);
        }
    };

    template<class T>
    struct to_little_endian<T, sizeof(uint64_t), false> {
        static T transform(T value)
        {
            static_assert(std::is_integral<T>::value, "Must be integral");

            uint64_t result;
            uint8_t* result_p = reinterpret_cast<uint8_t*>(&result);
            result_p[0] = static_cast<uint8_t>((value >> 56) & 0xFF);
            result_p[1] = static_cast<uint8_t>((value >> 48) & 0xFF);
            result_p[2] = static_cast<uint8_t>((value >> 40) & 0xFF);
            result_p[3] = static_cast<uint8_t>((value >> 32) & 0xFF);
            result_p[4] = static_cast<uint8_t>((value >> 24) & 0xFF);
            result_p[5] = static_cast<uint8_t>((value >> 16) & 0xFF);
            result_p[6] = static_cast<uint8_t>((value >> 8) & 0xFF);
            result_p[7] = static_cast<uint8_t>((value >> 0) & 0xFF);

            return static_cast<T>(result);
        }
    };

    template<class T>
    inline T host_to_network(T t)
    {
        static_assert(std::is_integral<T>::value, "Must be integral");

        return to_little_endian<T, sizeof(t), false>::transform(t);
    }

    template<class T>
    T network_to_host(T t)
    {
        static_assert(std::is_integral<T>::value, "Must be integral");

        return to_big_endian<T, sizeof(t), false>::transform(t);
    }
}