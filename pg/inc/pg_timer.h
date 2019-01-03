#pragma once

#include <boost/asio.hpp>

namespace PG {
    class timer {
    public:
        timer() {}
        virtual ~timer() {}

    public:

    protected:
        static boost::asio::io_service sIOService;
    };
};