
#include "Gold_data.hpp"

#include "fmt/core.h"

Lrand<uint8_t> Gold_data::rand_data;
Lrand<uint8_t> Gold_data::Chunk::rand_data;

std::string Gold_data::str() const {
    std::string msg;

    for (const auto c : chunks) {
        if (device) {
            msg.append(" DEVICE");
        }
        msg.append(fmt::format(" mem[{:x}:{:x}]=", c.addr, c.addr + c.data.size() - 1));

        for (auto b : c.data) {
            msg.append(fmt::format("{:2x}", b));
        }
    }

    return msg;
}
