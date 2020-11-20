#pragma once

// TODO: the mem is byte (not efficient maybe line base?)

#include <algorithm>

#include "Gold_data.hpp"
#include "robin_hood.hpp"

class Gold_mem {
  public:
    Gold_mem(std::function<uint8_t(uint64_t)> gb) : get_byte(gb) {}

    void st_perform(const Gold_data &st_data) {
        st_data.each_chunk([this](uint64_t addr, const std::vector<uint8_t> &data) {
            for (auto b_pos = 0u; b_pos < data.size(); ++b_pos) {
                mem_byte[addr + b_pos] = data[b_pos];
            }
        });
    }

    void ld_perform(Gold_data &ld_data) {
        ld_data.each_chunk([this, &ld_data](uint64_t addr, const std::vector<uint8_t> &data) {
            for (auto b_pos = 0u; b_pos < data.size(); ++b_pos) {
                auto a = addr + b_pos;

                auto it = mem_byte.find(a);
                if (it == mem_byte.end()) {
                    auto b      = get_byte(a);
                    mem_byte[a] = b;
                    ld_data.set_byte(a, b);
                } else {
                    ld_data.set_byte(a, it->second);
                }
            }
        });
    }

  protected:
    std::function<uint8_t(uint64_t)> get_byte;

    robin_hood::unordered_map<uint64_t, uint8_t> mem_byte;
};
