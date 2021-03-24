
#pragma once

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <functional>
#include <iostream>
#include <utility>
#include <vector>

#include "lrand.hpp"

class Gold_data {
  public:
    void clear() {
        device = false;
        chunks.clear();
    }

    void set_addr(const uint64_t addr, const uint8_t sz) {
        assert(!has_partial_overlap(addr, sz));  // No overlapping valid ranges
        chunks.emplace_back(Chunk(addr, sz));

        sort_chunks();
    }

    void add_addr(const uint64_t addr) {
        for (auto i = 0u; i < chunks.size(); ++i) {
            auto &c = chunks[i];

            if (c.is_hit(addr))
                return;  // done

            if (c.addr - 1 == addr) {
                --c.addr;
                assert(i > 0 && !chunks[i - 1].is_hit(addr - 1));
                c.data.insert(c.data.begin(), 1, rand_data.any());
                return;
            }

            if ((c.addr + c.data.size()) == addr) {
                c.data.emplace_back(rand_data.any());

                if (chunks.size() < i && chunks[i + 1].addr == addr) {  // merge with
                                                                        // next
                    c.data.insert(c.data.end(), chunks[i + 1].data.begin(), chunks[i + 1].data.end());
                    ++i;
                    chunks.erase(chunks.begin() + i);
                }
                return;
            }
        }

        set_addr(addr, 1);
    }

    void add_addr(const uint64_t addr, const uint8_t sz) {
        for (auto i = 0u; i < sz; ++i) {
            add_addr(addr + i);
        }
    }

    void set_data(const uint64_t addr, const uint8_t sz, uint64_t d) {
        assert(sz <= 8);
        for (int i = 0; i < sz; ++i) {
            set_byte(addr + i, d & 0xFF);
            d = d >> 8;
        }
    }

    uint64_t get_data(const uint64_t addr, const uint8_t sz) const {
        uint64_t d = 0;
        assert(sz <= 8);
        for (int i = 0; i < sz; ++i) {
            uint64_t b = get_byte(addr + sz - i - 1);
            d          = (d << 8) | b;
        }

        return d;
    }

    bool has_full_overlap(const uint64_t addr, const uint8_t sz) const {
        for (const auto &c : chunks) {
            if (c.addr <= addr && addr + sz <= c.addr + c.data.size()) {
                //     [c;              c+size]
                //          [addr; addr+sz]
                return true;
            }
        }
        return false;
    }

    bool has_partial_overlap(const uint64_t addr, const uint8_t sz) const {
        for (const auto &c : chunks) {
            if (c.addr <= addr && addr < c.addr + c.data.size()) {
                //     [c;        c+size]
                //          [addr;    addr+sz]
                return true;
            }
            if (c.addr < addr + sz && addr + sz <= c.addr + c.data.size()) {
                //        [c;        c+size]
                // [addr;    addr+sz]
                return true;
            }
        }
        return false;
    }
    bool has_partial_overlap(const Gold_data &d2) const {
        for (auto const &c : d2.chunks) {
            if (has_partial_overlap(c.addr, c.data.size()))
                return true;
        }
        return false;
    }

    bool has_byte(const uint64_t addr) const { return has_full_overlap(addr, 1); }

    void set_byte(const uint64_t addr, const uint8_t b) {
        for (auto &c : chunks) {
            if (!c.is_hit(addr))
                continue;

            c.set_byte(addr, b);
            return;
        }
        assert(false);  // do not call set_data/byte if addr may be invalid. Check first
    }

    uint8_t get_byte(const uint64_t addr) const {
        for (auto &c : chunks) {
            if (!c.is_hit(addr))
                continue;

            return c.get_byte(addr);
        }

        return rand_data.any();
    }

    bool has_data() const { return !chunks.empty(); }

    std::string str() const;

    void dump() const { std::cout << str(); }

    void add_newer(const Gold_data &d2) {
        for (const auto c : d2.chunks) {
            add_addr(c.addr, c.data.size());
            for (auto i = 0u; i < c.data.size(); ++i) {
                set_byte(c.addr + i, c.data[i]);
            }
        }
    }

    void update_newer(const Gold_data &d2) {
        for (const auto c : d2.chunks) {
            if (!has_partial_overlap(c.addr, c.data.size()))
                continue;

            for (auto i = 0u; i < c.data.size(); ++i) {
                if (!has_byte(c.addr + i))
                    continue;

                set_byte(c.addr + i, c.data[i]);
            }
        }
    }

    void set_device() { device = true; }

    void each_chunk(std::function<void(uint64_t, const std::vector<uint8_t> &)> fun) {
        for (const auto c : chunks) {
            fun(c.addr, c.data);
        }
    }

    void each_chunk(std::function<void(uint64_t, const std::vector<uint8_t> &)> fun) const {
        for (const auto c : chunks) {
            fun(c.addr, c.data);
        }
    }

    bool operator!=(const Gold_data &d2) const {
        if (device && d2.device) {
            return false;  // do not flag diff/error of device
        }

        auto it1 = chunks.begin();
        auto it2 = d2.chunks.begin();

        for (; it1 != chunks.end() && it2 != d2.chunks.end(); ++it1, ++it2) {
            if (it1->addr != it2->addr)
                return false;
            if (it1->data != it2->data)
                return false;
        }
        if ((it1 == chunks.end() && it2 != d2.chunks.end()) || (it1 != chunks.end() && it2 == d2.chunks.end())) {
            return false;
        }

        return true;
    }

    Gold_data() { device = false; }

  protected:
    static Lrand<uint8_t> rand_data;

    void sort_chunks() {
        std::sort(chunks.begin(), chunks.end(), [](const Chunk &a, const Chunk &b) -> bool { return a.addr < b.addr; });
#ifndef NDEBUG
        for (auto i = 1u; i < chunks.size(); ++i) {
            assert(chunks[i - 1].addr + chunks[i - 1].data.size() < chunks[i].addr);  // no overlap, no even concatenatable chunks
        }
#endif
    }

    struct Chunk {
        static Lrand<uint8_t> rand_data;
        Chunk() {
            addr = 0;
            data.clear();
        }

        Chunk(uint64_t a, uint8_t s) : addr(a) { data.resize(s, rand_data.any()); }

        bool is_hit(uint64_t a) const { return addr <= a && (addr + data.size()) > a; }

        void set_byte(uint64_t a, uint8_t b) {
            assert(is_hit(a));
            assert(data.size() > a - addr);

            data[a - addr] = b;
        }

        uint8_t get_byte(uint64_t a) const {
            assert(is_hit(a));
            assert(data.size() > a - addr);

            return data[a - addr];
        }

        uint64_t             addr;
        std::vector<uint8_t> data;
    };

    std::vector<Chunk> chunks;
    bool               device;
};
