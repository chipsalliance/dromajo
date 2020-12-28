//  This file is distributed under the BSD 3-Clause License. See LICENSE for
//  details.

// Get this a bit cleaner/faster
// Benchmark against this:
// https://lemire.me/blog/2019/03/19/the-fastest-conventional-random-number-generator-that-can-pass-big-crush/

#pragma once

#include <array>
#include <cassert>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <limits>
#include <sstream>
#include <type_traits>
//#include <random>
#include <utility>
//#include <stdlib.h>

// this is probably the fastest high quality 64bit random number generator that
// exists. Implements Small Fast Counting v4 RNG from PractRand.
class sfc64 {
  public:
    constexpr static uint64_t default_seed = 0x853c49e6748fea9b;
    using result_type                      = uint64_t;

#if 0
  sfc64()
    : sfc64(UINT64_C(0x853c49e6748fea9b)) {}
#else
    static bool initialized;
    size_t      lrand_get_seed() {
        static sfc64 seed{sfc64::default_seed};

        if (__builtin_expect(initialized, 1))
            return seed.uniform<size_t>();

        const char *lbench_seed = getenv("LBENCH_SEED");
        if (lbench_seed) {
            seed.seed(std::atoi(lbench_seed));
        }

        initialized = true;

        return seed.uniform<size_t>();
    }
    sfc64() : sfc64(lrand_get_seed()) {}
#endif

    sfc64(uint64_t a, uint64_t b, uint64_t c, uint64_t counter) : m_a{a}, m_b{b}, m_c{c}, m_counter{counter} {}

    sfc64(std::array<uint64_t, 4> const &state) : m_a{state[0]}, m_b{state[1]}, m_c{state[2]}, m_counter{state[3]} {}

    explicit sfc64(uint64_t seed) : m_a(seed), m_b(seed), m_c(seed), m_counter(1) {
        for (int i = 0; i < 12; ++i) {
            operator()();
        }
    }

    // no copy ctors so we don't accidentally get the same random again
    sfc64(sfc64 const &) = delete;
    sfc64 &operator=(sfc64 const &) = delete;

    sfc64(sfc64 &&) = default;
    sfc64 &operator=(sfc64 &&) = default;

    ~sfc64() = default;

    static constexpr uint64_t(min)() { return (std::numeric_limits<uint64_t>::min)(); }
    static constexpr uint64_t(max)() { return (std::numeric_limits<uint64_t>::max)(); }

#if 0
  void seed() {
    seed(std::random_device{}());
  }
#endif

    void seed(uint64_t seed) { state(sfc64{seed}.state()); }

    uint64_t operator()() noexcept {
        auto const tmp = m_a + m_b + m_counter++;
        m_a            = m_b ^ (m_b >> right_shift);
        m_b            = m_c + (m_c << left_shift);
        m_c            = rotl(m_c, rotation) + tmp;
        return tmp;
    }

    template <typename Output, typename Input>
    Output uniform(Input i) {
        return static_cast<Output>(operator()(static_cast<uint64_t>(i)));
    }

    template <typename T>
    T uniform() {
        return static_cast<T>(operator()());
    }

    // This is slow, but unfortunately I need want the same result in both 32bit
    // and 64bit so the tests work.
    uint64_t multhi64(uint64_t const a, uint64_t const b) {
        uint64_t a_lo = static_cast<uint32_t>(a);
        uint64_t a_hi = a >> 32u;
        uint64_t b_lo = static_cast<uint32_t>(b);
        uint64_t b_hi = b >> 32u;

        uint64_t a_x_b_hi  = a_hi * b_hi;
        uint64_t a_x_b_mid = a_hi * b_lo;
        uint64_t b_x_a_mid = b_hi * a_lo;
        uint64_t a_x_b_lo  = a_lo * b_lo;

        uint64_t carry_bit = (static_cast<uint64_t>(static_cast<uint32_t>(a_x_b_mid))
                              + static_cast<uint64_t>(static_cast<uint32_t>(b_x_a_mid)) + (a_x_b_lo >> 32u))
                             >> 32u;

        uint64_t multhi = a_x_b_hi + (a_x_b_mid >> 32u) + (b_x_a_mid >> 32u) + carry_bit;

        return multhi;
    }

    // Uses the java method. A bit slower than 128bit magic from
    // https://arxiv.org/pdf/1805.10941.pdf, but produces the exact same results
    // in both 32bit and 64 bit.
    uint64_t operator()(uint64_t boundExcluded) noexcept {
#ifdef __SIZEOF_INT128__
        return static_cast<uint64_t>((static_cast<unsigned __int128>(operator()()) * static_cast<unsigned __int128>(boundExcluded))
                                     >> 64u);
#else
        return multhi64(operator()(), boundExcluded);
#endif
    }

    std::array<uint64_t, 4> state() const { return {{m_a, m_b, m_c, m_counter}}; }

    void state(std::array<uint64_t, 4> const &s) {
        m_a       = s[0];
        m_b       = s[1];
        m_c       = s[2];
        m_counter = s[3];
    }

    std::ostream &print(std::ostream &os) const {
        os << "0x" << std::setfill('0') << std::setw(16) << std::hex << m_a << ", 0x" << std::setfill('0') << std::setw(16)
           << std::hex << m_b << ", 0x" << std::setfill('0') << std::setw(16) << std::hex << m_c << ", " << std::dec << m_counter;
        return os;
    }

  private:
    template <typename T>
    T rotl(T const x, size_t k) {
        return (x << k) | (x >> (8 * sizeof(T) - k));
    }

    static constexpr size_t rotation    = 24;
    static constexpr size_t right_shift = 11;
    static constexpr size_t left_shift  = 3;
    uint64_t                m_a;
    uint64_t                m_b;
    uint64_t                m_c;
    uint64_t                m_counter;
};

inline std::ostream &operator<<(std::ostream &os, sfc64 const &rng) { return rng.print(os); };

template <typename T>
class Lrand {
  protected:
    sfc64 rint;

  public:
    Lrand() {}
    Lrand(uint64_t seed) : rint(seed) {}

    T max(uint64_t m) { return rint.uniform<T>(m); }

    T between(uint64_t m1, uint64_t m2) {
        assert(m1 < m2);
        return m1 + rint.uniform<T>(m2 - m1);
    }

    T any() { return rint.uniform<T>(std::numeric_limits<T>::max()); }
};

template <typename T>
class Lrand_range {
  protected:
    sfc64 rint;

    const int base;
    const int delta;

    static_assert(std::numeric_limits<T>::max() <= std::numeric_limits<uint64_t>::max(),
                  "Lrand_rage only works for base types of less than 64bits");

  public:
    Lrand_range(int min, int max) : base(min), delta(max - min) { assert(max > min); }
    Lrand_range(int min, int max, uint64_t seed) : rint(seed), base(min), delta(max - min) { assert(max > min); }

    T max(uint64_t m) {
        assert(m > base);
        assert(m < (base + delta));
        return base + rint.uniform<int>(m - base);
    }

    T min(uint64_t m) {
        assert(m > base);
        assert(m < (base + delta));
        return base + m + rint.uniform<T>(delta - base - m);
    }

    T between(uint64_t m1, uint64_t m2) {
        assert(m1 < m2);
        return m1 + rint.uniform<T>(m2 - m1);
    }

    T any() { return base + rint.uniform<T>(delta); }
};

template <>
class Lrand<bool> {
  protected:
    static constexpr const size_t s_mask_left1 = size_t(1) << (sizeof(size_t) * 8 - 1);
    uint64_t                      m_rand       = 1;

    sfc64 rint;

  public:
    Lrand() {}
    Lrand(uint64_t seed) : rint(seed) {}

    bool any() {
        if (1 == m_rand) {
            m_rand = rint.uniform<uint64_t>(std::numeric_limits<uint64_t>::max()) | s_mask_left1;
        }
        bool const ret = m_rand & 1;
        m_rand >>= 1;
        return ret;
    }
};
