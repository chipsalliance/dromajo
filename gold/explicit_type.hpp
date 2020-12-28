//  This file is distributed under the BSD 3-Clause License. Jose Renau

#pragma once

template <typename T, typename Meaning, T inv_val>
struct Explicit_type {
    //! Default constructor does not initialize the value.
    constexpr inline Explicit_type() : value(inv_val) {}

    //! Construction from a fundamental value.
    constexpr inline Explicit_type(const T &_value) : value(_value) {}

    //! Implicit conversion back to the fundamental data type.
    [[nodiscard]] constexpr inline operator T() const noexcept { return value; }

    //! The actual fundamental value.
    T         value;
    typedef T type;

    bool is_invalid() const { return value == inv_val; }
    void invalidate() { value = inv_val; }
};
