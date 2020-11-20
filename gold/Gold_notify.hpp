
#pragma once

#include <set>
#include <string>

#include "fmt/core.h"

class Gold_nofity {
  protected:
    static void trace_int(uint64_t iid, const std::string &text);
    static void fail_int(const std::string &text);
    static void warn_int(const std::string &text);
    static void info_int(const std::string &text);

    static std::set<uint64_t> tracing;

  public:
    static void add_tracing(uint64_t iid) { tracing.insert(iid); }

    template <typename S, typename... Args>
    static void trace(uint64_t iid, const S &format, Args &&...args) {
        if (tracing.empty() || tracing.count(iid)) {
            trace_int(iid, fmt::format(format, args...));
        }
    }

    template <typename S, typename... Args>
    static void fail(const S &format, Args &&...args) {
        fail_int(fmt::format(format, args...));
    }

    template <typename S, typename... Args>
    static void warn(const S &format, Args &&...args) {
        warn_int(fmt::format(format, args...));
    }

    template <typename S, typename... Args>
    static void info(const S &format, Args &&...args) {
        info_int(fmt::format(format, args...));
    }
};
