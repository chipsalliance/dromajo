
#include "Gold_notify.hpp"

std::set<uint64_t> Gold_nofity::tracing;

void Gold_nofity::trace_int(uint64_t iid, const std::string &msg) { fmt::print("TRACE: iid:{} {}\n", iid, msg); }

void Gold_nofity::fail_int(const std::string &msg) { fmt::print("FAIL:{}\n", msg); }

void Gold_nofity::warn_int(const std::string &msg) { fmt::print("WARN:{}\n", msg); }

void Gold_nofity::info_int(const std::string &msg) { fmt::print("INFO:{}\n", msg); }
