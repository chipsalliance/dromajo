
#include <vector>

#include "Gold_core.hpp"
#include "Gold_notify.hpp"

/* dromajo is an emulator, so much of the OoO capabilities are not needed.
 */

extern uint8_t dromajo_get_byte_direct(uint64_t paddr);

static Gold_mem               mem(dromajo_get_byte_direct);
static std::vector<Gold_core> cores;

void check_inorder_init(int ncores) {
    for (int i = 0; i < ncores; ++i) {
        cores.emplace_back(mem, i);
    }
}

void check_inorder_load(int cid, uint64_t addr, uint8_t sz, uint64_t rd_data, bool io_map) {
    auto rid = cores[cid].inorder();

    auto &d = cores[cid].ld_data_ref(rid);
    d.add_addr(addr, sz);
    if (io_map)
        d.set_device();

    cores[cid].ld_perform(rid);

    uint64_t data2 = d.get_data(addr, sz);
    if (!io_map && data2 != rd_data) {
        Gold_nofity::fail("core:{} iid:{} ld mem[{:x}:{:x}] dut_data:{:x} gold_data:{:x}",
                          cid,
                          rid,
                          addr,
                          addr + sz - 1,
                          rd_data,
                          data2);
        cores[cid].dump();
        exit(-3);
    }
}

void check_inorder_store(int cid, uint64_t addr, uint8_t sz, uint64_t st_data, bool io_map) {
    auto rid = cores[cid].inorder();

    auto &d = cores[cid].st_data_ref(rid);

    d.add_addr(addr, sz);
    d.set_data(addr, sz, st_data);
    if (io_map)
        d.set_device();

    cores[cid].st_globally_perform(rid);
}

void check_inorder_amo(int cid, uint64_t addr, uint8_t sz, uint64_t st_data, uint64_t rd_data, bool io_map) {
    // In-order step
    auto rid = cores[cid].inorder();

    // Time that it gets globally performed
    auto &d_st = cores[cid].st_data_ref(rid);
    d_st.add_addr(addr, sz);
    d_st.set_data(addr, sz, st_data);

    auto &d_ld = cores[cid].ld_data_ref(rid);
    d_ld.add_addr(addr, sz);

    if (io_map) {
        d_st.set_device();
        d_ld.set_device();
    }

    cores[cid].ld_perform(rid);

    uint64_t data2 = d_ld.get_data(addr, sz);
    if (!io_map && data2 != rd_data) {
        Gold_nofity::fail("core:{} iid:{} amo mem[{:x}:{:x}] dut_data:{:x} gold_data:{:x}",
                          cid,
                          rid,
                          addr,
                          addr + sz - 1,
                          rd_data,
                          data2);
        cores[cid].dump();
        exit(-3);
    }

    cores[cid].st_globally_perform(rid);
}
