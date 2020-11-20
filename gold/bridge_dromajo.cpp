
#include <vector>

#include "Gold_core.hpp"

/* dromajo is an emulator, so much of the OoO capabilities are not needed.
 */

extern uint8_t dromajo_get_byte_direct(uint64_t paddr);

static Gold_mem mem(dromajo_get_byte_direct);
static std::vector<Gold_core> cores;


void check_dromajo_init(int ncores) {

  for(int i=0;i<ncores;++i) {
    cores.emplace_back(mem, i);
  }
}

void check_dromajo_load(int cid, uint64_t addr, uint8_t sz, uint64_t data, bool io_map) {

  auto rid = cores[cid].inorder();

  auto &d= cores[cid].ld_data_ref(rid);

  d.add_addr(addr, sz);
  if (io_map)
    d.set_device();

  cores[cid].ld_perform(rid);

  uint64_t data2 = d.get_data(addr, sz);
  if (!io_map && data2 != data) {
    std::cerr << "FAIL: dut_data:" << data
      << " gold_data:" << data2
      << "\n";
    cores[cid].dump();
    exit(-3);
  }
}

void check_dromajo_store(int cid, uint64_t addr, uint8_t sz, uint64_t data, bool io_map) {

  auto rid = cores[cid].inorder();

  auto &d= cores[cid].st_data_ref(rid);

  d.add_addr(addr, sz);
  d.set_data(addr, sz, data);
  if (io_map)
    d.set_device();

  cores[cid].st_globally_perform(rid);
}

