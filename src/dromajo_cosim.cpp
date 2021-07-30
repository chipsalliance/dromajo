/*
 * API for Dromajo-based cosimulation
 *
 * Copyright (C) 2018,2019, Esperanto Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License")
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "dromajo_cosim.h"

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>

#include "cutils.h"
#include "dromajo.h"
#include "iomem.h"
#include "riscv_machine.h"

#ifdef GOLDMEM_INORDER
void check_inorder_load(int cid, uint64_t addr, uint8_t sz, uint64_t ld_data, bool io_map);
void check_inorder_store(int cid, uint64_t addr, uint8_t sz, uint64_t st_data, bool io_map);
void check_inorder_amo(int cid, uint64_t addr, uint8_t sz, uint64_t st_data, uint64_t ld_data, bool io_map);
void check_inorder_init(int ncores);
#endif

/*
 * dromajo_cosim_init --
 *
 * Creates and initialize the state of the RISC-V ISA golden model
 * Returns NULL upon failure.
 */
dromajo_cosim_state_t *dromajo_cosim_init(int argc, char *argv[]) {
    RISCVMachine *m = virt_machine_main(argc, argv);

#ifdef GOLDMEM_INORDER
    check_inorder_init(m->ncpus);
#endif

    m->common.cosim             = true;
    m->common.pending_interrupt = -1;
    m->common.pending_exception = -1;

    return (dromajo_cosim_state_t *)m;
}

void dromajo_cosim_fini(dromajo_cosim_state_t *state) { virt_machine_end((RISCVMachine *)state); }

static bool is_store_conditional(uint32_t insn) {
    int opcode = insn & 0x7f, funct3 = insn >> 12 & 7;
    return opcode == 0x2f && insn >> 27 == 3 && (funct3 == 2 || funct3 == 3);
}

static inline uint32_t get_field1(uint32_t val, int src_pos, int dst_pos, int dst_pos_max) {
    int mask;
    assert(dst_pos_max >= dst_pos);
    mask = ((1 << (dst_pos_max - dst_pos + 1)) - 1) << dst_pos;
    if (dst_pos >= src_pos)
        return (val << (dst_pos - src_pos)) & mask;
    else
        return (val >> (src_pos - dst_pos)) & mask;
}

/* detect AMO instruction, including LR, but excluding SC */
static inline bool is_amo(uint32_t insn) {
    int opcode = insn & 0x7f;
    if (opcode != 0x2f)
        return false;

    switch (insn >> 27) {
        case 1:    /* amiswap.w */
        case 2:    /* lr.w */
        case 0:    /* amoadd.w */
        case 4:    /* amoxor.w */
        case 0xc:  /* amoand.w */
        case 0x8:  /* amoor.w */
        case 0x10: /* amomin.w */
        case 0x14: /* amomax.w */
        case 0x18: /* amominu.w */
        case 0x1c: /* amomaxu.w */ return true;
        default: return false;
    }
}

/*
 * is_mmio_load() --
 * calculated the effective address and check if the physical backing
 * is MMIO space.  NB: get_phys_addr() is the identity if the CPU is
 * running without virtual memory enabled.
 */
static inline bool is_mmio_load(RISCVCPUState *s, int reg, int offset, uint64_t mmio_start, uint64_t mmio_end) {
    uint64_t pa;
    uint64_t va = riscv_get_reg_previous(s, reg) + offset;

    if (!riscv_cpu_get_phys_addr(s, va, ACCESS_READ, &pa) && mmio_start <= pa && pa < mmio_end) {
        return true;
    }

    if (s->machine->mmio_addrset_size > 0) {
        RISCVMachine *m = s->machine;
        for (size_t i = 0; i < m->mmio_addrset_size; ++i) {
            uint64_t start = m->mmio_addrset[i].start;
            uint64_t end   = m->mmio_addrset[i].start + m->mmio_addrset[i].size;
            if (!riscv_cpu_get_phys_addr(s, va, ACCESS_READ, &pa) && start <= pa && pa < end)
                return true;
        }
    }

    return false;
}

/*
 * handle_dut_overrides --
 *
 * Certain sequences cannot be simulated faithfully so this function
 * is responsible for detecting them and overriding the simulation
 * with the DUT result.  Cases include interrupts, loads from MMIO
 * space, and certain CRSs like cycle and time.
 *
 * Right now we handle just mcycle.
 */
static inline void handle_dut_overrides(RISCVCPUState *s, uint64_t mmio_start, uint64_t mmio_end, int priv, uint64_t pc,
                                        uint32_t insn, uint64_t emu_wdata, uint64_t dut_wdata) {
    int opcode = insn & 0x7f;
    int csrno  = insn >> 20;
    int rd     = (insn >> 7) & 0x1f;
    int rdc    = ((insn >> 2) & 7) + 8;
    int reg, offset;

    /* Catch reads from CSR mcycle, ucycle, instret, hpmcounters,
     * hpmoverflows, mip, and sip.
     * If the destination register is x0 then it is actually a csr-write
     */
    if (opcode == 0x73 && rd != 0
        && (0xB00 <= csrno && csrno < 0xB20 || 0xC00 <= csrno && csrno < 0xC20
            || (csrno == 0x344 /* mip */ || csrno == 0x144 /* sip */)))
        riscv_set_reg(s, rd, dut_wdata);

    /* Catch loads and amo from MMIO space */
    if ((opcode == 3 || is_amo(insn)) && rd != 0) {
        reg    = (insn >> 15) & 0x1f;
        offset = opcode == 3 ? (int32_t)insn >> 20 : 0;
    } else if ((insn & 0xE003) == 0x6000 && rdc != 0) {
        // c.ld  011  uimm[5:3] rs1'[2:0]       uimm[7:6] rd'[2:0] 00
        reg    = ((insn >> 7) & 7) + 8;
        offset = get_field1(insn, 10, 3, 5) | get_field1(insn, 5, 6, 7);
        rd     = rdc;
    } else if ((insn & 0xE003) == 0x4000 && rdc != 0) {
        // c.lw  010  uimm[5:3] rs1'[2:0] uimm[2] uimm[6] rd'[2:0] 00
        reg    = ((insn >> 7) & 7) + 8;
        offset = (get_field1(insn, 10, 3, 5) | get_field1(insn, 6, 2, 2) | get_field1(insn, 5, 6, 6));
        rd     = rdc;
    } else
        return;

    if (is_mmio_load(s, reg, offset, mmio_start, mmio_end)) {
        riscv_set_reg(s, rd, dut_wdata);
    }
}

/*
 * dromajo_cosim_raise_trap --
 *
 * DUT raises a trap (exception or interrupt) and provides the cause.
 * MSB indicates an asynchronous interrupt, synchronous exception
 * otherwise.
 */
void dromajo_cosim_raise_trap(dromajo_cosim_state_t *state, int hartid, int64_t cause) {
    VirtMachine *m = (VirtMachine *)state;

    if (cause < 0) {
        assert(m->pending_interrupt == -1);
        m->pending_interrupt = cause & 63;
        fprintf(dromajo_stderr, "[DEBUG] DUT raised interrupt %d\n", m->pending_interrupt);
    } else {
        m->pending_exception = cause;
        fprintf(dromajo_stderr, "[DEBUG] DUT raised exception %d\n", m->pending_exception);
    }
}

/*
 * dromajo_cosim_step --
 *
 * executes exactly one instruction in the golden model and returns
 * zero if the supplied expected values match and execution should
 * continue.  A non-zero value signals termination with the exit code
 * being the upper bits (ie., all but LSB).  Caveat: the DUT provides
 * the instructions bit after expansion, so this is only matched on
 * non-compressed instruction.
 *
 * There are a number of situations where the model cannot match the
 * DUT, such as loads from IO devices, interrupts, and CSRs cycle,
 * time, and instret.  For all these cases the model will override
 * with the expected values.
 */
int dromajo_cosim_step(dromajo_cosim_state_t *state, int hartid, uint64_t dut_pc, uint32_t dut_insn, uint64_t dut_wdata,
                       uint64_t dut_mstatus, bool check) {
    RISCVMachine *r = (RISCVMachine *)state;
    assert(r->ncpus > hartid);
    RISCVCPUState *s = r->cpu_state[hartid];
    uint64_t       emu_pc, emu_wdata = 0;
    int            emu_priv;
    uint32_t       emu_insn;
    bool           emu_wrote_data = false;
    int            exit_code      = 0;
    bool           verbose        = true;
    int            iregno, fregno;

    /* Succeed after N instructions without failure. */
    if (r->common.maxinsns == 0) {
        return 1;
    }

    r->common.maxinsns--;

    if (riscv_terminated(s)) {
        return 1;
    }

    /*
     * Execute one instruction in the simulator.  Because exceptions
     * may fire, the current instruction may not be executed, thus we
     * have to iterate until one does.
     */
    iregno = -1;
    fregno = -1;

    for (;;) {
        emu_priv = riscv_get_priv_level(s);
        emu_pc   = riscv_get_pc(s);
        riscv_read_insn(s, &emu_insn, emu_pc);

        if ((emu_insn & 3) != 3)
            emu_insn &= 0xFFFF;

        if (emu_pc == dut_pc && emu_insn == dut_insn && is_store_conditional(emu_insn) && dut_wdata != 0) {
            /* When DUT fails an SC, we must simulate the same behavior */
            iregno = emu_insn >> 7 & 0x1f;
            if (iregno > 0)
                riscv_set_reg(s, iregno, dut_wdata);
            riscv_set_pc(s, emu_pc + 4);
            break;
        }

        if (r->common.pending_interrupt != -1 && r->common.pending_exception != -1) {
            /* On the DUT, the interrupt can race the exception.
               Let's try to match that behavior */

            fprintf(dromajo_stderr, "[DEBUG] DUT also raised exception %d\n", r->common.pending_exception);
            riscv_cpu_interp64(s, 1);  // Advance into the exception

            int cause = s->priv == PRV_S ? s->scause : s->mcause;

            if (r->common.pending_exception != cause) {
                char priv = s->priv["US?M"];

                /* Unfortunately, handling the error case is awkward,
                 * so we just exit from here */

                fprintf(dromajo_stderr, "%d 0x%016" PRIx64 " ", emu_priv, emu_pc);
                fprintf(dromajo_stderr, "(0x%08x) ", emu_insn);
                fprintf(dromajo_stderr,
                        "[error] EMU %cCAUSE %d != DUT %cCAUSE %d\n",
                        priv,
                        cause,
                        priv,
                        r->common.pending_exception);

                return 0x1FFF;
            }
        }

        if (r->common.pending_interrupt != -1) {
            riscv_cpu_set_mip(s, riscv_cpu_get_mip(s) | 1 << r->common.pending_interrupt);
            fprintf(dromajo_stderr,
                    "[DEBUG] Interrupt: MIP <- %d: Now MIP = %x\n",
                    r->common.pending_interrupt,
                    riscv_cpu_get_mip(s));
        }

        if (riscv_cpu_interp64(s, 1) != 0) {
            iregno = riscv_get_most_recently_written_reg(s);
            fregno = riscv_get_most_recently_written_fp_reg(s);

            //// ABE: I think this is the solution
            // r->common.pending_interrupt = -1;
            // r->common.pending_exception = -1;

            break;
        }

        r->common.pending_interrupt = -1;
        r->common.pending_exception = -1;
    }

#ifdef GOLDMEM_INORDER
    bool do_clw = (dut_insn & 0x3) == 0 && (dut_insn & 0xe000) == 0x4000;
    bool do_cld = (dut_insn & 0x3) == 0 && (dut_insn & 0xe000) == 0x6000;
    bool do_csw = (dut_insn & 0x3) == 0 && (dut_insn & 0xe000) == 0xC000;
    bool do_csd = (dut_insn & 0x3) == 0 && (dut_insn & 0xe000) == 0xe000;

    bool do_clwsp = (dut_insn & 0x3) == 2 && (dut_insn & 0xe000) == 0x4000;
    bool do_cldsp = (dut_insn & 0x3) == 2 && (dut_insn & 0xe000) == 0x6000;
    bool do_cswsp = (dut_insn & 0x3) == 2 && (dut_insn & 0xe000) == 0xC000;
    bool do_csdsp = (dut_insn & 0x3) == 2 && (dut_insn & 0xe000) == 0xe000;

    bool do_ld  = (dut_insn & 0x7F) == 0x03 || (dut_insn & 0x7F) == 0x07;
    bool do_ist = (dut_insn & 0x7F) == 0x23;
    bool do_fst = (dut_insn & 0x7F) == 0x27;
    bool do_amo = (dut_insn & 0x7F) == 0x2F;
    if (do_fst || do_ist || do_ld || do_amo) {
        uint8_t func3 = (dut_insn >> 12) & 0x7;
        int     sz    = 0;
        switch (func3) {
            case 0: sz = 1; break;
            case 1: sz = 2; break;
            case 2: sz = 4; break;
            case 3: sz = 8; break;
            case 4: sz = 1; break;
            case 5: sz = 2; break;
            case 6: sz = 4; break;
            default: sz = 0;
        }

        uint64_t         paddr  = s->last_data_paddr;
        PhysMemoryRange *pr     = get_phys_mem_range(s->mem_map, paddr);
        bool             io_map = !pr || !pr->is_ram;
        if (do_ld) {
            check_inorder_load(hartid, paddr, sz, dut_wdata, io_map);
        } else if (do_ist || do_fst) {
            uint64_t data = 0;
            uint8_t  rs2  = (dut_insn >> 20) & 0x1f;
            if (do_ist) {
                data = riscv_get_reg(s, rs2);
            } else {
                data = riscv_get_fpreg(s, rs2);
            }

            // Track same thing in two different ways (needed for atomics)
            assert(data == s->last_data_value);

            check_inorder_store(hartid, paddr, sz, data, io_map);
        } else if (do_amo) {
            uint8_t func5 = (dut_insn >> 27) & 0x1F;

            // dut_wdata is the load result in DUT
            uint8_t  rd          = (dut_insn >> 7) & 0x1f;
            uint64_t amo_rd_data = riscv_get_reg(s, rd);
            assert(dut_wdata == amo_rd_data);

            bool rl = (dut_insn >> 25) & 1;
            bool aq = (dut_insn >> 26) & 1;
            if (rl || aq) {
                fprintf(dromajo_stderr, "FIXME: implement aq/rl in goldmem\n");
            }

            if (func5 == 0x02) {
                fprintf(dromajo_stderr, "FIXME: implement ll in goldmem\n");
                exit(-3);
            } else if (func5 == 3) {
                fprintf(dromajo_stderr, "FIXME: implement sc in goldmem\n");
                exit(-3);
            } else {  // all the other amoadd/amooand/... ops
                check_inorder_amo(hartid, paddr, sz, s->last_data_value, dut_wdata, io_map);
            }
        } else {
            fprintf(dromajo_stderr, "FIXME: unknown opcode with goldmem\n");
            exit(-3);
        }
    } else if (do_clw || do_cld || do_clwsp || do_cldsp) {
        int sz = 4;
        if (do_cld || do_cldsp)
            sz = 8;

        uint64_t         paddr  = s->last_data_paddr;
        PhysMemoryRange *pr     = get_phys_mem_range(s->mem_map, paddr);
        bool             io_map = !pr || !pr->is_ram;

        check_inorder_load(hartid, paddr, sz, dut_wdata, io_map);
    } else if (do_csw || do_csd || do_cswsp || do_csdsp) {
        int sz = 4;
        if (do_csd || do_csdsp)
            sz = 8;

        uint8_t rs2 = (dut_insn >> 2) & 0x1f;
        if (do_csw || do_csd) {
            rs2 = (dut_insn >> 2) & 0x7;
            rs2 += 8;
        }

        uint64_t data = riscv_get_reg(s, rs2);

        uint64_t         paddr  = s->last_data_paddr;
        PhysMemoryRange *pr     = get_phys_mem_range(s->mem_map, paddr);
        bool             io_map = !pr || !pr->is_ram;

        check_inorder_store(hartid, paddr, sz, data, io_map);
    }
#endif

    if (check)
        handle_dut_overrides(s, r->mmio_start, r->mmio_end, emu_priv, emu_pc, emu_insn, emu_wdata, dut_wdata);

    if (verbose) {
        fprintf(dromajo_stderr, "%d 0x%016" PRIx64 " ", emu_priv, emu_pc);
        fprintf(dromajo_stderr, "(0x%08x) ", emu_insn);
    }

    if (iregno > 0) {
        emu_wdata      = riscv_get_reg(s, iregno);
        emu_wrote_data = 1;
        if (verbose)
            fprintf(dromajo_stderr, "x%-2d 0x%016" PRIx64, iregno, emu_wdata);
    } else if (fregno >= 0) {
        emu_wdata      = riscv_get_fpreg(s, fregno);
        emu_wrote_data = 1;
        if (verbose)
            fprintf(dromajo_stderr, "f%-2d 0x%016" PRIx64, fregno, emu_wdata);
    } else if (verbose)
        fprintf(dromajo_stderr, "                      ");

    if (verbose)
        fprintf(dromajo_stderr, " DASM(0x%08x)\n", emu_insn);

    if (!check)
        return 0;

    uint64_t emu_mstatus = riscv_cpu_get_mstatus(s);

    /*
     * XXX We currently do not compare mstatus because DUT's mstatus
     * varies between pre-commit (all FP instructions) and post-commit
     * (CSR instructions).
     */
    if (emu_pc != dut_pc || emu_insn != dut_insn && (emu_insn & 3) == 3 ||  // DUT expands all C instructions
        emu_wdata != dut_wdata && emu_wrote_data) {
        fprintf(dromajo_stderr, "[error] EMU PC %016" PRIx64 ", DUT PC %016" PRIx64 "\n", emu_pc, dut_pc);
        fprintf(dromajo_stderr, "[error] EMU INSN %08x, DUT INSN %08x\n", emu_insn, dut_insn);
        if (emu_wrote_data)
            fprintf(dromajo_stderr, "[error] EMU WDATA %016" PRIx64 ", DUT WDATA %016" PRIx64 "\n", emu_wdata, dut_wdata);
        fprintf(dromajo_stderr, "[error] EMU MSTATUS %08" PRIx64 ", DUT MSTATUS %08" PRIx64 "\n", emu_mstatus, dut_mstatus);
        fprintf(dromajo_stderr,
                "[error] DUT pending exception %d pending interrupt %d\n",
                r->common.pending_exception,
                r->common.pending_interrupt);
        exit_code = 0x1FFF;
    }

    riscv_cpu_sync_regs(s);

    if (exit_code == 0)
        riscv_cpu_sync_regs(s);

    return exit_code;
}

/*
 * dromajo_cosim_override_mem --
 *
 * DUT sets Dromajo memory. Used so that other devices (i.e. block device, accelerators, can write to memory).
 */
int dromajo_cosim_override_mem(dromajo_cosim_state_t *state, int hartid, uint64_t dut_paddr, uint64_t dut_val, int size_log2) {
    RISCVMachine * r = (RISCVMachine *)state;
    RISCVCPUState *s = r->cpu_state[hartid];

    uint8_t *        ptr;
    target_ulong     offset;
    PhysMemoryRange *pr = get_phys_mem_range(s->mem_map, dut_paddr);

    if (!pr) {
#ifdef DUMP_INVALID_MEM_ACCESS
        fprintf(dromajo_stderr, "riscv_cpu_write_memory: invalid physical address 0x%016" PRIx64 "\n", dut_paddr);
#endif
        return 1;
    } else if (pr->is_ram) {
        phys_mem_set_dirty_bit(pr, dut_paddr - pr->addr);
        ptr = pr->phys_mem + (uintptr_t)(dut_paddr - pr->addr);
        switch (size_log2) {
            case 0: *(uint8_t *)ptr = dut_val; break;
            case 1: *(uint16_t *)ptr = dut_val; break;
            case 2: *(uint32_t *)ptr = dut_val; break;
#if MLEN >= 64
            case 3: *(uint64_t *)ptr = dut_val; break;
#endif
#if MLEN >= 128
            case 4: *(uint128_t *)ptr = dut_val; break;
#endif
            default: abort();
        }
    } else {
        offset = dut_paddr - pr->addr;
        if (((pr->devio_flags >> size_log2) & 1) != 0) {
            pr->write_func(pr->opaque, offset, dut_val, size_log2);
        }
#if MLEN >= 64
        else if ((pr->devio_flags & DEVIO_SIZE32) && size_log2 == 3) {
            /* emulate 64 bit access */
            pr->write_func(pr->opaque, offset, dut_val & 0xffffffff, 2);
            pr->write_func(pr->opaque, offset + 4, (dut_val >> 32) & 0xffffffff, 2);
        }
#endif
        else {
#ifdef DUMP_INVALID_MEM_ACCESS
            fprintf(dromajo_stderr,
                    "unsupported device write access: addr=0x%016" PRIx64 "  width=%d bits\n",
                    dut_paddr,
                    1 << (3 + size_log2));
#endif
        }
    }
    return 0;
}
