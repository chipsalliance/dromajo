/*
 * RISCV emulator
 * 
 * Copyright (c) 2016 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#if XLEN == 32
#define uintx_t uint32_t
#define intx_t int32_t
#elif XLEN == 64
#define uintx_t uint64_t
#define intx_t int64_t
#elif XLEN == 128
#define uintx_t uint128_t
#define intx_t int128_t
#else
#error unsupported XLEN
#endif

static inline intx_t glue(div, XLEN)(intx_t a, intx_t b)
{
    if (b == 0) {
        return -1;
    } else if (a == ((intx_t)1 << (XLEN - 1)) && b == -1) {
        return a;
    } else {
        return a / b;
    }
}

static inline uintx_t glue(divu, XLEN)(uintx_t a, uintx_t b)
{
    if (b == 0) {
        return -1;
    } else {
        return a / b;
    }
}

static inline intx_t glue(rem, XLEN)(intx_t a, intx_t b)
{
    if (b == 0) {
        return a;
    } else if (a == ((intx_t)1 << (XLEN - 1)) && b == -1) {
        return 0;
    } else {
        return a % b;
    }
}

static inline uintx_t glue(remu, XLEN)(uintx_t a, uintx_t b)
{
    if (b == 0) {
        return a;
    } else {
        return a % b;
    }
}

#if XLEN == 32

static inline uint32_t mulh32(int32_t a, int32_t b)
{
    return ((int64_t)a * (int64_t)b) >> 32;
}

static inline uint32_t mulhsu32(int32_t a, uint32_t b)
{
    return ((int64_t)a * (int64_t)b) >> 32;
}

static inline uint32_t mulhu32(uint32_t a, uint32_t b)
{
    return ((int64_t)a * (int64_t)b) >> 32;
}

#elif XLEN == 64 && defined(HAVE_INT128)

static inline uint64_t mulh64(int64_t a, int64_t b)
{
    return ((int128_t)a * (int128_t)b) >> 64;
}

static inline uint64_t mulhsu64(int64_t a, uint64_t b)
{
    return ((int128_t)a * (int128_t)b) >> 64;
}

static inline uint64_t mulhu64(uint64_t a, uint64_t b)
{
    return ((int128_t)a * (int128_t)b) >> 64;
}

#else

#if XLEN == 64
#define UHALF uint32_t
#define UHALF_LEN 32
#elif XLEN == 128
#define UHALF uint64_t
#define UHALF_LEN 64
#else
#error unsupported XLEN
#endif

static uintx_t glue(mulhu, XLEN)(uintx_t a, uintx_t b)
{
    UHALF a0, a1, b0, b1, r2, r3;
    uintx_t r00, r01, r10, r11, c;
    a0 = a;
    a1 = a >> UHALF_LEN;
    b0 = b;
    b1 = b >> UHALF_LEN;

    r00 = (uintx_t)a0 * (uintx_t)b0;
    r01 = (uintx_t)a0 * (uintx_t)b1;
    r10 = (uintx_t)a1 * (uintx_t)b0;
    r11 = (uintx_t)a1 * (uintx_t)b1;
    
    //    r0 = r00;
    c = (r00 >> UHALF_LEN) + (UHALF)r01 + (UHALF)r10;
    //    r1 = c;
    c = (c >> UHALF_LEN) + (r01 >> UHALF_LEN) + (r10 >> UHALF_LEN) + (UHALF)r11;
    r2 = c;
    r3 = (c >> UHALF_LEN) + (r11 >> UHALF_LEN);

    //    *plow = ((uintx_t)r1 << UHALF_LEN) | r0;
    return ((uintx_t)r3 << UHALF_LEN) | r2;
}

#undef UHALF

static inline uintx_t glue(mulh, XLEN)(intx_t a, intx_t b)
{
    uintx_t r1;
    r1 = glue(mulhu, XLEN)(a, b);
    if (a < 0)
        r1 -= a;
    if (b < 0)
        r1 -= b;
    return r1;
}

static inline uintx_t glue(mulhsu, XLEN)(intx_t a, uintx_t b)
{
    uintx_t r1;
    r1 = glue(mulhu, XLEN)(a, b);
    if (a < 0)
        r1 -= a;
    return r1;
}

#endif

#define DUP2(F, n) F(n) F(n+1)
#define DUP4(F, n) DUP2(F, n) DUP2(F, n + 2)
#define DUP8(F, n) DUP4(F, n) DUP4(F, n + 4)
#define DUP16(F, n) DUP8(F, n) DUP8(F, n + 8)
#define DUP32(F, n) DUP16(F, n) DUP16(F, n + 16)

#define C_QUADRANT(n) \
    case n+(0 << 2): case n+(1 << 2): case n+(2 << 2): case n+(3 << 2): \
    case n+(4 << 2): case n+(5 << 2): case n+(6 << 2): case n+(7 << 2): \
    case n+(8 << 2): case n+(9 << 2): case n+(10 << 2): case n+(11 << 2): \
    case n+(12 << 2): case n+(13 << 2): case n+(14 << 2): case n+(15 << 2): \
    case n+(16 << 2): case n+(17 << 2): case n+(18 << 2): case n+(19 << 2): \
    case n+(20 << 2): case n+(21 << 2): case n+(22 << 2): case n+(23 << 2): \
    case n+(24 << 2): case n+(25 << 2): case n+(26 << 2): case n+(27 << 2): \
    case n+(28 << 2): case n+(29 << 2): case n+(30 << 2): case n+(31 << 2): 

#define GET_PC() (target_ulong)((uintptr_t)code_ptr + code_to_pc_addend)
#define GET_INSN_COUNTER() (insn_counter_addend - s->n_cycles)

#define C_NEXT_INSN code_ptr += 2; break
#define NEXT_INSN code_ptr += 4; break
#define JUMP_INSN do {   \
        code_ptr = NULL;           \
        code_end = NULL;           \
        code_to_pc_addend = s->pc; \
        goto jump_insn;            \
    } while (0)

static void no_inline glue(riscv_cpu_interp_x, XLEN)(RISCVCPUState *s,
                                                   int n_cycles1)
{
    uint32_t opcode, insn, rd, rs1, rs2, funct3;
    int32_t imm, cond, err;
    target_ulong addr, val, val2;
#ifndef USE_GLOBAL_VARIABLES
    uint8_t *code_ptr, *code_end;
    target_ulong code_to_pc_addend;
#endif
    uint64_t insn_counter_addend;
#if FLEN > 0
    uint32_t rs3;
    int32_t rm;
#endif

    if (n_cycles1 == 0)
        return;
    insn_counter_addend = s->insn_counter + n_cycles1;
    s->n_cycles = n_cycles1;

    /* check pending interrupts */
    if (unlikely((s->mip & s->mie) != 0)) {
        if (raise_interrupt(s)) {
            s->n_cycles--; 
            goto done_interp;
        }
    }

    s->pending_exception = -1;
    /* Note: we assume NULL is represented as a zero number */
    code_ptr = NULL;
    code_end = NULL;
    code_to_pc_addend = s->pc;
    
    /* we use a single execution loop to keep a simple control flow
       for emscripten */
    for(;;) {
        if (unlikely(code_ptr >= code_end)) {
            uint32_t tlb_idx;
            uint16_t insn_high;
            target_ulong addr;
            uint8_t *ptr;
            
            s->pc = GET_PC();
            /* we test n_cycles only between blocks so that timer
               interrupts only happen between the blocks. It is
               important to reduce the translated code size. */
            if (unlikely(s->n_cycles <= 0))
                goto the_end;

            /* check pending interrupts */
            if (unlikely((s->mip & s->mie) != 0)) {
                if (raise_interrupt(s)) {
                    s->n_cycles--; 
                    goto the_end;
                }
            }
    
            addr = s->pc;
            tlb_idx = (addr >> PG_SHIFT) & (TLB_SIZE - 1);
            if (likely(s->tlb_code[tlb_idx].vaddr == (addr & ~PG_MASK))) {
                /* TLB match */ 
                ptr = (uint8_t *)(s->tlb_code[tlb_idx].mem_addend +
                                  (uintptr_t)addr);
            } else {
                if (unlikely(target_read_insn_slow(s, &ptr, addr)))
                    goto mmu_exception;
            }
            code_ptr = ptr;
            code_end = ptr + (PG_MASK - 1 - (addr & PG_MASK));
            code_to_pc_addend = addr - (uintptr_t)code_ptr;
            if (unlikely(code_ptr >= code_end)) {
                /* instruction is potentially half way between two
                   pages ? */
                insn = *(uint16_t *)code_ptr;
                if ((insn & 3) == 3) {
                    /* instruction is half way between two pages */
                    if (unlikely(target_read_insn_u16(s, &insn_high, addr + 2)))
                        goto mmu_exception;
                    insn |= insn_high << 16;
                }
            } else {
                insn = get_insn32(code_ptr);
            }
        } else {
            /* fast path */
            insn = get_insn32(code_ptr);
        }
        s->n_cycles--;
#if 0
        if (1) {
#ifdef CONFIG_LOGFILE
            log_printf("pc=0x"); fprint_target_ulong(log_file, GET_PC()); log_printf(" insn=%08x\n", insn);
            fflush(log_file);
#else
            printf("pc=0x"); print_target_ulong(GET_PC()); printf(" insn=%08x\n", insn);
            //            dump_regs(s);
#endif
        }
#endif
        opcode = insn & 0x7f;
        rd = (insn >> 7) & 0x1f;
        rs1 = (insn >> 15) & 0x1f;
        rs2 = (insn >> 20) & 0x1f;
        switch(opcode) {
#ifdef CONFIG_EXT_C
        C_QUADRANT(0)
            funct3 = (insn >> 13) & 7;
            rd = ((insn >> 2) & 7) | 8;
            switch(funct3) {
            case 0: /* c.addi4spn */
                imm = get_field1(insn, 11, 4, 5) |
                    get_field1(insn, 7, 6, 9) |
                    get_field1(insn, 6, 2, 2) |
                    get_field1(insn, 5, 3, 3);
                if (imm == 0)
                    goto illegal_insn;
                s->reg[rd] = (intx_t)(s->reg[2] + imm);
                break;
#if XLEN >= 128
            case 1: /* c.lq */
                imm = get_field1(insn, 11, 4, 5) |
                    get_field1(insn, 10, 8, 8) |
                    get_field1(insn, 5, 6, 7);
                rs1 = ((insn >> 7) & 7) | 8;
                addr = (intx_t)(s->reg[rs1] + imm);
                if (target_read_u128(s, &val, addr))
                    goto mmu_exception;
                s->reg[rd] = val;
                break;
#elif FLEN >= 64
            case 1: /* c.fld */
                {
                    uint64_t rval;
                    if (s->fs == 0)
                        goto illegal_insn;
                    imm = get_field1(insn, 10, 3, 5) |
                        get_field1(insn, 5, 6, 7);
                    rs1 = ((insn >> 7) & 7) | 8;
                    addr = (intx_t)(s->reg[rs1] + imm);
                    if (target_read_u64(s, &rval, addr))
                        goto mmu_exception;
                    s->fp_reg[rd] = rval | F64_HIGH;
                    s->fs = 3;
                }
                break;
#endif
            case 2: /* c.lw */
                {
                    uint32_t rval;
                    imm = get_field1(insn, 10, 3, 5) |
                        get_field1(insn, 6, 2, 2) |
                        get_field1(insn, 5, 6, 6);
                    rs1 = ((insn >> 7) & 7) | 8;
                    addr = (intx_t)(s->reg[rs1] + imm);
                    if (target_read_u32(s, &rval, addr))
                        goto mmu_exception;
                    s->reg[rd] = (int32_t)rval;
                }
                break;
#if XLEN >= 64
            case 3: /* c.ld */
                {
                    uint64_t rval;
                    imm = get_field1(insn, 10, 3, 5) |
                        get_field1(insn, 5, 6, 7);
                    rs1 = ((insn >> 7) & 7) | 8;
                    addr = (intx_t)(s->reg[rs1] + imm);
                    if (target_read_u64(s, &rval, addr))
                        goto mmu_exception;
                    s->reg[rd] = (int64_t)rval;
                }
                break;
#elif FLEN >= 32
            case 3: /* c.flw */
                {
                    uint32_t rval;
                    if (s->fs == 0)
                        goto illegal_insn;
                    imm = get_field1(insn, 10, 3, 5) |
                        get_field1(insn, 6, 2, 2) |
                        get_field1(insn, 5, 6, 6);
                    rs1 = ((insn >> 7) & 7) | 8;
                    addr = (intx_t)(s->reg[rs1] + imm);
                    if (target_read_u32(s, &rval, addr))
                        goto mmu_exception;
                    s->fp_reg[rd] = rval | F32_HIGH;
                    s->fs = 3;
                }
                break;
#endif
#if XLEN >= 128
            case 5: /* c.sq */
                imm = get_field1(insn, 11, 4, 5) |
                    get_field1(insn, 10, 8, 8) |
                    get_field1(insn, 5, 6, 7);
                rs1 = ((insn >> 7) & 7) | 8;
                addr = (intx_t)(s->reg[rs1] + imm);
                val = s->reg[rd];
                if (target_write_u128(s, addr, val))
                    goto mmu_exception;
                break;
#elif FLEN >= 64
            case 5: /* c.fsd */
                if (s->fs == 0)
                    goto illegal_insn;
                imm = get_field1(insn, 10, 3, 5) |
                    get_field1(insn, 5, 6, 7);
                rs1 = ((insn >> 7) & 7) | 8;
                addr = (intx_t)(s->reg[rs1] + imm);
                if (target_write_u64(s, addr, s->fp_reg[rd]))
                    goto mmu_exception;
                break;
#endif
            case 6: /* c.sw */
                imm = get_field1(insn, 10, 3, 5) |
                    get_field1(insn, 6, 2, 2) |
                    get_field1(insn, 5, 6, 6);
                rs1 = ((insn >> 7) & 7) | 8;
                addr = (intx_t)(s->reg[rs1] + imm);
                val = s->reg[rd];
                if (target_write_u32(s, addr, val))
                    goto mmu_exception;
                break;
#if XLEN >= 64
            case 7: /* c.sd */
                imm = get_field1(insn, 10, 3, 5) |
                    get_field1(insn, 5, 6, 7);
                rs1 = ((insn >> 7) & 7) | 8;
                addr = (intx_t)(s->reg[rs1] + imm);
                val = s->reg[rd];
                if (target_write_u64(s, addr, val))
                    goto mmu_exception;
                break;
#elif FLEN >= 32
            case 7: /* c.fsw */
                if (s->fs == 0)
                    goto illegal_insn;
                imm = get_field1(insn, 10, 3, 5) |
                    get_field1(insn, 6, 2, 2) |
                    get_field1(insn, 5, 6, 6);
                rs1 = ((insn >> 7) & 7) | 8;
                addr = (intx_t)(s->reg[rs1] + imm);
                if (target_write_u32(s, addr, s->fp_reg[rd]))
                    goto mmu_exception;
                break;
#endif
            default:
                goto illegal_insn;
            }
            C_NEXT_INSN;
        C_QUADRANT(1)
            funct3 = (insn >> 13) & 7;
            switch(funct3) {
            case 0: /* c.addi/c.nop */
                if (rd != 0) {
                    imm = sext(get_field1(insn, 12, 5, 5) |
                               get_field1(insn, 2, 0, 4), 6);
                    s->reg[rd] = (intx_t)(s->reg[rd] + imm);
                }
                break;
#if XLEN == 32
            case 1: /* c.jal */
                imm = sext(get_field1(insn, 12, 11, 11) | 
                           get_field1(insn, 11, 4, 4) |
                           get_field1(insn, 9, 8, 9) |
                           get_field1(insn, 8, 10, 10) |
                           get_field1(insn, 7, 6, 6) |
                           get_field1(insn, 6, 7, 7) |
                           get_field1(insn, 3, 1, 3) |
                           get_field1(insn, 2, 5, 5), 12);
                s->reg[1] = GET_PC() + 2;
                s->pc = (intx_t)(GET_PC() + imm);
                JUMP_INSN;
#else
            case 1: /* c.addiw */
                if (rd != 0) {
                    imm = sext(get_field1(insn, 12, 5, 5) |
                               get_field1(insn, 2, 0, 4), 6);
                    s->reg[rd] = (int32_t)(s->reg[rd] + imm);
                }
                break;
#endif
            case 2: /* c.li */
                if (rd != 0) {
                    imm = sext(get_field1(insn, 12, 5, 5) |
                               get_field1(insn, 2, 0, 4), 6);
                    s->reg[rd] = imm;
                }
                break;
            case 3:
                if (rd == 2) {
                    /* c.addi16sp */
                    imm = sext(get_field1(insn, 12, 9, 9) |
                               get_field1(insn, 6, 4, 4) |
                               get_field1(insn, 5, 6, 6) |
                               get_field1(insn, 3, 7, 8) |
                               get_field1(insn, 2, 5, 5), 10);
                    if (imm == 0)
                        goto illegal_insn;
                    s->reg[2] = (intx_t)(s->reg[2] + imm);
                } else if (rd != 0) {
                    /* c.lui */
                    imm = sext(get_field1(insn, 12, 17, 17) |
                               get_field1(insn, 2, 12, 16), 18);
                    s->reg[rd] = imm;
                }
                break;
            case 4: 
                funct3 = (insn >> 10) & 3;
                rd = ((insn >> 7) & 7) | 8;
                switch(funct3) {
                case 0: /* c.srli */ 
                case 1: /* c.srai */ 
                    imm = get_field1(insn, 12, 5, 5) |
                        get_field1(insn, 2, 0, 4);
#if XLEN == 32
                    if (imm & 0x20)
                        goto illegal_insn;
#elif XLEN == 128
                    if (imm == 0)
                        imm = 64;
                    else if (imm >= 32)
                        imm = 128 - imm;
#endif
                    if (funct3 == 0)
                        s->reg[rd] = (intx_t)((uintx_t)s->reg[rd] >> imm);
                    else
                        s->reg[rd] = (intx_t)s->reg[rd] >> imm;
                    
                    break;
                case 2: /* c.andi */
                    imm = sext(get_field1(insn, 12, 5, 5) |
                               get_field1(insn, 2, 0, 4), 6);
                    s->reg[rd] &= imm;
                    break;
                case 3: 
                    rs2 = ((insn >> 2) & 7) | 8;
                    funct3 = ((insn >> 5) & 3) | ((insn >> (12 - 2)) & 4);
                    switch(funct3) {
                    case 0: /* c.sub */
                        s->reg[rd] = (intx_t)(s->reg[rd] - s->reg[rs2]);
                        break;
                    case 1: /* c.xor */
                        s->reg[rd] = s->reg[rd] ^ s->reg[rs2];
                        break;
                    case 2: /* c.or */
                        s->reg[rd] = s->reg[rd] | s->reg[rs2];
                        break;
                    case 3: /* c.and */
                        s->reg[rd] = s->reg[rd] & s->reg[rs2];
                        break;
#if XLEN >= 64
                    case 4: /* c.subw */
                        s->reg[rd] = (int32_t)(s->reg[rd] - s->reg[rs2]);
                        break;
                    case 5: /* c.addw */
                        s->reg[rd] = (int32_t)(s->reg[rd] + s->reg[rs2]);
                        break;
#endif
                    default:
                        goto illegal_insn;
                    }
                    break;
                }
                break;
            case 5: /* c.j */
                imm = sext(get_field1(insn, 12, 11, 11) | 
                           get_field1(insn, 11, 4, 4) |
                           get_field1(insn, 9, 8, 9) |
                           get_field1(insn, 8, 10, 10) |
                           get_field1(insn, 7, 6, 6) |
                           get_field1(insn, 6, 7, 7) |
                           get_field1(insn, 3, 1, 3) |
                           get_field1(insn, 2, 5, 5), 12);
                s->pc = (intx_t)(GET_PC() + imm);
                JUMP_INSN;
            case 6: /* c.beqz */
                rs1 = ((insn >> 7) & 7) | 8;
                imm = sext(get_field1(insn, 12, 8, 8) | 
                           get_field1(insn, 10, 3, 4) |
                           get_field1(insn, 5, 6, 7) |
                           get_field1(insn, 3, 1, 2) |
                           get_field1(insn, 2, 5, 5), 9);
                if (s->reg[rs1] == 0) {
                    s->pc = (intx_t)(GET_PC() + imm);
                    JUMP_INSN;
                }
                break;
            case 7: /* c.bnez */
                rs1 = ((insn >> 7) & 7) | 8;
                imm = sext(get_field1(insn, 12, 8, 8) | 
                           get_field1(insn, 10, 3, 4) |
                           get_field1(insn, 5, 6, 7) |
                           get_field1(insn, 3, 1, 2) |
                           get_field1(insn, 2, 5, 5), 9);
                if (s->reg[rs1] != 0) {
                    s->pc = (intx_t)(GET_PC() + imm);
                    JUMP_INSN;
                }
                break;
            default:
                goto illegal_insn;
            }
            C_NEXT_INSN;
        C_QUADRANT(2)
            funct3 = (insn >> 13) & 7;
            rs2 = (insn >> 2) & 0x1f;
            switch(funct3) {
            case 0: /* c.slli */
                imm = get_field1(insn, 12, 5, 5) | rs2;
#if XLEN == 32
                if (imm & 0x20)
                    goto illegal_insn;
#elif XLEN == 128
                if (imm == 0)
                    imm = 64;
#endif
                if (rd != 0)
                    s->reg[rd] = (intx_t)(s->reg[rd] << imm);
                break;
#if XLEN == 128
            case 1: /* c.lqsp */
                imm = get_field1(insn, 12, 5, 5) |
                    (rs2 & (1 << 4)) |
                    get_field1(insn, 2, 6, 9);
                addr = (intx_t)(s->reg[2] + imm);
                if (target_read_u128(s, &val, addr))
                    goto mmu_exception;
                if (rd != 0)
                    s->reg[rd] = val;
                break;
#elif FLEN >= 64
            case 1: /* c.fldsp */
                {
                    uint64_t rval;
                    if (s->fs == 0)
                        goto illegal_insn;
                    imm = get_field1(insn, 12, 5, 5) |
                        (rs2 & (3 << 3)) |
                        get_field1(insn, 2, 6, 8);
                    addr = (intx_t)(s->reg[2] + imm);
                    if (target_read_u64(s, &rval, addr))
                        goto mmu_exception;
                    s->fp_reg[rd] = rval | F64_HIGH;
                    s->fs = 3;
                }
                break;
#endif
            case 2: /* c.lwsp */
                {
                    uint32_t rval;
                    imm = get_field1(insn, 12, 5, 5) |
                        (rs2 & (7 << 2)) |
                        get_field1(insn, 2, 6, 7);
                    addr = (intx_t)(s->reg[2] + imm);
                    if (target_read_u32(s, &rval, addr))
                        goto mmu_exception;
                    if (rd != 0)
                        s->reg[rd] = (int32_t)rval;
                }
                break;
#if XLEN >= 64
            case 3: /* c.ldsp */
                {
                    uint64_t rval;
                    imm = get_field1(insn, 12, 5, 5) |
                        (rs2 & (3 << 3)) |
                        get_field1(insn, 2, 6, 8);
                    addr = (intx_t)(s->reg[2] + imm);
                    if (target_read_u64(s, &rval, addr))
                        goto mmu_exception;
                    if (rd != 0)
                        s->reg[rd] = (int64_t)rval;
                }
                break;
#elif FLEN >= 32
            case 3: /* c.flwsp */
                {
                    uint32_t rval;
                    if (s->fs == 0)
                        goto illegal_insn;
                    imm = get_field1(insn, 12, 5, 5) |
                        (rs2 & (7 << 2)) |
                        get_field1(insn, 2, 6, 7);
                    addr = (intx_t)(s->reg[2] + imm);
                    if (target_read_u32(s, &rval, addr))
                        goto mmu_exception;
                    s->fp_reg[rd] = rval | F32_HIGH;
                    s->fs = 3;
                }
                break;
#endif
            case 4:
                if (((insn >> 12) & 1) == 0) {
                    if (rs2 == 0) {
                        /* c.jr */
                        if (rd == 0)
                            goto illegal_insn;
                        s->pc = s->reg[rd] & ~1;
                        JUMP_INSN;
                    } else {
                        /* c.mv */
                        if (rd != 0)
                            s->reg[rd] = s->reg[rs2];
                    }
                } else {
                    if (rs2 == 0) {
                        if (rd == 0) {
                            /* c.ebreak */
                            s->pending_exception = CAUSE_BREAKPOINT;
                            goto exception;
                        } else {
                            /* c.jalr */
                            val = GET_PC() + 2;
                            s->pc = s->reg[rd] & ~1;
                            s->reg[1] = val;
                            JUMP_INSN;
                        }
                    } else {
                        if (rd != 0) {
                            s->reg[rd] = (intx_t)(s->reg[rd] + s->reg[rs2]);
                        }
                    }
                }
                break;
#if XLEN == 128
            case 5: /* c.sqsp */
                imm = get_field1(insn, 10, 3, 5) |
                    get_field1(insn, 7, 6, 8);
                addr = (intx_t)(s->reg[2] + imm);
                if (target_write_u128(s, addr, s->reg[rs2]))
                    goto mmu_exception;
                break;
#elif FLEN >= 64
            case 5: /* c.fsdsp */
                if (s->fs == 0)
                    goto illegal_insn;
                imm = get_field1(insn, 10, 3, 5) |
                    get_field1(insn, 7, 6, 8);
                addr = (intx_t)(s->reg[2] + imm);
                if (target_write_u64(s, addr, s->fp_reg[rs2]))
                    goto mmu_exception;
                break;
#endif 
            case 6: /* c.swsp */
                imm = get_field1(insn, 9, 2, 5) |
                    get_field1(insn, 7, 6, 7);
                addr = (intx_t)(s->reg[2] + imm);
                if (target_write_u32(s, addr, s->reg[rs2]))
                    goto mmu_exception;
                break;
#if XLEN >= 64
            case 7: /* c.sdsp */
                imm = get_field1(insn, 10, 3, 5) |
                    get_field1(insn, 7, 6, 8);
                addr = (intx_t)(s->reg[2] + imm);
                if (target_write_u64(s, addr, s->reg[rs2]))
                    goto mmu_exception;
                break;
#elif FLEN >= 32
            case 7: /* c.swsp */
                if (s->fs == 0)
                    goto illegal_insn;
                imm = get_field1(insn, 9, 2, 5) |
                    get_field1(insn, 7, 6, 7);
                addr = (intx_t)(s->reg[2] + imm);
                if (target_write_u32(s, addr, s->fp_reg[rs2]))
                    goto mmu_exception;
                break;
#endif
            default:
                goto illegal_insn;
            }
            C_NEXT_INSN;
#endif /* CONFIG_EXT_C */

        case 0x37: /* lui */
            if (rd != 0)
                s->reg[rd] = (int32_t)(insn & 0xfffff000);
            NEXT_INSN;
        case 0x17: /* auipc */
            if (rd != 0)
                s->reg[rd] = (intx_t)(GET_PC() + (int32_t)(insn & 0xfffff000));
            NEXT_INSN;
        case 0x6f: /* jal */
            imm = ((insn >> (31 - 20)) & (1 << 20)) |
                ((insn >> (21 - 1)) & 0x7fe) |
                ((insn >> (20 - 11)) & (1 << 11)) |
                (insn & 0xff000);
            imm = (imm << 11) >> 11;
            if (rd != 0)
                s->reg[rd] = GET_PC() + 4;
            s->pc = (intx_t)(GET_PC() + imm);
            JUMP_INSN;
        case 0x67: /* jalr */
            imm = (int32_t)insn >> 20;
            val = GET_PC() + 4;
            s->pc = (intx_t)(s->reg[rs1] + imm) & ~1;
            if (rd != 0)
                s->reg[rd] = val;
            JUMP_INSN;
        case 0x63:
            funct3 = (insn >> 12) & 7;
            switch(funct3 >> 1) {
            case 0: /* beq/bne */
                cond = (s->reg[rs1] == s->reg[rs2]);
                break;
            case 2: /* blt/bge */
                cond = ((target_long)s->reg[rs1] < (target_long)s->reg[rs2]);
                break;
            case 3: /* bltu/bgeu */
                cond = (s->reg[rs1] < s->reg[rs2]);
                break;
            default:
                goto illegal_insn;
            }
            cond ^= (funct3 & 1);
            if (cond) {
                imm = ((insn >> (31 - 12)) & (1 << 12)) |
                    ((insn >> (25 - 5)) & 0x7e0) |
                    ((insn >> (8 - 1)) & 0x1e) |
                    ((insn << (11 - 7)) & (1 << 11));
                imm = (imm << 19) >> 19;
                s->pc = (intx_t)(GET_PC() + imm);
                JUMP_INSN;
            }
            NEXT_INSN;
        case 0x03: /* load */
            funct3 = (insn >> 12) & 7;
            imm = (int32_t)insn >> 20;
            addr = s->reg[rs1] + imm;
            switch(funct3) {
            case 0: /* lb */
                {
                    uint8_t rval;
                    if (target_read_u8(s, &rval, addr))
                        goto mmu_exception;
                    val = (int8_t)rval;
                }
                break;
            case 1: /* lh */
                {
                    uint16_t rval;
                    if (target_read_u16(s, &rval, addr))
                        goto mmu_exception;
                    val = (int16_t)rval;
                }
                break;
            case 2: /* lw */
                {
                    uint32_t rval;
                    if (target_read_u32(s, &rval, addr))
                        goto mmu_exception;
                    val = (int32_t)rval;
                }
                break;
            case 4: /* lbu */
                {
                    uint8_t rval;
                    if (target_read_u8(s, &rval, addr))
                        goto mmu_exception;
                    val = rval;
                }
                break;
            case 5: /* lhu */
                {
                    uint16_t rval;
                    if (target_read_u16(s, &rval, addr))
                        goto mmu_exception;
                    val = rval;
                }
                break;
#if XLEN >= 64
            case 3: /* ld */
                {
                    uint64_t rval;
                    if (target_read_u64(s, &rval, addr))
                        goto mmu_exception;
                    val = (int64_t)rval;
                }
                break;
            case 6: /* lwu */
                {
                    uint32_t rval;
                    if (target_read_u32(s, &rval, addr))
                        goto mmu_exception;
                    val = rval;
                }
                break;
#endif
#if XLEN >= 128
            case 7: /* ldu */
                {
                    uint64_t rval;
                    if (target_read_u64(s, &rval, addr))
                        goto mmu_exception;
                    val = rval;
                }
                break;
#endif
            default:
                goto illegal_insn;
            }
            if (rd != 0)
                s->reg[rd] = val;
            NEXT_INSN;
        case 0x23: /* store */
            funct3 = (insn >> 12) & 7;
            imm = rd | ((insn >> (25 - 5)) & 0xfe0);
            imm = (imm << 20) >> 20;
            addr = s->reg[rs1] + imm;
            val = s->reg[rs2];
            switch(funct3) {
            case 0: /* sb */
                if (target_write_u8(s, addr, val))
                    goto mmu_exception;
                break;
            case 1: /* sh */
                if (target_write_u16(s, addr, val))
                    goto mmu_exception;
                break;
            case 2: /* sw */
                if (target_write_u32(s, addr, val))
                    goto mmu_exception;
                break;
#if XLEN >= 64
            case 3: /* sd */
                if (target_write_u64(s, addr, val))
                    goto mmu_exception;
                break;
#endif
#if XLEN >= 128
            case 4: /* sq */
                if (target_write_u128(s, addr, val))
                    goto mmu_exception;
                break;
#endif
            default:
                goto illegal_insn;
            }
            NEXT_INSN;
        case 0x13:
            funct3 = (insn >> 12) & 7;
            imm = (int32_t)insn >> 20;
            switch(funct3) {
            case 0: /* addi */
                val = (intx_t)(s->reg[rs1] + imm);
                break;
            case 1: /* slli */
                if ((imm & ~(XLEN - 1)) != 0)
                    goto illegal_insn;
                val = (intx_t)(s->reg[rs1] << (imm & (XLEN - 1)));
                break;
            case 2: /* slti */
                val = (target_long)s->reg[rs1] < (target_long)imm;
                break;
            case 3: /* sltiu */
                val = s->reg[rs1] < (target_ulong)imm;
                break;
            case 4: /* xori */
                val = s->reg[rs1] ^ imm;
                break;
            case 5: /* srli/srai */
                if ((imm & ~((XLEN - 1) | 0x400)) != 0)
                    goto illegal_insn;
                if (imm & 0x400)
                    val = (intx_t)s->reg[rs1] >> (imm & (XLEN - 1));
                else
                    val = (intx_t)((uintx_t)s->reg[rs1] >> (imm & (XLEN - 1)));
                break;
            case 6: /* ori */
                val = s->reg[rs1] | imm;
                break;
            default:
            case 7: /* andi */
                val = s->reg[rs1] & imm;
                break;
            }
            if (rd != 0)
                s->reg[rd] = val;
            NEXT_INSN;
#if XLEN >= 64
        case 0x1b:/* OP-IMM-32 */
            funct3 = (insn >> 12) & 7;
            imm = (int32_t)insn >> 20;
            val = s->reg[rs1];
            switch(funct3) {
            case 0: /* addiw */
                val = (int32_t)(val + imm);
                break;
            case 1: /* slliw */
                if ((imm & ~31) != 0)
                    goto illegal_insn;
                val = (int32_t)(val << (imm & 31));
                break;
            case 5: /* srliw/sraiw */
                if ((imm & ~(31 | 0x400)) != 0)
                    goto illegal_insn;
                if (imm & 0x400)
                    val = (int32_t)val >> (imm & 31);
                else
                    val = (int32_t)((uint32_t)val >> (imm & 31));
                break;
            default:
                goto illegal_insn;
            }
            if (rd != 0)
                s->reg[rd] = val;
            NEXT_INSN;
#endif
#if XLEN >= 128
        case 0x5b: /* OP-IMM-64 */
            funct3 = (insn >> 12) & 7;
            imm = (int32_t)insn >> 20;
            val = s->reg[rs1];
            switch(funct3) {
            case 0: /* addid */
                val = (int64_t)(val + imm);
                break;
            case 1: /* sllid */
                if ((imm & ~63) != 0)
                    goto illegal_insn;
                val = (int64_t)(val << (imm & 63));
                break;
            case 5: /* srlid/sraid */
                if ((imm & ~(63 | 0x400)) != 0)
                    goto illegal_insn;
                if (imm & 0x400)
                    val = (int64_t)val >> (imm & 63);
                else
                    val = (int64_t)((uint64_t)val >> (imm & 63));
                break;
            default:
                goto illegal_insn;
            }
            if (rd != 0)
                s->reg[rd] = val;
            NEXT_INSN;
#endif
        case 0x33:
            imm = insn >> 25;
            val = s->reg[rs1];
            val2 = s->reg[rs2];
            if (imm == 1) {
                funct3 = (insn >> 12) & 7;
                switch(funct3) {
                case 0: /* mul */
                    val = (intx_t)((intx_t)val * (intx_t)val2);
                    break;
                case 1: /* mulh */
                    val = (intx_t)glue(mulh, XLEN)(val, val2);
                    break;
                case 2:/* mulhsu */
                    val = (intx_t)glue(mulhsu, XLEN)(val, val2);
                    break;
                case 3:/* mulhu */
                    val = (intx_t)glue(mulhu, XLEN)(val, val2);
                    break;
                case 4:/* div */
                    val = glue(div, XLEN)(val, val2);
                    break;
                case 5:/* divu */
                    val = (intx_t)glue(divu, XLEN)(val, val2);
                    break;
                case 6:/* rem */
                    val = glue(rem, XLEN)(val, val2);
                    break;
                case 7:/* remu */
                    val = (intx_t)glue(remu, XLEN)(val, val2);
                    break;
                default:
                    goto illegal_insn;
                }
            } else {
                if (imm & ~0x20)
                    goto illegal_insn;
                funct3 = ((insn >> 12) & 7) | ((insn >> (30 - 3)) & (1 << 3));
                switch(funct3) {
                case 0: /* add */
                    val = (intx_t)(val + val2);
                    break;
                case 0 | 8: /* sub */
                    val = (intx_t)(val - val2);
                    break;
                case 1: /* sll */
                    val = (intx_t)(val << (val2 & (XLEN - 1)));
                    break;
                case 2: /* slt */
                    val = (target_long)val < (target_long)val2;
                    break;
                case 3: /* sltu */
                    val = val < val2;
                    break;
                case 4: /* xor */
                    val = val ^ val2;
                    break;
                case 5: /* srl */
                    val = (intx_t)((uintx_t)val >> (val2 & (XLEN - 1)));
                    break;
                case 5 | 8: /* sra */
                    val = (intx_t)val >> (val2 & (XLEN - 1));
                    break;
                case 6: /* or */
                    val = val | val2;
                    break;
                case 7: /* and */
                    val = val & val2;
                    break;
                default:
                    goto illegal_insn;
                }
            }
            if (rd != 0)
                s->reg[rd] = val;
            NEXT_INSN;
#if XLEN >= 64
        case 0x3b: /* OP-32 */
            imm = insn >> 25;
            val = s->reg[rs1];
            val2 = s->reg[rs2];
            if (imm == 1) {
                funct3 = (insn >> 12) & 7;
                switch(funct3) {
                case 0: /* mulw */
                    val = (int32_t)((int32_t)val * (int32_t)val2);
                    break;
                case 4:/* divw */
                    val = div32(val, val2);
                    break;
                case 5:/* divuw */
                    val = (int32_t)divu32(val, val2);
                    break;
                case 6:/* remw */
                    val = rem32(val, val2);
                    break;
                case 7:/* remuw */
                    val = (int32_t)remu32(val, val2);
                    break;
                default:
                    goto illegal_insn;
                }
            } else {
                if (imm & ~0x20)
                    goto illegal_insn;
                funct3 = ((insn >> 12) & 7) | ((insn >> (30 - 3)) & (1 << 3));
                switch(funct3) {
                case 0: /* addw */
                    val = (int32_t)(val + val2);
                    break;
                case 0 | 8: /* subw */
                    val = (int32_t)(val - val2);
                    break;
                case 1: /* sllw */
                    val = (int32_t)((uint32_t)val << (val2 & 31));
                    break;
                case 5: /* srlw */
                    val = (int32_t)((uint32_t)val >> (val2 & 31));
                    break;
                case 5 | 8: /* sraw */
                    val = (int32_t)val >> (val2 & 31);
                    break;
                default:
                    goto illegal_insn;
                }
            }
            if (rd != 0)
                s->reg[rd] = val;
            NEXT_INSN;
#endif
#if XLEN >= 128
        case 0x7b: /* OP-64 */
            imm = insn >> 25;
            val = s->reg[rs1];
            val2 = s->reg[rs2];
            if (imm == 1) {
                funct3 = (insn >> 12) & 7;
                switch(funct3) {
                case 0: /* muld */
                    val = (int64_t)((int64_t)val * (int64_t)val2);
                    break;
                case 4:/* divd */
                    val = div64(val, val2);
                    break;
                case 5:/* divud */
                    val = (int64_t)divu64(val, val2);
                    break;
                case 6:/* remd */
                    val = rem64(val, val2);
                    break;
                case 7:/* remud */
                    val = (int64_t)remu64(val, val2);
                    break;
                default:
                    goto illegal_insn;
                }
            } else {
                if (imm & ~0x20)
                    goto illegal_insn;
                funct3 = ((insn >> 12) & 7) | ((insn >> (30 - 3)) & (1 << 3));
                switch(funct3) {
                case 0: /* addd */
                    val = (int64_t)(val + val2);
                    break;
                case 0 | 8: /* subd */
                    val = (int64_t)(val - val2);
                    break;
                case 1: /* slld */
                    val = (int64_t)((uint64_t)val << (val2 & 63));
                    break;
                case 5: /* srld */
                    val = (int64_t)((uint64_t)val >> (val2 & 63));
                    break;
                case 5 | 8: /* srad */
                    val = (int64_t)val >> (val2 & 63);
                    break;
                default:
                    goto illegal_insn;
                }
            }
            if (rd != 0)
                s->reg[rd] = val;
            NEXT_INSN;
#endif
        case 0x73:
            funct3 = (insn >> 12) & 7;
            imm = insn >> 20;
            if (funct3 & 4)
                val = rs1;
            else
                val = s->reg[rs1];
            funct3 &= 3;
            switch(funct3) {
            case 1: /* csrrw */
                s->insn_counter = GET_INSN_COUNTER();
                if (csr_read(s, &val2, imm, TRUE))
                    goto illegal_insn;
                val2 = (intx_t)val2;
                err = csr_write(s, imm, val);
                if (err < 0)
                    goto illegal_insn;
                if (rd != 0)
                    s->reg[rd] = val2;
                if (err > 0) {
                    s->pc = GET_PC() + 4;
                    if (err == 2)
                        JUMP_INSN;
                    else
                        goto done_interp;
                }
                break;
            case 2: /* csrrs */
            case 3: /* csrrc */
                s->insn_counter = GET_INSN_COUNTER();
                if (csr_read(s, &val2, imm, (rs1 != 0)))
                    goto illegal_insn;
                val2 = (intx_t)val2;
                if (rs1 != 0) {
                    if (funct3 == 2)
                        val = val2 | val;
                    else
                        val = val2 & ~val;
                    err = csr_write(s, imm, val);
                    if (err < 0)
                        goto illegal_insn;
                } else {
                    err = 0;
                }
                if (rd != 0)
                    s->reg[rd] = val2;
                if (err > 0) {
                    s->pc = GET_PC() + 4;
                    if (err == 2)
                        JUMP_INSN;
                    else
                        goto done_interp;
                }
                break;
            case 0:
                switch(imm) {
                case 0x000: /* ecall */
                    if (insn & 0x000fff80)
                        goto illegal_insn;
                    s->pending_exception = CAUSE_USER_ECALL + s->priv;
                    goto exception;
                case 0x001: /* ebreak */
                    if (insn & 0x000fff80)
                        goto illegal_insn;
                    s->pending_exception = CAUSE_BREAKPOINT;
                    goto exception;
                case 0x102: /* sret */
                    {
                        if (insn & 0x000fff80)
                            goto illegal_insn;
                        if (s->priv < PRV_S)
                            goto illegal_insn;
                        s->pc = GET_PC();
                        handle_sret(s);
                        goto done_interp;
                    }
                    break;
                case 0x302: /* mret */
                    {
                        if (insn & 0x000fff80)
                            goto illegal_insn;
                        if (s->priv < PRV_M)
                            goto illegal_insn;
                        s->pc = GET_PC();
                        handle_mret(s);
                        goto done_interp;
                    }
                    break;
                case 0x105: /* wfi */
                    if (insn & 0x00007f80)
                        goto illegal_insn;
                    if (s->priv == PRV_U)
                        goto illegal_insn;
                    /* go to power down if no enabled interrupts are
                       pending */
                    if ((s->mip & s->mie) == 0) {
                        s->power_down_flag = TRUE;
                        s->pc = GET_PC() + 4;
                        goto done_interp;
                    }
                    break;
                default:
                    if ((imm >> 5) == 0x09) {
                        /* sfence.vma */
                        if (insn & 0x00007f80)
                            goto illegal_insn;
                        if (s->priv == PRV_U)
                            goto illegal_insn;
                        if (rs1 == 0) {
                            tlb_flush_all(s);
                        } else {
                            tlb_flush_vaddr(s, s->reg[rs1]);
                        }
                        /* the current code TLB may have been flushed */
                        s->pc = GET_PC() + 4;
                        JUMP_INSN;
                    } else {
                        goto illegal_insn;
                    }
                    break;
                }
                break;
            default:
                goto illegal_insn;
            }
            NEXT_INSN;
        case 0x0f: /* misc-mem */
            funct3 = (insn >> 12) & 7;
            switch(funct3) {
            case 0: /* fence */
                if (insn & 0xf00fff80)
                    goto illegal_insn;
                break;
            case 1: /* fence.i */
                if (insn != 0x0000100f)
                    goto illegal_insn;
                break;
#if XLEN >= 128
            case 2: /* lq */
                imm = (int32_t)insn >> 20;
                addr = s->reg[rs1] + imm;
                if (target_read_u128(s, &val, addr))
                    goto mmu_exception;
                if (rd != 0)
                    s->reg[rd] = val;
                break;
#endif
            default:
                goto illegal_insn;
            }
            NEXT_INSN;
        case 0x2f:
            funct3 = (insn >> 12) & 7;
#define OP_A(size)                                                      \
            {                                                           \
                uint ## size ##_t rval;                                 \
                                                                        \
                addr = s->reg[rs1];                                     \
                funct3 = insn >> 27;                                    \
                switch(funct3) {                                        \
                case 2: /* lr.w */                                      \
                    if (rs2 != 0)                                       \
                        goto illegal_insn;                              \
                    if (target_read_u ## size(s, &rval, addr))          \
                        goto mmu_exception;                             \
                    val = (int## size ## _t)rval;                       \
                    s->load_res = addr;                                 \
                    break;                                              \
                case 3: /* sc.w */                                      \
                    if (s->load_res == addr) {                          \
                        if (target_write_u ## size(s, addr, s->reg[rs2])) \
                            goto mmu_exception;                         \
                        val = 0;                                        \
                    } else {                                            \
                        val = 1;                                        \
                    }                                                   \
                    break;                                              \
                case 1: /* amiswap.w */                                 \
                case 0: /* amoadd.w */                                  \
                case 4: /* amoxor.w */                                  \
                case 0xc: /* amoand.w */                                \
                case 0x8: /* amoor.w */                                 \
                case 0x10: /* amomin.w */                               \
                case 0x14: /* amomax.w */                               \
                case 0x18: /* amominu.w */                              \
                case 0x1c: /* amomaxu.w */                              \
                    if (target_read_u ## size(s, &rval, addr))          \
                        goto mmu_exception;                             \
                    val = (int## size ## _t)rval;                       \
                    val2 = s->reg[rs2];                                 \
                    switch(funct3) {                                    \
                    case 1: /* amiswap.w */                             \
                        break;                                          \
                    case 0: /* amoadd.w */                              \
                        val2 = (int## size ## _t)(val + val2);          \
                        break;                                          \
                    case 4: /* amoxor.w */                              \
                        val2 = (int## size ## _t)(val ^ val2);          \
                        break;                                          \
                    case 0xc: /* amoand.w */                            \
                        val2 = (int## size ## _t)(val & val2);          \
                        break;                                          \
                    case 0x8: /* amoor.w */                             \
                        val2 = (int## size ## _t)(val | val2);          \
                        break;                                          \
                    case 0x10: /* amomin.w */                           \
                        if ((int## size ## _t)val < (int## size ## _t)val2) \
                            val2 = (int## size ## _t)val;               \
                        break;                                          \
                    case 0x14: /* amomax.w */                           \
                        if ((int## size ## _t)val > (int## size ## _t)val2) \
                            val2 = (int## size ## _t)val;               \
                        break;                                          \
                    case 0x18: /* amominu.w */                          \
                        if ((uint## size ## _t)val < (uint## size ## _t)val2) \
                            val2 = (int## size ## _t)val;               \
                        break;                                          \
                    case 0x1c: /* amomaxu.w */                          \
                        if ((uint## size ## _t)val > (uint## size ## _t)val2) \
                            val2 = (int## size ## _t)val;               \
                        break;                                          \
                    default:                                            \
                        goto illegal_insn;                              \
                    }                                                   \
                    if (target_write_u ## size(s, addr, val2))          \
                        goto mmu_exception;                             \
                    break;                                              \
                default:                                                \
                    goto illegal_insn;                                  \
                }                                                       \
            }

            switch(funct3) {
            case 2:
                OP_A(32);
                break;
#if XLEN >= 64
            case 3:
                OP_A(64);
                break;
#endif
#if XLEN >= 128
            case 4:
                OP_A(128);
                break;
#endif
            default:
                goto illegal_insn;
            }
            if (rd != 0)
                s->reg[rd] = val;
            NEXT_INSN;
#if FLEN > 0
            /* FPU */
        case 0x07: /* fp load */
            if (s->fs == 0)
                goto illegal_insn;
            funct3 = (insn >> 12) & 7;
            imm = (int32_t)insn >> 20;
            addr = s->reg[rs1] + imm;
            switch(funct3) {
            case 2: /* flw */
                {
                    uint32_t rval;
                    if (target_read_u32(s, &rval, addr))
                        goto mmu_exception;
                    s->fp_reg[rd] = rval | F32_HIGH;
                }
                break;
#if FLEN >= 64
            case 3: /* fld */
                {
                    uint64_t rval;
                    if (target_read_u64(s, &rval, addr))
                        goto mmu_exception;
                    s->fp_reg[rd] = rval | F64_HIGH;
                }
                break;
#endif 
#if FLEN >= 128
            case 4: /* flq */
                {
                    uint128_t rval;
                    if (target_read_u128(s, &rval, addr))
                        goto mmu_exception;
                    s->fp_reg[rd] = rval;
                }
                break;
#endif
            default:
                goto illegal_insn;
            }
            s->fs = 3;
            NEXT_INSN;
        case 0x27: /* fp store */
            if (s->fs == 0)
                goto illegal_insn;
            funct3 = (insn >> 12) & 7;
            imm = rd | ((insn >> (25 - 5)) & 0xfe0);
            imm = (imm << 20) >> 20;
            addr = s->reg[rs1] + imm;
            switch(funct3) {
            case 2: /* fsw */
                if (target_write_u32(s, addr, s->fp_reg[rs2]))
                    goto mmu_exception;
                break;
#if FLEN >= 64
            case 3: /* fsd */
                if (target_write_u64(s, addr, s->fp_reg[rs2]))
                    goto mmu_exception;
                break;
#endif
#if FLEN >= 128
            case 4: /* fsq */
                if (target_write_u128(s, addr, s->fp_reg[rs2]))
                    goto mmu_exception;
                break;
#endif
            default:
                goto illegal_insn;
            }
            NEXT_INSN;
        case 0x43: /* fmadd */
            if (s->fs == 0)
                goto illegal_insn;
            funct3 = (insn >> 25) & 3;
            rs3 = insn >> 27;
            rm = get_insn_rm(s, (insn >> 12) & 7);
            if (rm < 0)
                goto illegal_insn;
            switch(funct3) {
            case 0:
                s->fp_reg[rd] = fma_sf32(s->fp_reg[rs1], s->fp_reg[rs2],
                                         s->fp_reg[rs3], rm, &s->fflags) | F32_HIGH;
                break;
#if FLEN >= 64
            case 1:
                s->fp_reg[rd] = fma_sf64(s->fp_reg[rs1], s->fp_reg[rs2],
                                         s->fp_reg[rs3], rm, &s->fflags) | F64_HIGH;
                break;
#endif
#if FLEN >= 128
            case 3:
                s->fp_reg[rd] = fma_sf128(s->fp_reg[rs1], s->fp_reg[rs2],
                                          s->fp_reg[rs3], rm, &s->fflags);
                break;
#endif
            default:
                goto illegal_insn;
            }
            s->fs = 3;
            NEXT_INSN;
        case 0x47: /* fmsub */
            if (s->fs == 0)
                goto illegal_insn;
            funct3 = (insn >> 25) & 3;
            rs3 = insn >> 27;
            rm = get_insn_rm(s, (insn >> 12) & 7);
            if (rm < 0)
                goto illegal_insn;
            switch(funct3) {
            case 0:
                s->fp_reg[rd] = fma_sf32(s->fp_reg[rs1],
                                         s->fp_reg[rs2],
                                         s->fp_reg[rs3] ^ FSIGN_MASK32,
                                         rm, &s->fflags) | F32_HIGH;
                break;
#if FLEN >= 64
            case 1:
                s->fp_reg[rd] = fma_sf64(s->fp_reg[rs1],
                                         s->fp_reg[rs2],
                                         s->fp_reg[rs3] ^ FSIGN_MASK64,
                                         rm, &s->fflags) | F64_HIGH;
                break;
#endif
#if FLEN >= 128
            case 3:
                s->fp_reg[rd] = fma_sf128(s->fp_reg[rs1],
                                          s->fp_reg[rs2],
                                          s->fp_reg[rs3] ^ FSIGN_MASK128,
                                          rm, &s->fflags);
                break;
#endif
            default:
                goto illegal_insn;
            }
            s->fs = 3;
            NEXT_INSN;
        case 0x4b: /* fnmsub */
            if (s->fs == 0)
                goto illegal_insn;
            funct3 = (insn >> 25) & 3;
            rs3 = insn >> 27;
            rm = get_insn_rm(s, (insn >> 12) & 7);
            if (rm < 0)
                goto illegal_insn;
            switch(funct3) {
            case 0:
                s->fp_reg[rd] = fma_sf32(s->fp_reg[rs1] ^ FSIGN_MASK32,
                                         s->fp_reg[rs2],
                                         s->fp_reg[rs3],
                                         rm, &s->fflags) | F32_HIGH;
                break;
#if FLEN >= 64
            case 1:
                s->fp_reg[rd] = fma_sf64(s->fp_reg[rs1] ^ FSIGN_MASK64,
                                         s->fp_reg[rs2],
                                         s->fp_reg[rs3],
                                         rm, &s->fflags) | F64_HIGH;
                break;
#endif
#if FLEN >= 128
            case 3:
                s->fp_reg[rd] = fma_sf128(s->fp_reg[rs1] ^ FSIGN_MASK128,
                                          s->fp_reg[rs2],
                                          s->fp_reg[rs3],
                                          rm, &s->fflags);
                break;
#endif
            default:
                goto illegal_insn;
            }
            s->fs = 3;
            NEXT_INSN;
        case 0x4f: /* fnmadd */
            if (s->fs == 0)
                goto illegal_insn;
            funct3 = (insn >> 25) & 3;
            rs3 = insn >> 27;
            rm = get_insn_rm(s, (insn >> 12) & 7);
            if (rm < 0)
                goto illegal_insn;
            switch(funct3) {
            case 0:
                s->fp_reg[rd] = fma_sf32(s->fp_reg[rs1] ^ FSIGN_MASK32,
                                         s->fp_reg[rs2],
                                         s->fp_reg[rs3] ^ FSIGN_MASK32,
                                         rm, &s->fflags) | F32_HIGH;
                break;
#if FLEN >= 64
            case 1:
                s->fp_reg[rd] = fma_sf64(s->fp_reg[rs1] ^ FSIGN_MASK64,
                                         s->fp_reg[rs2],
                                         s->fp_reg[rs3] ^ FSIGN_MASK64,
                                         rm, &s->fflags) | F64_HIGH;
                break;
#endif
#if FLEN >= 128
            case 3:
                s->fp_reg[rd] = fma_sf128(s->fp_reg[rs1] ^ FSIGN_MASK128,
                                          s->fp_reg[rs2],
                                          s->fp_reg[rs3] ^ FSIGN_MASK128,
                                          rm, &s->fflags);
                break;
#endif
            default:
                goto illegal_insn;
            }
            s->fs = 3;
            NEXT_INSN;
        case 0x53:
            if (s->fs == 0)
                goto illegal_insn;
            imm = insn >> 25;
            rm = (insn >> 12) & 7;
            switch(imm) {

#define F_SIZE 32
#include "riscv_cpu_fp_template.h"
#if FLEN >= 64
#define F_SIZE 64
#include "riscv_cpu_fp_template.h"
#endif
#if FLEN >= 128
#define F_SIZE 128
#include "riscv_cpu_fp_template.h"
#endif

            default:
                goto illegal_insn;
            }
            NEXT_INSN;
#endif
        default:
            goto illegal_insn;
        }
        /* update PC for next instruction */
    jump_insn: ;
    } /* end of main loop */
 illegal_insn:
    s->pending_exception = CAUSE_ILLEGAL_INSTRUCTION;
    s->pending_tval = insn;
 mmu_exception:
 exception:
    s->pc = GET_PC();
    if (s->pending_exception >= 0) {
        /* Note: the idea is that one exception counts for one cycle. */
        s->n_cycles--; 
        raise_exception2(s, s->pending_exception, s->pending_tval);
    }
    /* we exit because XLEN may have changed */
 done_interp:
the_end:
    s->insn_counter = GET_INSN_COUNTER();
#if 0
    printf("done interp %lx int=%x mstatus=%lx prv=%d\n",
           (uint64_t)s->insn_counter, s->mip & s->mie, (uint64_t)s->mstatus,
           s->priv);
#endif
}

#undef uintx_t
#undef intx_t
#undef XLEN
#undef OP_A
