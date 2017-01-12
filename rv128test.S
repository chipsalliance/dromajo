/*
 * RV128I test
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
/* warning; this file is executed with RV32I, RV64I and RV128I ISA but
   compiled as RV64I */
#define HTIF_TOHOST   0x40008000

.globl _start
        
_start:
        /* set mstatus to a known state and allow FPU usage if available */
        li a0, 1 << 13
        csrw mstatus, a0 
        
        la a0, banner_str
        jal putstring

        /* get the current base isa */
        csrr a0, misa
        bgez a0, rv32_test
        slli a0, a0, 1
        bgez a0, rv64_test

        /* RV128I code */
        la a0, rv128_str
        jal putstring

        li a0,-1
        jal putnum_dec
        
        la a0, lf_str
        jal putstring

        /* FP128 test */
        csrr a0, misa
        li a1, 1 << ('Q' - 'A')
        and a0, a0, a1
        beqz a0, no_fp128

        csrw fcsr, zero
        
        la a0, fp128_str
        jal putstring
        
        li a0, 2
        /* fcvt.q.w fa0, a0 */
        .int (0x1a << 27) | (3 << 25) | (0 << 20) | (10 << 15) | (7 << 12) | (10 << 7) | 0x53
        /* fsqrt.q fa0, fa0 */
        .int (0x0b << 27) | (3 << 25) | (0 << 20) | (10 << 15) | (7 << 12) | (10 << 7) | 0x53
        /* multiply by 1e33 */
        li a0, 100000000000000000
        li a1, 10000000000000000
        mul a1, a1, a0
        /* fcvt.q.tu fa1, a1 */
        .int (0x1a << 27) | (3 << 25) | (5 << 20) | (11 << 15) | (7 << 12) | (11 << 7) | 0x53
        /* fmul.q fa0, fa1, fa0 */
        .int (0x02 << 27) | (3 << 25) | (10 << 20) | (11 << 15) | (7 << 12) | (10 << 7) | 0x53
        
        /* fcvt.tu.q a0, fa0, rtz */
        .int (0x18 << 27) | (3 << 25) | (5 << 20) | (10 << 15) | (1 << 12) | (10 << 7) | 0x53
        jal putnum_dec_fp
        
        la a0, lf_str
        jal putstring
no_fp128:        
        
        /* switch to RV64I */
        li a0, 1
        li a1, 126
        sll a0, a0, a1 /* cannot use slli because no 128 bit support in gas */
        csrrc s0, misa, a0

        /* RV64I code */
rv64_test:      
        la a0, rv64_str
        jal putstring

        li a0,-1
        jal putnum_dec
        
        la a0, lf_str
        jal putstring

        /* FP64 test */
        csrr a0, misa
        andi a0, a0, 1 << ('D' - 'A')
        beqz a0, no_fp64

        csrw fcsr, zero
        
        la a0, fp64_str
        jal putstring
        
        li a0, 2
        fcvt.d.w fa0, a0
        fsqrt.d fa0, fa0
        li a1, 1000000000000000
        fcvt.d.l fa1, a1
        fmul.d fa0, fa1, fa0
        
        fcvt.lu.d a0, fa0, rtz
        jal putnum_dec_fp
        
        la a0, lf_str
        jal putstring
no_fp64:        

        /* switch to RV32I */
        csrr a0, misa
        li a1, 1 << 62
        sub a0, a0, a1
        csrw misa, a0

        /* RV32I code */
rv32_test:
        la a0, rv32_str
        jal putstring

        li a0,-1
        jal putnum_dec
        
        la a0, lf_str
        jal putstring


        /* FP32 test */
        csrr a0, misa
        andi a0, a0, 1 << ('F' - 'A')
        beqz a0, no_fp32

        csrw fcsr, zero
        
        la a0, fp32_str
        jal putstring
        
        li a0, 2
        fcvt.s.w fa0, a0
        fsqrt.s fa0, fa0
        /* multiply by 1e6 */
        lui a1, 0xf4 
        addi a1, a1, 0x240
        fcvt.s.w fa1, a1
        fmul.s fa0, fa1, fa0
        
        fcvt.wu.s a0, fa0, rtz
        jal putnum_dec_fp
        
        la a0, lf_str
        jal putstring

no_fp32:
        j exit

putstring:
        li a2, HTIF_TOHOST
        li a3, (1 << 24) | (1 << 16)
1:      
        lbu a1, (a0)
        beqz a1, 2f
/* Note: we use 32 bit accesses to work in all base isa modes */
        sw a1, 0(a2)
        sw a3, 4(a2)
/* wait until the char is handled */
3:      
        lw a1, 0(a2)
        lw a4, 4(a2)
        or a1, a1, a4
        bnez a1, 3b
        addi a0, a0, 1
        j 1b
2:
        ret

exit:
        li a2, HTIF_TOHOST
        li a1, 1
        sw a1, 0(a2)
        sw zero, 4(a2)
1:
        wfi
        j 1b

# write the number in a0 in base 10
putnum_dec:
        la a1, putnum_buf_end
        li a2, 10
1:
        addi a1, a1, -1
        remu a3, a0, a2
        addi a3, a3, '0'
        sb a3, (a1)
        divu a0, a0, a2
        bnez a0, 1b
        mv a0, a1
        j putstring

# write the number in a0 in base 10 with a decimal point
putnum_dec_fp:
        la a1, putnum_buf_end
        li a2, 10
1:
        remu a3, a0, a2
        addi a3, a3, '0'
        addi a1, a1, -1
        divu a0, a0, a2
        beqz a0, 2f
        sb a3, (a1)
        j 1b
2:      
        li a0, '.'
        sb a0, (a1)
        addi a1, a1, -1
        sb a3, (a1)
        mv a0, a1
        j putstring

        .section ".rodata"
        
banner_str:
        .asciz "RISCV dynamic base ISA change:\n"
rv128_str:
        .asciz "RV128I: max register value="
rv64_str:
        .asciz "RV64I:  max register value="
rv32_str:
        .asciz "RV32I:  max register value="
lf_str:
        .asciz "\n"
fp32_str:
        .asciz "FP32:   sqrt(2)="
fp64_str:
        .asciz "FP64:   sqrt(2)="
fp128_str:
        .asciz "FP128:  sqrt(2)="
        
        .section ".data"
        
putnum_buf:
        .rept 64
        .byte 0
        .endr
putnum_buf_end:
        
