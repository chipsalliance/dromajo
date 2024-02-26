/*
 * Test Issue "fcvt.s.w cannot handle input 0x80000000 correctly #77"
 */

        .file   "regress-compress.c"
        .option nopic
        .section .text.startup,"ax",@progbits
        .globl  _start
        .type   _start, @function


_start:
        // Enable FP and clear flags
        lui      a0,2
        csrs     mstatus,a0
        csrwi    fcsr,0

        li       t0, 0x80000000
        fcvt.s.w f0, t0
        fmv.x.w  t1, f0

	// We only currently check this one
        li       t0, 0x80000000
        fcvt.d.w f0, t0
        fmv.x.d  t2, f0

        la      t1, tohost

        // Expected output 
        li       a2, 0xc1e0000000000000
        beq      t2, a2, got_0xc1e0000000000000

        // Faulty output
        li       a2, 0x8000000000000000
        beq      t2, a2, got_0x8000000000000000

        // Got something else
        li      t0, 3
        sh      t0, 0(t1)
0:      j       0b

got_0xc1e0000000000000:
        li      t0, 1           // Success (0 * 2 + 1)
        sh      t0, 0(t1)
0:      j       0b

got_0x8000000000000000:
        li      t0, 5
        sh      t0, 0(t1)
0:      j       0b

        .size   _start, .-_start

        .section ".tohost","aw",@progbits
        .align 6
        .globl tohost
        tohost: .dword 0
        .align 6
        .globl fromhost
        fromhost: .dword 0
