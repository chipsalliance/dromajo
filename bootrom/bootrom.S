//******************************************************************************
// Copyright (C) 2018,2019, Esperanto Technologies Inc.
// The copyright to the computer program(s) herein is the
// property of Esperanto Technologies, Inc. All Rights Reserved.
// The program(s) may be used and/or copied only with
// the written permission of Esperanto Technologies and
// in accordance with the terms and conditions stipulated in the
// agreement/contract under which the program(s) have been supplied.
//------------------------------------------------------------------------------

//========================================================================
// cosim bootrom
//========================================================================
// BootROM code used for the purposes of cosimulation.  Currently, the RTL
// implementation includes a cosimulation configuration which sets the
// processor in debug mode.  The bootrom code essentially sets the debug
// pc and the debug csr register values accordingly to reset the processor
// to the start of the test programs.

        .section .text.init
        .option  norvc
        .globl   _start

_start: csrr     a0, mhartid
        beqz     a0, 1f           // We only allow hart0 to proceed

0:      wfi
        j        0b

1:      la       a1, _start + 256 // DTB is at boot start + 256

        li       s0, 0x603
        csrw     dcsr, s0

        li       s0, MEMORY_START // Start kernel and exit debug
        csrw     dpc, s0
        dret
