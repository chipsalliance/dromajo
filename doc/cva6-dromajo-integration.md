# Tutorial: Integration of Dromajo into Ariane for co-simulation

## Introduction
This tutorial will teach you in 8 steps (with some minor sub-steps 😃), how to integrate dromajo into the RTL implementation of a 64-bit RISCV core for co-simulation purposes. This tutorial will demonstrate the process on a specific example: [Ariane RISC-V CPU](https://github.com/pulp-platform/ariane). Visit the page, for more information on this particular core.

The integration process might be implementation specific. Nevertheless, you should be able to get understanding about the general flow and apply the concepts to your own implementation.

## Overview
### The goal
At the end of this tutorial we want to do the following:
```
make verilate DROMAJO=1
./work-ver/Variane_testharness +checkpoint=./dromajo/snapshots/ds
```
This will run dhrystone code both on Ariane and Dromajo at the same time and perform co-simulation **runtime**.

### Checkpoints/snapshots
One of the features of Dromajo is the ability to create checkpoints. Given any arbitrary binary, we can run Dromajo stand alone for a certain amount of time and dump the whole architectural state of the model into several files. The checkpoint can later be loaded back to Dromajo or any RISCV core implementation. 

**Here is the important point.** The beauty of the checkpoint that it dumps complete architectural state. It generates a boot code. If you were to run that code it will restore the whole architectural state! This means that you can bring any two or more cores into complete synced architectural state by running this piece of code.

### General flow
There are many dirty and clean ways you can integrate dromajo into your design. We recommend to do it in the following way, refer to Figure 1.

![cosim overview](https://user-images.githubusercontent.com/8511359/84510824-7ceb3b80-ac7a-11ea-9530-24c428ee87d9.png)

Figure 1 - Overview of Cosimulation Process

1. Load the binary of interest into Dromajo.
2. Run Dromajo stand alone and let several instructions to complete.
3. Dump the checkpoint.
4. Load the checkpoint into the RTL memory and the instance of Dromajo in RTL.
5. Run the RTL simulation and perform co-simulation.

## Integration
### Step 1: clone Ariane repo and Dromajo repo
```
git clone https://github.com/pulp-platform/ariane.git
git submodule update --init --recursive
cd ariane
git clone https://github.com/chipsalliance/dromajo.git
```

### Step 2: start integration into existing infrastructure
One of the things you might want think about is how you will integrate Dromajo into existing infrastructure. In other words you will have to change your build flow and testbench a bit in a way that will allow the process that is shown in Figure 1 to happen. To be specific, steps 4 and 5.

Of course, we want to make sure that we don't break the existing code. Ariane, for example, has the option to enable tracing (generate .vcd waveform) at build time. You can run `make verilate DEBUG=1` and this will basically make bunch of `#ifdefs` alive and compile simulator with tracing/debug capabilities.

I decided to take the same approach. Next, I will discuss which parts of the Ariane infrastructure you need to change to add `make verilate DROMAJO=1` option. This will enable and disable different parts of the code and compile the simulator with co-simulation enabled. 

At the end, after building with `DROMAJO=1`, we want to be able to simulate Ariane with the following command:
```
./work-ver/Variane_testharness +checkpoint=[path to checkpoint files]
```

Re-building without `DROMAJO=1` should keep the existing infrastructure working.

#### Step 2.1: change Makefile
Find the `verilate_command` in the Makefile. This is the verilator command that generates the simulator. Add the following 2 lines to this command:
```make
$(if $(DROMAJO), -DDROMAJO=1,) \
```
This will define `DROMAJO` in **verilog** code. And change -CFLAGS line:
```
-CFLAGS "$(CFLAGS)$(if $(PROFILE), -g -pg,) $(if $(DROMAJO), -DDROMAJO=1,)" -Wall --cc  --vpi \
```
This will define `DROMAJO` in **tesbench**.

#### Step 2.2: disable HTIF
By default, Ariane supports the classic Berkeley loading of the binary into the core -- through host-target interface. We will disable it and load the binary right into the memory in verilog.

Here are the things you will need to change. View the patch for [tb/ariane_tb.cpp](https://github.com/kabylkas/ariane/commit/e35cec5517160fc23bc349045b1e354cea62b284#diff-a8e87ab36831cb765b7ffed52710187fL46).

### Step 3: add Dromajo to Ariane and keep changing infrastructure
What we will do now is basically number 4 in Figure 1. First, we will be creating an instance of the emulator in the RTL. 
I include Dromajo into Ariane as a submodule. Dromajo is compiled as a shared library and gets linked to verilator or whatever simulator you want to use. Let's do this...

#### Step 3.1: compile Dromajo
```
cd dromajo/src
make
```
This should create `libdromajo_cosim.a`

#### Step 3.2: linking shared library
Edit make file. Find CFLAGS and add:
```
...
-std=c++11 -I../tb/dpi              \
$(if $(DROMAJO),-I../dromajo/src,)
```
Also, find verilate_command, and change this line:
```
-LDFLAGS "-L$(RISCV)/lib -Wl,-rpath,$(RISCV)/lib -lfesvr$(if $(PROFILE), -g -pg,) -lpthread" \
```
to this:
```
-LDFLAGS "-L$(RISCV)/lib -Wl,-rpath,$(RISCV)/lib -lfesvr$(if $(PROFILE), -g -pg,) $(if $(DROMAJO), -L../dromajo/src -ldromajo_cosim,) -lpthread" \
```

#### Step 3.3: DPI functions
After we have linked Dromajo with your simulation infrastructure we will need to write some C code. To be specific, we will write several function in C and call them from verilog through DPI.

There are 2 main functions that we will be calling from verilog:
1. `dromajo_init(char* cfg_f_name)` - creates Dromajo emulator instance. We read a verilog plusargs with the path to the checkpoint files. One of the file should be a cfg file. The example of a cfg file:
```
{
  "version":1,
  "machine":"riscv64",
  "bios": "/mada/software/riscv/riscv64-unknown-elf/share/riscv-tests/benchmarks/dhrystone.riscv",
  "load": "/soe/nkabylka/ariane/dromajo/snapshots/ds",
  "memory_base_addr": 0x80000000,
  "memory_size":256,
  "clint_base_addr": 0x02000000,
  "clint_size": 0xC0000,
  "plic_base_addr": 0x0C000000,
  "plic_size": 0x3FFFFFF,
  "uart_base_addr": 0x10000000,
  "uart_size": 0x1000
} 
```
This file contains all the information needed to initialize the emulator. Some important things to note:
* `load` argument is the path to the memory files that were discussed in earlier sections (bootram and mainram). 
* This file also contains SOC specific information, such as: memory map, memory region sizes, etc.
* This file is subject to changes... we are currently thinking about optimizing some of the things.

2. Second function is `dromajo_step(int hart_id, longint pc, int insn, longint wdata);` - this function is responsible for progressing the emulation every single time RTL commits an instruction.

Here is the link to the file with the implementation of these functions: [tb/dpi/cosim.cc](https://github.com/kabylkas/ariane/blob/master/tb/dpi/cosim.cc). The functions, in turn, call nice Dromajo API funcitons to interface with the emulator. 

We also need to make sure that verilator knows about this functions, so we need to change Makefile again. Find `verilate_command` in Makefile and change this line:
```
tb/dpi/remote_bitbang.cc tb/dpi/msim_helper.cc
```
to this:
```
tb/dpi/remote_bitbang.cc tb/dpi/msim_helper.cc $(if $(DROMAJO), tb/dpi/cosim.cc)
```

### Step 4: loading code into RTL
This is the second part of *number 4* in Figure 1. We somehow need to make sure that whatever Dromajo has in its memory, we need to have same stuff in RTL.

#### Step 4.1: changing (syncing) bootrom
We have already said that Dromajo generates a boot code that restores the architectural state. Guess what, we need to assure that this is the very first thing that Ariane runs. So we need to change the bootrom. Ariane has a bootrom generator script in `ariane/bootrom/` directory. You can tweak the generator python script or you can just take what the script has generated, copy that to separate file and change that. By patching the file that has been generated compared to coding bootrom from scratch will make sure that you didn't screw up the read/write interface. 

Patch is not significant. You just take the path to the hex file that Dromajo generated and load it up to the memory:
```verilog
    initial begin
      integer hex_file, num_bytes;
      longint address, value;
      string f_name;
      // init to 0
      for (int k=0; k<RomSize; k++) begin
        mem[k] = 0;
      end

      // sync with dromajo
      if ($value$plusargs("checkpoint=%s", f_name)) begin
        hex_file = $fopen({f_name,".bootram.hex"}, "r");
        while (!$feof(hex_file)) begin
          num_bytes = $fscanf(hex_file, "%d %h\n", address, value);
          $display("%d %h", address, value);
          mem[address] = value;
        end
        $display("Done syncing RAM with dromajo...\n");
      end else begin
        $display("Dromajo error: provide path to a checkpoint.\n");
      end
    end
```
You can have a look at the file: [bootrom/dromajo_bootrom.sv](https://github.com/kabylkas/ariane/commit/74d6bf8f82b147d7959c3fb8479c8782da7a13be)

#### Step 4.2: small change to testbench
We now need to patch the testbench so that it understands the `+checkpoint=` argument. Check [this](https://github.com/kabylkas/ariane/commit/74d6bf8f82b147d7959c3fb8479c8782da7a13be) patch in `tb/ariane_tb.cpp`

Also, let the testbench bypass the binary check if DROMAJO was defined. Here is the [patch](https://github.com/kabylkas/ariane/commit/0f492c94118c42f733d653beba795acc04190e26).

#### Step 4.3: change test harness
Let's make sure that the bootrom module that we changed gets instantiated.
```verilog
`ifdef DROMAJO
  dromajo_bootrom i_bootrom (
    .clk_i      ( clk_i     ),
    .req_i      ( rom_req   ),
    .addr_i     ( rom_addr  ),
    .rdata_o    ( rom_rdata )
  );
`else
  bootrom i_bootrom (
    .clk_i      ( clk_i     ),
    .req_i      ( rom_req   ),
    .addr_i     ( rom_addr  ),
    .rdata_o    ( rom_rdata )
  );
`endif
```

### Step 5: changing (syncing) main memory
Same thing must be done to the main memory. The RISC-V code that Ariane will be running is in the Dromajo checkpoint. 

#### Step 5.1: changing sram code
Ariane instantiates the sram module that is located in of the submodules for fpga support: `src/fpga-support/rtl/SyncSpRamBeNx64.sv`. This module has already been design with some initialization logic. To be specific, it has `SIM_INIT` parameter. Based on the value, memory will be initialized to all zeros (`SIM_INIT=1`), random (`SIM_INIT=2`), `0xdeadbeef` (`SIM_INIT=3`) or will not be initialized at all (`SIM_INIT=0`). I decided to extend on this logic and add `SIM_INIT=4`. When 4 is set we will read plus arg "+checkpoint" and initialize memory to whatever Dromajo had dumped. You will need to add this piece of code:

```verilog
  initial begin
    if (SIM_INIT == 4) begin
      integer hex_file, num_bytes;
      longint address, value;
      string f_name;
      // init to 0
      for (int k=0; k<DATA_DEPTH; k++) begin
        Mem_DP[k] = 0;
      end

      // sync with dromajo
      if ($value$plusargs("checkpoint=%s", f_name)) begin
        hex_file = $fopen({f_name,".mainram.hex"}, "r");
        while (!$feof(hex_file)) begin
          num_bytes = $fscanf(hex_file, "%d %h\n", address, value);
          $display("%d %h", address, value);
          Mem_DP[address] = value;
        end
        $display("Done syncing RAM with dromajo...\n");
      end else begin
        $display("Failed syncing RAM: provide path to a checkpoint.\n");
      end
    end
  end
```

Also change the reset logic to this:
```verilog
      if(Rst_RBI == 1'b0 && SIM_INIT>0) begin
        if (SIM_INIT<4) begin // <-- this line was added
          for(int k=0; k<DATA_DEPTH;k++) begin
            if(SIM_INIT==1) val = '0;
        `ifndef VERILATOR
            else if(SIM_INIT==2) void'(randomize(val));
        `endif
            else val = 64'hdeadbeefdeadbeef;
            Mem_DP[k] = val;
          end
        end
      end else
....
```

#### Step 5.2: small patch to sram that in upper level of hierarchy 
Since we decided to extend the memory initialization logic, we want to bring SIM_INIT parameter up the hierarchy. See this patch: [src/util/sram.sv](https://github.com/kabylkas/ariane/commit/22948e3ddef2aea8527d6c24fc56b3085c12443c).

Also, now we want to make sure that the sram get instantiated with `parameter SIM_INIT=4` in `tb/ariane_testharness.sv`:
```verilog
  sram #(
    .DATA_WIDTH ( AXI_DATA_WIDTH ),
    `ifdef DROMAJO // <-- this line
    .SIM_INIT(4),  // <-- this line
    `endif         // <-- this line
    .NUM_WORDS  ( NUM_WORDS      )
  ) i_sram (
    .clk_i      ( clk_i 
```
### Step 6: Initializing Dromajo in RTL and calling step function
Check [this](https://github.com/kabylkas/ariane/commit/8ac5af75c62465a77283c5224ed9f64adbd61cce) out. Pretty self-explanatory patch: 
1) importing DPI functions 
2) initializing Dromajo 
3) placing step function where the instruction commits.

### Step 7: booting in debug mode
Dromajo assumes that the core will be booted in debug mode. It uses dscratch registers to restore architectural state and the last instruction that steers instruction flow to the point where checkpoint was created is `dret`. Therefore, we need to change RTL only for co-simulation purposes. For Ariane, this can be done by changing one line in [CSR register file](https://github.com/kabylkas/ariane/commit/609327c798846b095305509a703fa62291303167):
```verilog
`ifdef DROMAJO
            debug_mode_q           <= 1'b1;
`else
            debug_mode_q           <= 1'b0;
`endif
```

### Step 8: aligning RTL implementation with Dromajo assumptions
I am currently working on fixing this. However, there are some assumptions that Dromajo makes about CPU model. For example dromajo creates CSR writes to a wide range of CSRs when generating boot code to restore the architectural state. However, not all of those CSRs maybe implemented. Ariane doesn't have bunch of performance counters implemented.

For now, I added them in RTL, but in very recent future I will figure out how to exclude CSR writes when Dromajo creates a boot code.

Check [this](https://github.com/kabylkas/ariane/commit/5647491d20d4fdfbfa2491b7ce903891cdf0d05e) patch I made to csr register file and `include/riscv_pkg.sv`.

## Running
You should be able to run co-simulation now. Let's run dhrystone:
```
make verilate DROMAJO=1
./work-ver/Variane_testharness +checkpoint=./dromajo/snapshots/ds
```