# Example things on run on Dromajo

## Bare-metal riscv-tests (~ 2 min)

Assumption: you have the `riscv64-unknown-elf-` (Newlib) toolchain.

```
git clone --recursive https://github.com/riscv/riscv-tests
cd riscv-tests
autoconf
./configure --prefix=${PWD}/../riscv-tests-root/
make
make install
cd ..
```

To run one of the benchmarks with trace enabled

```
../src/dromajo --trace 0 riscv-tests-root/share/riscv-tests/isa/rv64ua-p-amoadd_d
```

## Linux with buildroot

### Get a trivial buildroot (~ 23 min)

```
wget -nc https://github.com/buildroot/buildroot/archive/2019.08.1.tar.gz
tar xzf 2019.08.1.tar.gz
cp config-buildroot-2019.08.1 buildroot-2019.08.1/.config
make -j16 -C buildroot-2019.08.1
```


### Get the Linux kernel up and running (~ 3 min)

Assumption: you have the `riscv64-linux-gnu-` (GlibC) toolchain.

```
wget -nc https://github.com/torvalds/linux/archive/v5.3.tar.gz
tar xzf v5.3.tar.gz
cp config-linux-5.3 linux-5.3/.config
make -C linux-5.3 -j16 ARCH=riscv CROSS_COMPILE=riscv64-linux-gnu-
```

### openSBI (~ 1 min)

```
export CROSS_COMPILE=riscv64-unknown-elf-
wget -nc https://github.com/riscv/opensbi/archive/v0.5.tar.gz
tar xzf v0.5.tar.gz
tar xzCf opensbi-0.5 opensbi.dromajo.tar.gz
make -C opensbi-0.5 PLATFORM=dromajo FW_PAYLOAD_PATH=../linux-5.3/arch/riscv/boot/Image
```

### To boot Linux (login:root password:root)

```
cp opensbi-0.5/build/platform/dromajo/firmware/fw_payload.bin .
../src/dromajo boot.cfg
```

### To boot a quad-core RISC-V CPU

```
../src/dromajo --ncpus 4 boot.cfg
```

### Create and run checkpoints

Dromajo creates checkpoints by dumping the memory state, and creating a bootram
that includes a sequence of valid RISC-V instructions to recover the CPU to the
same state as before the checkpoint was created. This information includes not
only the architectural state, but CSRs, and PLIC/CLINT programmed registers. It
does not include any state in a hardware devices.

It allows to create Linux boot checkpoints. E.g:

Run 1M instructions and create a checkpoint from a Linux+openSBI boot:

```
../src/dromajo --save ck1 --maxinsn 1000000 ./boot.cfg

OpenSBI v0.5 (Jan 24 2020 12:27:39)
   ____                    _____ ____ _____
  / __ \                  / ____|  _ \_   _|
 | |  | |_ __   ___ _ __ | (___ | |_) || |
 | |  | | '_ \ / _ \ '_ \ \___ \|  _ < | |
 | |__| | |_) |  __/ | | |____) | |_) || |_
  \____/| .__/ \___|_| |_|_____/|____/_____|
        | |
        |_|

Platform Name          : Dromajo
Platform HART Features : RV64ACDFIMSU
Platform Max HARTs     : 4
Current Hart           : 0
Firmware Base          : 0x80000000
Firmware Size          : 84 KB
Runtime SBI Version    : 0.2

PMP0: 0x0000000080000000-0x000000008001ffff (A)
PMP1: 0x0000000000000000-0x000001ffffffffff (A,R,W,X)

Power off.
plic: 0 0 timecmp=ffffffffffffffff
NOTE: creating a new boot rom
clint hartid=0 timecmp=-1 cycles (62499)
```

The previous example creates 3 files. ck1.re_regs is an ascii dump for
debugging. The ck1.mainram is a memory dump of the main memory after 1M cycles.
The ck1.bootram is the new bootram needed to recover the state.

To continue booting Linux:

```
src/dromajo --load ck1 ./boot.cfg
[    0.000000] OF: fdt: Ignoring memory range 0x80000000 - 0x80200000
[    0.000000] Linux version 5.3.0 (renau) (gcc version 9.2.0 (GCC)) #1 SMP Fri Jan 24 12:24:34 PST 2020
[    0.000000] initrd not found or empty - disabling initrd
[    0.000000] Zone ranges:
[    0.000000]   DMA32    [mem 0x0000000080200000-0x00000000bfffffff]
[    0.000000]   Normal   empty
[    0.000000] Movable zone start for each node
[    0.000000] Early memory node ranges
[    0.000000]   node   0: [mem 0x0000000080200000-0x00000000bfffffff]
[    0.000000] Initmem setup node 0 [mem 0x0000000080200000-0x00000000bfffffff]
[    0.000000] software IO TLB: mapped [mem 0xbb1fe000-0xbf1fe000] (64MB)
[    0.000000] elf_hwcap is 0x112d
[    0.000000] percpu: Embedded 13 pages/cpu s23776 r0 d29472 u53248
[    0.000000] Built 1 zonelists, mobility grouping on.  Total pages: 258055
[    0.000000] Kernel command line: root=/dev/generic-blkdef rw
[    0.000000] Dentry cache hash table entries: 131072 (order: 8, 1048576 bytes, linear)
[    0.000000] Inode-cache hash table entries: 65536 (order: 7, 524288 bytes, linear)
[    0.000000] Sorting __ex_table...
[    0.000000] mem auto-init: stack:off, heap alloc:off, heap free:off
[    0.000000] Memory: 959288K/1046528K available (1777K kernel code, 135K rwdata, 493K rodata, 2747K init, 217K bss, 87240K reserved, 0K cma-reserved)
[    0.000000] SLUB: HWalign=64, Order=0-3, MinObjects=0, CPUs=1, Nodes=1
[    0.000000] rcu: Hierarchical RCU implementation.
[    0.000000] rcu:     RCU restricting CPUs from NR_CPUS=8 to nr_cpu_ids=1.
[    0.000000] rcu: RCU calculated value of scheduler-enlistment delay is 25 jiffies.
[    0.000000] rcu: Adjusting geometry for rcu_fanout_leaf=16, nr_cpu_ids=1
[    0.000000] NR_IRQS: 0, nr_irqs: 0, preallocated irqs: 0
[    0.000000] plic: mapped 31 interrupts with 1 handlers for 2 contexts.
[    0.000000] riscv_timer_init_dt: Registering clocksource cpuid [0] hartid [0]
[    0.000000] clocksource: riscv_clocksource: mask: 0xffffffffffffffff max_cycles: 0x24e6a1710, max_idle_ns: 440795202120 ns
[    0.000024] sched_clock: 64 bits at 10MHz, resolution 100ns, wraps every 4398046511100ns
[    0.009020] printk: console [hvc0] enabled
[    0.009260] Calibrating delay loop (skipped), value calculated using timer frequency.. 20.00 BogoMIPS (lpj=40000)
[    0.009768] pid_max: default: 32768 minimum: 301
[    0.010423] Mount-cache hash table entries: 2048 (order: 2, 16384 bytes, linear)
[    0.010812] Mountpoint-cache hash table entries: 2048 (order: 2, 16384 bytes, linear)
[    0.014073] rcu: Hierarchical SRCU implementation.
[    0.014875] smp: Bringing up secondary CPUs ...
[    0.015109] smp: Brought up 1 node, 1 CPU
[    0.016163] devtmpfs: initialized
[    0.016767] clocksource: jiffies: mask: 0xffffffff max_cycles: 0xffffffff, max_idle_ns: 7645041785100000 ns
[    0.017247] futex hash table entries: 256 (order: 2, 16384 bytes, linear)
[    0.024433] vgaarb: loaded
[    0.024853] clocksource: Switched to clocksource riscv_clocksource
[    0.026804] thermal_sys: Registered thermal governor 'step_wise'
[    0.026819] thermal_sys: Registered thermal governor 'user_space'
[    0.027163] PCI: CLS 0 bytes, default 64
...
```


