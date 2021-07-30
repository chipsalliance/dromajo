
# Instructions to generate the SimPoint


## Install SimPoint

Download a viable simpoint tool (patched for latest gcc helps)

```
cd run
git clone https://github.com/southerngs/simpoint.git
make -C simpoint
```

## Compile dromajo with simpoint

```
mkdir build
cd build
cmake -DSIMPOINT=On ../
make
```


## Select the benchmark to run

The buildroot should have the benchmarks that you want to run. To avoid rebuilding a buildroot
for each benchmark, you can use the S50bench script.


Copy the binary and inputs sets XXX to the buildroot target directory. Make
sure that S50bench has an option for your new benchmark.

```
riscv64-linux-gnu-gcc -Wall -Os -static roi.c -o buildroot-2020.05.1/output/target/sbin/roi

cp -f S50bench buildroot-2020.05.1/output/target/etc/init.d/

mkdir buildroot-2020.05.1/output/target/bench
cp XXXX buildroot-2020.05.1/output/target/bench
```

Afterwards rebuild the buildroot, and copy the rootfs.cpio

```
make -j16 -C buildroot-2020.05.1
cp buildroot-2020.05.1/output/images/rootfs.cpio .
```

Edit the boot.cfg to specify the benchmark to run. For example, to run
spec06_gcc option in S50bench.

```
  "cmdline": "root=/dev/ram rw earlycon=sbi console=hvc0 bench=spec06_gcc",
```

## Run your benchmark

Dromajo will generate a dromajo_simpoint.bb trace for your execution

```
cd run
../build/dromajo ./boot.cfg
```

The simpoint_size constant at dromajo.cpp sets the simpoint size. Make sure
that the trace is long enough. Typically, it should have over 100 entries. If
it has less, you may want to consider to create smaller checkpoints. To check
the number of entries:

```
wc -l dromajo_simpoint.bb
```

## Select your simpoint region

This depends on your restrictions, but usual parameter:

```
./simpoint/bin/simpoint -maxK 30 -saveSimpoints simpoints -saveSimpointWeights weights -loadFVFile dromajo_simpoint.bb
```

This saves the recommended simpoints and weights. Save the simpoints and
weights file. These are needed to created simpoint checkpoints and to report
performance numbers (weights).

## Select your simpoint region automatically

The simpoints file should have the list of checkpoints and the location. For
example, this contents means that there are 15 checkpoints, and the first
starts at 193*simpoint_size.  The 2nd starts at 89*simpoint_size... All the
checkpoints have the same size of simpoint_size.

```
193 0
89 1
69 2
77 3
3 4
165 5
24 6
0 7
65 8
62 9
79 10
51 11
130 12
10 13
23 14
```

```
../build/dromajo --simpoint simpoints ./boot.cfg
```


## Create a checkpoint for each simpoint manually


Given the previous example and simpoint_size of 1M instructions, to create
the sp01 (89 1 entry), run dromajo:

```
../build/dromajo --save sp01 --maxinsn 89000000 ./boot.cfg
```

Repeat the checkpoint creation for each simpoint, and they are ready.

NOTE: You can use a dromajo with or without SIMPOINT enabled for creating checkpoints. It ill be a bit faster without SIMPOINT.

This means that to create checkpoints, you should use the default dromajo build options:
```
mkdir build
cd build
cmake ../
make
```

If you want the checkpoints to have cache warmup:
```
mkdir build
cd build
cmake -DWARMUP=On ../
make
```

Cache warmup will increase the boomrom size to insert all the memory requests needed. The advantage is that it can reduce the
simpoint size to have accurate results.


## Run a checkpoint for each simpoint to characterize your application

Each checkpoint created has an associated weight, if you want to run sp01, load
the checkpoint and execute only for the simpoint_size selected (1M in this
example).

```
../build/dromajo --load sp01 --maxinsn 1000000 ./boot.cfg
```

Congratulations, You run your first dromajo simpoint created checkpoint!


## Benchmarking recommendations

The RISC-V platform (dromajo) has a high frequency clock interrupt. By default, the Linux kernel boots
omitting clock ticks for idle CPUs, but it still has a timer interrupt when 1 single application is running.
For benchmarking (or HPC), it is common to disable the timer interrupt also if there is only one running thread.
This can be done by changing the "Timer subsystem" options in the linux configuration. For Linux kernel 5.7:

```
#
# Timers subsystem
#
CONFIG_TICK_ONESHOT=y
CONFIG_NO_HZ_COMMON=y
# CONFIG_HZ_PERIODIC is not set
# CONFIG_NO_HZ_IDLE is not set
CONFIG_NO_HZ_FULL=y
CONFIG_CONTEXT_TRACKING=y
# CONFIG_CONTEXT_TRACKING_FORCE is not set
# CONFIG_NO_HZ is not set
CONFIG_HIGH_RES_TIMERS=y
# end of Timers subsystem
```


## Locate the most different simpoints

To create a trace of execution, you can save the list of labels (-saveLabels sl). This saves the distance
from the recomended simpoint. This can be used to create an execution trace to "match" the original, but also
to pin-point the code sections more different that have not "related" simpoint.

```
for a in `sort -n -k2 sl  | tail -50 | cut -d" " -f2 `; do grep -n "${a}"$ sl; done | cut -d: -f1 | sort -n
```

