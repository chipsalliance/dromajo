

# Cosimulation summary

Dromajo is built to have cosimulation against another simulator or RTL. The
goal is to support single core and multicore.



## Build dromajo to cosim against a trace file


To understand the cosimulation API, a trace driven cosimulation is possible.

```
mkdir build_trace
cd build_trace
cmake -DCMAKE_BUILD_TYPE=Debug ../
make -j
```

To create a trace, run any risc-v executable or checkpoint with dromajo as usual
but create a trace

```
./dromajo  --maxinsns 10k --trace 0 ~/projs/dromajo-old/run/riscv-tests/benchmarks/dhrystone.riscv 2>pp.trace
```

To read the trace and check that it is correct:

```
./dromajo_cosim_test read pp.trace
```

To co-simulate the trace against another instance of dromajo, and disassemble the trace

```
./dromajo_cosim_test  cosim pp.trace ~/projs/dromajo-old/run/riscv-tests/benchmarks/dhrystone.riscv | spike-dasm
```

