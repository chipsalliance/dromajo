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

### openSBI (~ ? min)

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
