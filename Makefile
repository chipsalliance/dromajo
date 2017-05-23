#
# RISCV emulator
# 
# Copyright (c) 2016-2017 Fabrice Bellard
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

# if set, network filesystem is enabled. libcurl and libcrypto
# (openssl) must be installed.
CONFIG_FS_NET=y
# if set, compile the 128 bit emulator. Note: the 128 bit target does
# not compile if gcc does not support the int128 type (32 bit hosts).
CONFIG_INT128=y
# build x86emu
CONFIG_X86EMU=y

CROSS_PREFIX=
CC=$(CROSS_PREFIX)gcc
STRIP=$(CROSS_PREFIX)strip
CFLAGS=-O2 -Wall -g -Werror -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -MMD
CFLAGS+=-D_GNU_SOURCE -DCONFIG_VERSION=\"$(shell cat VERSION)\"
LDFLAGS=

# only used to build rv128test.bin
RISCV_CROSS_PREFIX=riscv64-unknown-linux-gnu-

bindir=/usr/local/bin
INSTALL=install

PROGS+= riscvemu32 riscvemu64 riscvemu
ifdef CONFIG_INT128
PROGS+=riscvemu128
endif
ifdef CONFIG_X86EMU
PROGS+=x86emu
endif
# compile rv128test.bin if a RISCV toolchain is available
#PROGS+=rv128test.bin
ifdef CONFIG_FS_NET
PROGS+=build_filelist
endif

all: $(PROGS)

EMU_OBJS:=virtio.o fs.o fs_disk.o cutils.o iomem.o
EMU_LIBS=-lrt
ifdef CONFIG_FS_NET
CFLAGS+=-DCONFIG_FS_NET
EMU_OBJS+=fs_net.o fs_wget.o fs_utils.o
EMU_LIBS+=-lcurl -lcrypto
endif

RISCVEMU_OBJS:=$(EMU_OBJS) riscvemu.o riscv_machine.o softfp.o 

X86EMU_OBJS:=$(EMU_OBJS) x86emu.o x86_cpu.o x86_machine.o

riscvemu32: riscv_cpu32.o $(RISCVEMU_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(EMU_LIBS)

riscvemu64: riscv_cpu64.o $(RISCVEMU_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(EMU_LIBS)

riscvemu128: riscv_cpu128.o $(RISCVEMU_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(EMU_LIBS)

riscvemu.o: riscvemu.c
	$(CC) $(CFLAGS) -DCONFIG_CPU_RISCV -c -o $@ $<

riscv_cpu32.o: riscv_cpu.c
	$(CC) $(CFLAGS) -DMAX_XLEN=32 -c -o $@ $<

riscv_cpu64.o: riscv_cpu.c
	$(CC) $(CFLAGS) -DMAX_XLEN=64 -c -o $@ $<

riscv_cpu128.o: riscv_cpu.c
	$(CC) $(CFLAGS) -DMAX_XLEN=128 -c -o $@ $<

riscvemu:
	ln -sf riscvemu64 riscvemu

x86emu: $(X86EMU_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(EMU_LIBS)

x86emu.o: riscvemu.c
	$(CC) $(CFLAGS) -DCONFIG_CPU_X86 -c -o $@ $<

build_filelist: build_filelist.o fs_utils.o
	$(CC) $(LDFLAGS) -o $@ $^ -lm

install: $(PROGS)
	$(STRIP) $(PROGS)
	$(INSTALL) -m755 $(PROGS) "$(DESTDIR)$(bindir)"

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o *.d *~ $(PROGS)

rv128test: rv128test.o rv128test.lds
	$(RISCV_CROSS_PREFIX)ld -T rv128test.lds -o $@ rv128test.o

rv128test.bin: rv128test
	$(RISCV_CROSS_PREFIX)objcopy -O binary $< $@

rv128test.o: rv128test.S
	$(RISCV_CROSS_PREFIX)gcc -c -o $@ $<

-include $(wildcard *.d)
