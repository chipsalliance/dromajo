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

# if set, network filesystem is enabled. libcurl must be installed.
CONFIG_FS_NET=y

CC=gcc
CFLAGS=-O2 -Wall -g -Werror -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -MMD
CFLAGS+=-DCONFIG_VERSION=\"$(shell cat VERSION)\"
LDFLAGS=

CROSS_PREFIX=riscv64-unknown-linux-gnu-
CROSS_CC=$(CROSS_PREFIX)gcc
CROSS_LD=$(CROSS_PREFIX)ld
CROSS_OBJCOPY=$(CROSS_PREFIX)objcopy
CROSS_CFLAGS=-O2 -Wall -g -Werror
CROSS_LDFLAGS=-static

PROGS= riscvemu32 riscvemu64 riscvemu build_filelist
# Note: the 128 bit target does not compile if gcc does not support
# the int128 type (32 bit hosts).
PROGS+=riscvemu128 
# compile rv128test.bin if a RISCV toolchain is available
#PROGS+=rv128test.bin

all: $(PROGS)

RISCVEMU_OBJS:=softfp.o virtio.o fs_disk.o
RISCVEMU_LIBS=-lrt
ifdef CONFIG_FS_NET
CFLAGS+=-DCONFIG_FS_NET
RISCVEMU_OBJS+=fs_net.o
RISCVEMU_LIBS+=-lcurl
endif

riscvemu32: riscvemu32.o $(RISCVEMU_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(RISCVEMU_LIBS)

riscvemu64: riscvemu64.o $(RISCVEMU_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(RISCVEMU_LIBS)

riscvemu128: riscvemu128.o $(RISCVEMU_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(RISCVEMU_LIBS)

riscvemu32.o: riscvemu.c
	$(CC) $(CFLAGS) -DMAX_XLEN=32 -c -o $@ $<

riscvemu64.o: riscvemu.c
	$(CC) $(CFLAGS) -DMAX_XLEN=64 -c -o $@ $<

riscvemu128.o: riscvemu.c
	$(CC) $(CFLAGS) -DMAX_XLEN=128 -c -o $@ $<

riscvemu:
	ln -sf riscvemu64 riscvemu

build_filelist: build_filelist.o
	$(CC) $(LDFLAGS) -o $@ $^ -lm

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o *.d *~ $(PROGS)

rv128test: rv128test.o rv128test.lds
	$(CROSS_LD) -T rv128test.lds -o $@ rv128test.o

rv128test.bin: rv128test
	$(CROSS_OBJCOPY) -O binary $< $@

rv128test.o: rv128test.S
	$(CROSS_CC) -c -o $@ $<

-include $(wildcard *.d)
