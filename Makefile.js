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

# Build Javascript version of riscvemu
EMCC=emcc
EMCFLAGS=-O2 -Wall -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -MMD -fno-strict-aliasing
#EMCFLAGS+=-Werror
EMCFLAGS+=-DMAX_XLEN=64 -DDEFAULT_RAM_SIZE=128
EMLDFLAGS=-g -O3 -s TOTAL_MEMORY=201326592 --memory-init-file 0 --closure 0 -s NO_EXIT_RUNTIME=1 -s "EXPORTED_FUNCTIONS=['_console_queue_char','_main']"

all: js/riscvemu.js

JS_OBJS=riscvemu.js.o softfp.js.o virtio.js.o fs_net.js.o

js/riscvemu.js: $(JS_OBJS)
	$(EMCC) $(EMLDFLAGS) -o $@ $(JS_OBJS)

%.js.o: %.c
	$(EMCC) $(EMCFLAGS) -c -o $@ $<

