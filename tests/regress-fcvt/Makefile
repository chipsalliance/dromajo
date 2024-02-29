SHELL=/bin/bash
RVPREFIX=riscv64-linux-gnu-
CC=$(RVPREFIX)gcc -mcmodel=medany
OPT=-g
OPT=-O -ffast-math
CFLAGS=-std=gnu99 -Iinclude $(OPT)
TOP=regress-fcvt
BOOM_TEMPLATE=$(HOME)/boom-template

top: $(TOP)

$(TOP).dis: $(TOP)
	$(RVPREFIX)objdump -D $^ > $@

test-sqrt.o: test-sqrt.c
	$(CC) $(CFLAGS) -c $< -o $@

new-test-sqrt.o: new-test-sqrt.S
	$(RVPREFIX)gcc -c $< -o $@

$(TOP): $(TOP).o
	$(RVPREFIX)ld $^ -Ttext=0x80000000 -o $@

run: $(TOP)
	../../build/dromajo --ctrlc --memory_addr=0x80000000 $<

$(TOP).bin: $(TOP)
	$(RVPREFIX)objcopy -O binary $< $@

$(TOP).cfg: $(TOP).bin
	echo "{version:1,machine:\"riscv64\",memory_size:256,bios:\"$(TOP).bin\",memory_base_addr:0x80000000}" > $@

$(TOP).hex: $(TOP)
	$(RVPREFIX)elf2hex --bit-width 64 --input $< > $@

$(TOP).spout: $(TOP)
	spike -l $< >& $@

$(TOP).drout: $(TOP) Makefile
	../../build/dromajo --ctrlc --trace=0 $(TOP) |& ../commitlog-helper.py | spike-dasm | head -80
