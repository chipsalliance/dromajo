CC=riscv64-unknown-elf-gcc -mcmodel=medany
OPT=-g
OPT=-O -ffast-math
LDFLAGS=-nostdlib
CFLAGS=-std=gnu99 -Iinclude $(OPT)
TOP=regress-compress
BOOM_TEMPLATE=$(HOME)/boom-template

top: $(TOP).out

$(TOP).dis: $(TOP)
	riscv64-unknown-elf-objdump -D $^ > $@

test-sqrt.o: test-sqrt.c
	$(CC) $(CFLAGS) -c $< -o $@

new-test-sqrt.o: new-test-sqrt.S
	riscv64-unknown-elf-gcc -c $< -o $@

$(TOP): $(TOP).o
	riscv64-unknown-elf-gcc $(LDFLAGS) $^ -Wl,-Ttext=0x80000000 -o $@

run: $(TOP)
	../../build/dromajo --memory_addr=0x80000000 ./main

$(TOP).bin: $(TOP)
	riscv64-unknown-elf-objcopy -O binary $< $@

$(TOP).cfg: $(TOP).bin
	echo "{version:1,machine:\"riscv64\",memory_size:256,bios:\"$(TOP).bin\",memory_base_addr:0x80000000}" > $@

$(TOP).hex: $(TOP)
	riscv64-unknown-elf-elf2hex --bit-width 64 --input $< > $@

$(TOP).spout: $(TOP)
	spike -l $< >& $@

$(TOP).drout: $(TOP) Makefile
	../../build/dromajo --trace=0 $(TOP) |& ./commitlog-helper.py | spike-dasm | head -80
