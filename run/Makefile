laur-repro: laur
	../build/dromajo --ctrlc --ncpus=4 laur

laur: laur.S
	riscv64-unknown-elf-gcc -march=rv64g -mabi=lp64 -static -mcmodel=medany -nostdlib -nostartfiles \
		laur.S -lgcc -T test.ld -o laur
