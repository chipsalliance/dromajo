// Code based on Sifive HIFive uart base https://wiki.osdev.org/HiFive-1_Bare_Bones

/* UART */
#define UART0_CTRL_ADDR 0x54000000UL
#define UART_REG_TXFIFO         0x00

typedef unsigned char u8;
typedef unsigned int  u32;
typedef unsigned long size_t;

/* This function will read a 32-bit value from an MMIO register */
static inline u32 mmio_read_u32(unsigned long reg, unsigned int offset) {
  return (*(volatile u32 *) ((reg) + (offset)));
}

/* This function will write a byte to an MMIO register */
static inline void mmio_write_u8(unsigned long reg, unsigned int offset, u8 val) {
  (*(volatile u32 *) ((reg) + (offset))) = val;
}

/*This function will write a 32-bit value to an MMIO register */
static inline void mmio_write_u32(unsigned long reg, unsigned int offset, u32 val) {
  (*(volatile u32 *) ((reg) + (offset))) = val;
}

/* Transmit a single byte over the UART */
static void __uart_write(u8 byte) {
  /* wait for the UART to become ready */
  while (mmio_read_u32(UART0_CTRL_ADDR, UART_REG_TXFIFO) & 0x80000000)
    ;

  /* write to the UART transmit FIFO */
  mmio_write_u8(UART0_CTRL_ADDR, UART_REG_TXFIFO, byte);
}

/* Transmit a buffer of length "len" over the UART */
static void uart_write(u8 *buf, size_t len) {
  int i;
  for (i = 0; i < len; i ++) {
    __uart_write(buf[i]);
    /* If an LF was written, also write a CR */
    if (buf[i] == '\n') {
      __uart_write('\r');
    }
  }
}

/* People, the simplest ever strlen function */
static size_t strlen(char *str) {
  int len = 0;
  int i;

  for (i = 0; str[i] != 0; i ++)
    len ++;

  return len;
}

/* Write a null-terminated string to the UART, transmitting it */
static void uart_write_string(u8 *buf) {
  uart_write(buf, strlen((char *) buf));
}

void _init(int cid, int nc) {
  uart_write_string("initializing...\n");

  for (;;);
}

//  riscv64-unknown-elf-gcc -march=rv64g -mabi=lp64 -static -mcmodel=medany -nostdlib -nostartfiles uart_test.c crt.S -lgcc -T test.ld
