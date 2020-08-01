
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

void usage(const char *prg) {
  printf("usage\n\t%s <begin|end|terminate|maxinsn>\n", prg);
  printf("\t\tbegin the ROI region\n");
  printf("\t\tend the ROI region\n");
  printf("\t\tterminate simulation/power off\n");
  printf("\t\tmaxinsn adjust maxinsns in simulation\n");
  exit(1);
}

int main(int argc, char **argv) {

  if (argc != 2) {
    usage(argv[0]);
  }

  int tmp;
  if (strcasecmp(argv[1], "begin") == 0) {
    asm volatile ("csrrs %0, 0x8c2, %1" : "=r"(tmp) : "i"(1));
  }else if (strcasecmp(argv[1], "end") == 0) {
    asm volatile("csrrs %0, 0x8c2, %1" : "=r"(tmp) : "i"(0));
  }else if (strcasecmp(argv[1], "terminate") == 0) {
    asm volatile("csrrs %0, 0x8c2, %1" : "=r"(tmp) : "i"(2));
  } else {
    unsigned long val = atol(argv[1]);
    int last = strlen(argv[1])-1;
    if (argv[1][last]=='K' || argv[1][last]=='k')
      val *= 1000;
    else if (argv[1][last]=='M' || argv[1][last]=='m')
      val *= 1000000;
    else if (argv[1][last]=='G' || argv[1][last]=='B' || argv[1][last]=='g' || argv[1][last]=='b')
      val *= 1000000000;
    if (val==0)
      usage(argv[0]);

    asm volatile("csrrs %0, 0x8c2, %1" : "=r"(tmp) : "r"((val<<2)|3));
  }

  return 0;
}

