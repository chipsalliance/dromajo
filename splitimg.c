/*
 * Disk image splitter
 * 
 * Copyright (c) 2016 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>

int main(int argc, char **argv)
{
    int blocksize, ret, i;
    const char *infilename, *outpath;
    FILE *f, *fo;
    char buf1[1024];
    uint8_t *buf;

    if ((optind + 1) >= argc) {
        printf("splitimg version " CONFIG_VERSION ", Copyright (c) 2011-2016 Fabrice Bellard\n"
               "usage: splitimg infile outpath [blocksize]\n"
               "Create a multi-file disk image for the RISCVEMU HTTP block device\n"
               "\n"
               "outpath must be a directory\n"
               "blocksize is the block size in KB\n");
        exit(1);
    }

    infilename = argv[optind++];
    outpath = argv[optind++];
    blocksize = 256;
    if (optind < argc)
        blocksize = strtol(argv[optind++], NULL, 0);

    blocksize *= 1024;
    
    buf = malloc(blocksize);

    f = fopen(infilename, "rb");
    if (!f) {
        perror(infilename);
        exit(1);
    }
    i = 0;
    for(;;) {
        ret = fread(buf, 1, blocksize, f);
        if (ret < 0) {
            perror("fread");
            exit(1);
        }
        if (ret == 0)
            break;
        if (ret < blocksize) {
            printf("warning: last block is not full\n");
            memset(buf + ret, 0, blocksize - ret);
        }
        snprintf(buf1, sizeof(buf1), "%s/blk%09u.bin", outpath, i);
        fo = fopen(buf1, "wb");
        if (!fo) {
            perror(buf1);
            exit(1);
        }
        fwrite(buf, 1, blocksize, fo);
        fclose(fo);
        i++;
    }
    fclose(f);
    printf("%d blocks\n", i);

    snprintf(buf1, sizeof(buf1), "%s/blk.txt", outpath);
    fo = fopen(buf1, "wb");
    if (!fo) {
        perror(buf1);
        exit(1);
    }
    fprintf(fo, "{\n");
    fprintf(fo, "  block_size: %d,\n", blocksize / 1024);
    fprintf(fo, "  n_block: %d,\n", i);
    fprintf(fo, "}\n");
    fclose(fo);
    return 0;
}
