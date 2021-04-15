/*
 * File list builder for RISCVEMU network filesystem
 * 
 * Copyright (c) 2017 Fabrice Bellard
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
#include <string.h>
#include <inttypes.h>
#include <assert.h>
#include <stdarg.h>
#include <sys/statfs.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/sysmacros.h>

#include "cutils.h"
#include "fs_utils.h"

void print_str(FILE *f, const char *str)
{
    const char *s;
    int c;
    s = str;
    while (*s != '\0') {
        if (*s <= ' ' || *s > '~')
            goto use_quote;
        s++;
    }
    fputs(str, f);
    return;
 use_quote:
    s = str;
    fputc('"', f);
    while (*s != '\0') {
        c = *(uint8_t *)s;
        if (c < ' ' || c == 127) {
            fprintf(f, "\\x%02x", c);
        } else if (c == '\\' || c == '\"') {
            fprintf(f, "\\%c", c);
        } else {
            fputc(c, f);
        }
        s++;
    }
    fputc('"', f);
}

#define COPY_BUF_LEN (1024 * 1024)

static void copy_file(const char *src_filename, const char *dst_filename)
{
    uint8_t *buf;
    FILE *fi, *fo;
    int len;
    
    buf = malloc(COPY_BUF_LEN);
    fi = fopen(src_filename, "rb");
    if (!fi) {
        perror(src_filename);
        exit(1);
    }
    fo = fopen(dst_filename, "wb");
    if (!fo) {
        perror(dst_filename);
        exit(1);
    }
    for(;;) {
        len = fread(buf, 1, COPY_BUF_LEN, fi);
        if (len == 0)
            break;
        fwrite(buf, 1, len, fo);
    }
    fclose(fo);
    fclose(fi);
}

typedef struct {
    char *files_path;
    uint64_t next_inode_num;
    uint64_t fs_size;
    uint64_t fs_max_size;
    FILE *f;
} ScanState;

static void add_file_size(ScanState *s, uint64_t size)
{
    s->fs_size += block_align(size, FS_BLOCK_SIZE);
    if (s->fs_size > s->fs_max_size) {
        fprintf(stderr, "Filesystem Quota exceeded (%" PRId64 " bytes)\n", s->fs_max_size);
        exit(1);
    }
}

void scan_dir(ScanState *s, const char *path)
{
    FILE *f = s->f;
    DIR *dirp;
    struct dirent *de;
    const char *name;
    struct stat st;
    char *path1;
    uint32_t mode, v;

    dirp = opendir(path);
    if (!dirp) {
        perror(path);
        exit(1);
    }
    for(;;) {
        de = readdir(dirp);
        if (!de)
            break;
        name = de->d_name;
        if (!strcmp(name, ".") || !strcmp(name, ".."))
            continue;
        path1 = compose_path(path, name);
        if (lstat(path1, &st) < 0) {
            perror(path1);
            exit(1);
        }

        mode = st.st_mode & 0xffff;
        fprintf(f, "%06o %u %u", 
                mode, 
                (int)st.st_uid,
                (int)st.st_gid);
        if (S_ISCHR(mode) || S_ISBLK(mode)) {
            fprintf(f, " %u %u",
                    (int)major(st.st_rdev),
                    (int)minor(st.st_rdev));
        }
        if (S_ISREG(mode)) {
            fprintf(f, " %" PRIu64, st.st_size);
        }
        /* modification time (at most ms resolution) */
        fprintf(f, " %u", (int)st.st_mtim.tv_sec);
        v = st.st_mtim.tv_nsec;
        if (v != 0) {
            fprintf(f, ".");
            while (v != 0) {
                fprintf(f, "%u", v / 100000000);
                v = (v % 100000000) * 10;
            }
        }
        
        fprintf(f, " ");
        print_str(f, name);
        if (S_ISLNK(mode)) {
            char buf[1024];
            int len;
            len = readlink(path1, buf, sizeof(buf) - 1);
            if (len < 0) {
                perror("readlink");
                exit(1);
            }
            buf[len] = '\0';
            fprintf(f, " ");
            print_str(f, buf);
        } else if (S_ISREG(mode) && st.st_size > 0) {
            char buf1[FILEID_SIZE_MAX], *fname;
            FSFileID file_id;
            file_id = s->next_inode_num++;
            fprintf(f, " %" PRIx64, file_id);
            file_id_to_filename(buf1, file_id);
            fname = compose_path(s->files_path, buf1);
            copy_file(path1, fname);
            add_file_size(s, st.st_size);
        }

        fprintf(f, "\n");
        if (S_ISDIR(mode)) {
            scan_dir(s, path1);
        }
        free(path1);
    }

    closedir(dirp);
    fprintf(f, ".\n"); /* end of directory */
}

void help(void)
{
    printf("usage: build_filelist [options] source_path dest_path\n"
           "\n"
           "Options:\n"
           "-m size_mb  set the max filesystem size in MiB\n");
    exit(1);
}

#define LOCK_FILENAME "lock"

int main(int argc, char **argv)
{
    const char *dst_path, *src_path;
    ScanState s_s, *s = &s_s;
    FILE *f;
    char *filename;
    FSFileID root_id;
    char fname[FILEID_SIZE_MAX];
    struct stat st;
    uint64_t first_inode, fs_max_size;
    int c;
    
    first_inode = 1;
    fs_max_size = (uint64_t)1 << 30;
    for(;;) {
        c = getopt(argc, argv, "hi:m:");
        if (c == -1)
            break;
        switch(c) {
        case 'h':
            help();
        case 'i':
            first_inode = strtoul(optarg, NULL, 0);
            break;
        case 'm':
            fs_max_size = (uint64_t)strtoul(optarg, NULL, 0) << 20;
            break;
        default:
            exit(1);
        }
    }

    if (optind + 1 >= argc)
        help();
    src_path = argv[optind];
    dst_path = argv[optind + 1];
    
    mkdir(dst_path, 0755);

    s->files_path = compose_path(dst_path, ROOT_FILENAME);
    s->next_inode_num = first_inode;
    s->fs_size = 0;
    s->fs_max_size = fs_max_size;
        
    mkdir(s->files_path, 0755);

    root_id = s->next_inode_num++;
    file_id_to_filename(fname, root_id);
    filename = compose_path(s->files_path, fname);
    f = fopen(filename, "wb");
    if (!f) {
        perror(filename);
        exit(1);
    }
    fprintf(f, "Version: 1\n");
    fprintf(f, "Revision: 1\n");
    fprintf(f, "\n");
    s->f = f;
    scan_dir(s, src_path);
    fclose(f);

    /* take into account the filelist size */
    if (stat(filename, &st) < 0) {
        perror(filename);
        exit(1);
    }
    add_file_size(s, st.st_size);
    
    free(filename);
    
    filename = compose_path(dst_path, HEAD_FILENAME);
    f = fopen(filename, "wb");
    if (!f) {
        perror(filename);
        exit(1);
    }
    fprintf(f, "Version: 1\n");
    fprintf(f, "Revision: 1\n");
    fprintf(f, "NextFileID: %" PRIx64 "\n", s->next_inode_num);
    fprintf(f, "FSFileCount: %" PRIu64 "\n", s->next_inode_num - 1);
    fprintf(f, "FSSize: %" PRIu64 "\n", s->fs_size);
    fprintf(f, "FSMaxSize: %" PRIu64 "\n", s->fs_max_size);
    fprintf(f, "Key:\n"); /* not encrypted */
    fprintf(f, "RootID: %" PRIx64 "\n", root_id);
    fclose(f);
    free(filename);
    
    filename = compose_path(dst_path, LOCK_FILENAME);
    f = fopen(filename, "wb");
    if (!f) {
        perror(filename);
        exit(1);
    }
    fclose(f);
    free(filename);

    return 0;
}
