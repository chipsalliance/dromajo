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

#include <sys/sysmacros.h>
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

static char *compose_path(const char *path, const char *name)
{
    int path_len, name_len;
    char *d;

    path_len = strlen(path);
    name_len = strlen(name);
    d = malloc(path_len + 1 + name_len + 1);
    memcpy(d, path, path_len);
    d[path_len] = '/';
    memcpy(d + path_len + 1, name, name_len + 1);
    return d;
}

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
    fprintf(f, str);
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


void scan_dir(FILE *f, const char *path)
{
    DIR *dirp;
    struct dirent *de;
    const char *name;
    struct stat st;
    char *path1, type, xu, xg, xo;
    uint32_t mode;

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

        mode = st.st_mode;
        switch(mode & S_IFMT) {
        case S_IFIFO:
            type = 'p';
            break;
        case S_IFCHR:
            type = 'c';
            break;
        case S_IFDIR:
            type = 'd';
            break;
        case S_IFBLK:
            type = 'b';
            break;
        case S_IFREG:
            type = '-';
            break;
        case S_IFLNK:
            type = 'l';
            break;
        case S_IFSOCK:
            type = 's';
            break;
        default:
            abort();
        }

        if (mode & S_ISUID)
            xu = mode & 0100 ? 's' : 'S';
        else
            xu = mode & 0100 ? 'x' : '-';
        if (mode & S_ISGID)
            xg = mode & 0010 ? 's' : 'S';
        else
            xg = mode & 0010 ? 'x' : '-';
        if (mode & S_ISVTX)
            xo = mode & 0001 ? 't' : 'T';
        else
            xo = mode & 0001 ? 'x' : '-';
                
        fprintf(f, "%c%c%c%c%c%c%c%c%c%c %u %u", 
                type, 
                mode & 0400 ? 'r' : '-',
                mode & 0200 ? 'w' : '-',
                xu,
                mode & 0040 ? 'r' : '-',
                mode & 0020 ? 'w' : '-',
                xg,
                mode & 0004 ? 'r' : '-',
                mode & 0002 ? 'w' : '-',
                xo,
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
        if (st.st_mtim.tv_nsec != 0) {
            fprintf(f, ".%03u", 
                    (int)(st.st_mtim.tv_nsec / 1000000));
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
        }

        fprintf(f, "\n");
        if (S_ISDIR(mode)) {
            scan_dir(f, path1);
        }
        free(path1);
    }

    closedir(dirp);
    fprintf(f, ".\n"); /* end of directory */
}

void help(void)
{
    printf("usage: build_filelist filelist path\n");
    exit(1);
}

int main(int argc, char **argv)
{
    const char *filename, *path;
    FILE *f;

    if (argc < 3)
        help();
    filename = argv[1];
    path = argv[2];
    f = fopen(filename, "wb");
    fprintf(f, "Version: 1\n");
    fprintf(f, "\n");
    if (!f) {
        perror(filename);
        exit(1);
    }
    scan_dir(f, path);
    fclose(f);
    return 0;
}
