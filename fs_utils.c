/*
 * Misc FS utilities
 * 
 * Copyright (c) 2016-2017 Fabrice Bellard
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
#include <stdarg.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <sys/file.h>

#include "cutils.h"
#include "list.h"
#include "fs_utils.h"

/* last byte is the version */
const uint8_t encrypted_file_magic[4] = { 0xfb, 0xa2, 0xe9, 0x01 };

char *compose_path(const char *path, const char *name)
{
    int path_len, name_len;
    char *d, *q;

    if (path[0] == '\0') {
        d = strdup(name);
    } else {
        path_len = strlen(path);
        name_len = strlen(name);
        d = malloc(path_len + 1 + name_len + 1);
        q = d;
        memcpy(q, path, path_len);
        q += path_len;
        if (path[path_len - 1] != '/')
            *q++ = '/';
        memcpy(q, name, name_len + 1);
    }
    return d;
}

char *compose_url(const char *base_url, const char *name)
{
    if (strchr(name, ':')) {
        return strdup(name);
    } else {
        return compose_path(base_url, name);
    }
}

void skip_line(const char **pp)
{
    const char *p;
    p = *pp;
    while (*p != '\n' && *p != '\0')
        p++;
    if (*p == '\n')
        p++;
    *pp = p;
}

char *quoted_str(const char *str)
{
    const char *s;
    char *q;
    int c;
    char *buf;

    if (str[0] == '\0')
        goto use_quote;
    s = str;
    while (*s != '\0') {
        if (*s <= ' ' || *s > '~')
            goto use_quote;
        s++;
    }
    return strdup(str);
 use_quote:
    buf = malloc(strlen(str) * 4 + 2 + 1);
    q = buf;
    s = str;
    *q++ = '"';
    while (*s != '\0') {
        c = *(uint8_t *)s;
        if (c < ' ' || c == 127) {
            q += sprintf(q, "\\x%02x", c);
        } else if (c == '\\' || c == '\"') {
            q += sprintf(q, "\\%c", c);
        } else {
            *q++ = c;
        }
        s++;
    }
    *q++ = '"';
    *q = '\0';
    return buf;
}

int parse_fname(char *buf, int buf_size, const char **pp)
{
    const char *p;
    char *q;
    int c, h;
    
    p = *pp;
    while (isspace_nolf(*p))
        p++;
    if (*p == '\0')
        return -1;
    q = buf;
    if (*p == '"') {
        p++;
        for(;;) {
            c = *p++;
            if (c == '\0' || c == '\n') {
                return -1;
            } else if (c == '\"') {
                break;
            } else if (c == '\\') {
                c = *p++;
                switch(c) {
                case '\'':
                case '\"':
                case '\\':
                    goto add_char;
                case 'n':
                    c = '\n';
                    goto add_char;
                case 'r':
                    c = '\r';
                    goto add_char;
                case 't':
                    c = '\t';
                    goto add_char;
                case 'x':
                    h = from_hex(*p++);
                    if (h < 0)
                        return -1;
                    c = h << 4;
                    h = from_hex(*p++);
                    if (h < 0)
                        return -1;
                    c |= h;
                    goto add_char;
                default:
                    return -1;
                }
            } else {
            add_char:
                if (q >= buf + buf_size - 1)
                    return -1;
                *q++ = c;
            }
        }
    } else {
        while (!isspace_nolf(*p) && *p != '\0' && *p != '\n') {
            if (q >= buf + buf_size - 1)
                return -1;
            *q++ = *p++;
        }
    }
    *q = '\0';
    *pp = p;
    return 0;
}

int parse_uint32_base(uint32_t *pval, const char **pp, int base)
{
    const char *p, *p1;
    p = *pp;
    while (isspace_nolf(*p))
        p++;
    *pval = strtoul(p, (char **)&p1, base);
    if (p1 == p)
        return -1;
    *pp = p1;
    return 0;
}

int parse_uint64_base(uint64_t *pval, const char **pp, int base)
{
    const char *p, *p1;
    p = *pp;
    while (isspace_nolf(*p))
        p++;
    *pval = strtoull(p, (char **)&p1, base);
    if (p1 == p)
        return -1;
    *pp = p1;
    return 0;
}

int parse_uint64(uint64_t *pval, const char **pp)
{
    return parse_uint64_base(pval, pp, 0);
}

int parse_uint32(uint32_t *pval, const char **pp)
{
    return parse_uint32_base(pval, pp, 0);
}

int parse_time(uint32_t *psec, uint32_t *pnsec, const char **pp)
{
    const char *p;
    uint32_t v, m;
    p = *pp;
    if (parse_uint32(psec, &p) < 0)
        return -1;
    v = 0;
    if (*p == '.') {
        p++;
        /* XXX: inefficient */
        m = 1000000000;
        v = 0;
        while (*p >= '0' && *p <= '9') {
            m /= 10;
            v += (*p - '0') * m;
            p++;
        }
    }
    *pnsec = v;
    *pp = p;
    return 0;
}

int parse_file_id(FSFileID *pval, const char **pp)
{
    return parse_uint64_base(pval, pp, 16);
}

char *file_id_to_filename(char *buf, FSFileID file_id)
{
    sprintf(buf, "%016" PRIx64, file_id);
    return buf;
}

void encode_hex(char *str, const uint8_t *buf, int len)
{
    int i;
    for(i = 0; i < len; i++)
        sprintf(str + 2 * i, "%02x", buf[i]);
}

int decode_hex(uint8_t *buf, const char *str, int len)
{
    int h0, h1, i;

    for(i = 0; i < len; i++) {
        h0 = from_hex(str[2 * i]);
        if (h0 < 0)
            return -1;
        h1 = from_hex(str[2 * i + 1]);
        if (h1 < 0)
            return -1;
        buf[i] = (h0 << 4) | h1;
    }
    return 0;
}

/* return NULL if no end of header found */
const char *skip_header(const char *p)
{
    p = strstr(p, "\n\n");
    if (!p)
        return NULL;
    return p + 2;
}

/* return 0 if OK, < 0 if error */
int parse_tag(char *buf, int buf_size, const char *str, const char *tag)
{
    char tagname[128], *q;
    const char *p, *p1;
    int len;
    
    p = str;
    for(;;) {
        if (*p == '\0' || *p == '\n')
            break;
        q = tagname;
        while (*p != ':' && *p != '\n' && *p != '\0') {
            if ((q - tagname) < sizeof(tagname) - 1)
                *q++ = *p;
            p++;
        }
        *q = '\0';
        if (*p != ':')
            return -1;
        p++;
        while (isspace_nolf(*p))
            p++;
        p1 = p;
        p = strchr(p, '\n');
        if (!p)
            len = strlen(p1);
        else
            len = p - p1;
        if (!strcmp(tagname, tag)) {
            if (len > buf_size - 1)
                len = buf_size - 1;
            memcpy(buf, p1, len);
            buf[len] = '\0';
            return 0;
        }
        if (!p)
            break;
        else
            p++;
    }
    return -1;
}

int parse_tag_uint64(uint64_t *pval, const char *str, const char *tag)
{
    char buf[64];
    const char *p;
    if (parse_tag(buf, sizeof(buf), str, tag))
        return -1;
    p = buf;
    return parse_uint64(pval, &p);
}

int parse_tag_file_id(FSFileID *pval, const char *str, const char *tag)
{
    char buf[64];
    const char *p;
    if (parse_tag(buf, sizeof(buf), str, tag))
        return -1;
    p = buf;
    return parse_uint64_base(pval, &p, 16);
}

int parse_tag_version(const char *str)
{
    uint64_t version;
    if (parse_tag_uint64(&version, str, "Version"))
        return -1;
    return version;
}

BOOL is_url(const char *path)
{
    return (strstart(path, "http:", NULL) ||
            strstart(path, "https:", NULL) ||
            strstart(path, "file:", NULL));
}
