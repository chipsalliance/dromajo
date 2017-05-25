/*
 * RISCV emulator
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
#include <getopt.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/stat.h>
#include <signal.h>

#include "cutils.h"
#include "iomem.h"
#include "virtio.h"
#include "machine.h"
#ifdef CONFIG_CPU_RISCV
#include "riscv_cpu.h"
#endif

#ifndef DEFAULT_RAM_SIZE
#define DEFAULT_RAM_SIZE 256
#endif


typedef struct {
    int stdin_fd;
    int console_esc_state;
    BOOL resize_pending;
} STDIODevice;

static struct termios oldtty;
static int old_fd0_flags;
static STDIODevice *global_stdio_device;

static void term_exit(void)
{
    tcsetattr (0, TCSANOW, &oldtty);
    fcntl(0, F_SETFL, old_fd0_flags);
}

static void term_init(BOOL allow_ctrlc)
{
    struct termios tty;

    memset(&tty, 0, sizeof(tty));
    tcgetattr (0, &tty);
    oldtty = tty;
    old_fd0_flags = fcntl(0, F_GETFL);

    tty.c_iflag &= ~(IGNBRK|BRKINT|PARMRK|ISTRIP
                          |INLCR|IGNCR|ICRNL|IXON);
    tty.c_oflag |= OPOST;
    tty.c_lflag &= ~(ECHO|ECHONL|ICANON|IEXTEN);
    if (!allow_ctrlc)
        tty.c_lflag &= ~ISIG;
    tty.c_cflag &= ~(CSIZE|PARENB);
    tty.c_cflag |= CS8;
    tty.c_cc[VMIN] = 1;
    tty.c_cc[VTIME] = 0;

    tcsetattr (0, TCSANOW, &tty);

    atexit(term_exit);
}

static void console_write(void *opaque, const uint8_t *buf, int len)
{
    fwrite(buf, 1, len, stdout);
    fflush(stdout);
}

static int console_read(void *opaque, uint8_t *buf, int len)
{
    STDIODevice *s = opaque;
    int ret, i, j;
    uint8_t ch;
    
    if (len <= 0)
        return 0;

    ret = read(s->stdin_fd, buf, len);
    if (ret < 0)
        return 0;
    if (ret == 0) {
        /* EOF */
        exit(1);
    }

    j = 0;
    for(i = 0; i < ret; i++) {
        ch = buf[i];
        if (s->console_esc_state) {
            s->console_esc_state = 0;
            switch(ch) {
            case 'x':
                printf("Terminated\n");
                exit(0);
            case 'h':
                printf("\n"
                       "C-a h   print this help\n"
                       "C-a x   exit emulator\n"
                       "C-a C-a send C-a\n");
                break;
            case 1:
                goto output_char;
            default:
                break;
            }
        } else {
            if (ch == 1) {
                s->console_esc_state = 1;
            } else {
            output_char:
                buf[j++] = ch;
            }
        }
    }
    return j;
}

static void term_resize_handler(int sig)
{
    if (global_stdio_device)
        global_stdio_device->resize_pending = TRUE;
}

static void console_get_size(STDIODevice *s, int *pw, int *ph)
{
    struct winsize ws;
    int width, height;
    /* default values */
    width = 80;
    height = 25;
    if (ioctl(s->stdin_fd, TIOCGWINSZ, &ws) == 0 &&
        ws.ws_col >= 4 && ws.ws_row >= 4) {
        width = ws.ws_col;
        height = ws.ws_row;
    }
    *pw = width;
    *ph = height;
}

CharacterDevice *console_init(BOOL allow_ctrlc)
{
    CharacterDevice *dev;
    STDIODevice *s;
    struct sigaction sig;

    term_init(allow_ctrlc);

    dev = mallocz(sizeof(*dev));
    s = mallocz(sizeof(*s));
    s->stdin_fd = 0;
    /* Note: the glibc does not properly tests the return value of
       write() in printf, so some messages on stdout may be lost */
    fcntl(s->stdin_fd, F_SETFL, O_NONBLOCK);

    s->resize_pending = TRUE;
    global_stdio_device = s;
    
    /* use a signal to get the host terminal resize events */
    sig.sa_handler = term_resize_handler;
    sigemptyset(&sig.sa_mask);
    sig.sa_flags = 0;
    sigaction(SIGWINCH, &sig, NULL);
    
    dev->opaque = s;
    dev->write_data = console_write;
    dev->read_data = console_read;
    return dev;
}

static void load_kernel(VirtMachine *s, const char *filename)
{
    FILE *f;
    int size;
    uint8_t *buf;
    
    f = fopen(filename, "rb");
    if (!f) {
        perror(filename);
        exit(1);
    }
    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, 0, SEEK_SET);
    buf = malloc(size);
    if (fread(buf, 1, size, f) != size) {
        fprintf(stderr, "%s: read error\n", filename);
        exit(1);
    }
    fclose(f);
    copy_kernel(s, buf, size);
    free(buf);
}

typedef enum {
    BF_MODE_RO,
    BF_MODE_RW,
    BF_MODE_SNAPSHOT,
} BlockDeviceModeEnum;

#define SECTOR_SIZE 512

typedef struct BlockDeviceFile {
    FILE *f;
    int64_t nb_sectors;
    BlockDeviceModeEnum mode;
    uint8_t **sector_table;
} BlockDeviceFile;

static int64_t bf_get_sector_count(BlockDevice *bs)
{
    BlockDeviceFile *bf = bs->opaque;
    return bf->nb_sectors;
}

static int bf_read_async(BlockDevice *bs,
                         uint64_t sector_num, uint8_t *buf, int n,
                         BlockDeviceCompletionFunc *cb, void *opaque)
{
    BlockDeviceFile *bf = bs->opaque;
    //    printf("bf_read_async: sector_num=%" PRId64 " n=%d\n", sector_num, n);
    if (!bf->f)
        return -1;
    if (bf->mode == BF_MODE_SNAPSHOT) {
        int i;
        for(i = 0; i < n; i++) {
            if (!bf->sector_table[sector_num]) {
                fseek(bf->f, sector_num * SECTOR_SIZE, SEEK_SET);
                fread(buf, 1, SECTOR_SIZE, bf->f);
            } else {
                memcpy(buf, bf->sector_table[sector_num], SECTOR_SIZE);
            }
            sector_num++;
            buf += SECTOR_SIZE;
        }
    } else {
        fseek(bf->f, sector_num * SECTOR_SIZE, SEEK_SET);
        fread(buf, 1, n * SECTOR_SIZE, bf->f);
    }
    /* synchronous read */
    return 0;
}

static int bf_write_async(BlockDevice *bs,
                          uint64_t sector_num, const uint8_t *buf, int n,
                          BlockDeviceCompletionFunc *cb, void *opaque)
{
    BlockDeviceFile *bf = bs->opaque;
    int ret;

    switch(bf->mode) {
    case BF_MODE_RO:
        ret = -1; /* error */
        break;
    case BF_MODE_RW:
        fseek(bf->f, sector_num * SECTOR_SIZE, SEEK_SET);
        fwrite(buf, 1, n * SECTOR_SIZE, bf->f);
        ret = 0;
        break;
    case BF_MODE_SNAPSHOT:
        {
            int i;
            if ((sector_num + n) > bf->nb_sectors)
                return -1;
            for(i = 0; i < n; i++) {
                if (!bf->sector_table[sector_num]) {
                    bf->sector_table[sector_num] = malloc(SECTOR_SIZE);
                }
                memcpy(bf->sector_table[sector_num], buf, SECTOR_SIZE);
                sector_num++;
                buf += SECTOR_SIZE;
            }
            ret = 0;
        }
        break;
    default:
        abort();
    }

    return ret;
}

static BlockDevice *block_device_init(const char *filename,
                                      BlockDeviceModeEnum mode)
{
    BlockDevice *bs;
    BlockDeviceFile *bf;
    int64_t file_size;
    FILE *f;
    const char *mode_str;

    if (mode == BF_MODE_RW) {
        mode_str = "r+b";
    } else {
        mode_str = "rb";
    }
    
    f = fopen(filename, mode_str);
    if (!f) {
        perror(filename);
        exit(1);
    }
    fseek(f, 0, SEEK_END);
    file_size = ftello(f);

    bs = mallocz(sizeof(*bs));
    bf = mallocz(sizeof(*bf));

    bf->mode = mode;
    bf->nb_sectors = file_size / 512;
    bf->f = f;

    if (mode == BF_MODE_SNAPSHOT) {
        bf->sector_table = mallocz(sizeof(bf->sector_table[0]) *
                                   bf->nb_sectors);
    }
    
    bs->opaque = bf;
    bs->get_sector_count = bf_get_sector_count;
    bs->read_async = bf_read_async;
    bs->write_async = bf_write_async;
    return bs;
}

#define MAX_EXEC_CYCLE 500000
#define MAX_SLEEP_TIME 10 /* in ms */

void virt_machine_run(VirtMachine *m)
{
    fd_set rfds, wfds, efds;
    int fd_max, ret, delay, net_fd, stdin_fd;
    struct timeval tv;
    
    delay = virt_machine_get_sleep_duration(m, MAX_SLEEP_TIME);
    
    /* wait for an event */
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    FD_ZERO(&efds);
    fd_max = -1;
    if (m->console_dev && virtio_console_can_write_data(m->console_dev)) {
        STDIODevice *s = m->console->opaque;
        stdin_fd = s->stdin_fd;
        FD_SET(stdin_fd, &rfds);
        fd_max = stdin_fd;

        if (s->resize_pending) {
            int width, height;
            console_get_size(s, &width, &height);
            virtio_console_resize_event(m->console_dev, width, height);
            s->resize_pending = FALSE;
        }
    }
    if (m->net_dev && virtio_net_can_write_packet(m->net_dev)) {
        net_fd = (intptr_t)m->net->opaque;
        FD_SET(net_fd, &rfds);
        fd_max = max_int(fd_max, net_fd);
    } else {
        net_fd = -1;
    }
#ifdef CONFIG_FS_NET
    fs_net_set_fdset(&fd_max, &rfds, &wfds, &efds, &delay);
#endif
    tv.tv_sec = delay / 1000;
    tv.tv_usec = delay % 1000;
    ret = select(fd_max + 1, &rfds, &wfds, &efds, &tv);
    if (ret > 0) {
        if (m->console_dev && FD_ISSET(stdin_fd, &rfds)) {
            uint8_t buf[128];
            int ret, len;
            len = virtio_console_get_write_len(m->console_dev);
            len = min_int(len, sizeof(buf));
            ret = m->console->read_data(m->console->opaque, buf, len);
            if (ret > 0) {
                virtio_console_write_data(m->console_dev, buf, ret);
            }
        }
        if (net_fd >= 0 && FD_ISSET(net_fd, &rfds)) {
            uint8_t buf[2048];
            int ret;
            ret = read(net_fd, buf, sizeof(buf));
            if (ret > 0)
                virtio_net_write_packet(m->net_dev, buf, ret);
        }
    }

    virt_machine_interp(m, MAX_EXEC_CYCLE);
}

static void tun_write_packet(EthernetDevice *bs,
                             const uint8_t *buf, int len)
{
    int fd = (intptr_t)(bs->opaque);
    write(fd, buf, len);
}

/* configure with:
# bridge configuration (connect tap0 to bridge interface br0)
   ip link add br0 type bridge
   ip tuntap add dev tap0 mode tap [user x] [group x]
   ip link set tap0 master br0
   ip link set dev br0 up
   ip link set dev tap0 up

# NAT configuration (eth1 is the interface connected to internet)
   ifconfig br0 192.168.3.1
   echo 1 > /proc/sys/net/ipv4/ip_forward
   iptables -D FORWARD 1
   iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE

   In the VM:
   ifconfig eth0 192.168.3.2
   route add -net 0.0.0.0 netmask 0.0.0.0 gw 192.168.3.1
*/
static EthernetDevice *tun_open(const char *ifname)
{
    struct ifreq ifr;
    int fd, ret;
    EthernetDevice *net;

    fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "Error: could not open /dev/net/tun\n");
        return NULL;
    }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    pstrcpy(ifr.ifr_name, sizeof(ifr.ifr_name), ifname);
    ret = ioctl(fd, TUNSETIFF, (void *) &ifr);
    if (ret != 0) {
        fprintf(stderr, "Error: could not configure /dev/net/tun\n");
        close(fd);
        return NULL;
    }
    fcntl(fd, F_SETFL, O_NONBLOCK);

    net = mallocz(sizeof(*net));
    net->opaque = (void *)(intptr_t)fd;
    net->write_packet = tun_write_packet;
    return net;
}

static struct option options[] = {
    { "help", no_argument, NULL, 'h' },
    { "ctrlc", no_argument },
    { "rw", no_argument },
    { "ro", no_argument },
    { "net", required_argument },
    { "append", required_argument },
    { "no-accel", no_argument },
    { NULL },
};

void help(void)
{
    printf("riscvemu version " CONFIG_VERSION ", Copyright (c) 2016-2017 Fabrice Bellard\n"
           "usage: riscvemu [options] [kernel.bin|url] [hdimage.bin|filesystem_path]...\n"
           "options are:\n"
#ifdef CONFIG_CPU_RISCV
           "-b [32|64|128]    set the integer register width in bits\n"
#endif
           "-m ram_size       set the RAM size in MB (default=%d)\n"
           "-rw               allow write access to the disk image (default=snapshot)\n"
           "-ctrlc            the C-c key stops the emulator instead of being sent to the\n"
           "                  emulated software\n"
           "-net ifname       set virtio network tap device\n"
           "-append cmdline   append cmdline to the kernel command line\n"
#ifdef CONFIG_CPU_X86
           "-no-accel         disable VM acceleration (KVM)\n"
#endif
           "\n"
           "Console keys:\n"
           "Press C-a x to exit the emulator, C-a h to get some help.\n",
           DEFAULT_RAM_SIZE);
    exit(1);
}

#ifdef CONFIG_CPU_RISCV
void launch_alternate_executable(char **argv, int xlen)
{
    char filename[1024];
    char new_exename[64];
    const char *p, *exename;
    int len;

    snprintf(new_exename, sizeof(new_exename), "riscvemu%d", xlen);
    exename = argv[0];
    p = strrchr(exename, '/');
    if (p) {
        len = p - exename + 1;
    } else {
        len = 0;
    }
    if (len + strlen(new_exename) > sizeof(filename) - 1) {
        fprintf(stderr, "%s: filename too long\n", exename);
        exit(1);
    }
    memcpy(filename, exename, len);
    filename[len] = '\0';
    strcat(filename, new_exename);
    argv[0] = filename;

    if (execvp(argv[0], argv) < 0) {
        perror(argv[0]);
        exit(1);
    }
}
#endif

int main(int argc, char **argv)
{
    VirtMachine *s;
    const char *kernel_filename, *netif_name, *path;
    int c, option_index;
    BOOL allow_ctrlc;
    BlockDeviceModeEnum drive_mode;
    BlockDevice *drive;
    FSDevice *fs;
    BOOL has_kernel;
    VirtMachineParams p_s, *p = &p_s;

    virt_machine_set_defaults(p);
    p->ram_size = (uint64_t)DEFAULT_RAM_SIZE << 20;
    allow_ctrlc = FALSE;
    drive_mode = BF_MODE_SNAPSHOT;
    netif_name = NULL;
    for(;;) {
        c = getopt_long_only(argc, argv, "hb:m:", options, &option_index);
        if (c == -1)
            break;
        switch(c) {
        case 0:
            switch(option_index) {
            case 1: /* ctrlc */
                allow_ctrlc = TRUE;
                break;
            case 2: /* rw */
                drive_mode = BF_MODE_RW;
                break;
            case 3: /* ro */
                drive_mode = BF_MODE_RO;
                break;
            case 4: /* net */
                netif_name = optarg;
                break;
            case 5: /* append */
                p->cmdline = optarg;
                break;
            case 6: /* no-accel */
                p->accel_enable = FALSE;
                break;
            default:
                fprintf(stderr, "unknown option index: %d\n", option_index);
                exit(1);
            }
            break;
        case 'h':
            help();
            break;
#ifdef CONFIG_CPU_RISCV
        case 'b':
            {
                int xlen;
                xlen = atoi(optarg);
                if (xlen != 32 && xlen != 64 && xlen != 128) {
                    fprintf(stderr, "Invalid integer register width\n");
                    exit(1);
                }
                if (xlen != riscv_cpu_get_max_xlen()) {
                    launch_alternate_executable(argv, xlen);
                }
            }
            break;
#endif
        case 'm':
            p->ram_size = (uint64_t)strtoul(optarg, NULL, 0) << 20;
            break;
        default:
            exit(1);
        }
    }

    if (optind >= argc) {
        help();
    }

    p->drive_count = 0;
    p->fs_count = 0;
    has_kernel = FALSE;
    kernel_filename = NULL;
    while (optind < argc) {
        path = argv[optind++];
#ifdef CONFIG_FS_NET
        if (strstart(path, "http:", NULL) ||
            strstart(path, "https:", NULL) ||
            strstart(path, "file:", NULL)) {
            
            if (p->fs_count >= MAX_FS_DEVICE) {
                fprintf(stderr, "too many filesystems\n");
                exit(1);
            }
            if (!strcmp(path, "net:")) {
                /* the URL is provided in the mount command */
                fs = fs_net_init(NULL, NULL, NULL);
                if (!fs)
                    exit(1);
            } else {
                uint8_t *kernel_buf;
                fs = fs_net_init(path, NULL, NULL);
                if (!fs)
                    exit(1);
                fs_net_event_loop(NULL, NULL);
                if (p->fs_count == 0 &&
                    fs_net_get_file(fs, &kernel_buf, "kernel.bin") > 0) {
                    has_kernel = TRUE;
                }
            }
            p->tab_fs[p->fs_count++] = fs;
        } else
#endif
       {
            struct stat st;

            if (stat(path, &st) < 0) {
                perror(path);
                exit(1);
            }
            if (!has_kernel) {
                /* first file is the kernel filename */
                kernel_filename = path;
                has_kernel = TRUE;
            } else if (S_ISDIR(st.st_mode)) {
                /* directory: use a filesystem */
                fs = fs_disk_init(path);
                if (!fs) {
                    fprintf(stderr, "%s: must be a directory\n", path);
                    exit(1);
                }
                p->tab_fs[p->fs_count++] = fs;
            } else {
                drive = block_device_init(path, drive_mode);
                p->tab_drive[p->drive_count++] = drive;
            }
        }
    }
    
    p->net = NULL;
    if (netif_name) {
        p->net = tun_open(netif_name);
        if (!p->net)
            exit(1);
    }

    p->console = console_init(allow_ctrlc);
    p->rtc_real_time = TRUE;
    s = virt_machine_init(p);
    
    if (has_kernel) {
#ifdef CONFIG_FS_NET
        if (!kernel_filename) {
            uint8_t *kernel_buf;
            int kernel_size;
            kernel_size = fs_net_get_file(p->tab_fs[0], &kernel_buf,
                                           "kernel.bin");
            if (kernel_size <= 0)
                goto no_kernel_error;
            copy_kernel(s, kernel_buf, kernel_size);
        } else
#endif
        {
            load_kernel(s, kernel_filename);
        }
    } else {
#ifdef CONFIG_FS_NET
    no_kernel_error:
#endif
        fprintf(stderr, "Kernel filename must be provided\n");
        exit(1);
    }
    setup_linux_config(s);

    for(;;) {
        virt_machine_run(s);
    }
    virt_machine_end(s);
    return 0;
}
