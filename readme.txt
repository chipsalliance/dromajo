TinyEMU System Emulator by Fabrice Bellard
==========================================

1) Features
-----------

- RISC-V system emulator supporting the RV128IMAFDQC base ISA (user
  level ISA version 2.2, priviledged architecture version 1.10)
  including:

  - 32/64/128 bit integer registers
  - 32/64/128 bit floating point instructions
  - Compressed instructions
  - dynamic XLEN change

- x86 system emulator based on KVM

- VirtIO console, network, block device, input and 9P filesystem

- Graphical display with SDL

- JSON configuration file

- Remote HTTP block device and filesystem

- small code, easy to modify, no external dependancies

- Javascript demo version

2) Installation
---------------

- The libraries libcurl, OpenSSL and SDL should be installed. On a Fedora
  system you can do it with:

  sudo dnf install openssl-devel libcurl-devel SDL-devel

  It is possible to compile the programs without these libraries by
  commenting CONFIG_FS_NET and/or CONFIG_SDL in the Makefile.

- Edit the Makefile to disable the 128 bit target if you compile on a
  32 bit host (for the 128 bit RISCV target the compiler must support
  the __int128 C extension).

- Use 'make' to compile the binaries.

- You can optionally install the program to '/usr/local/bin' with:

  make install

3) Usage
--------

3.1 Quick examples
------------------

- Use the VM images available from https://bellard.org/jslinux (no
  need to download them):

  Terminal:

  ./temu https://bellard.org/jslinux/buildroot-riscv64.cfg

  Graphical (with SDL):

  ./temu https://bellard.org/jslinux/buildroot-x86-xwin.cfg

  ./temu https://bellard.org/jslinux/win2k.cfg

- Download the example RISC-V Linux image
  (diskimage-linux-riscv-yyyy-mm-dd.tar.gz) and use it:

  ./temu root-riscv64.cfg

  ./temu rv128test/rv128test.cfg

- Access to your local hard disk (/tmp directory) in the guest:

  ./temu root_9p-riscv64.cfg

then type:
mount -t 9p /dev/root /mnt

in the guest. The content of the host '/tmp' directory is visible in '/mnt'.

3.2 Invocation
--------------

usage: temu [options] config_file
options are:
-m ram_size       set the RAM size in MB
-rw               allow write access to the disk image (default=snapshot)
-ctrlc            the C-c key stops the emulator instead of being sent to the
                  emulated software
-append cmdline   append cmdline to the kernel command line
-no-accel         disable VM acceleration (KVM, x86 machine only)

Console keys:
Press C-a x to exit the emulator, C-a h to get some help.

3.3 Network usage
-----------------

The easiest way is to use the "user" mode network driver. No specific
configuration is necessary.

TinyEMU also supports a "tap" network driver to redirect the network
traffic from a VirtIO network adapter.

You can look at the netinit.sh script to create the tap network
interface and to redirect the virtual traffic to Internet thru a
NAT. The exact configuration may depend on the Linux distribution and
local firewall configuration.

The VM configuration file must include:

eth0: { driver: "tap", ifname: "tap0" }

and configure the network in the guest system with:

ifconfig eth0 192.168.3.2
route add -net 0.0.0.0 gw 192.168.3.1 eth0

3.4 Network filesystem
----------------------

TinyEMU supports the VirtIO 9P filesystem to access local or remote
filesystems. For remote filesystems, it does HTTP requests to download
the files. The protocol is compatible with the vfsync utility. In the
"mount" command, "/dev/rootN" must be used as device name where N is
the index of the filesystem. When N=0 it is omitted.

The build_filelist tool builds the file list from a root directory. A
simple web server is enough to serve the files.

The '.preload' file gives a list of files to preload when opening a
given file.

3.5 Network block device
------------------------

TinyEMU supports an HTTP block device. The disk image is split into
small files. Use the 'splitimg' utility to generate images. The URL of
the JSON blk.txt file must be provided as disk image filename.

4) Technical notes
------------------

4.1) 128 bit support

The RISC-V specification does not define all the instruction encodings
for the 128 bit integer and floating point operations. The missing
ones were interpolated from the 32 and 64 ones.

Unfortunately there is no RISC-V 128 bit toolchain nor OS now
(volunteers for the Linux port ?), so rv128test.bin may be the first
128 bit code for RISC-V !

4.2) Floating point emulation

The floating point emulation is bit exact and supports all the
specified instructions for 32, 64 and 128 bit floating point
numbers. It uses the new SoftFP library.

4.3) HTIF console

The standard HTIF console uses registers at variable addresses which
are deduced by loading specific ELF symbols. TinyEMU does not rely on
an ELF loader, so it is much simpler to use registers at fixed
addresses (0x40008000). A small modification was made in the
"riscv-pk" boot loader to support it. The HTIF console is only used to
display boot messages and to power off the virtual system. The OS
should use the VirtIO console.

4.4) Javascript version

The Javascript version (JSLinux) can be compiled with Makefile.js and
emscripten. A complete precompiled and preconfigured demo is available
in the jslinux-yyyy-mm-dd.tar.gz archive (read the readme.txt file
inside the archive).

4.5) x86 emulator

A small x86 emulator is included. It is not really an emulator because
it uses the Linux KVM API to run the x86 code at near native
performance. The x86 emulator uses the same set of VirtIO devices as
the RISCV emulator and is able to run many operating systems.

The x86 emulator accepts a Linux kernel image (bzImage). No BIOS image
is necessary.

The x86 emulator comes from my JS/Linux project (2011) which was one
of the first emulator running Linux fully implemented in
Javascript. It is provided to allow easy access to the x86 images
hosted at https://bellard.org/jslinux .


5) License / Credits
--------------------

TinyEMU is released under the MIT license. If there is no explicit
license in a file, the license from MIT-LICENSE.txt applies.

The SLIRP library has its own license (two clause BSD license).
