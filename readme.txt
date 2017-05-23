RISCV Emulator by Fabrice Bellard
=================================

1) Features
-----------

- RISC-V system emulator supporting the RV128IMAFDQC base ISA (user
  level ISA version 2.2, priviledged architecture version 1.10)
  including:

  - 32/64/128 bit integer registers
  - 32/64/128 bit floating point instructions
  - Compressed instructions
  - dynamic XLEN change

- VirtIO console, network, block device and 9P filesystem

- x86 system emulator based on KVM

- small code, easy to modify, no external dependancies

- Javascript demo version running 64 bit Linux

2) Installation
---------------

- The libraries libcurl and OpenSSL should be installed. On a Fedora
  system you can do it with:

  sudo yum install openssl-devel libcurl-devel

  It is possible to compile the programs without these libraries by
  commenting CONFIG_FS_NET in the Makefile.

- Edit the Makefile to disable the 128 bit target if you compile on a
  32 bit host (for the 128 bit RISCV target the compiler must support
  the __int128 C extension).

- Use 'make' to compile the binaries.

- You can optionally install the programs to '/usr/local/bin' with:

  make install

3) Usage
--------

3.1 Quick examples
------------------

- Test the compiled binaries with:

  ./riscvemu -b 32 rv128test.bin
  
  ./riscvemu -b 64 rv128test.bin
  
  ./riscvemu -b 128 rv128test.bin

  [rv128test.bin is a small program working with the 32/64/128 bit ISA]

- Use Linux images available from https://vfsync.org (no need to
  download them):

  ./riscvemu https://vfsync.org/u/os/riscv-poky

  ./x86emu https://vfsync.org/u/os/buildroot-x86

- Download the example Linux image and use it:

  ./riscvemu bbl.bin root.bin

- Access to your local hard disk (/tmp directory) in the guest:

  ./riscvemu https://vfsync.org/u/os/riscv-poky /tmp

then type:

mount -t 9p -o trans=virtio /dev/root1 /mnt

in the guest. The content of the host '/tmp' directory is visible in '/mnt'.

3.2 Invocation
--------------

usage: riscvemu [options] [kernel.bin|url] [hdimage.bin|filesystem_path]...
options are:
-b [32|64|128]    set the integer register width in bits
-m ram_size       set the RAM size in MB (default=256)
-rw               allow write access to the disk image (default=snapshot)
-ctrlc            the C-c key stops the emulator instead of being sent to the
                  emulated software
-net ifname       set virtio network tap device
-append cmdline   append cmdline to the kernel command line

Console keys:
Press C-a x to exit the emulator, C-a h to get some help.

3.3 Network usage
-----------------

RISCVEMU uses a "tap" network interface to redirect the network
traffic from a VirtIO network adapter.

You can look at the netinit.sh script to create the tap network
interface and to redirect the virtual traffic to Internet thru a
NAT. The exact configuration may depend on the Linux distribution and
local firewall configuration.

Then start RISCVEMU with:

./riscvemu -net tap0 bbl.bin root.bin

and configure the network in the guest system with:

ifconfig eth0 192.168.3.2
route add -net 0.0.0.0 gw 192.168.3.1 eth0

3.4 Network filesystem
----------------------

When using a URL as parameter, RISCVEMU instanciates the VirtIO 9P
filesystem and does HTTP requests to download the files. The protocol
is compatible with the vfsync utility. In the "mount" command,
"/dev/rootN" must be used as device name where N is the index of the
filesystem. When N=0 is it omitted.

The build_filelist tool builds the file list from a root directory. A
simple web server is enough to serve the files.

The emulator loads the Linux kernel from the '/kernel.bin' file if it
is present. The '.preload' file gives a list of files to preload when
opening a given file.

4) Technical notes
------------------

4.1) 128 bit support

The RISC-V specification does not define all the instruction encodings
for the 128 bit integer and floating point operations. The missing
ones were interpolated from the 32 and 64 ones.

Unfortunately there is no RISC-V 128 bit tool chain nor OS now
(volunteers for the Linux port ?), so rv128test.bin may be the first
128 bit code for RISC-V !

4.2) Floating point emulation

The floating point emulation is bit exact and supports all the
specified instructions for 32, 64 and 128 bit floating point
numbers. It uses the new SoftFP library.

4.3) HTIF console

The standard HTIF console uses registers at variable addresses which
are deduced by loading specific ELF symbols. RISCVEMU does not rely on
an ELF loader, so it is much simpler to use registers at fixed
addresses (0x40008000). A small modification was made in the
"riscv-pk" boot loader to support it. The HTIF console is only use a
display boot messages and to power off the virtual system. The OS
should use the VirtIO console.

4.4) Javascript version

A RISC-V 64 bit Javascript demo is provided using emscripten. A 32 bit
version would be much faster, but it is less fun because there are
already plenty of other Javascript 32 bit emulators such as JSLinux or
JOR1K.

4.5) x86 emulator

A very small x86 emulator is included. It is not really an emulator
because it uses the Linux KVM API to run the x86 code at near native
performance. The x86 emulator uses the same set of VirtIO devices as
the RISCV emulator and is able to run a Linux kernel.

The x86 emulator only accepts a flat kernel binary image which is
loaded at 0x00200000 and started in protected mode. It can be easily
generated from a compiled kernel tree with:

objcopy -O binary vmlinux kernel.bin

No BIOS image is necessary.

The x86 emulator comes from my JS/Linux project (2011) which was one
of the first emulator running Linux fully implemented in
Javascript. It is provided to allow easy access to the x86 images
hosted at https://vfsync.org .

5) License
----------

riscvemu and x86emu are released under the MIT license.
