RISCV Emulator by Fabrice Bellard
=================================

1) Features
-----------

- RISC-V system emulator supporting the RV128IMAFDQC base ISA (user
  level ISA version 2.1, priviledged architecture version 1.9.1)
  including:

  - 32/64/128 bit integer registers
  - 32/64/128 bit floating point instructions
  - Compressed instructions
  - Private extension to change the integer register width (XLEN) dynamically
  
- VirtIO console, network, block device and 9P filesystem

- HTIF console

- small code, easy to modify, no external dependancies

- Javascript demo version running 64 bit Linux

2) Installation
---------------

- Edit the Makefile to disable the 128 bit target if you compile on a
  32 bit host (for the 128 bit target the compiler must support the
  __int128 C extension).

- Comment CONFIG_FS_NET in the makefile if libcurl is not available on
  your system.

- Use 'make' to compile the binaries.

3) Usage
--------

3.1 Quick examples
------------------

- Test the compiled binaries with:

  ./riscvemu -b 32 rv128test.bin
  
  ./riscvemu -b 64 rv128test.bin
  
  ./riscvemu -b 128 rv128test.bin

  [rv128test.bin is a small program working with the 32/64/128 bit ISA]

- Use the Linux image of the JS demo (no need to download it)

  ./riscvemu http://bellard.org/riscvemu/js/riscv-poky

- Download the example Linux image and use it:

  ./riscvemu bbl.bin root.bin

- Access to your local hard disk (/tmp directory) in the guest:

  ./riscvemu bbl.bin root.bin /tmp

then type:

mount -t 9p -o trans=virtio /dev/root /mnt

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

and configure the network on the guest system with:

ifconfig eth0 192.168.3.2
route add -net 0.0.0.0 gw 192.168.3.1 eth0

3.4 Network filesystem
----------------------

When using a URL of a file list as parameter, RISCVEMU instanciates
the VirtIO 9P filesystem and does HTTP requests to download the
files. Currently there is no persistent write support (the changes are
kept in memory only).

The build_filelist tool builds the file list from a root directory.

The kernel filename can be specified with the "Kernel:" header in the
file list.

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

4.3) Dynamic XLEN change

The emulator contains a private extension to dynamically change the
integer register width. It is needed so that for example a 64 bit
Linux can run 32 bit executables. Unfortunately no such feature is
implemented yet in RISC-V Linux, but with this emulator it is possible
to support it.

The 'misa' BASE bits are writable and can be used to make the switch
(see the rv128test.bin demo).

The MSTATUS bits includes the new 'XB' and 'XPB' bits (X=U, S, H or M)
to change the XLEN value when entering and exiting an exception.

4.4) HTIF console

The standard HTIF console uses registers at variable addresses which
are deduced by loading specific ELF symbols. RISCVEMU does not rely on
an ELF loader, so it is much simpler to use registers at fixed
addresses (0x40008000). A small modification was made in the
"riscv-pk" boot loader to support it. The HTIF console is only use a
display boot messages and to power off the virtual system. The OS
should use the VirtIO console.

4.5) Javascript version

A RISC-V 64 bit Javascript demo is provided using emscripten. A 32 bit
version would be much faster, but it is less fun because there are
already plenty of other Javascript 32 bit emulators such as JSLinux or
JOR1K.

4.6) Optimization

The code is not fully optimized yet, so I expect the speed could be
improved, mainly by optimizing the code fetch. Of course the code base
should be kept small and simple, otherwise it is better to invest time
in QEMU !

5) License
----------

RISCVEMU is released under the MIT license.
