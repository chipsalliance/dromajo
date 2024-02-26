#!/usr/bin/env python3
# Script that takes on a commit log (say, from spike) and adds the dissassembly.

# Input:
#   * a commit log text file.
#   * Or if no file specified, stdin.
#
#   The format of the commit log should be this:
#       prv-mode          pc        inst   rd              wdata
#       0 3 0x00000000800018fa (0x00000785) x15 0x0000000080006056
#   or...
#       0 3 0x0000000080002e5c (0x715d) x 2 0x000000008000de60
#
# Output:
#   * stdout
#
# Recommended Usage:
#   cat commitlog.txt | ./commitlog-helper.py | spike-dasm
#
#


import optparse
import fileinput

def main():
    parser = optparse.OptionParser()
    parser.add_option('-f', '--file', dest='filename', help='input commit log file')
    (options, args) = parser.parse_args()

    if options.filename:
        f = open(options.filename)
    else:
        f = fileinput.input()

    for line in f:

        # lengths are either 59 or 36 (with or without WB data)
        # (or even 32 if 2-byte instructions only print 4 nibbles).
        l = len(line)
        if l < 32:
            print(line),
            continue

        inst = "0x0000"
        isrvc = False
        rvcpad = ""
        if line[30]== ')':
            isrvc = True
            rvcpad = "    "
            inst = line[24:30]
        elif line[34] == ')':
            inst = line[24:34]
        else:
            # malformed line
            print(line),
            continue


        if l == 59 or (l == 55 and isrvc):
            # ignore newline
            new = line[:-1] + rvcpad + "  DASM(" + inst + ")"
        else:
            # pad out to equal line sizes
            new = line[:-1] + rvcpad + "                         DASM(" + inst + ")"
        print(new)

if __name__ == '__main__':
    main()
