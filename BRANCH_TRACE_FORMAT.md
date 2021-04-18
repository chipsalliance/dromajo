# Branch Trace Format  20210418

When studying branch predictors, it's practical to use traces of
branches rather than having to deal with a complete simulation.  This
version of Tinyemu has been argumented with primitive support for
that.

As branch traces can be billions of branch events it's important that
they be stored compactly (we can also compress them but that slows
down the use).  The trace format must include address of branch,
taken/not-taken, # of non-branch instructions since last branch (to
reconstruct the sequence number, important for reporting
Misses-Per-Kilo-Instruction, etc).  Note I don't not include anything
from the instruction itself.  This might be a limitation for some
studies.

Exploiting the fact that Addresses are from Sv48 (at most), means we
have 64-48-1=15 bits for the count. 

We use the following format: header:8192 event:64*
where events are of this work (stored little endian)

   was-taken:1 delta:15 signed:address:48

The header can be ignored and is merely informational.
