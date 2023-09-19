#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
#
# nvmereq    NVMe block requests observability tool.
#
# Requires drivers/nvme/host/nvme.h
#
# Requires a copy of the drivers/nvme/host/nvme.h header:
# https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/drivers/nvme/host/nvme.h?h=master
#
# Copyright (c) 2023 Samsung Electronics Co., Ltd. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 06-Nov-2023   Daniel Gomez   Created this.
from __future__ import print_function
from bcc import BPF
import argparse
import os

# arguments
examples = """examples:
  nvmeblk                          # Observe all NVMe requests
  nvmeblk --ops 0                  # Observe reads requests on all NVMe
  nvmeblk --ops 1                  # Observe writes requests on all NVMe
  nvmeblk --ops 1 --disk nvme9n1   # Observe writes request on 9th NVMe node
  nvmeblk --debug                  # Print eBPF program before observe
"""

parser = argparse.ArgumentParser(
    description="NVMe block requests observe tool",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-d", "--disk", type=str,
    help="NVMe disk")
parser.add_argument("-o", "--ops", type=int,
    help="trace this operation only")
parser.add_argument("--debug", action="store_true",
    help="Debug")
args = parser.parse_args()

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/blk-mq.h>
#include <linux/blk_types.h>
#include "nvme.h"

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char disk[DISK_NAME_LEN];
    u32 op;
    u32 len;
    u32 lba;
};

BPF_PERF_OUTPUT(events);
BPF_HISTOGRAM(blen, u32, 64);

/* local strcmp function, max length 16 to protect instruction loops */
#define CMPMAX	16

static int local_strcmp(const char *cs, const char *ct)
{
    int len = 0;
    unsigned char c1, c2;

    while (len++ < CMPMAX) {
        c1 = *cs++;
        c2 = *ct++;
        if (c1 != c2)
            return c1 < c2 ? -1 : 1;
        if (!c1)
            break;
    }
    return 0;
}
"""

bpf_text_disk_filter = ""
if args.disk:
    bpf_text_disk_filter = """
        if (local_strcmp(req->q->disk->disk_name, "{disk}"))
            return;
    """.format(disk=args.disk)

bpf_text_ops_filter = ""
if args.ops:
    bpf_text_ops_filter = """
        if ((req->cmd_flags & 0xff) != {ops})
            return;
    """.format(ops=args.ops)

bpf_text += """
void kprobe__nvme_setup_cmd(struct pt_regs *ctx, struct nvme_ns *ns, struct request *req)
{{
        struct data_t data = {{}};

        {disk_filter}
        {ops_filter}

        data.pid = bpf_get_current_pid_tgid() >> 32;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        bpf_probe_read_kernel(&data.disk, sizeof(data.disk), req->q->disk->disk_name);
        data.op = req->cmd_flags & 0xff;
        data.len = req->__data_len;
	    data.lba = req->__sector >> (ns->lba_shift - SECTOR_SHIFT);

        events.perf_submit(ctx, &data, sizeof(data));

        blen.increment(bpf_log2l(req->__data_len));
}}
""".format(disk_filter=bpf_text_disk_filter, ops_filter=bpf_text_ops_filter)

if args.debug:
    print(args)
    print(bpf_text)

b = BPF(text=bpf_text)
print("Tracing NVMe requests... Hit Ctrl-C to end.")
print("%-10s %-8s %-8s %-10s %-10s %-16s %-8s" % ("DISK", "REQ", "LEN", "LBA", "PID", "COMM", "ALGN"))

def print_event(cpu, data, size):
    event = b["events"].event(data)
    # Check LBA and size alignment (4k - 512k) and print
    max_alig_size = 0
    alig_size = 4096
    for _ in range(1, 9):
        lba_len = alig_size/4096
        aligned = not (event.len % alig_size) and not (event.lba % lba_len)
        if aligned:
            max_alig_size = alig_size
        alig_size = alig_size << 1

    print("%-10s %-8s %-8s %-10s %-10s %-16s %-8s" % (
            event.disk.decode('utf-8', 'replace'),
            event.op,
            event.len,
            event.lba,
            event.pid,
            event.comm.decode('utf-8', 'replace'),
            max_alig_size,
    ),)

b["events"].open_perf_buffer(print_event)
blen = b.get_table("blen")
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        print()
        blen.print_log2_hist("Block size", "operation", section_print_fn=bytes.decode)
        blen.clear()
        exit()
