#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
#
# nvmecmd NVMe command observability tool.
#
# Copyright (c) 2023 Samsung Electronics Co., Ltd. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 06-Nov-2023   Daniel Gomez   Created this.
from __future__ import (
    absolute_import, division, unicode_literals, print_function
)
from bcc import BPF
import argparse
import logging
import time

examples = """examples:
  nvmecmd                          # Observe all NVMe commands
  nvmecmd --disk nvme9n1           # Observe all commands on 9th NVMe node
  nvmecmd --ops 0                  # Observe read commands on all NVMe
  nvmecmd --ops 1                  # Observe write commands on all NVMe
  nvmecmd --ops 1 --disk nvme9n1   # Observe write commands on 9th NVMe node
  nvmecmd --debug                  # Print eBPF program before observe
  nvmecmd --trace                  # Print NVMe captured events
  nvmecmd --interval 0.1           # Poll data ring buffer every 100 ms
"""

parser = argparse.ArgumentParser(
    description="NVMe commands observer tool",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples,
)
parser.add_argument(
    "-d",
    "--disk",
    type=str,
    help="capture commands for this NVMe disk node only"
)
parser.add_argument(
    "-o",
    "--ops",
    type=int,
    help="capture this command operation only"
)
parser.add_argument("--debug", action="store_true", help="debug")
parser.add_argument(
    "--trace",
    action="store_true",
    help="trace NVMe captured commands"
)
parser.add_argument(
    "--interval",
    type=float,
    help="polling interval"
)

args = parser.parse_args()

level = logging.INFO
if args.debug:
    level = logging.DEBUG

logging.basicConfig(level=level)

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/blk-mq.h>
#include <linux/blk_types.h>
#include <linux/nvme.h>

struct nvme_ns {
    struct list_head list;

    struct nvme_ctrl *ctrl;
    struct request_queue *queue;
    struct gendisk *disk;
#ifdef CONFIG_NVME_MULTIPATH
    enum nvme_ana_state ana_state;
    u32 ana_grpid;
#endif
    struct list_head siblings;
    struct kref kref;
    struct nvme_ns_head *head;

    int lba_shift;
    // [...]
};

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char disk[DISK_NAME_LEN];
    u32 op;
    u32 len;
    u32 lba;
    u32 algn;
};

BPF_HISTOGRAM(block_len, u32, 64);
BPF_HISTOGRAM(algn, u32, 64);
BPF_ARRAY(counts, u64, 1);
BPF_RINGBUF_OUTPUT(events, 8);

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
    """.format(
        disk=args.disk
    )

bpf_text_ops_filter = ""
if args.ops:
    bpf_text_ops_filter = """
        if ((req->cmd_flags & 0xff) != {ops})
            return;
    """.format(
        ops=args.ops
    )

bpf_text += """
void kprobe__nvme_setup_cmd(struct pt_regs *ctx, struct nvme_ns *ns,
                            struct request *req)
{{
        struct data_t data = {{}};
        u32 max_algn_size = 4096, algn_size = 4096;
        u32 lba_len = algn_size / 4096;
        bool is_algn = false;
        u8 i;

        {disk_filter}
        {ops_filter}

        data.pid = bpf_get_current_pid_tgid() >> 32;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        bpf_probe_read_kernel(&data.disk, sizeof(data.disk),
                              req->q->disk->disk_name);
        data.op = req->cmd_flags & 0xff;
        data.len = req->__data_len;
        data.lba = req->__sector >> (ns->lba_shift - SECTOR_SHIFT);

        for (i=0; i<8; i++) {{
            is_algn = !(data.len % algn_size) && !(data.lba % lba_len);
            if (is_algn) {{
                max_algn_size = algn_size;
            }}
            algn_size = algn_size << 1;
            lba_len = algn_size / 4096;
        }}
        data.algn = max_algn_size;

        events.ringbuf_output(&data, sizeof(data), 0);
        block_len.increment(bpf_log2l(req->__data_len));
        algn.increment(bpf_log2l(max_algn_size));
}}
""".format(
    disk_filter=bpf_text_disk_filter, ops_filter=bpf_text_ops_filter
)

if args.debug:
    print(args)
    print(bpf_text)

bpf = BPF(text=bpf_text)
if args.trace:
    print("Tracing NVMe commands... Hit Ctrl-C to end.")
    print(
        "%-10s %-8s %-8s %-10s %-10s %-16s %-8s"
        % ("DISK", "REQ", "LEN", "LBA", "PID", "COMM", "ALGN")
    )


def capture_event(ctx, data, size):
    event = bpf["events"].event(data)
    if args.trace:
        print_event(event)


def print_event(event):
    print(
        "%-10s %-8s %-8s %-10s %-10s %-16s %-8s"
        % (
            event.disk.decode("utf-8", "replace"),
            event.op,
            event.len,
            event.lba,
            event.pid,
            event.comm.decode("utf-8", "replace"),
            event.algn,
        ),
    )


bpf["events"].open_ring_buffer(capture_event)
block_len = bpf["block_len"]
algn = bpf["algn"]
while 1:
    try:
        bpf.ring_buffer_poll(30)
        if args.interval:
            time.sleep(abs(args.interval))
    except KeyboardInterrupt:
        bpf.ring_buffer_consume()
        print()
        block_len.print_log2_hist(
            "Block size", "operation", section_print_fn=bytes.decode
        )
        block_len.clear()
        print()
        algn.print_log2_hist("Algn size", "operation",
                             section_print_fn=bytes.decode)
        algn.clear()
        break
exit()
