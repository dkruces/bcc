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
import sqlite3

# arguments
examples = """examples:
  nvmeblk                          # Observe all NVMe requests
  nvmeblk --ops 0                  # Observe reads requests on all NVMe
  nvmeblk --ops 1                  # Observe writes requests on all NVMe
  nvmeblk --ops 1 --disk nvme9n1   # Observe writes request on 9th NVMe node
  nvmeblk --debug                  # Print eBPF program before observe
  nvmeblk --trace                  # Print NVMe captured events
  nvmeblk --output nvmecmd.db      # Capture NVMe commands in sqlite database
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
parser.add_argument("--trace", action="store_true",
    help="Trace")
parser.add_argument("--db", action="store_true",
    help="db")
parser.add_argument("--db1", action="store_true",
    help="db1")
parser.add_argument(
    "--output",
    type=str,
    help="database output file (.db)",
    default="nvmecmd.db",
)
parser.add_argument(
    "--force",
    action="store_true",
    help="db1",
)

subparser = parser.add_subparsers(help="command help", dest="cmd")
db = subparser.add_parser("parser", help="parser tool", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
db.add_argument(
    "--file",
    type=str,
    help="database file",
    default="nvmecmd.db",
)

args = parser.parse_args()


def print_log2_histogram(data):
    max_count = max(data)

    for idx, count in enumerate(data):
        block_size = idx
        block_start = 2 ** block_size
        block_end = 2 ** (block_size + 1)
        block_range = f"2^{block_size} -> 2^{block_size + 1}"
        bar_width = max(int(count / max_count * 40), 1)  # Ensure a minimum bar width of 1
        bar = '*' * bar_width + ' ' * (40 - bar_width)  # Ensure the bar width is 40 characters

        print(f"{block_range:<20} : {count:<6} |{bar}|")


def print_log2_histogram_tuples(data):
    max_count = max(data, key=lambda x: x[1])[1]

    for value, count in data:
        block_range = f"{value:<8} : {count:<6}"
        bar_width = max(int(count / max_count * 40), 1)  # Ensure a minimum bar width of 1
        bar = '*' * bar_width + ' ' * (40 - bar_width)  # Ensure the bar width is 40 characters

        print(f"{block_range} |{bar}|")


if args.cmd and "parser" in args.cmd:
    if not os.path.exists(args.file):
        print(f"File {args.file} does not exist")
        exit()
    conn = sqlite3.connect(f"{args.output}")
    cursor = conn.cursor()

    #cursor.execute('SELECT len FROM events WHERE disk = ? AND req = ? AND comm = ?', (target_disk, target_req, target_comm))
    target_disk = "nvme0n1"
    cursor.execute('SELECT algn, COUNT(*) FROM events WHERE disk = ? GROUP BY algn', (target_disk,))
    length_counts = cursor.fetchall()
    if not length_counts:
        conn.close()
        exit()

    for length, count in length_counts:
        print(f"Length: {length}, Count: {count}")

    # Convert the result to a list of tuples
    length_counts_list = [(length, count) for length, count in length_counts]

    # Print the retrieved length counts as a list of tuples
    print(length_counts_list)
    print_log2_histogram_tuples(length_counts_list)

    conn.close()
    print("parser done")
    exit()

# database setup to capture events
if args.output:
    if os.path.exists(args.output) and not args.force:
        print(f"File {args.output} exist. Use '--force' to overwrite.")
        exit()
    conn = sqlite3.connect(f"{args.output}")
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY,
            disk TEXT,
            req INTEGER,
            len INTEGER,
            lba INTEGER,
            pid INTEGER,
            comm TEXT,
            algn INTEGER
        )
    ''')
    conn.close()

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

    if args.output:
        events_data = [(
             event.disk.decode('utf-8', 'replace'),
             event.op,
             event.len,
             event.lba,
             event.pid,
             event.comm.decode('utf-8', 'replace'),
             max_alig_size)
        ]

        cursor.executemany('''
            INSERT INTO events (disk, req, len, lba, pid, comm, algn)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', events_data)
        conn.commit()

    if not args.trace:
        return

    print("%-10s %-8s %-8s %-10s %-10s %-16s %-8s" % (
            event.disk.decode('utf-8', 'replace'),
            event.op,
            event.len,
            event.lba,
            event.pid,
            event.comm.decode('utf-8', 'replace'),
            max_alig_size,
    ),)


if args.db:
    cursor.execute('SELECT * FROM events')
    events = cursor.fetchall()
    for event in events:
        print(event)
    print_log2_histogram(events)
    conn.close()
    exit()

if args.db1:
    conn = sqlite3.connect(f"{args.output}")
    cursor = conn.cursor()

    target_disk = 'nvme0n2'
    target_req = 1
    target_comm = 'postgres'
    cursor.execute('SELECT len FROM events WHERE disk = ? AND req = ? AND comm = ?', (target_disk, target_req, target_comm))
    # events = cursor.fetchall()
    blen = [row[0] for row in cursor.fetchall()]
    print(blen)
    # print_log2_histogram(blen)

    cursor.execute('SELECT algn, COUNT(*) FROM events GROUP BY algn')
    length_counts = cursor.fetchall()

    for length, count in length_counts:
        print(f"Length: {length}, Count: {count}")

    # Convert the result to a list of tuples
    length_counts_list = [(length, count) for length, count in length_counts]

    # Print the retrieved length counts as a list of tuples
    print(length_counts_list)
    print_log2_histogram_tuples(length_counts_list)

    conn.close()
    exit()

b["events"].open_perf_buffer(print_event)
blen = b.get_table("blen")

if args.output:
    conn = sqlite3.connect(f"{args.output}")
    cursor = conn.cursor()

while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        print()
        blen.print_log2_hist("Block size", "operation", section_print_fn=bytes.decode)
        blen.clear()
        target_disk = 'nvme0n2'
        target_req = 1
        target_comm = 'postgres'
        if args.output:
            cursor.execute('SELECT len FROM events WHERE disk = ? AND req = ? AND comm = ?', (target_disk, target_req, target_comm))
            events = cursor.fetchall()
            print(events)

            cursor.execute('SELECT len FROM events WHERE disk = ? AND req = ? AND comm = ?', (target_disk, target_req, target_comm))
            blen = [row[0] for row in cursor.fetchall()]
            print(blen)
            print_log2_histogram(blen)

            cursor.execute('SELECT algn, COUNT(*) FROM events GROUP BY algn')
            length_counts = cursor.fetchall()

            for length, count in length_counts:
                print(f"Length: {length}, Count: {count}")

            # Convert the result to a list of tuples
            length_counts_list = [(length, count) for length, count in length_counts]

            # Print the retrieved length counts as a list of tuples
            print(length_counts_list)
            print_log2_histogram_tuples(length_counts_list)

            conn.close()
        exit()
