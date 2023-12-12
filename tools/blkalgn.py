#!/usr/bin/env python
# SPDX-License-Identifier: Apache-2.0
#
# Block alignment observability tool.
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
import os
import time
import sqlite3

examples = """examples:
  blkalgn                             # Observe all blk commands
  blkalgn --disk nvme9n1              # Observe all commands on 9th NVMe node
  blkalgn --ops read                  # Observe read commands on all NVMe
  blkalgn --ops write                 # Observe write commands on all NVMe
  blkalgn --ops write --disk nvme9n1  # Observe write commands on 9th NVMe node
  blkalgn --debug                     # Print eBPF program before observe
  blkalgn --trace                     # Print NVMe captured events
  blkalgn --interval 0.1              # Poll data ring buffer every 100 ms
  blkalgn --output blkalgn.db         # Capture blk commands in sqlite database
  blkalgn parser
    --file blkalgn.db
    --select "*"                      # Query NVMe commands in captured db file
  blkalgn parser
    --file blkalgn.db
    --select "algn"                   # Print alignment in a power-of-2
    --groupby "algn"                  # histogram
  blkalgn parser
    --file blkalgn.db
    --select "*"                      # Query only commands with an alignment
    --algn "< 16384"                  # < 16k
  blkalgn parser
    --file blkalgn.db
    --select "*"
    --len ">= 8192"                   # Query only commands with a length >= 8k
    --algn "< 16384"                  # and alignment < 16k
"""

parser = argparse.ArgumentParser(
    description="Block commands observer tool",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples,
)
parser.add_argument(
    "-d",
    "--disk",
    type=str,
    help="capture commands for this block device node only"
)
parser.add_argument(
    "-o",
    "--ops",
    type=str,
    help="capture this command operation only"
)
parser.add_argument("--debug", action="store_true", help="debug")
parser.add_argument(
    "--trace",
    action="store_true",
    help="trace block captured commands"
)
parser.add_argument(
    "--interval",
    type=float,
    help="polling interval"
)
parser.add_argument(
    "--output",
    type=str,
    help="database output file (.db)"
)
parser.add_argument(
    "--force",
    action="store_true",
    help="force overwrite database",
)

subparser = parser.add_subparsers(help="subcommand list", dest="cmd")
dbparser = subparser.add_parser(
    "parser",
    help="db parser tool",
    formatter_class=argparse.RawDescriptionHelpFormatter
)
dbparser.add_argument(
    "--info",
    action="store_true",
    help="database info",
)
dbparser.add_argument(
    "--file",
    type=str,
    help="database file",
    default="nvmecmd.db",
)
dbparser.add_argument(
    "--select",
    type=str,
    help="SELECT",
)
dbparser.add_argument(
    "--groupby",
    type=str,
    help="GROUP BY",
)
dbparser.add_argument(
    "--disk",
    type=str,
    help="disk name",
)
dbparser.add_argument(
    "--req",
    type=int,
    help="command operation",
)
dbparser.add_argument(
    "--len",
    type=str,
    help="command length",
    action="append",
)
dbparser.add_argument(
    "--lba",
    type=int,
    help="command LBA",
)
dbparser.add_argument(
    "--comm",
    type=str,
    help="process name",
)
dbparser.add_argument(
    "--pid",
    type=int,
    help="process id",
)
dbparser.add_argument(
    "--algn",
    type=str,
    help="max alignment",
    action="append",
)

args = parser.parse_args()

level = logging.INFO
if args.debug:
    level = logging.DEBUG

logging.basicConfig(level=level)


def print_log2_histogram_tuples(data):
    max_count = max(data, key=lambda x: x[1])[1]

    for value, count in data:
        block_range = f"{value:<8} : {count:<6}"
        bar_width = max(
            int(count / max_count * 40), 1
        )  # Ensure a minimum bar width of 1
        bar = "*" * bar_width + " " * (
            40 - bar_width
        )  # Ensure the bar width is 40 characters

        print(f"{block_range} |{bar}|")


def open_and_validate_db_file():
    if not os.path.exists(args.file):
        print(f"File {args.file} does not exist")
        exit()

    conn = sqlite3.connect(f"{args.file}")
    cursor = conn.cursor()

    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    table_names = cursor.fetchall()

    if not table_names or ("events",) not in table_names:
        logging.error("Table name 'events' not found")
        logging.error(f"table_names: {table_names}")
        conn.close()
        exit()

    if args.info:
        print(f"Tables: {table_names}")

    cursor.execute("PRAGMA table_info(events)")
    table_info = cursor.fetchall()

    expected_columns = [
        "id", "disk", "req", "len", "lba", "pid", "comm", "algn"
    ]
    table_columns = [column[1] for column in table_info]
    if expected_columns != table_columns:
        logging.error("'events' table structure mismatch")
        logging.error(f"expected: {expected_columns}")
        logging.error(f"found: {table_columns}")
        conn.close()
        exit()

    if args.info:
        print("'events' table description:")
        for column_info in table_info:
            print(column_info)
        conn.close()
        exit()

    return conn, cursor


if args.cmd and "parser" in args.cmd:
    conn, cursor = open_and_validate_db_file()

    """SELECT statement composer:
    SELECT {args.select}
    FROM events
    WHERE {args.disk} = ?
    AND {args.req} = ?
    GROUP BY {args.groupby}
    """
    select = f"SELECT {args.select} FROM events"
    where = " WHERE"
    disk = req = comm = ""
    where_vars = ()
    if args.disk:
        where += " AND disk = ?"
        where_vars += (f"{args.disk}",)
    if args.req is not None:
        where += " AND req = ?"
        where_vars += (args.req,)
    if args.len is not None:
        for alen in args.len:
            if any(x in alen for x in ["=", ">", "<"]):
                where += f" AND len {alen}"
            else:
                where += " AND len = ?"
                where_vars += (alen,)
    if args.lba is not None:
        where += " AND lba = ?"
        where_vars += (args.lba,)
    if args.pid is not None:
        where += " AND pid = ?"
        where_vars += (args.pid,)
    if args.comm:
        where += " AND comm = ?"
        where_vars += (f"{args.comm}",)
    if args.algn is not None:
        for aalgn in args.algn:
            if any(x in aalgn for x in ["=", ">", "<"]):
                where += f" AND algn {aalgn}"
            else:
                where += " AND algn = ?"
                where_vars += (aalgn,)

    if where != " WHERE":
        where = where.replace("WHERE AND", "WHERE")
        select += where
    if args.groupby and args.groupby != "*":
        select += f" GROUP BY {args.groupby}"

    count = False
    if args.select == args.groupby and args.select != "*":
        select = select.replace("FROM events", ", COUNT(*) FROM events")
        count = True

    logging.debug(f"{select}, {where_vars}")
    cursor.execute(select, where_vars)
    events = cursor.fetchall()

    if len(events) > 10:
        user_input = input("Large output. Do you want to proceed? (yes/no)")
        if not user_input.lower() in ["yes", "y"]:
            conn.close()
            exit()

    twidth = [
        max(max(5, len(str(item))) for item in col) for col in zip(*events)
    ]

    if not count and events and len(events[0]) != 2:
        if len(events[0]) == 8:
            header = [
                "IDX", "DISK", "REQ", "LEN", "LBA", "PID", "COMM", "ALGN"
            ]
            header = ' '.join('{:<{}}'.format(field, width)
                              for field, width in zip(header, twidth))
            print(header)
            for row in events:
                formatted_row = " ".join(
                    "{:<{}}".format(item, width)
                    for item, width in zip(row, twidth)
                )
                print(formatted_row)
            print(f"Total: {len(events)}")

    if count and events and len(events[0]) == 2:
        print_log2_histogram_tuples(events)

    conn.close()
    exit()

# database setup to capture events
if args.output:
    if os.path.exists(args.output) and not args.force:
        print(f"File {args.output} exist. Use '--force' to overwrite.")
        exit()
    if os.path.exists(args.output) and args.force:
        os.remove(args.output)
    conn = sqlite3.connect(f"{args.output}")
    cursor = conn.cursor()

    cursor.execute(
        """
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
    """
    )
    conn.close()
    logging.debug("Capturing NVMe commands into database...")


# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/blk-mq.h>

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
# Operation dictionary. Full list of operations at Linux kernel
# 'include/linux/blk_types.h' header file.
blk_ops = {
    0: "read",
    1: "write",
    "read": 0,
    "write": 1,
}
if args.ops:
    operation = blk_ops[args.ops]
    bpf_text_ops_filter = """
        if ((req->cmd_flags & 0xff) != {ops})
            return;
    """.format(
        ops=operation
    )

bpf_text += """
void start_request(struct pt_regs *ctx, struct request *req)
{{
        struct data_t data = {{}};
        u32 max_algn_size = 4096, algn_size = 4096;
        u32 lba_len = algn_size / 4096;
        bool is_algn = false;
        u8 i;
        u32 lba_shift;

        {disk_filter}
        {ops_filter}

        data.pid = bpf_get_current_pid_tgid() >> 32;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        bpf_probe_read_kernel(&data.disk, sizeof(data.disk),
                              req->q->disk->disk_name);
        data.op = req->cmd_flags & 0xff;
        data.len = req->__data_len;
        lba_shift = bpf_log2(req->q->limits.logical_block_size);
        data.lba = req->__sector >> (lba_shift - SECTOR_SHIFT);

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
    print("Tracing block commands... Hit Ctrl-C to end.")
    print(
        "%-10s %-8s %-8s %-10s %-10s %-16s %-8s"
        % ("DISK", "OPS", "LEN", "LBA", "PID", "COMM", "ALGN")
    )

if BPF.get_kprobe_functions(b"blk_mq_start_request"):
    bpf.attach_kprobe(event="blk_mq_start_request", fn_name="start_request")


events_data_acc = []


def capture_event(ctx, data, size):
    event = bpf["events"].event(data)
    if args.trace:
        print_event(event)
    if args.output:
        acc_event(event)


def print_event(event):
    print(
        "%-10s %-8s %-8s %-10s %-10s %-16s %-8s"
        % (
            event.disk.decode("utf-8", "replace"),
            blk_ops[event.op],
            event.len,
            event.lba,
            event.pid,
            event.comm.decode("utf-8", "replace"),
            event.algn,
        ),
    )


def acc_event(event):
    event_data = (
        event.disk.decode("utf-8", "replace"),
        event.op,
        event.len,
        event.lba,
        event.pid,
        event.comm.decode("utf-8", "replace"),
        event.algn,
    )
    events_data_acc.append(event_data)


def db_commit_event(events_data):
    if not len(events_data_acc):
        return
    conn = sqlite3.connect(f"{args.output}")
    cursor = conn.cursor()
    cursor.executemany(
        """
        INSERT INTO events (disk, req, len, lba, pid, comm, algn)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """,
        events_data,
    )
    conn.commit()
    conn.close()
    events_data_acc.clear()


bpf["events"].open_ring_buffer(capture_event)
block_len = bpf["block_len"]
algn = bpf["algn"]
while 1:
    try:
        bpf.ring_buffer_poll(30)
        db_commit_event(events_data_acc)
        if args.interval:
            time.sleep(abs(args.interval))
    except KeyboardInterrupt:
        bpf.ring_buffer_consume()
        db_commit_event(events_data_acc)
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
