# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

BCC (BPF Compiler Collection) is a toolkit for creating efficient kernel tracing and manipulation programs using eBPF. This repository contains a fork focused on development of the `blkalgn` tool - a block I/O alignment observability tool for analyzing storage I/O patterns.

## Build System

### Building blkalgn (libbpf-tools version)

```bash
cd libbpf-tools
make blkalgn
```

**Dependencies:**
- `libjson-c` (for JSON output)
- `libm` (math library)
- `blazesym` (Rust-based symbolization library for stack traces)
- `libbpf` (modern eBPF library)
- `clang` and `llvm` for BPF compilation

### Architecture Notes

The build system automatically detects if `cargo` is available and sets `USE_BLAZESYM=1` for x86 and arm64 architectures. The blkalgn tool is built separately from the standard APPS list with custom linker flags.

**Key Makefile targets:**
- `make all` - builds all standard tools plus blkalgn
- `make blkalgn` - builds only blkalgn
- `make clean` - removes build artifacts

### Known Build Issues

**Current Issue: blazesym linking errors**

The project recently updated blazesym from v0.1.0 to v0.2.0 (commit 72983ce4). This update was necessary due to Rust version compatibility but introduced linking errors:

```
undefined reference to `blazesym_symbolize'
undefined reference to `blazesym_result_free'
undefined reference to `blazesym_new'
undefined reference to `blazesym_free'
undefined reference to `libbpf_errstr'
```

The blazesym library is built via cargo and linked statically. The Makefile handles this at lines 167-176:
- Builds blazesym Rust library with C header generation
- Copies `libblazesym_c.a` to OUTPUT directory
- Copies `blazesym.h` header

**When fixing blazesym issues:**
1. Check the blazesym submodule at `libbpf-tools/blazesym`
2. Verify the C API hasn't changed between versions
3. Review `blazesym.h` generated header for API changes
4. Check if new linker flags are needed in Makefile line 159

## Code Architecture

### blkalgn Tool - Dual Implementation

**Two versions exist:**

1. **Legacy BCC/Python version** (`tools/blkalgn.py`)
   - Original implementation using BCC Python framework
   - Inline BPF C code as Python strings
   - Feature-rich: database capture, WAF measurement, parser subcommand
   - Located in `tools/` directory

2. **Modern libbpf version** (`libbpf-tools/blkalgn.[c|bpf.c|h]`)
   - Rewrite using libbpf CO-RE (Compile Once, Run Everywhere)
   - Separated BPF and userspace code
   - Currently at version 0.2
   - **Development focus: Port features from Python version here**

### libbpf-tools Structure

**Three-file pattern for each tool:**

1. `blkalgn.bpf.c` - BPF kernel-space code
   - Traces `block_rq_issue` tracepoint
   - Filters by device, operation, length, comm
   - Captures stack traces (optional)
   - Sends events via ring buffer

2. `blkalgn.c` - Userspace code
   - Argument parsing with argp
   - Ring buffer event handling
   - Histogram generation (granularity & alignment)
   - JSON output support
   - Stack trace symbolization via blazesym

3. `blkalgn.h` - Shared definitions
   - Event structure with stack traces
   - Histogram key/value structures
   - Constants (MAX_SLOTS, MAX_STACK_DEPTH)

**Key data flow:**
- BPF code → Ring buffer → Userspace handler → Histograms/JSON

### Stack Trace Support

Uses blazesym for symbolization:
- `show_stack_trace()` in blkalgn.c:471
- Handles both kernel and userspace stacks
- Resolves symbols with file paths and line numbers

## Development Workflow

### Adding Features to blkalgn

When porting features from Python version to libbpf version:

1. **Identify feature in `tools/blkalgn.py`**
   - Check git history for context: `git log --follow tools/blkalgn.py`
   - Review Python BPF code and userspace logic

2. **Modify BPF code (`blkalgn.bpf.c`)**
   - Add new filters or data collection
   - Update event structure if needed
   - Keep kernel compatibility in mind (check LINUX_KERNEL_VERSION)

3. **Update userspace (`blkalgn.c`)**
   - Add argp options for new features
   - Implement event processing logic
   - Update histogram or JSON output

4. **Update shared header (`blkalgn.h`)**
   - Add new structures or constants
   - Keep BPF and userspace in sync

5. **Test and format**
   - Format C code: `clang-format -i blkalgn.c blkalgn.bpf.c`
   - Test with various workloads (see `tools/blkalgn_example.txt`)

### Git Commit Style

Based on recent history, use descriptive commit messages:
```
blkalgn: <brief description>
```

Examples from development:
- `blkalgn: bump to 0.2`
- `blkalgn: add lbs information in granularity hist`
- `blkalgn: fix granularity encoding`

## Commit Guidelines

### One commit per change

As with the Linux kernel, this project prefers commits to be atomic and to the point. We don't want spell fixes to be blended in with code changes. Spell fixes should go into separate commits. When in doubt, just don't do any spell fixes unless asked explicitly to do that.

### Use the Signed-off-by tag

We want to use the Signed-off-by tag which embodies the application of the Developer Certificate or Origin. Use the git configured user name and email for the Signed-off-by tag (check with `git config user.name` and `git config user.email`).

### Use Generated-by: Claude AI

Use this tag for code generated by Claude code AI. Put this before the Signed-off-by tag.

**CRITICAL FORMATTING RULE**: When using "Generated-by: Claude AI", it MUST be immediately followed by the "Signed-off-by:" tag with NO empty lines between them. These two lines must be consecutive.

Correct format:
```
Subject line

Detailed description of changes...

Generated-by: Claude AI
Signed-off-by: Your Name <email@example.com>
```

**WRONG** - Do NOT add empty lines between Generated-by and Signed-off-by:
```
Generated-by: Claude AI

Signed-off-by: Your Name <email@example.com>
```

**WRONG** - Do NOT add extra empty lines:
```
Generated-by: Claude AI


Signed-off-by: Your Name <email@example.com>
```

### Avoid Shopping cart lists

Generative AI seems to like to make commit logs long itemized lists of things it did. This is stupid. This should be avoided. It is creating very silly commit logs. Use plain english and get to the point. Be as clear a possible and get to the point of not what you want to communicate, but rather what will make a reviewer easily understand what the heck you are implementing.

You should *think* hard about your commit log, always.

### Feature Parity Tracking

**Python version features NOT yet in libbpf version:**
- Database capture (`--capture` flag with SQLite)
- Parser subcommand for querying captured data
- WAF (Write Amplification Factor) measurement
- Daemon mode
- Flags filter support (e.g., Sync, Idle flags)
- Ring buffer size configuration

**Refer to Python version for implementation details of missing features.**

## Alignment Algorithm

The alignment calculation is critical to blkalgn:

**Userspace (blkalgn.c:221):**
```c
static inline __u32 align(const struct event *e)
```
- Determines largest power-of-2 alignment for I/O
- Checks both length and LBA alignment
- Uses logical block size (lbs) for calculations

**Granularity vs Alignment histograms:**
- Granularity: I/O size in LBS steps (linear)
- Alignment: Maximum alignment as power-of-2 (log2)

## Important Constants

- `MAX_SLOTS`: 16384 + 1 (supports up to 8 MiB granularity)
- `MAX_STACK_DEPTH`: 128 frames
- `SECTOR_SHIFT`: 9 (512 bytes)
- Ring buffer: 2097152 bytes (2 MiB)

## Testing

Use fio workloads for testing (examples in `tools/blkalgn_example.txt`):

```bash
# Basic alignment test
fio -bs=64k -iodepth=1 -rw=write -ioengine=sync -size=64k \
    -name=sync -direct=1 -filename=/dev/nvme0n1 -loop 100

# Misaligned test
fio -bs=64k -iodepth=1 -rw=write -ioengine=sync -size=64k \
    -name=sync -direct=1 -filename=/dev/nvme0n1 -loop 100 -offset=4096
```

Compare results between Python and libbpf versions to ensure correctness.

## Branch Information

- Main branch: `lbs`
- Focus: Block alignment with logical block size support
