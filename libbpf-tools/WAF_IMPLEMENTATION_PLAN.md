# WAF (Write Amplification Factor) Implementation Plan for libbpf blkalgn

## Understanding WAF Calculation

### Core Formula
```
Per-I/O WAF = (ceil((off_adj + len) / IU) * IU) / len

Where:
  off_adj = offset within IU boundary
          = (lba * lbs) % IU
  len     = I/O size in bytes
  IU      = Indirection Unit (power-of-2: 4K, 8K, 16K, ..., 2MB)
  lbs     = Logical Block Size (typically 4K)
```

### Workload WAF (WWAF)
```
WWAF = sum(IO_iu) / sum(IO_host)

Where:
  IO_iu   = Total bytes written to device (after IU amplification)
  IO_host = Total bytes requested by host
```

### Example Calculation

**Scenario 1: Well-aligned I/O**
- I/O: 64K at offset 0, IU=16K
- off_adj = 0
- WAF = ceil((0 + 65536) / 16384) * 16384 / 65536 = 4 * 16384 / 65536 = 1.0
- **Perfect! No amplification**

**Scenario 2: Misaligned I/O**
- I/O: 64K at offset 4K, IU=16K
- off_adj = 4096
- WAF = ceil((4096 + 65536) / 16384) * 16384 / 65536 = 5 * 16384 / 65536 = 1.25
- **25% amplification!**

**Scenario 3: Severely misaligned**
- I/O: 64K at offset 4K, IU=64K
- off_adj = 4096
- WAF = ceil((4096 + 65536) / 65536) * 65536 / 65536 = 2 * 65536 / 65536 = 2.0
- **100% amplification! Double the I/O**

### Key Insight

**WAF depends on THREE factors:**
1. **I/O size** (len)
2. **I/O alignment** (determines off_adj)
3. **Indirection Unit** (IU - storage device property)

**We already have #1 and #2 in our io_size_alignment map!**

## Current Data Availability

From `io_size_alignment` map we have:
```json
{
  "65536": {      // I/O size
    "4096": 10,   // 10 I/Os with 4K alignment
    "16384": 10,  // 10 I/Os with 16K alignment
    "65536": 10   // 10 I/Os with 64K alignment
  }
}
```

**What we can calculate for each (io_size, alignment, IU) combination:**

Given alignment A, we know:
- I/O starts at offset that is A-aligned but NOT (A*2)-aligned
- For alignment bucket A, worst-case off_adj = A (I/O starts at A boundary)
- Best-case: off_adj = 0 (I/O starts at multiple of IU)

**Problem:** We don't know the **exact offset** of each I/O, only its **maximum alignment**.

## Solution Approaches

### Option 1: Average/Worst-case WAF Estimation

For each (io_size, alignment) pair, calculate **worst-case WAF** for various IUs.

**Assumption:** If I/O has alignment A:
- It's aligned to A-byte boundary
- Worst case: starts at offset = A (within IU)

**Algorithm:**
```c
for each (io_size, alignment, count) in io_size_alignment_map:
    for each IU in [4K, 8K, 16K, 32K, 64K, 128K, 256K, 512K, 1M, 2M]:
        // Worst-case offset within IU
        off_adj = min(alignment, IU)
        if alignment >= IU:
            off_adj = 0  // Already IU-aligned

        // Calculate WAF for this I/O pattern
        io_iu = ceil((off_adj + io_size) / IU) * IU
        waf = io_iu / io_size

        // Accumulate for workload WAF
        total_io_host[IU] += count * io_size
        total_io_iu[IU] += count * io_iu

// Final WWAF per IU
for each IU:
    WWAF[IU] = total_io_iu[IU] / total_io_host[IU]
```

**Limitation:** This is worst-case. Actual WAF might be better if I/Os happen to land on IU boundaries.

### Option 2: Statistical Sampling of Offsets

Track a sample of actual offsets in BPF to get more accurate distribution.

**Not recommended:** Adds complexity, memory overhead, defeats the "post-processing" approach.

### Option 3: Refined Estimation Using Alignment Distribution

Better estimation by understanding alignment semantics:

**If I/O has max_alignment = A, it means:**
- Offset % A == 0 (aligned to A)
- Offset % (A*2) != 0 (NOT aligned to A*2)

**This gives us offset distribution within IU:**

For IU > alignment:
- I/Os are distributed at alignment boundaries within IU
- Possible offsets within IU: 0, A, 2A, 3A, ..., IU-A
- Assuming uniform distribution: avg_off_adj = IU / 2 (approximately)

For IU <= alignment:
- I/O is IU-aligned (off_adj = 0)
- WAF = 1.0 (no amplification)

**Refined Algorithm:**
```c
for each (io_size, alignment, count) in io_size_alignment_map:
    for each IU in [4K, 8K, ..., 2M]:
        if alignment >= IU:
            // I/O is IU-aligned, no amplification
            waf = 1.0
            off_adj = 0
        else:
            // I/O lands somewhere within IU at 'alignment' boundaries
            // Worst case: off_adj = IU - alignment (I/O crosses boundary)
            // Best case: off_adj = 0 (lucky alignment)
            // Conservative estimate: use worst case
            off_adj = IU - (IU % alignment)
            if off_adj == IU:
                off_adj = 0  // Already aligned

        io_iu = ceil_div(off_adj + io_size, IU) * IU
        waf = (double)io_iu / io_size

        total_io_host[disk][IU] += count * io_size
        total_io_iu[disk][IU] += count * io_iu

WWAF[disk][IU] = total_io_iu[disk][IU] / total_io_host[disk][IU]
```

## Recommended Implementation: Option 3 (Conservative Estimation)

### Data Structures

```c
// WAF statistics per disk per IU
struct waf_stats {
    __u64 total_io_host;  // Total host I/O bytes
    __u64 total_io_iu;    // Total IU-amplified I/O bytes
    __u64 io_count;       // Number of I/Os
    double wwaf;          // Workload WAF
};

// IU sizes to calculate WAF for (in bytes)
static const __u32 iu_sizes[] = {
    4096,     // 4K
    8192,     // 8K
    16384,    // 16K
    32768,    // 32K
    65536,    // 64K
    131072,   // 128K
    262144,   // 256K
    524288,   // 512K
    1048576,  // 1M
    2097152,  // 2M
};

#define NUM_IUS (sizeof(iu_sizes) / sizeof(iu_sizes[0]))

// Per-disk WAF table
struct disk_waf_table {
    char disk[NAME_LEN];
    struct waf_stats iu_stats[NUM_IUS];
};
```

### Implementation Steps

#### 1. Add WAF Calculation Function (blkalgn.c)

```c
static __u64 calculate_io_iu(__u32 io_size, __u32 alignment, __u32 iu)
{
    __u64 off_adj;

    if (alignment >= iu) {
        // I/O is already IU-aligned, no offset adjustment
        return ((__u64)io_size + iu - 1) / iu * iu;
    }

    // Conservative: assume worst-case offset within IU
    // I/O at alignment boundary, calculate worst position
    off_adj = iu - (iu % alignment);
    if (off_adj == iu)
        off_adj = 0;

    // Calculate IU-aligned I/O size
    return (off_adj + io_size + iu - 1) / iu * iu;
}

static void calculate_waf_stats(int fd, struct disk_waf_table *waf_tables,
                                int *num_disks)
{
    struct hkey_iosize lookup_key = {}, next_key;
    struct hval val;
    int disk_idx, iu_idx;
    __u32 alignment;
    __u64 io_iu;

    *num_disks = 0;

    // Iterate through io_size_alignment map
    while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
        if (bpf_map_lookup_elem(fd, &next_key, &val) != 0) {
            lookup_key = next_key;
            continue;
        }

        // Find or create disk entry
        disk_idx = -1;
        for (int i = 0; i < *num_disks; i++) {
            if (strncmp(waf_tables[i].disk, next_key.disk, NAME_LEN) == 0) {
                disk_idx = i;
                break;
            }
        }

        if (disk_idx == -1) {
            disk_idx = (*num_disks)++;
            strncpy(waf_tables[disk_idx].disk, next_key.disk, NAME_LEN);
            memset(waf_tables[disk_idx].iu_stats, 0,
                   sizeof(waf_tables[disk_idx].iu_stats));
        }

        // Process each alignment bucket for this I/O size
        for (int slot = 0; slot < MAX_SLOTS; slot++) {
            if (val.slots[slot] == 0)
                continue;

            alignment = 1 << slot;  // Power-of-2 alignment
            __u64 count = val.slots[slot];

            // Calculate WAF for each IU
            for (iu_idx = 0; iu_idx < NUM_IUS; iu_idx++) {
                __u32 iu = iu_sizes[iu_idx];

                io_iu = calculate_io_iu(next_key.io_size, alignment, iu);

                waf_tables[disk_idx].iu_stats[iu_idx].io_count += count;
                waf_tables[disk_idx].iu_stats[iu_idx].total_io_host +=
                    count * next_key.io_size;
                waf_tables[disk_idx].iu_stats[iu_idx].total_io_iu +=
                    count * io_iu;
            }
        }

        lookup_key = next_key;
    }

    // Calculate final WWAF for each (disk, IU)
    for (int i = 0; i < *num_disks; i++) {
        for (iu_idx = 0; iu_idx < NUM_IUS; iu_idx++) {
            if (waf_tables[i].iu_stats[iu_idx].total_io_host > 0) {
                waf_tables[i].iu_stats[iu_idx].wwaf =
                    (double)waf_tables[i].iu_stats[iu_idx].total_io_iu /
                    (double)waf_tables[i].iu_stats[iu_idx].total_io_host;
            }
        }
    }
}
```

#### 2. Add WAF Output Function (blkalgn.c)

```c
static void print_waf_table(struct disk_waf_table *waf_tables, int num_disks)
{
    printf("\n=== Workload Write Amplification Factor (WWAF) ===\n");

    for (int i = 0; i < num_disks; i++) {
        printf("\nDevice: %s\n", waf_tables[i].disk);

        // Header
        printf("%-10s %-10s %-15s %-15s %-10s\n",
               "IU", "IU (KB)", "Host I/O (MB)", "IU I/O (MB)", "WWAF");
        printf("%-10s %-10s %-15s %-15s %-10s\n",
               "----------", "----------", "---------------",
               "---------------", "----------");

        // Rows
        for (int j = 0; j < NUM_IUS; j++) {
            struct waf_stats *s = &waf_tables[i].iu_stats[j];

            if (s->io_count == 0)
                continue;

            printf("%-10u %-10u %-15.2f %-15.2f %-10.4f\n",
                   iu_sizes[j],
                   iu_sizes[j] / 1024,
                   s->total_io_host / (1024.0 * 1024.0),
                   s->total_io_iu / (1024.0 * 1024.0),
                   s->wwaf);
        }
    }
}
```

#### 3. Add WAF JSON Output (blkalgn.c)

```c
static int waf_to_json(struct disk_waf_table *waf_tables, int num_disks,
                      json_object *jroot)
{
    json_object *jdisks, *jdisk, *jwaf, *jiu;

    _json_object_init(jroot, "disks", &jdisks);

    for (int i = 0; i < num_disks; i++) {
        _json_object_init(jdisks, waf_tables[i].disk, &jdisk);
        _json_object_init(jdisk, "waf", &jwaf);

        for (int j = 0; j < NUM_IUS; j++) {
            struct waf_stats *s = &waf_tables[i].iu_stats[j];

            if (s->io_count == 0)
                continue;

            char iu_str[16];
            snprintf(iu_str, sizeof(iu_str), "%u", iu_sizes[j]);

            jiu = json_object_new_object();
            json_object_object_add(jiu, "wwaf",
                                  json_object_new_double(s->wwaf));
            json_object_object_add(jiu, "io_count",
                                  json_object_new_int64(s->io_count));
            json_object_object_add(jiu, "io_host_mb",
                                  json_object_new_double(
                                      s->total_io_host / (1024.0 * 1024.0)));
            json_object_object_add(jiu, "io_iu_mb",
                                  json_object_new_double(
                                      s->total_io_iu / (1024.0 * 1024.0)));

            json_object_object_add(jwaf, iu_str, jiu);
        }
    }

    return 0;
}
```

#### 4. Update print_histograms() and print_json()

```c
void print_histograms(struct map_fd_ctx *fd)
{
    // ... existing histogram code ...

    /* Calculate and print WAF statistics */
    struct disk_waf_table waf_tables[16];  // Support up to 16 disks
    int num_disks;

    calculate_waf_stats(fd->halign_iosize, waf_tables, &num_disks);
    print_waf_table(waf_tables, num_disks);
}

void print_json(struct map_fd_ctx *fd)
{
    json_object *jroot = json_object_new_object();
    FILE *fp;
    struct disk_waf_table waf_tables[16];
    int num_disks;

    hash_to_json(fd->hgran, jroot, "granularity");
    hash_to_json(fd->halign, jroot, "alignment");
    hash_iosize_to_json(fd->halign_iosize, jroot, "io_size_alignment");

    /* Add WAF statistics */
    calculate_waf_stats(fd->halign_iosize, waf_tables, &num_disks);
    waf_to_json(waf_tables, num_disks, jroot);

    // ... rest of JSON output ...
}
```

## Expected Output

### Terminal Output
```
=== Workload Write Amplification Factor (WWAF) ===

Device: nvme0n1
IU         IU (KB)    Host I/O (MB)   IU I/O (MB)     WWAF
---------- ---------- --------------- --------------- ----------
4096       4          5.63            5.63            1.0000
8192       8          5.63            5.86            1.0417
16384      16         5.63            6.56            1.1667
32768      32         5.63            7.50            1.3333
65536      64         5.63            8.44            1.5000
131072     128        5.63            9.38            1.6667
```

**Interpretation:**
- At 4K IU: No amplification (all I/Os are at least 4K aligned)
- At 16K IU: 16.67% amplification (poor 4K alignment causes extra IU writes)
- At 64K IU: 50% amplification (significant waste)

### JSON Output
```json
{
  "disks": {
    "nvme0n1": {
      "waf": {
        "4096": {
          "wwaf": 1.0,
          "io_count": 90,
          "io_host_mb": 5.63,
          "io_iu_mb": 5.63
        },
        "16384": {
          "wwaf": 1.1667,
          "io_count": 90,
          "io_host_mb": 5.63,
          "io_iu_mb": 6.56
        }
      }
    }
  }
}
```

## Advantages of This Approach

1. **No BPF changes needed** - Pure userspace post-processing
2. **Leverages existing data** - Uses io_size_alignment map
3. **Multiple IU analysis** - Shows WAF for various storage configurations
4. **Conservative estimates** - Worst-case WAF, actual may be better
5. **Backward compatible** - Adds new output, doesn't change existing

## Limitations

1. **Approximation** - Not exact per-I/O tracking (would need offset tracking)
2. **Conservative** - May overestimate WAF in best-case scenarios
3. **Write-only context** - WAF concept applies mainly to writes (should filter by operation)

## Testing Plan

Use same test script with known patterns:

```bash
# 64K I/Os at different alignments
fio -bs=64k -offset=0     # Perfect alignment
fio -bs=64k -offset=4096  # 4K misalignment
fio -bs=64k -offset=16384 # 16K alignment
```

**Expected WAF for 16K IU:**
- offset=0: WAF=1.0 (4 * 16K = 64K, no waste)
- offset=4K: WAF=1.25 (5 * 16K = 80K, 16K waste)
- offset=16K: WAF=1.0 (4 * 16K = 64K, no waste)

## Files to Modify

1. **blkalgn.c**
   - Add `waf_stats` structure
   - Add `disk_waf_table` structure
   - Add `calculate_io_iu()` function
   - Add `calculate_waf_stats()` function
   - Add `print_waf_table()` function
   - Add `waf_to_json()` function
   - Update `print_histograms()` to call WAF printing
   - Update `print_json()` to include WAF data

2. **No changes needed:**
   - blkalgn.h (all new structs are local to blkalgn.c)
   - blkalgn.bpf.c (no BPF changes)

## Implementation Checklist

- [ ] Add WAF data structures to blkalgn.c
- [ ] Implement `calculate_io_iu()` helper
- [ ] Implement `calculate_waf_stats()` main function
- [ ] Implement `print_waf_table()` for terminal output
- [ ] Implement `waf_to_json()` for JSON output
- [ ] Update `print_histograms()` to calculate and display WAF
- [ ] Update `print_json()` to include WAF data
- [ ] Test with known alignment patterns
- [ ] Verify WAF calculations match expected values
- [ ] Commit changes following guidelines
