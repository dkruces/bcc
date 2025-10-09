// SPDX-License-Identifier: GPL-2.0
/* WAF calculation test suite
 * Based on Rust reference implementation
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <assert.h>

/* Type definitions compatible with kernel types */
typedef uint32_t __u32;
typedef uint64_t __u64;

/* Helper: Round up to nearest multiple of base */
static inline int round_up(int len, int base)
{
	return ((len + base - 1) / base) * base;
}

/* Helper: Round down to nearest multiple of base */
static inline int round_down(int len, int base)
{
	return (len / base) * base;
}

/**
 * calculate_waf - Calculate Write Amplification Factor
 * @offset: I/O offset in units (e.g., 4K units)
 * @len: I/O length in units (e.g., 4K units)
 * @iu: Indirection Unit size in same units
 *
 * Returns: WAF as a double (1.0 = no amplification, 2.0 = 100% amplification)
 *
 * Example: offset=1 (4KB), len=2 (8KB), iu=4 (16KB)
 *   - Offset in bytes: 4KB
 *   - Length in bytes: 8KB
 *   - I/O spans: 4KB to 12KB
 *   - io_start = round_down(4, 16) = 0
 *   - io_end = round_up(12, 16) = 16
 *   - WAF = 16 / 8 = 2.0 (100% amplification)
 */
double calculate_waf(int offset, int len, int iu)
{
	int io_end = round_up(offset + len, iu);
	int io_start = round_down(offset, iu);

	return (double)(io_end - io_start) / (double)len;
}

/**
 * calculate_waf_bytes - Calculate WAF using byte values
 * @offset_bytes: I/O offset in bytes
 * @len_bytes: I/O length in bytes
 * @iu_bytes: Indirection Unit size in bytes
 *
 * Wrapper for calculate_waf() that handles byte conversions
 */
double calculate_waf_bytes(__u64 offset_bytes, __u32 len_bytes, __u32 iu_bytes)
{
	/* Convert to 4K units for calculation */
	int offset = offset_bytes / 4096;
	int len = len_bytes / 4096;
	int iu = iu_bytes / 4096;

	return calculate_waf(offset, len, iu);
}

/**
 * calculate_waf_from_alignment - Estimate worst-case WAF from alignment
 * @io_size: I/O size in bytes
 * @alignment: Maximum alignment in bytes (power of 2)
 * @iu: Indirection Unit in bytes
 *
 * This is used when we only know alignment, not exact offset.
 * Returns conservative (worst-case) WAF estimate.
 */
double calculate_waf_from_alignment(__u32 io_size, __u32 alignment, __u32 iu)
{
	__u64 offset;

	/* If I/O is IU-aligned or larger, no amplification */
	if (alignment >= iu)
		return 1.0;

	/* Worst case: I/O starts at alignment boundary that maximizes IU usage
	 * For alignment < IU, worst offset is just before an IU boundary
	 */
	offset = iu - alignment;

	return calculate_waf_bytes(offset, io_size, iu);
}

/* Test helper: assert double values are approximately equal */
static void assert_double_eq(double actual, double expected, double tolerance,
			     const char *test_name)
{
	double diff = fabs(actual - expected);
	if (diff > tolerance) {
		fprintf(stderr, "FAIL: %s\n", test_name);
		fprintf(stderr, "  Expected: %.8f\n", expected);
		fprintf(stderr, "  Actual:   %.8f\n", actual);
		fprintf(stderr, "  Diff:     %.8f (tolerance: %.8f)\n",
			diff, tolerance);
		exit(1);
	}
	printf("PASS: %s (%.8f)\n", test_name, actual);
}

/* Test suite from Rust implementation */
void test_waf_stress(void)
{
	double result;

	printf("\n=== WAF Stress Test Suite ===\n");

	/* offset 4k, length 8k, iu 16k */
	result = calculate_waf(1, 2, 4);
	assert_double_eq(result, 2.0, 0.000001,
			 "4KB offset, 8KB length, 16KB IU");

	/* offset 12k, length 8k, iu 16k */
	result = calculate_waf(3, 2, 4);
	assert_double_eq(result, 4.0, 0.000001,
			 "12KB offset, 8KB length, 16KB IU");

	/* offset 12k, length 20k, iu 16k */
	result = calculate_waf(3, 5, 4);
	assert_double_eq(result, 1.6, 0.000001,
			 "12KB offset, 20KB length, 16KB IU");

	/* offset 4k, length 12k, iu 16k */
	result = calculate_waf(1, 3, 4);
	assert_double_eq(result, 1.33, 0.01,
			 "4KB offset, 12KB length, 16KB IU");

	/* offset 8k, length 12k, iu 16k */
	result = calculate_waf(2, 3, 4);
	assert_double_eq(result, 2.66, 0.01,
			 "8KB offset, 12KB length, 16KB IU");

	/* offset 8k, length 512k, iu 16k */
	result = calculate_waf(2, 128, 4);
	assert_double_eq(result, 1.03125, 0.000001,
			 "8KB offset, 512KB length, 16KB IU");

	/* offset 8k, length 40k, iu 16k */
	result = calculate_waf(2, 10, 4);
	assert_double_eq(result, 1.2, 0.000001,
			 "8KB offset, 40KB length, 16KB IU");

	/* offset 24k, length 32k, iu 16k */
	result = calculate_waf(6, 8, 4);
	assert_double_eq(result, 1.5, 0.000001,
			 "24KB offset, 32KB length, 16KB IU");

	/* offset 12k, length 256k, iu 16k */
	result = calculate_waf(3, 64, 4);
	assert_double_eq(result, 1.0625, 0.000001,
			 "12KB offset, 256KB length, 16KB IU");

	/* offset 32k, length 24k, iu 16k */
	result = calculate_waf(8, 6, 4);
	assert_double_eq(result, 1.33, 0.01,
			 "32KB offset, 24KB length, 16KB IU");

	/* offset 8k, length 32k, iu 16k */
	result = calculate_waf(2, 8, 4);
	assert_double_eq(result, 1.5, 0.000001,
			 "8KB offset, 32KB length, 16KB IU");
}

/* Test worst-case WAF for various I/O sizes */
void test_worst_case_waf(void)
{
	int iu = 4; /* 16KB in 4K units */
	int i, o;
	double waf_worst;

	printf("\n=== Worst-Case WAF Analysis ===\n");
	printf("IU: %dKB\n", iu * 4);
	printf("%-10s %-15s\n", "I/O Size", "Worst-case WAF");
	printf("%-10s %-15s\n", "--------", "--------------");

	for (i = 1; i <= 32; i++) {
		waf_worst = 1.0;

		/* Try all possible offsets within IU */
		for (o = 0; o < iu; o++) {
			double waf = calculate_waf(o, i, iu);
			if (waf > waf_worst)
				waf_worst = waf;
		}

		printf("%-10dKB %-15.8f\n", i * 4, waf_worst);
	}
}

/* Test WAF calculation with byte values (real-world usage) */
void test_waf_bytes(void)
{
	double result;

	printf("\n=== WAF Byte-level Tests ===\n");

	/* 64KB I/O at offset 0, 16KB IU - perfect alignment */
	result = calculate_waf_bytes(0, 65536, 16384);
	assert_double_eq(result, 1.0, 0.000001,
			 "64KB @ 0, IU=16KB (perfect)");

	/* 64KB I/O at offset 4KB, 16KB IU - misaligned */
	result = calculate_waf_bytes(4096, 65536, 16384);
	assert_double_eq(result, 1.25, 0.000001,
			 "64KB @ 4KB, IU=16KB (misaligned)");

	/* 64KB I/O at offset 16KB, 16KB IU - IU-aligned */
	result = calculate_waf_bytes(16384, 65536, 16384);
	assert_double_eq(result, 1.0, 0.000001,
			 "64KB @ 16KB, IU=16KB (IU-aligned)");

	/* 128KB I/O at offset 4KB, 16KB IU */
	result = calculate_waf_bytes(4096, 131072, 16384);
	assert_double_eq(result, 1.125, 0.000001,
			 "128KB @ 4KB, IU=16KB");

	/* 512KB I/O at offset 4KB, 64KB IU */
	result = calculate_waf_bytes(4096, 524288, 65536);
	assert_double_eq(result, 1.125, 0.000001,
			 "512KB @ 4KB, IU=64KB");
}

/* Test alignment-based WAF estimation */
void test_waf_from_alignment(void)
{
	double result;

	printf("\n=== Alignment-based WAF Estimation Tests ===\n");

	/* 64KB I/O with 4KB alignment, 16KB IU - worst case */
	result = calculate_waf_from_alignment(65536, 4096, 16384);
	printf("64KB I/O, 4KB-aligned, IU=16KB: WAF=%.4f (worst-case)\n",
	       result);

	/* 64KB I/O with 16KB alignment, 16KB IU - should be 1.0 */
	result = calculate_waf_from_alignment(65536, 16384, 16384);
	assert_double_eq(result, 1.0, 0.000001,
			 "64KB I/O, 16KB-aligned, IU=16KB (no amplification)");

	/* 64KB I/O with 64KB alignment, 16KB IU - should be 1.0 */
	result = calculate_waf_from_alignment(65536, 65536, 16384);
	assert_double_eq(result, 1.0, 0.000001,
			 "64KB I/O, 64KB-aligned, IU=16KB (no amplification)");

	/* 128KB I/O with 4KB alignment, 16KB IU */
	result = calculate_waf_from_alignment(131072, 4096, 16384);
	printf("128KB I/O, 4KB-aligned, IU=16KB: WAF=%.4f (worst-case)\n",
	       result);

	/* 512KB I/O with 256KB alignment, 64KB IU */
	result = calculate_waf_from_alignment(524288, 262144, 65536);
	assert_double_eq(result, 1.0, 0.000001,
			 "512KB I/O, 256KB-aligned, IU=64KB (no amplification)");
}

/* Demonstrate WAF for fio test workload patterns */
void test_fio_workload_patterns(void)
{
	printf("\n=== FIO Workload Pattern Analysis ===\n");
	printf("Analyzing: 64KB, 128KB, 512KB I/Os with various alignments\n");
	printf("IU: 16KB\n\n");

	printf("%-15s %-15s %-15s\n", "I/O Size", "Offset", "WAF");
	printf("%-15s %-15s %-15s\n", "-------------", "-------------",
	       "-------------");

	/* 64KB I/Os */
	printf("%-15s %-15s %-15.4f\n", "64KB", "0",
	       calculate_waf_bytes(0, 65536, 16384));
	printf("%-15s %-15s %-15.4f\n", "64KB", "4KB",
	       calculate_waf_bytes(4096, 65536, 16384));
	printf("%-15s %-15s %-15.4f\n", "64KB", "16KB",
	       calculate_waf_bytes(16384, 65536, 16384));

	/* 128KB I/Os */
	printf("%-15s %-15s %-15.4f\n", "128KB", "0",
	       calculate_waf_bytes(0, 131072, 16384));
	printf("%-15s %-15s %-15.4f\n", "128KB", "4KB",
	       calculate_waf_bytes(4096, 131072, 16384));
	printf("%-15s %-15s %-15.4f\n", "128KB", "16KB",
	       calculate_waf_bytes(16384, 131072, 16384));

	/* 512KB I/Os */
	printf("%-15s %-15s %-15.4f\n", "512KB", "0",
	       calculate_waf_bytes(0, 524288, 16384));
	printf("%-15s %-15s %-15.4f\n", "512KB", "4KB",
	       calculate_waf_bytes(4096, 524288, 16384));
	printf("%-15s %-15s %-15.4f\n", "512KB", "256KB",
	       calculate_waf_bytes(262144, 524288, 16384));
}

int main(void)
{
	printf("WAF Calculation Test Suite\n");
	printf("==========================\n");

	test_waf_stress();
	test_worst_case_waf();
	test_waf_bytes();
	test_waf_from_alignment();
	test_fio_workload_patterns();

	printf("\n=== All Tests Passed! ===\n");
	return 0;
}
