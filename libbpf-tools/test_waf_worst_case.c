// SPDX-License-Identifier: GPL-2.0
/* Worst-case WAF calculation test suite for post-processing implementation
 * Tests the WAF calculation using only I/O size and alignment (no offset)
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>

typedef uint32_t __u32;
typedef uint64_t __u64;

/* I/O pattern structure for WWAF calculation */
struct io_pattern {
	__u32 io_size;
	__u32 alignment;
	__u32 count;
};

/**
 * calculate_waf_worst_case - Calculate worst-case WAF from alignment only
 * @io_size: I/O size in bytes
 * @alignment: I/O alignment in bytes (power of 2)
 * @iu: Indirection Unit size in bytes (power of 2)
 *
 * Returns: WAF as a double (1.0 = no amplification)
 *
 * This is the key function for post-processing WAF calculation.
 * Since we only know alignment (not exact offset), we calculate worst-case.
 */
double calculate_waf_worst_case(__u32 io_size, __u32 alignment, __u32 iu)
{
	__u64 off_adj;
	__u64 io_iu;

	/* Case 1: I/O is IU-aligned or larger */
	if (alignment >= iu) {
		off_adj = 0;
	} else {
		/* Case 2: Worst-case position within IU */
		off_adj = iu - alignment;
	}

	/* Calculate total IU-aligned I/O needed (ceiling division) */
	io_iu = ((off_adj + io_size + iu - 1) / iu) * iu;

	return (double)io_iu / (double)io_size;
}

/**
 * calculate_wwaf - Calculate Workload WAF for a set of I/Os
 * @io_patterns: Array of (io_size, alignment, count) tuples
 * @num_patterns: Number of patterns
 * @iu: Indirection Unit size
 *
 * Returns: WWAF (Workload Write Amplification Factor)
 */
double calculate_wwaf(struct io_pattern *io_patterns, int num_patterns, __u32 iu)
{
	__u64 total_io_host = 0;
	__u64 total_io_iu = 0;

	for (int i = 0; i < num_patterns; i++) {
		double waf = calculate_waf_worst_case(io_patterns[i].io_size,
						      io_patterns[i].alignment,
						      iu);

		__u64 io_host = (__u64)io_patterns[i].count * io_patterns[i].io_size;
		__u64 io_iu = (__u64)(io_host * waf);

		total_io_host += io_host;
		total_io_iu += io_iu;
	}

	if (total_io_host == 0)
		return 1.0;

	return (double)total_io_iu / (double)total_io_host;
}

/* Test helper */
static void assert_waf_eq(double actual, double expected, double tolerance,
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

void test_perfect_alignment(void)
{
	double waf;

	printf("\n=== Test Case 1: Perfect Alignment (alignment >= IU) ===\n");

	/* When alignment >= IU, WAF should be 1.0 or very close */
	waf = calculate_waf_worst_case(65536, 65536, 16384);
	assert_waf_eq(waf, 1.0, 0.00001,
		      "64KB I/O, 64KB alignment, 16KB IU");

	waf = calculate_waf_worst_case(131072, 131072, 16384);
	assert_waf_eq(waf, 1.0, 0.00001,
		      "128KB I/O, 128KB alignment, 16KB IU");

	waf = calculate_waf_worst_case(524288, 524288, 65536);
	assert_waf_eq(waf, 1.0, 0.00001,
		      "512KB I/O, 512KB alignment, 64KB IU");

	/* Alignment larger than I/O size */
	waf = calculate_waf_worst_case(65536, 131072, 16384);
	assert_waf_eq(waf, 1.0, 0.00001,
		      "64KB I/O, 128KB alignment, 16KB IU");
}

void test_severe_amplification(void)
{
	double waf;

	printf("\n=== Test Case 2: Severe Amplification (small I/O, large IU) ===\n");

	/* 4KB I/O, 4KB alignment, 16KB IU
	 * Worst case: offset at 12KB (16KB - 4KB)
	 * I/O spans: [12KB, 16KB]
	 * Touches: [0-16KB], [16-32KB]
	 * off_adj = 16384 - 4096 = 12288
	 * io_iu = ceil((12288 + 4096) / 16384) * 16384
	 *       = ceil(16384 / 16384) * 16384
	 *       = 1 * 16384 = 16384
	 * waf = 16384 / 4096 = 4.0
	 */
	waf = calculate_waf_worst_case(4096, 4096, 16384);
	printf("4KB I/O, 4KB alignment, 16KB IU: WAF = %.4f\n", waf);
	assert_waf_eq(waf, 4.0, 0.00001,
		      "4KB I/O, 4KB alignment, 16KB IU");

	waf = calculate_waf_worst_case(4096, 4096, 65536);
	printf("4KB I/O, 4KB alignment, 64KB IU: WAF = %.4f\n", waf);

	waf = calculate_waf_worst_case(8192, 4096, 16384);
	printf("8KB I/O, 4KB alignment, 16KB IU: WAF = %.4f\n", waf);
}

void test_moderate_amplification(void)
{
	double waf;

	printf("\n=== Test Case 3: Moderate Amplification (large I/O, small alignment) ===\n");

	/* 64KB I/O, 4KB alignment, 16KB IU
	 * Worst case: offset at 12KB (16KB - 4KB)
	 * I/O spans: [12KB, 76KB]
	 * IU blocks: [0-16KB], [16-32KB], [32-48KB], [48-64KB], [64-80KB]
	 * Total: 5 * 16KB = 80KB
	 * WAF = 80KB / 64KB = 1.25
	 */
	waf = calculate_waf_worst_case(65536, 4096, 16384);
	assert_waf_eq(waf, 1.25, 0.00001,
		      "64KB I/O, 4KB alignment, 16KB IU");

	/* 128KB I/O, 4KB alignment, 16KB IU */
	waf = calculate_waf_worst_case(131072, 4096, 16384);
	assert_waf_eq(waf, 1.125, 0.00001,
		      "128KB I/O, 4KB alignment, 16KB IU");

	/* 256KB I/O, 4KB alignment, 16KB IU */
	waf = calculate_waf_worst_case(262144, 4096, 16384);
	assert_waf_eq(waf, 1.0625, 0.00001,
		      "256KB I/O, 4KB alignment, 16KB IU");

	/* 512KB I/O, 4KB alignment, 16KB IU */
	waf = calculate_waf_worst_case(524288, 4096, 16384);
	assert_waf_eq(waf, 1.03125, 0.00001,
		      "512KB I/O, 4KB alignment, 16KB IU");
}

void test_edge_cases(void)
{
	double waf;

	printf("\n=== Test Case 4: Edge Cases ===\n");

	/* I/O size == IU, alignment < IU */
	waf = calculate_waf_worst_case(16384, 4096, 16384);
	printf("16KB I/O, 4KB alignment, 16KB IU: WAF = %.4f\n", waf);

	/* I/O size < IU, alignment == I/O size */
	waf = calculate_waf_worst_case(4096, 4096, 16384);
	printf("4KB I/O, 4KB alignment, 16KB IU: WAF = %.4f\n", waf);

	/* Very large I/O */
	waf = calculate_waf_worst_case(8388608, 4096, 16384);
	printf("8MB I/O, 4KB alignment, 16KB IU: WAF = %.8f\n", waf);
	assert_waf_eq(waf, 1.001953125, 0.00001,
		      "8MB I/O, 4KB alignment, 16KB IU");

	/* Alignment exactly half of IU */
	waf = calculate_waf_worst_case(65536, 8192, 16384);
	printf("64KB I/O, 8KB alignment, 16KB IU: WAF = %.4f\n", waf);
}

void test_wwaf_accumulation(void)
{
	double wwaf;

	printf("\n=== Test Case 5: WWAF Accumulation ===\n");

	/* Test workload from FIO:
	 * 10x 64KB @ 4KB alignment
	 * 10x 64KB @ 16KB alignment
	 * 10x 64KB @ 64KB alignment
	 */
	struct io_pattern patterns[] = {
		{65536, 4096, 10},
		{65536, 16384, 10},
		{65536, 65536, 10},
	};

	/* IU = 16KB */
	wwaf = calculate_wwaf(patterns, 3, 16384);
	printf("FIO workload @ IU=16KB: WWAF = %.4f\n", wwaf);

	/* Manual calculation:
	 * WAF(64KB, 4KB, 16KB) = 1.25
	 * WAF(64KB, 16KB, 16KB) = 1.0
	 * WAF(64KB, 64KB, 16KB) = 1.0
	 *
	 * total_io_host = 10*64K + 10*64K + 10*64K = 1920KB
	 * total_io_iu = 10*64K*1.25 + 10*64K*1.0 + 10*64K*1.0
	 *             = 800K + 640K + 640K = 2080KB
	 * WWAF = 2080KB / 1920KB = 1.0833...
	 */
	assert_waf_eq(wwaf, 1.0833333, 0.0001,
		      "FIO workload WWAF @ IU=16KB");

	/* Test with different IU sizes */
	printf("\nWWAF for FIO workload across different IUs:\n");
	printf("%-10s %-15s\n", "IU", "WWAF");
	__u32 ius[] = {4096, 8192, 16384, 32768, 65536, 131072};
	for (int i = 0; i < 6; i++) {
		wwaf = calculate_wwaf(patterns, 3, ius[i]);
		printf("%-10u %-15.4f\n", ius[i], wwaf);
	}
}

void test_all_iu_sizes(void)
{
	double waf;

	printf("\n=== Test Case 6: WAF across all target IU sizes ===\n");
	printf("64KB I/O with 4KB alignment:\n\n");
	printf("%-10s %-15s\n", "IU", "WAF");
	printf("%-10s %-15s\n", "--------", "-------------");

	__u32 ius[] = {4096, 8192, 16384, 32768, 65536, 131072, 262144,
		       524288, 1048576, 2097152, 4194304, 8388608};

	for (int i = 0; i < 12; i++) {
		waf = calculate_waf_worst_case(65536, 4096, ius[i]);
		printf("%-10u %-15.4f\n", ius[i], waf);
	}
}

void test_realistic_workload(void)
{
	double wwaf;

	printf("\n=== Test Case 7: Realistic Mixed Workload ===\n");

	/* Simulated workload:
	 * - 100x 4KB I/Os @ 4KB alignment (metadata)
	 * - 50x 64KB I/Os @ 4KB alignment (poorly aligned data)
	 * - 30x 128KB I/Os @ 128KB alignment (well-aligned data)
	 * - 20x 512KB I/Os @ 4KB alignment (large misaligned)
	 */
	struct io_pattern patterns[] = {
		{4096, 4096, 100},
		{65536, 4096, 50},
		{131072, 131072, 30},
		{524288, 4096, 20},
	};

	printf("\nWorkload composition:\n");
	printf("  100x 4KB @ 4KB alignment\n");
	printf("  50x 64KB @ 4KB alignment\n");
	printf("  30x 128KB @ 128KB alignment\n");
	printf("  20x 512KB @ 4KB alignment\n\n");

	printf("%-10s %-15s %-15s\n", "IU", "WWAF", "Amplification");
	printf("%-10s %-15s %-15s\n", "--------", "-------------", "-------------");

	__u32 ius[] = {4096, 8192, 16384, 32768, 65536, 131072};
	for (int i = 0; i < 6; i++) {
		wwaf = calculate_wwaf(patterns, 4, ius[i]);
		double amp_pct = (wwaf - 1.0) * 100.0;
		printf("%-10u %-15.4f %-15.2f%%\n", ius[i], wwaf, amp_pct);
	}
}

void test_fio_workload(void)
{
	double wwaf;

	printf("\n=== Test Case 8: FIO Test Workload (output-0000.txt) ===\n");

	/* Actual captured workload from output-0000.txt:
	 * From io_size_alignment map analysis:
	 * - 3x 128KB @ 4KB alignment
	 * - 3x 512KB @ 4KB alignment
	 * - 3x 512KB @ 512KB alignment
	 *
	 * Total: 9 I/Os, 3.375 MB (3538944 bytes)
	 *
	 * Note: The test_waf_setup.sh script generates 21 I/Os total, but
	 * blkalgn only captured 9. The 64KB writes completed too quickly.
	 */
	struct io_pattern patterns[] = {
		{131072, 4096, 3},   /* 128KB @ 4KB alignment */
		{524288, 4096, 3},   /* 512KB @ 4KB alignment */
		{524288, 524288, 3}, /* 512KB @ 512KB alignment */
	};

	printf("\nActual captured workload (from blkalgn output):\n");
	printf("  3x 128KB @ 4KB alignment\n");
	printf("  3x 512KB @ 4KB alignment\n");
	printf("  3x 512KB @ 512KB alignment\n");

	/* Calculate total I/O */
	__u64 total_io = 3*131072 + 3*524288 + 3*524288;
	printf("  Total: 9 I/Os, %.2f MB\n\n", total_io / (1024.0 * 1024.0));

	/* Test all 12 IU sizes */
	printf("%-10s %-15s %-15s %-15s\n", "IU", "IU (KB)", "WWAF", "Amplification");
	printf("%-10s %-15s %-15s %-15s\n", "--------", "--------", "-------------", "-------------");

	__u32 ius[] = {4096, 8192, 16384, 32768, 65536, 131072, 262144,
		       524288, 1048576, 2097152, 4194304, 8388608};

	for (int i = 0; i < 12; i++) {
		wwaf = calculate_wwaf(patterns, 3, ius[i]);
		double amp_pct = (wwaf - 1.0) * 100.0;
		printf("%-10u %-15u %-15.4f %-14.2f%%\n",
		       ius[i], ius[i] / 1024, wwaf, amp_pct);
	}

}

int main(void)
{
	printf("Worst-Case WAF Calculation Test Suite\n");
	printf("======================================\n");

	test_perfect_alignment();
	test_severe_amplification();
	test_moderate_amplification();
	test_edge_cases();
	test_wwaf_accumulation();
	test_all_iu_sizes();
	test_realistic_workload();
	test_fio_workload();

	printf("\n=== All Tests Completed Successfully! ===\n");
	return 0;
}
