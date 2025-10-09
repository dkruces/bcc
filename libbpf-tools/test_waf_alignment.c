// SPDX-License-Identifier: GPL-2.0
/* Test WAF calculation from alignment information only
 * This explores what WAF we can expect given only I/O size and alignment
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>

typedef uint32_t __u32;
typedef uint64_t __u64;

static inline int round_up(int len, int base)
{
	return ((len + base - 1) / base) * base;
}

static inline int round_down(int len, int base)
{
	return (len / base) * base;
}

double calculate_waf(__u64 offset, __u32 len, __u32 iu)
{
	__u64 io_end = round_up(offset + len, iu);
	__u64 io_start = round_down(offset, iu);
	return (double)(io_end - io_start) / (double)len;
}

/**
 * calculate_waf_distribution - Calculate WAF distribution for a given alignment
 * @io_size: I/O size in bytes
 * @alignment: I/O alignment in bytes (I/O offset % alignment == 0)
 * @iu: Indirection Unit size in bytes
 * @avg_waf: Output - average WAF
 * @min_waf: Output - minimum (best) WAF
 * @max_waf: Output - maximum (worst) WAF
 *
 * Given that an I/O has a certain alignment, it can land at different
 * positions within an IU boundary. This function explores all possible
 * positions and calculates the WAF distribution.
 */
void calculate_waf_distribution(__u32 io_size, __u32 alignment, __u32 iu,
				double *avg_waf, double *min_waf, double *max_waf)
{
	double waf_sum = 0.0;
	int count = 0;
	__u64 offset;

	*min_waf = 999999.0;
	*max_waf = 0.0;

	/* If alignment >= IU, all I/Os are IU-aligned */
	if (alignment >= iu) {
		*avg_waf = *min_waf = *max_waf = 1.0;
		return;
	}

	/* Try all possible offsets within one IU that satisfy the alignment */
	for (offset = 0; offset < iu; offset += alignment) {
		double waf = calculate_waf(offset, io_size, iu);

		waf_sum += waf;
		count++;

		if (waf < *min_waf)
			*min_waf = waf;
		if (waf > *max_waf)
			*max_waf = waf;
	}

	*avg_waf = waf_sum / count;
}

int main(void)
{
	double avg, min, max;

	printf("WAF Distribution Analysis for Alignment-Only Data\n");
	printf("==================================================\n\n");

	/* Test case from FIO: 64KB I/O with 4KB alignment, 16KB IU */
	printf("=== 64KB I/O, 4KB alignment, 16KB IU ===\n");
	calculate_waf_distribution(65536, 4096, 16384, &avg, &min, &max);
	printf("Average WAF: %.4f\n", avg);
	printf("Min WAF:     %.4f (best case)\n", min);
	printf("Max WAF:     %.4f (worst case)\n\n", max);

	/* Show all possible offsets */
	printf("Detailed breakdown:\n");
	printf("%-15s %-15s\n", "Offset in IU", "WAF");
	for (__u64 off = 0; off < 16384; off += 4096) {
		printf("%-15llu %-15.4f\n", off,
		       calculate_waf(off, 65536, 16384));
	}

	/* More test cases */
	printf("\n=== 64KB I/O, 16KB alignment, 16KB IU ===\n");
	calculate_waf_distribution(65536, 16384, 16384, &avg, &min, &max);
	printf("Average WAF: %.4f\n", avg);
	printf("Min WAF:     %.4f\n", min);
	printf("Max WAF:     %.4f\n\n", max);

	printf("=== 128KB I/O, 4KB alignment, 16KB IU ===\n");
	calculate_waf_distribution(131072, 4096, 16384, &avg, &min, &max);
	printf("Average WAF: %.4f\n", avg);
	printf("Min WAF:     %.4f\n", min);
	printf("Max WAF:     %.4f\n\n", max);

	printf("=== 512KB I/O, 256KB alignment, 16KB IU ===\n");
	calculate_waf_distribution(524288, 262144, 16384, &avg, &min, &max);
	printf("Average WAF: %.4f\n", avg);
	printf("Min WAF:     %.4f\n", min);
	printf("Max WAF:     %.4f\n\n", max);

	/* Edge case: Very small alignment */
	printf("=== 64KB I/O, 512B alignment, 16KB IU ===\n");
	calculate_waf_distribution(65536, 512, 16384, &avg, &min, &max);
	printf("Average WAF: %.4f\n", avg);
	printf("Min WAF:     %.4f\n", min);
	printf("Max WAF:     %.4f\n\n", max);

	/* Table for different IU sizes */
	printf("\n=== WAF for 64KB I/O with 4KB alignment across different IUs ===\n");
	printf("%-10s %-15s %-15s %-15s\n", "IU", "Avg WAF", "Min WAF", "Max WAF");
	printf("%-10s %-15s %-15s %-15s\n", "----------", "----------", "----------", "----------");

	__u32 ius[] = {4096, 8192, 16384, 32768, 65536, 131072, 262144, 524288, 1048576, 2097152};
	for (int i = 0; i < 10; i++) {
		calculate_waf_distribution(65536, 4096, ius[i], &avg, &min, &max);
		printf("%-10u %-15.4f %-15.4f %-15.4f\n", ius[i], avg, min, max);
	}

	return 0;
}
