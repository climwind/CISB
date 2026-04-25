#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Minimal stand-in for EVM digest container. */
struct evm_digest_data {
	uint8_t digest[16];
};

/* Deterministic toy digest so the testcase stays self-contained. */
static void calc_digest(const uint8_t *msg, size_t len, uint8_t out[16])
{
	uint32_t s = 0x13579bdfu;
	for (size_t i = 0; i < len; i++) {
		s = (s << 5) ^ (s >> 2) ^ msg[i];
	}
	for (size_t i = 0; i < 16; i++) {
		s = s * 1664525u + 1013904223u;
		out[i] = (uint8_t)(s >> 24);
	}
}

/*
 * Vulnerable pattern from the commit: digest compare uses memcmp().
 * This may leak prefix-match length through timing.
 */
static int vm_verify_hmac_vuln(const uint8_t *msg, size_t msg_len,
							   const struct evm_digest_data *xattr_data)
{
	struct evm_digest_data calc;

	calc_digest(msg, msg_len, calc.digest);

	/* Vulnerability: non-constant-time compare. */
	if (memcmp(xattr_data->digest, calc.digest, sizeof(calc.digest)) != 0) {
		return -1;
	}
	return 0;
}

/* Constant-time replacement similar in spirit to crypto_memneq(). */
static int crypto_memneq_local(const uint8_t *a, const uint8_t *b, size_t n)
{
	uint8_t diff = 0;
	for (size_t i = 0; i < n; i++) {
		diff |= (uint8_t)(a[i] ^ b[i]);
	}
	return diff != 0;
}

static int vm_verify_hmac_fixed(const uint8_t *msg, size_t msg_len,
								const struct evm_digest_data *xattr_data)
{
	struct evm_digest_data calc;

	calc_digest(msg, msg_len, calc.digest);
	if (crypto_memneq_local(xattr_data->digest, calc.digest,
							sizeof(calc.digest))) {
		return -1;
	}
	return 0;
}

static long long elapsed_ns(struct timespec a, struct timespec b)
{
	long long sec = (long long)(b.tv_sec - a.tv_sec);
	long long nsec = (long long)(b.tv_nsec - a.tv_nsec);
	return sec * 1000000000LL + nsec;
}

static long long bench_vuln(const uint8_t *msg, size_t msg_len,
							const struct evm_digest_data *probe,
							int rounds)
{
	struct timespec t1, t2;
	volatile int sink = 0;

	clock_gettime(CLOCK_MONOTONIC, &t1);
	for (int i = 0; i < rounds; i++) {
		sink += vm_verify_hmac_vuln(msg, msg_len, probe);
	}
	clock_gettime(CLOCK_MONOTONIC, &t2);

	return elapsed_ns(t1, t2) + sink * 0;
}

int main(void)
{
	const uint8_t msg[] = "evm timing side-channel testcase";
	struct evm_digest_data real;
	struct evm_digest_data probe_short;
	struct evm_digest_data probe_long;
	const int rounds = 800000;

	calc_digest(msg, sizeof(msg) - 1, real.digest);

	/* Trigger condition: attacker controls compared MAC bytes. */
	memset(probe_short.digest, 0, sizeof(probe_short.digest));
	memset(probe_long.digest, 0, sizeof(probe_long.digest));

	/* Short prefix match (1 byte). */
	probe_short.digest[0] = real.digest[0];

	/* Long prefix match (12 bytes) -> typically longer memcmp path. */
	memcpy(probe_long.digest, real.digest, 12);
	probe_long.digest[12] = (uint8_t)(real.digest[12] ^ 0x5a);

	printf("vuln(short prefix) = %lld ns\n",
		   bench_vuln(msg, sizeof(msg) - 1, &probe_short, rounds));
	printf("vuln(long  prefix) = %lld ns\n",
		   bench_vuln(msg, sizeof(msg) - 1, &probe_long, rounds));

	/* Keep fixed function reachable and compiled. */
	printf("fixed check(rc=%d)\n",
		   vm_verify_hmac_fixed(msg, sizeof(msg) - 1, &probe_long));

	return 0;
}
