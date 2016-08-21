#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

static volatile int debug;
static volatile uint32_t correct;

static volatile uint32_t guess_start;
static volatile uint32_t guess_end;

static volatile int rounds;
static volatile int seconds;


#define PACKETS_PER_ROUND 4000

typedef struct block_struct {
	u_long start;
	u_long end;
	int chacks;
} block_t;


#ifdef USE_SPINNER
const char spintxt[] = {
	'/', '-', '\\', '|'
};

void spinner(void)
{
	static int pos;
	static int first = 1;
	static char buf[2];

	if (pos >= (int)sizeof(spintxt))
		pos = 0;
	if (first) {
		first = 0;
		buf[0] = '\r';
	}

	buf[1] = spintxt[pos];
	write(fileno(stdout), buf, sizeof(buf));
	pos++;
}
#endif


int binary_search(u_long start, u_long end)
{
	u_long mid;

#ifdef DEBUG_CALLS
	printf("binary_search(%lu, %lu)\n", start, end);
#endif
	if (start == end) {
#define DEBUG_BIN_SEARCH_WIN
#ifdef DEBUG_BIN_SEARCH_WIN
		if (debug)
			printf("found instant winner: %lu\n", start);
#endif
		return 1;
	}

	++rounds;
#define DEBUG_ROUNDS
#ifdef DEBUG_ROUNDS
	if (debug)
		printf("round %d\n", rounds);
#endif

	while (start < end) {
		mid = (start + end) / 2;

		if (correct < mid || correct >= end) {
#define DEBUG_BIN_SEARCH
#ifdef DEBUG_BIN_SEARCH
			if (debug)
				printf("  scanned %lu - %lu (%lu packets) - NO\n", mid, end - 1, (end - mid));
#endif
			end = mid;
		} else {
#ifdef DEBUG_BIN_SEARCH
			if (debug)
				printf("  scanned %lu - %lu (%lu packets) - OK\n", mid, end - 1, (end - mid));
#endif
			start = mid;
		}

		seconds++; // processing one block takes one second

		if (mid == end - 1) {
#ifdef DEBUG_BIN_SEARCH_WIN
			if (debug)
				printf("found winner: %lu\n", mid);
#endif
			if (mid != correct) {
				fprintf(stderr, "WTF?\n");
				return 0;
			}
			guess_start = guess_end = mid;
			return 1;
		}
	}

	fprintf(stderr, "failed to find value %lu!\n", (u_long)correct);
	return 0;
}


block_t *build_schedule(u_long start, u_long end, int *pnblocks)
{
	int i, num, nblocks, block_sz = PACKETS_PER_ROUND;
	block_t *schedule = NULL;

	num = end - start;
	if (num <= block_sz) {
		fprintf(stderr, "WTF? don't call build_schedule with this shit!\n");
		return NULL;
	}
	nblocks = (num / block_sz) + 1;

	//printf("  block_sz: %d\n", block_sz);

	schedule = (block_t *)malloc(sizeof(block_t) * nblocks);
	if (!schedule) {
		perror("malloc");
		return NULL;
	}

	for (i = 0; i < nblocks; i++) {
		schedule[i].start = start + (i * block_sz);
		schedule[i].end = start + ((i + 1) * block_sz);
		if (schedule[i].end > end)
			schedule[i].end = end;

		//printf("  schedule[%d]: %lu - %lu\n", i, (u_long)schedule[i].start, (u_long)schedule[i].end);
	}

	*pnblocks = nblocks;
	return schedule;
}


int hybrid_search(u_long start, u_long end)
{
	int num;

#ifdef DEBUG_CALLS
	printf("hybrid_search(%lu, %lu)\n", start, end);
#endif
	num = end - start;
	while (num > PACKETS_PER_ROUND) {
		int nblocks, i;
		block_t *round_schedule;

		round_schedule = build_schedule(start, end, &nblocks);
		if (!round_schedule) {
			return 0;
		}

		++rounds;
#ifdef DEBUG_ROUNDS
		if (debug)
			printf("round %d - %d blocks\n", rounds, nblocks);
#endif

		for (i = 0; i < nblocks; i++) {
			round_schedule[i].chacks = 100;
			if (correct >= round_schedule[i].start && correct < round_schedule[i].end) {
				round_schedule[i].chacks = 99;
			}

#define DEBUG_SCHEDULE
#ifdef DEBUG_SCHEDULE
			if(debug)
				printf("  scanned %lu - %lu (%lu packets) - %s\n", 
						round_schedule[i].start,
						round_schedule[i].end,
						(round_schedule[i].end - round_schedule[i].start) + 1,
						round_schedule[i].chacks == 99 ? "OK" : "NO");
#endif

			seconds++; // processing one block takes one second

			if (round_schedule[i].chacks == 99) {
				start = round_schedule[i].start;
				end = round_schedule[i].end;
				free(round_schedule);
				break;
			}
		}

		num = end - start;
	}

	return binary_search(start, end + 1);
}


int main(int argc, char *argv[])
{
	int max_rounds = 1, max_seconds = 1;
	int min_rounds = 99, min_seconds = 99;
	u_long tot_rounds = 0, tot_seconds = 0;
	int manual_mode = 0;
	int num_attempts;

	srand(getpid());

	guess_start = 32768;
	guess_end = 65535;

	/* allow overriding the start/end */
	if (argc > 1) {
		guess_start = atoi(argv[1]);
		if (guess_start > 65535) {
			fprintf(stderr, "invalid port: %s\n", argv[1]);
			return 1;
		}
	}
	if (argc > 2) {
		guess_end = atoi(argv[2]);
		if (guess_end > 65536) {
			fprintf(stderr, "invalid port: %s\n", argv[2]);
			return 1;
		}
	}

	if (guess_end < guess_start) {
		fprintf(stderr, "invalid range: %lu - %lu\n", (u_long)guess_start, (u_long)guess_end);
		return 1;
	} else if (guess_start == guess_end) {
		guess_end++;
		debug = 1;
		manual_mode = 1;
	}

	num_attempts = 0;
	for (correct = guess_start; correct < guess_end; correct++) {
		/* reset stats */
		num_attempts++;
		rounds = 0;
		seconds = 0;

		if (!hybrid_search(guess_start, guess_end))
			break;

		tot_rounds += rounds;
		if (rounds > max_rounds)
			max_rounds = rounds;
		if (rounds < min_rounds)
			min_rounds = rounds;

		tot_seconds += seconds;
		if (seconds > max_seconds)
			max_seconds = seconds;
		if (seconds < min_seconds)
			min_seconds = seconds;

#ifdef USE_SPINNER
		spinner();
#else
		printf("found %lu after %d rounds and %d seconds\n", (u_long)correct, rounds, seconds);
#endif

		if (manual_mode)
			break;
	}

	if (!manual_mode)
		printf("min/max/avg rounds: %d/%d/%lu, min/max/avg seconds: %d/%d/%lu\n",
				min_rounds, max_rounds, 
				tot_rounds / num_attempts,
				min_seconds, max_seconds,
				tot_seconds / num_attempts);

	return 0;
}
