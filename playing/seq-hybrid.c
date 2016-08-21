#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

static volatile int debug;
static volatile uint32_t correct;

static volatile uint32_t guess_start;
static volatile uint32_t guess_end;

static volatile int winsz = 29200;
static volatile int half_win;

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


int in_seq_window(u_long seq_guess)
{
	uint32_t correct_end = correct + winsz;

	if (correct_end < correct) {
		if (seq_guess >= correct || seq_guess < correct_end)
			return 1;
	} else if (seq_guess >= correct && seq_guess < correct_end) {
		return 1;
	}
	return 0;
}


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

#ifdef DEBUG_BIN_SEARCH_FAIL
	fprintf(stderr, "failed to find value %lu!\n", (u_long)correct);
#endif
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
	int num, found;

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

		/* reverse the order of the schedule as higher values are more likely
		 * to be correct */
		for (i = 0; i < nblocks / 2; i++) {
			block_t tmp;

			tmp = round_schedule[i];
			round_schedule[i] = round_schedule[nblocks - i - 1];
			round_schedule[nblocks - i - 1] = tmp;
		}

		++rounds;
#ifdef DEBUG_ROUNDS
		if (debug)
			printf("round %d - %d blocks\n", rounds, nblocks);
#endif

		found = 0;
		for (i = 0; i < nblocks; i++) {
			u_long seq_guess;

			round_schedule[i].chacks = 100;
			for (seq_guess = round_schedule[i].start; seq_guess <= round_schedule[i].end; seq_guess++) {
				if (seq_guess == correct)
					round_schedule[i].chacks--;
				/*
				if (in_seq_window(seq_guess))
					round_schedule[i].chacks--;
				 */
			}

			seconds++; // processing one block takes one second

#define DEBUG_SCHEDULE
#ifdef DEBUG_SCHEDULE
			if(debug) {
				u_long start_seq = round_schedule[i].start; // * half_win;
				u_long end_seq = round_schedule[i].end; // * half_win;

				printf("  scanned %lu - %lu (%lu packets) - %d chacks\n", 
						start_seq, end_seq,
						(round_schedule[i].end - round_schedule[i].start) + 1,
						round_schedule[i].chacks);
			}
#endif

			if (round_schedule[i].chacks < 100) {
				start = round_schedule[i].start;
				end = round_schedule[i].end;
				free(round_schedule);
				found = 1;
				break;
			}
		}

		if (!found) {
			fprintf(stderr, "[!] sequence number not found?!\n");
			return 0;
		}

		num = end - start;
	}

	return binary_search(start, end + 1);
}


int infer_seq_step1(int *pchacks)
{
	int seq_nblocks, nblocks, i, found;
	block_t *round_schedule;
	u_long tmp;

	/* build a schedule to search for windows that trigger chacks < 100 */
	seq_nblocks = (UINT32_MAX / half_win) + 1;
	round_schedule = build_schedule(0, seq_nblocks, &nblocks);
	if (!round_schedule) {
		return 0;
	}

	++rounds;
#ifdef DEBUG_ROUNDS
	if (debug)
		printf("round %d - %d blocks\n", rounds, nblocks);
#endif

	/* process the blocks of window-based guesses */
	found = 0;
	for (i = 0; i < nblocks; i++) {
		u_long j;

		//printf("%d-%d (%lu)\n", round_schedule[i].start, round_schedule[i].end, (u_long)seq_guess);

		/* emulate the remote logic for generating challenge ACKs */
		round_schedule[i].chacks = 100;
		for (j = round_schedule[i].start; j < round_schedule[i].end; j++) {
			uint32_t seq_guess = j * half_win;

			if (in_seq_window(seq_guess))
				round_schedule[i].chacks--;
		}

		seconds++; // processing one block takes one second

#define DEBUG_SCHEDULE
#ifdef DEBUG_SCHEDULE
		if (debug) {
			u_long start_seq = round_schedule[i].start * half_win;
			u_long end_seq = round_schedule[i].end * half_win;

			printf("  scanned %lu - %lu (%lu packets) - %d chacks\n", 
					start_seq, end_seq,
					(round_schedule[i].end - round_schedule[i].start) + 1,
					round_schedule[i].chacks);
		}
#endif

		if (round_schedule[i].chacks < 100) {
			found = 1;
			break;

			/* should we keep processing the schedule?
			 * if the window size is wrong, it could trigger in multiple chunks */

			/* NO. the only case where multiple chunks triggers is when
			 * the guessed window size is less than the real window and the
			 * two blocks straddle a packets-per-second split.
			 *
			 * in that case, the first trigger is sufficient for further
			 * searching efforts since we know the actual sequence number
			 * is to the left.
			 */
		}
	}

	if (!found) {
		fprintf(stderr, "[!] sequence number is not in any window?!\n");
		return 0;
	}

	/* success! we have a block of windows to search further */
	guess_start = round_schedule[i].start * half_win;
	tmp = round_schedule[i].end * half_win;
	if (tmp > UINT32_MAX)
		tmp = UINT32_MAX;
	guess_end = tmp;
	*pchacks = round_schedule[i].chacks;
	free(round_schedule);

	return 1;
}


int infer_seq_step2(void)
{
	u_long start, end, mid;

	start = guess_start / half_win;
	end = (guess_end / half_win) + 1;

	++rounds;
#ifdef DEBUG_ROUNDS
	if (debug)
		printf("round %d\n", rounds);
#endif

	while (start < end) {
		int chacks = 100;
		u_long guess, mid_seq, end_seq;

		mid = (start + end) / 2;
		mid_seq = mid * half_win;
		end_seq = end * half_win;

		// XXX: TODO: optimize last part!
		//if (end - mid < 14) {
		//} else {

		/* see which of these fall in the window */
		for (guess = mid; guess < end; guess++) {
			uint32_t seq_guess = guess * half_win;

			if (in_seq_window(seq_guess))
				chacks--;
		}

		if (chacks == 100) {
#define DEBUG_BIN_SEARCH
#ifdef DEBUG_BIN_SEARCH
			if (debug)
				printf("  scanned %lu - %lu (%lu packets) - NO\n", mid_seq, end_seq - 1, (end - mid));
#endif
			end = mid;
		} else {
#ifdef DEBUG_BIN_SEARCH
			if (debug)
				printf("  scanned %lu - %lu (%lu packets) - OK\n", mid_seq, end_seq - 1, (end - mid));
#endif
			start = mid;
		}

		seconds++; // processing one block takes one second

		if (mid == end - 1) {
#ifdef DEBUG_BIN_SEARCH_WIN
			if (debug)
				printf("found winner window: %lu\n", mid_seq);
#endif
			guess_start = mid_seq - half_win;
			guess_end = mid_seq;
			return 1;
		}
	}

	fprintf(stderr, "failed to find window value %lu!\n", (u_long)correct);
	return 0;
}


int main(int argc, char *argv[])
{
	int max_rounds = 1, max_seconds = 1;
	int min_rounds = 99, min_seconds = 99;
	u_long tot_rounds = 0, tot_seconds = 0;
	int manual_mode = 0;
	int num_attempts;
	int x;
#define NUM_TESTS 4096 // 1048576
	uint32_t test_cases[NUM_TESTS] = {
		0, 0, 0, 0, 1, 31337, 1831146600, 1831146601, UINT32_MAX
	};

	srand(getpid());

	/* set up the window size */
	if (argc > 1)
		winsz = atoi(argv[1]);
	half_win = winsz; // / 2; //14600;

	if (argc > 2) {
		correct = strtoul(argv[2], NULL, 0);
		debug = 1;
		manual_mode = 1;
	}

	if (correct != 0)
		test_cases[0] = correct;
	else
		test_cases[0] = winsz;
	test_cases[2] = (winsz * 2) - 1;
	test_cases[3] = (winsz * 4) - 2;
	for (x = 9; x < (int)(sizeof(test_cases) / sizeof(test_cases[0])); x++) {
		test_cases[x] = (uint32_t)rand();
		test_cases[x] <<= 1;
		test_cases[x] += rand() & 1;
	}

	num_attempts = 0;
	for (x = 0; x < (int)(sizeof(test_cases) / sizeof(test_cases[0])); x++) {
		int chacks;

		correct = test_cases[x];

		/* reset stats */
		num_attempts++;
		rounds = 0;
		seconds = 0;

#define DEBUG_CORRECT
#ifdef DEBUG_CORRECT
		if (debug)
			printf("\n--- winsz guess: %d, winsz: %d, window: %lu - %lu\n", half_win, winsz, (u_long)correct, (u_long)correct + winsz);
#endif

		/* step 1 - identify the approximate sequence number range */
		if (!infer_seq_step1(&chacks))
			return 1;

#define DEBUG_SEARCH_SEQS
#ifdef DEBUG_SEARCH_SEQS
		if (debug) {
			printf("window block %lu - %lu: got %d chacks. searching further...\n", 
					(u_long)guess_start, (u_long)guess_end,
					chacks);
		}
#endif

		// XXX: TODO: adjust window size as needed based on chacks

		/* step 2 - identify the correct sequence block */
		if (!infer_seq_step2())
			return 1;

#define DEBUG_SEARCH_SEQS
#ifdef DEBUG_SEARCH_SEQS
		if (debug) {
			printf("window block %lu - %lu: got %d chacks. searching further...\n", 
					(u_long)guess_start, (u_long)guess_end,
					chacks);
		}
#endif

		/* step 3 - get the exact sequence number */
		if (guess_start < guess_end) {
			if (!hybrid_search(guess_start, guess_end))
				return 1;
		} else {
			if (!hybrid_search(0, guess_end)) {
				if (!hybrid_search(guess_start, UINT32_MAX))
					return 1;
			}
		}

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
