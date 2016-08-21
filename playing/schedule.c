#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define PACKETS_PER_ROUND 4000

typedef struct block_struct {
	uint32_t start;
	uint32_t end;
	uint32_t chacks;
} block_t;

block_t *build_schedule(int start, int end, int *pnblocks)
{
	int i, nblocks, num, block_sz = PACKETS_PER_ROUND;
	block_t *schedule = NULL;

	num = end - start;
	while (num < block_sz) {
		block_sz /= 2;
	}
	if (block_sz < 1)
		block_sz = 1;
	nblocks = (num / block_sz) + 1;

	printf("  block_sz: %d\n", block_sz);

	schedule = (block_t *)malloc(sizeof(block_t) * nblocks);
	if (!schedule) {
		perror("malloc");
		return NULL;
	}

	for (i = 0; i < nblocks; i++) {
		schedule[i].start = start + (i * block_sz);
		schedule[i].end = start + ((i + 1) * block_sz) - 1;
		if (schedule[i].end > end)
			schedule[i].end = end;

		printf("  schedule[%d]: %lu - %lu\n", i, (u_long)schedule[i].start, (u_long)schedule[i].end);
	}

	*pnblocks = nblocks;
	return schedule;
}

int main(int argc, char *argv[])
{
	int guess_start, guess_end, nblocks;
	block_t *round_schedule;
	int win, round = 0;

	srand(getpid());

	guess_start = 32768;
	guess_end = 65535;

	do {
		if (guess_start == guess_end) {
			printf("found port: %d\n", guess_start);
			break;
		}

		printf("\nround %d:\n", round + 1);
		round_schedule = build_schedule(guess_start, guess_end, &nblocks);
		if (!round_schedule)
			break;

		win = rand() % nblocks;
		guess_start = round_schedule[win].start;
		guess_end = round_schedule[win].end;
		free(round_schedule);

		round++;
	} while (1);

	return 0;
}
