#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int main(int argc, char *argv[])
{
	int guess_start, guess_end, guess_mid;
	int win, round = 0;

	srand(getpid());

	guess_start = 32768;
	guess_end = 65535;

	do {
		guess_mid = (guess_start + guess_end) / 2;

		printf("scanning %d - %d (%d packets)\n", guess_mid, guess_end - 1, (guess_end - guess_mid));

		if (rand() % 1) {
			guess_end = guess_mid - 1;
		} else {
			guess_start = guess_mid;
		}

		if (guess_mid == guess_end - 1)
			break;

	} while (1);

	return 0;
}
