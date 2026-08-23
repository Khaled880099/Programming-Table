#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_THRESHOLD 5
#define DEFAULT_WINDOW 100
#define MAX_LINE 4096
#define IP_SIZE 64
#define USER_SIZE 128

typedef struct {
	char ip[IP_SIZE];
	char user[USER_SIZE];
	unsigned long line;
} FailedAttempt;

typedef struct {
	char ip[IP_SIZE];
	size_t total;
	unsigned long first_line;
	unsigned long last_line;
	int alerted;
} IpSummary;

static void usage(const char *program) {
	fprintf(stderr,
		"Usage: %s <log-file> [-t threshold] [-w line-window]\n"
		"\nAnalyze failed SSH authentication attempts.\n"
		"  -t threshold    Alert after this many attempts (default: %d)\n"
		"  -w line-window  Count attempts within this many log lines (default: %d)\n",
		program, DEFAULT_THRESHOLD, DEFAULT_WINDOW);
}

static int parse_positive(const char *text, unsigned long *value) {
	char *end = NULL;
	unsigned long parsed;

	errno = 0;
	parsed = strtoul(text, &end, 10);
	if (errno != 0 || end == text || *end != '\0' || parsed == 0) {
		return 0;
	}
	*value = parsed;
	return 1;
}

static void trim_token(char *token) {
	size_t length = strlen(token);
	while (length > 0 && ispunct((unsigned char)token[length - 1])) {
		token[--length] = '\0';
	}
}

static int parse_failed_attempt(const char *line, FailedAttempt *attempt, unsigned long line_number) {
	const char *failed = strstr(line, "Failed password");
	const char *from = strstr(line, " from ");
	const char *for_text;
	char user[USER_SIZE];
	char ip[IP_SIZE];

	if (failed == NULL || from == NULL || from <= failed ||
		sscanf(from + 6, "%63s", ip) != 1) {
		return 0;
	}

	for_text = strstr(failed, " for ");
	if (for_text == NULL || for_text >= from ||
		sscanf(for_text + 5, "%127s", user) != 1) {
		return 0;
	}

	trim_token(ip);
	trim_token(user);
	if (ip[0] == '\0' || user[0] == '\0') {
		return 0;
	}

	snprintf(attempt->ip, sizeof(attempt->ip), "%s", ip);
	snprintf(attempt->user, sizeof(attempt->user), "%s", user);
	attempt->line = line_number;
	return 1;
}

static IpSummary *find_summary(IpSummary **summaries, size_t *count, size_t *capacity,
							   const char *ip, unsigned long line) {
	size_t index;

	for (index = 0; index < *count; ++index) {
		if (strcmp((*summaries)[index].ip, ip) == 0) {
			return &(*summaries)[index];
		}
	}

	if (*count == *capacity) {
		size_t new_capacity = *capacity == 0 ? 16 : *capacity * 2;
		IpSummary *grown = realloc(*summaries, new_capacity * sizeof(*grown));
		if (grown == NULL) {
			return NULL;
		}
		*summaries = grown;
		*capacity = new_capacity;
	}

	snprintf((*summaries)[*count].ip, IP_SIZE, "%s", ip);
	(*summaries)[*count].total = 0;
	(*summaries)[*count].first_line = line;
	(*summaries)[*count].last_line = line;
	(*summaries)[*count].alerted = 0;
	return &(*summaries)[(*count)++];
}

static size_t count_recent(const FailedAttempt *attempts, size_t count,
						   const char *ip, unsigned long current_line,
						   unsigned long window) {
	size_t recent = 0;
	size_t index;

	for (index = 0; index < count; ++index) {
		if (strcmp(attempts[index].ip, ip) == 0 &&
			current_line - attempts[index].line < window) {
			++recent;
		}
	}
	return recent;
}

int main(int argc, char **argv) {
	const char *filename;
	unsigned long threshold = DEFAULT_THRESHOLD;
	unsigned long window = DEFAULT_WINDOW;
	unsigned long line_number = 0;
	size_t attempts_count = 0;
	size_t attempts_capacity = 0;
	size_t summaries_count = 0;
	size_t summaries_capacity = 0;
	FailedAttempt *attempts = NULL;
	IpSummary *summaries = NULL;
	char line[MAX_LINE];
	FILE *log_file;
	int argument;

	if (argc < 2) {
		usage(argv[0]);
		return EXIT_FAILURE;
	}

	filename = argv[1];
	for (argument = 2; argument < argc; ++argument) {
		unsigned long value;
		if ((strcmp(argv[argument], "-t") == 0 || strcmp(argv[argument], "-w") == 0) &&
			argument + 1 < argc && parse_positive(argv[++argument], &value)) {
			if (strcmp(argv[argument - 1], "-t") == 0) {
				threshold = value;
			} else {
				window = value;
			}
		} else {
			usage(argv[0]);
			return EXIT_FAILURE;
		}
	}

	log_file = fopen(filename, "r");
	if (log_file == NULL) {
		fprintf(stderr, "Cannot open '%s': %s\n", filename, strerror(errno));
		return EXIT_FAILURE;
	}

	while (fgets(line, sizeof(line), log_file) != NULL) {
		FailedAttempt attempt;
		IpSummary *summary;
		size_t recent;

		++line_number;
		if (!parse_failed_attempt(line, &attempt, line_number)) {
			continue;
		}

		if (attempts_count == attempts_capacity) {
			size_t new_capacity = attempts_capacity == 0 ? 32 : attempts_capacity * 2;
			FailedAttempt *grown = realloc(attempts, new_capacity * sizeof(*grown));
			if (grown == NULL) {
				fprintf(stderr, "Out of memory while reading log.\n");
				fclose(log_file);
				free(attempts);
				free(summaries);
				return EXIT_FAILURE;
			}
			attempts = grown;
			attempts_capacity = new_capacity;
		}
		attempts[attempts_count++] = attempt;

		summary = find_summary(&summaries, &summaries_count, &summaries_capacity,
							   attempt.ip, attempt.line);
		if (summary == NULL) {
			fprintf(stderr, "Out of memory while grouping IP addresses.\n");
			fclose(log_file);
			free(attempts);
			free(summaries);
			return EXIT_FAILURE;
		}
		++summary->total;
		summary->last_line = attempt.line;
		recent = count_recent(attempts, attempts_count, attempt.ip, attempt.line, window);
		if (!summary->alerted && recent >= threshold) {
			printf("[ALERT] %s reached %zu failed attempts within %lu log lines\n",
				   attempt.ip, recent, window);
			summary->alerted = 1;
		}
	}
	fclose(log_file);

	printf("\n=== SSH AUTHENTICATION SUMMARY ===\n");
	printf("Scanned lines: %lu | Failed attempts: %zu | Threshold: %lu | Window: %lu\n",
		   line_number, attempts_count, threshold, window);
	for (size_t index = 0; index < summaries_count; ++index) {
		printf("%-16s total=%-4zu lines=%lu-%lu%s\n",
			   summaries[index].ip, summaries[index].total,
			   summaries[index].first_line, summaries[index].last_line,
			   summaries[index].alerted ? "  [FLAGGED]" : "");
	}

	free(attempts);
	free(summaries);
	return EXIT_SUCCESS;
}
