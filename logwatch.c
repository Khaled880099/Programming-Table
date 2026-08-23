#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_THRESHOLD 5
#define DEFAULT_LINE_WINDOW 100
#define DEFAULT_TIME_WINDOW 300
#define MAX_LINE 4096
#define IP_SIZE 64
#define USER_SIZE 128

typedef struct { char ip[IP_SIZE]; char user[USER_SIZE]; unsigned long line; time_t timestamp; int has_timestamp; } FailedAttempt;
typedef struct { char ip[IP_SIZE]; size_t total; unsigned long first_line; unsigned long last_line; int alerted; } IpSummary;
typedef struct { char **items; size_t count; } IpList;

static void usage(const char *program) {
	fprintf(stderr, "Usage: %s <log-file> [options]\n\nAnalyze failed SSH authentication attempts.\n  -t N       Alert after N attempts (default: %d)\n  -w N       Line window (default: %d)\n  -s N       Timestamp window in seconds (default: %d)\n  -f         Follow the file like tail -f\n  -j         Emit JSON Lines for SIEM ingestion\n  -W FILE    Whitelist IPs, one per line\n  -B FILE    Blacklist IPs, one per line\n", program, DEFAULT_THRESHOLD, DEFAULT_LINE_WINDOW, DEFAULT_TIME_WINDOW);
}

static int parse_positive(const char *text, unsigned long *value) {
	char *end = NULL; unsigned long parsed;
	errno = 0; parsed = strtoul(text, &end, 10);
	if (errno != 0 || end == text || *end != '\0' || parsed == 0) return 0;
	*value = parsed; return 1;
}

static void trim_token(char *token) {
	size_t length = strlen(token);
	while (length > 0 && isspace((unsigned char)token[length - 1])) token[--length] = '\0';
	while (length > 0 && ispunct((unsigned char)token[length - 1])) token[--length] = '\0';
}

static int month_number(const char *month) {
	static const char *months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
	int index;
	for (index = 0; index < 12; ++index) if (strncmp(month, months[index], 3) == 0) return index;
	return -1;
}

static int parse_timestamp(const char *line, time_t *result) {
	char month[4]; int day, hour, minute, second, month_index; time_t now = time(NULL); struct tm current, parsed;
	if (sscanf(line, "%3s %d %d:%d:%d", month, &day, &hour, &minute, &second) != 5) return 0;
	month_index = month_number(month);
	if (month_index < 0 || day < 1 || day > 31 || hour < 0 || hour > 23 || minute < 0 || minute > 59 || second < 0 || second > 60 || localtime_r(&now, &current) == NULL) return 0;
	parsed = current; parsed.tm_mon = month_index; parsed.tm_mday = day; parsed.tm_hour = hour; parsed.tm_min = minute; parsed.tm_sec = second; parsed.tm_isdst = -1;
	*result = mktime(&parsed); return *result != (time_t)-1;
}

static int parse_failed_attempt(const char *line, FailedAttempt *attempt, unsigned long line_number) {
	const char *failed = strstr(line, "Failed password"); const char *from = strstr(line, " from "); const char *for_text; char user[USER_SIZE], ip[IP_SIZE];
	if (failed == NULL || from == NULL || from <= failed || sscanf(from + 6, "%63s", ip) != 1) return 0;
	for_text = strstr(failed, " for "); if (for_text == NULL || for_text >= from || sscanf(for_text + 5, "%127s", user) != 1) return 0;
	trim_token(ip); trim_token(user); if (ip[0] == '\0' || user[0] == '\0') return 0;
	snprintf(attempt->ip, sizeof(attempt->ip), "%s", ip); snprintf(attempt->user, sizeof(attempt->user), "%s", user); attempt->line = line_number;
	attempt->has_timestamp = parse_timestamp(line, &attempt->timestamp); return 1;
}

static int list_contains(const IpList *list, const char *ip) {
	size_t index; for (index = 0; index < list->count; ++index) if (strcmp(list->items[index], ip) == 0) return 1; return 0;
}

static void free_ip_list(IpList *list) { size_t index; for (index = 0; index < list->count; ++index) free(list->items[index]); free(list->items); list->items = NULL; list->count = 0; }

static int load_ip_list(const char *filename, IpList *list) {
	FILE *file = fopen(filename, "r"); char line[IP_SIZE];
	if (file == NULL) return 0;
	while (fgets(line, sizeof(line), file) != NULL) { char *entry = line; char **grown; while (isspace((unsigned char)*entry)) ++entry; trim_token(entry); if (*entry == '\0' || *entry == '#') continue;
		grown = realloc(list->items, (list->count + 1) * sizeof(*grown)); if (grown == NULL) { fclose(file); return 0; } list->items = grown; list->items[list->count] = strdup(entry); if (list->items[list->count] == NULL) { fclose(file); return 0; } ++list->count;
	}
	fclose(file); return 1;
}

static IpSummary *find_summary(IpSummary **summaries, size_t *count, size_t *capacity, const char *ip, unsigned long line) {
	size_t index; for (index = 0; index < *count; ++index) if (strcmp((*summaries)[index].ip, ip) == 0) return &(*summaries)[index];
	if (*count == *capacity) { size_t new_capacity = *capacity == 0 ? 16 : *capacity * 2; IpSummary *grown = realloc(*summaries, new_capacity * sizeof(*grown)); if (grown == NULL) return NULL; *summaries = grown; *capacity = new_capacity; }
	snprintf((*summaries)[*count].ip, IP_SIZE, "%s", ip); (*summaries)[*count].total = 0; (*summaries)[*count].first_line = line; (*summaries)[*count].last_line = line; (*summaries)[*count].alerted = 0; return &(*summaries)[(*count)++];
}

static size_t count_recent(const FailedAttempt *attempts, size_t count, const FailedAttempt *current, unsigned long line_window, unsigned long time_window) {
	size_t recent = 0, index;
	for (index = 0; index < count; ++index) { if (strcmp(attempts[index].ip, current->ip) != 0) continue; if (current->has_timestamp && attempts[index].has_timestamp) { if (current->timestamp >= attempts[index].timestamp && (unsigned long)(current->timestamp - attempts[index].timestamp) <= time_window) ++recent; } else if (current->line >= attempts[index].line && current->line - attempts[index].line < line_window) ++recent; }
	return recent;
}

#ifndef LOGWATCH_TEST
int main(int argc, char **argv) {
	const char *filename; unsigned long threshold = DEFAULT_THRESHOLD, line_window = DEFAULT_LINE_WINDOW, time_window = DEFAULT_TIME_WINDOW, line_number = 0; size_t attempts_count = 0, attempts_capacity = 0, summaries_count = 0, summaries_capacity = 0;
	FailedAttempt *attempts = NULL; IpSummary *summaries = NULL; IpList whitelist = {0}, blacklist = {0}; char line[MAX_LINE]; FILE *log_file; int argument, follow = 0, json = 0;
	if (argc < 2) { usage(argv[0]); return EXIT_FAILURE; } filename = argv[1];
	for (argument = 2; argument < argc; ++argument) { unsigned long value;
		if (strcmp(argv[argument], "-f") == 0) follow = 1; else if (strcmp(argv[argument], "-j") == 0) json = 1;
		else if ((strcmp(argv[argument], "-t") == 0 || strcmp(argv[argument], "-w") == 0 || strcmp(argv[argument], "-s") == 0) && argument + 1 < argc && parse_positive(argv[++argument], &value)) { if (strcmp(argv[argument - 1], "-t") == 0) threshold = value; else if (strcmp(argv[argument - 1], "-w") == 0) line_window = value; else time_window = value; }
		else if ((strcmp(argv[argument], "-W") == 0 || strcmp(argv[argument], "-B") == 0) && argument + 1 < argc) { IpList *list = strcmp(argv[argument], "-W") == 0 ? &whitelist : &blacklist; if (!load_ip_list(argv[++argument], list)) { fprintf(stderr, "Cannot load IP list.\n"); return EXIT_FAILURE; } }
		else { usage(argv[0]); return EXIT_FAILURE; }
	}
	log_file = fopen(filename, "r"); if (log_file == NULL) { fprintf(stderr, "Cannot open '%s': %s\n", filename, strerror(errno)); return EXIT_FAILURE; }
	while (1) { if (fgets(line, sizeof(line), log_file) == NULL) { if (!follow) break; clearerr(log_file); sleep(1); continue; }
		FailedAttempt attempt; IpSummary *summary; size_t recent; ++line_number;
		if (!parse_failed_attempt(line, &attempt, line_number) || list_contains(&whitelist, attempt.ip)) continue;
		if (list_contains(&blacklist, attempt.ip)) { if (json) printf("{\"type\":\"blocked\",\"ip\":\"%s\",\"user\":\"%s\",\"line\":%lu}\n", attempt.ip, attempt.user, attempt.line); else printf("[BLOCKED] %s attempted login (blacklist)\n", attempt.ip); continue; }
		if (attempts_count == attempts_capacity) { size_t new_capacity = attempts_capacity == 0 ? 32 : attempts_capacity * 2; FailedAttempt *grown = realloc(attempts, new_capacity * sizeof(*grown)); if (grown == NULL) { fprintf(stderr, "Out of memory.\n"); break; } attempts = grown; attempts_capacity = new_capacity; }
		attempts[attempts_count++] = attempt; summary = find_summary(&summaries, &summaries_count, &summaries_capacity, attempt.ip, attempt.line); if (summary == NULL) { fprintf(stderr, "Out of memory.\n"); break; } ++summary->total; summary->last_line = attempt.line; recent = count_recent(attempts, attempts_count, &attempt, line_window, time_window);
		if (!summary->alerted && recent >= threshold) { if (json) printf("{\"type\":\"alert\",\"ip\":\"%s\",\"user\":\"%s\",\"timestamp\":%lld,\"attempts\":%zu,\"window_seconds\":%lu}\n", attempt.ip, attempt.user, (long long)(attempt.has_timestamp ? attempt.timestamp : 0), recent, time_window); else printf("[ALERT] %s reached %zu failed attempts\n", attempt.ip, recent); summary->alerted = 1; }
	}
	if (!json) { printf("\n=== SSH AUTHENTICATION SUMMARY ===\nScanned lines: %lu | Failed attempts: %zu | Threshold: %lu\n", line_number, attempts_count, threshold); for (size_t index = 0; index < summaries_count; ++index) printf("%-16s total=%-4zu lines=%lu-%lu%s\n", summaries[index].ip, summaries[index].total, summaries[index].first_line, summaries[index].last_line, summaries[index].alerted ? "  [FLAGGED]" : ""); }
	else printf("{\"type\":\"summary\",\"scanned_lines\":%lu,\"failed_attempts\":%zu,\"threshold\":%lu}\n", line_number, attempts_count, threshold);
	fclose(log_file); free(attempts); free(summaries); free_ip_list(&whitelist); free_ip_list(&blacklist); return EXIT_SUCCESS;
}
#endif
