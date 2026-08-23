#define _POSIX_C_SOURCE 200809L
#define LOGWATCH_TEST
#pragma GCC diagnostic ignored "-Wunused-function"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "logwatch.c"

int main(void) {
	FailedAttempt first, second, plain;
	FailedAttempt attempts[2];
	time_t first_time;
	IpList list = {0};

	assert(parse_failed_attempt("Jan 01 12:00:00 host sshd: Failed password for root from 203.0.113.9 port 22 ssh2", &first, 1));
	assert(strcmp(first.ip, "203.0.113.9") == 0);
	assert(strcmp(first.user, "root") == 0);
	assert(first.has_timestamp);
	first_time = first.timestamp;
	assert(parse_failed_attempt("Jan 01 12:04:00 host sshd: Failed password for admin from 203.0.113.9 port 22 ssh2", &second, 2));
	assert(second.timestamp > first_time);
	attempts[0] = first;
	attempts[1] = second;
	assert(count_recent(attempts, 2, &second, 100, 300) == 2);
	assert(count_recent(attempts, 2, &second, 100, 60) == 1);
	assert(parse_failed_attempt("not-a-timestamp sshd: Failed password for test from 192.0.2.5 port 22", &plain, 3));
	assert(!plain.has_timestamp);
	assert(count_recent(attempts, 2, &plain, 100, 300) == 0);
	list.items = malloc(sizeof(*list.items));
	list.items[0] = strdup("203.0.113.9");
	list.count = 1;
	assert(list_contains(&list, "203.0.113.9"));
	assert(!list_contains(&list, "192.0.2.5"));
	free_ip_list(&list);
	puts("logwatch unit tests: ok");
	return 0;
}
