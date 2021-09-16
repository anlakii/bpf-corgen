#ifndef __DEBUG_H
#define __DEBUG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

#define C_RED "\x1B[31m"
#define C_GRE "\x1B[32m"
#define C_YEL "\x1B[33m"
#define C_BLU "\x1B[34m"
#define C_CLR "\x1B[0m"

#ifdef LOG
#define _log(fmt, ...)                                                                                                                               \
	do {                                                                                                                                             \
		fprintf(stderr, "[%u] [LOG] %s (%d): " fmt "\n", (unsigned) time(NULL), __FILENAME__, __LINE__, ##__VA_ARGS__);                              \
	} while (0)
#else
#define _log(fmt, ...)                                                                                                                               \
	do {                                                                                                                                             \
	} while (0)
#endif

#ifdef WARNING
#define _warning(fmt, ...)                                                                                                                           \
	do {                                                                                                                                             \
		fprintf(stderr, "[%u] %s[WRN] %s (%d): " fmt "%s\n", (unsigned) time(NULL), isatty(STDERR_FILENO) ? C_YEL : "", __FILENAME__, __LINE__,      \
				##__VA_ARGS__, isatty(STDERR_FILENO) ? C_CLR : "");                                                                                  \
	} while (0)
#else
#define _warning(fmt, ...)                                                                                                                           \
	do {                                                                                                                                             \
	} while (0)
/ bpf - corgen
#endif

#ifdef ERROR
#define _error(fmt, ...)                                                                                                                             \
	do {                                                                                                                                             \
		fprintf(stderr, "[%u] %s[ERR] %s (%d): " fmt "%s\n", (unsigned) time(NULL), isatty(STDERR_FILENO) ? C_RED : "", __FILENAME__, __LINE__,      \
				##__VA_ARGS__, isatty(STDERR_FILENO) ? C_CLR : "");                                                                                  \
	} while (0)
#else
#define _error(fmt, ...)                                                                                                                             \
	do {                                                                                                                                             \
	} while (0)
#endif

#ifdef DEBUG
#define _debug(fmt, ...)                                                                                                                             \
	do {                                                                                                                                             \
		fprintf(stderr, "[%u] [DBG] %s (%d): " fmt "\n", (unsigned) time(NULL), __FILENAME__, __LINE__, ##__VA_ARGS__);                              \
	} while (0)
#else
#define _debug(fmt, ...)                                                                                                                             \
	do {                                                                                                                                             \
	} while (0)
#endif

#define _abort(fmt, ...)                                                                                                                             \
	do {                                                                                                                                             \
		fprintf(stderr, "[%u] %s[ABRT] %s (%d): " fmt "%s\n", (unsigned) time(NULL), isatty(STDERR_FILENO) ? C_RED : "", __FILENAME__, __LINE__,     \
				##__VA_ARGS__, isatty(STDERR_FILENO) ? C_CLR : "");                                                                                  \
		abort();                                                                                                                                     \
	} while (0)

#define _success(fmt, ...)                                                                                                                           \
	do {                                                                                                                                             \
		fprintf(stdout, "[%u] %s[SUCC] %s (%d): " fmt "%s\n", (unsigned) time(NULL), isatty(STDOUT_FILENO) ? C_GRE : "", __FILENAME__, __LINE__,     \
				##__VA_ARGS__, isatty(STDOUT_FILENO) ? C_CLR : "");                                                                                  \
	} while (0)

#define _progress(fmt, ...)                                                                                                                          \
	do {                                                                                                                                             \
		fprintf(stdout, "\r[%u] %s[PROG] %s (%d): " fmt "%s", (unsigned) time(NULL), isatty(STDOUT_FILENO) ? C_BLU : "", __FILENAME__, __LINE__,     \
				##__VA_ARGS__, isatty(STDOUT_FILENO) ? C_CLR : "");                                                                                  \
	} while (0)

#endif
