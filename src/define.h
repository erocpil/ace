#ifndef __DEFINE_H__
#define __DEFINE_H__

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <math.h>
#include <time.h>
#define Blue "\033[94m"
#define Cyan "\033[96m"
#define Green "\033[92m"
#define Gray "\033[97m"
#define Pink "\033[95m"
#define Red "\033[91m"
#define Smoke "\033[90m"
#define Yellow "\033[93m"

#define RESET "\033[m"

#define log(fmt, ...) \
	do { \
		int saved_errno = errno; \
		time_t t; \
		time(&t); \
		struct tm *tm = localtime(&t); \
		printf(Blue "[ " Cyan "%02d:%02d:%02d" Green " %s %d " Blue "] " \
				RESET fmt "\n", tm->tm_hour, tm->tm_min, tm->tm_sec, \
				__func__, __LINE__, ##__VA_ARGS__); \
		errno = saved_errno; \
	} while (0)

#define blog(fmt, ...) \
	do { \
		int saved_errno = errno; \
		time_t t; \
		time(&t); \
		struct tm *tm = localtime(&t); \
		printf(Blue "[ " Blue "%02d:%02d:%02d" Blue " %s %d " Blue "] " \
				RESET fmt "\n", tm->tm_hour, tm->tm_min, tm->tm_sec, \
				__func__, __LINE__, ##__VA_ARGS__); \
		errno = saved_errno; \
	} while (0)

#define clog(fmt, ...) \
	do { \
		int saved_errno = errno; \
		time_t t; \
		time(&t); \
		struct tm *tm = localtime(&t); \
		printf(Cyan "[ " Cyan "%02d:%02d:%02d" Cyan " %s %d " Cyan "] " \
				RESET fmt "\n", tm->tm_hour, tm->tm_min, tm->tm_sec, \
				__func__, __LINE__, ##__VA_ARGS__); \
		errno = saved_errno; \
	} while (0)

#define glog(fmt, ...) \
	do { \
		int saved_errno = errno; \
		time_t t; \
		time(&t); \
		struct tm *tm = localtime(&t); \
		printf(Gray "[ " Gray "%02d:%02d:%02d" Gray " %s %d " Gray "] " \
				RESET fmt "\n", tm->tm_hour, tm->tm_min, tm->tm_sec, \
				__func__, __LINE__, ##__VA_ARGS__); \
		errno = saved_errno; \
	} while (0)

#define plog(fmt, ...) \
	do { \
		int saved_errno = errno; \
		time_t t; \
		time(&t); \
		struct tm *tm = localtime(&t); \
		printf(Pink "[ " Pink "%02d:%02d:%02d" Pink " %s %d " Pink "] " \
				RESET fmt "\n", tm->tm_hour, tm->tm_min, tm->tm_sec, \
				__func__, __LINE__, ##__VA_ARGS__); \
		errno = saved_errno; \
	} while (0)

#define rlog(fmt, ...) \
	do { \
		int saved_errno = errno; \
		time_t t; \
		time(&t); \
		struct tm *tm = localtime(&t); \
		printf(Red "[ " Red "%02d:%02d:%02d" Red " %s %d " Red "] " \
				fmt RESET "\n", tm->tm_hour, tm->tm_min, tm->tm_sec, \
				__func__, __LINE__, ##__VA_ARGS__); \
		errno = saved_errno; \
	} while (0)

#define slog(fmt, ...) \
	do { \
		int saved_errno = errno; \
		time_t t; \
		time(&t); \
		struct tm *tm = localtime(&t); \
		printf(Smoke "[ " Smoke "%02d:%02d:%02d" Smoke " %s %d " Smoke "] " \
				RESET fmt "\n", tm->tm_hour, tm->tm_min, tm->tm_sec, \
				__func__, __LINE__, ##__VA_ARGS__); \
		errno = saved_errno; \
	} while (0)

#define ylog(fmt, ...) \
	do { \
		int saved_errno = errno; \
		time_t t; \
		time(&t); \
		struct tm *tm = localtime(&t); \
		printf(Yellow "[ " Yellow "%02d:%02d:%02d" Yellow " %s %d " Yellow "] " \
				RESET fmt "\n", tm->tm_hour, tm->tm_min, tm->tm_sec, \
				__func__, __LINE__, ##__VA_ARGS__); \
		errno = saved_errno; \
	} while (0)

#define elog(fmt, ...) \
	do { \
		int saved_errno = errno; \
		time_t t; \
		time(&t); \
		struct tm *tm = localtime(&t); \
		printf(Blue "[ " Cyan "%02d:%02d:%02d" Red " %s %d " Blue "] " \
				RESET fmt "\n", tm->tm_hour, tm->tm_min, tm->tm_sec, \
				__func__, __LINE__, ##__VA_ARGS__); \
		errno = saved_errno; \
	} while (0)

#define eslog(fmt, ...) \
	do { \
		elog("%d \"" Red "%s" RESET "\" " fmt , errno, strerror(errno), ##__VA_ARGS__); \
	} while (0)

#define hplog(fmt, ...) \
	do { \
		int saved_errno = errno; \
		time_t t; \
		time(&t); \
		struct timespec ts; \
		clock_gettime(CLOCK_REALTIME_COARSE, &ts); \
		struct tm *tm = localtime(&t); \
		printf(Blue "[ " Cyan "%02d:%02d:%02d.%010ld" Green " %s %d " Blue "] " \
				RESET fmt "\n", tm->tm_hour, tm->tm_min, tm->tm_sec, ts.tv_nsec, \
				__func__, __LINE__, ##__VA_ARGS__); \
		errno = saved_errno; \
	} while (0)

#define hpelog(fmt, ...) \
	do { \
		int saved_errno = errno; \
		time_t t; \
		time(&t); \
		struct timespec ts; \
		clock_gettime(CLOCK_REALTIME_COARSE, &ts); \
		struct tm *tm = localtime(&t); \
		printf(Blue "[ " Cyan "%02d:%02d:%02d.%09ld" Red " %s %d " Blue "] " \
				RESET fmt "\n", tm->tm_hour, tm->tm_min, tm->tm_sec, ts.tv_nsec, \
				__func__, __LINE__, ##__VA_ARGS__); \
		errno = saved_errno; \
	} while (0)

#define hpeslog(fmt, ...) \
	do { \
		int saved_errno = errno; \
		time_t t; \
		time(&t); \
		struct timespec ts; \
		clock_gettime(CLOCK_REALTIME_COARSE, &ts); \
		struct tm *tm = localtime(&t); \
		printf(Blue "[ " Cyan "%02d:%02d:%02d.%09ld" Red " %s %d " Blue "]" RESET " %d \"" Red "%s" RESET "\" " \
				RESET fmt "\n", tm->tm_hour, tm->tm_min, tm->tm_sec, ts.tv_nsec, \
				__func__, __LINE__, errno, strerror(errno), ##__VA_ARGS__); \
		errno = saved_errno; \
	} while (0)

#define MAX(a, b) ({ \
		const typeof(a) _a = (a); \
		const typeof(b) _b = (b); \
		(void)(&_a == &_b); \
		_a > _b ? _a : _b; \
		})

#define SET_USED(x) (void)(x)

#define DUMP(d, l) \
	do { \
		unsigned char *_d = (unsigned char*)(d); \
		size_t _l = (size_t)(l); \
		log("DUMP %p %lu", _d, (size_t)_l); \
		printf("'"); \
		for (size_t i = 0; i < _l; i++) { \
			printf("%c", _d[i]); \
		} \
		printf("'\n"); \
	} while (0)

#define DUMP_HEX(d, l) \
	do { \
		unsigned char *_d = (unsigned char*)(d); \
		size_t _l = (size_t)(l); \
		log("DUMP_HEX %p %lu", _d, (size_t)_l); \
		printf("[ "); \
		for (size_t i = 0; i < _l; i++) { \
			printf("%02x ", _d[i]); \
		} \
		printf("]\n"); \
	} while (0)

/* from dpdk */
/** C extension macro for environments lacking C11 features. */
#if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 201112L
#define RTE_STD_C11 __extension__
#else
#define RTE_STD_C11
#endif
static inline unsigned long rdtsc(void)
{
	union {
		unsigned long tsc_64;
		RTE_STD_C11
			struct {
				unsigned int lo_32;
				unsigned int hi_32;
			};
	} tsc;

#ifdef RTE_LIBRTE_EAL_VMWARE_TSC_MAP_SUPPORT
	if (unlikely(rte_cycles_vmware_tsc_map)) {
		/* ecx = 0x10000 corresponds to the physical TSC for VMware */
		asm volatile("rdpmc" :
				"=a" (tsc.lo_32),
				"=d" (tsc.hi_32) :
				"c"(0x10000));
		return tsc.tsc_64;
	}
#endif

	asm volatile("rdtsc" :
			"=a" (tsc.lo_32),
			"=d" (tsc.hi_32));
	return tsc.tsc_64;
}

#if 0
/* from dpdk __rte_arm64_cntvct() */
/** Read generic counter */
static inline __attribute__((always_inline)) unsigned long arm64_cntvct(void)
{
	unsigned long tsc;

	asm volatile("mrs %0, cntvct_el0" : "=r" (tsc));
	return tsc;
}
#endif

#endif
