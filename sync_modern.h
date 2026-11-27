#ifndef SYNC_MODERN_H
#define SYNC_MODERN_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sched.h>
#include <errno.h>
#include <pthread.h>

#ifndef FREEBSD
#include <sys/syscall.h>
#include <linux/futex.h>
#ifndef FUTEX_WAIT_PRIVATE
#define FUTEX_WAIT_PRIVATE (FUTEX_WAIT | 128)
#endif
#ifndef FUTEX_WAKE_PRIVATE
#define FUTEX_WAKE_PRIVATE (FUTEX_WAKE | 128)
#endif
#endif

#include "sync.h"

#if defined(__ATOMIC_RELEASE)
#define VM_ATOMIC_STORE_RELEASE(v, val) __atomic_store_n(&(v), (val), __ATOMIC_RELEASE)
#define VM_ATOMIC_STORE_RELAXED(v, val) __atomic_store_n(&(v), (val), __ATOMIC_RELAXED)
#else
#define VM_ATOMIC_STORE_RELEASE(v, val) do { __sync_synchronize(); (v) = (val); } while(0)
#define VM_ATOMIC_STORE_RELAXED(v, val) ((v) = (val))
#endif

#ifndef VM_CACHELINE_SIZE
#define VM_CACHELINE_SIZE 64
#endif

// Cache-line-isolated waiter-flag-elided hybrid spin-then-futex eventcount (C++98 / GCC 4.4.5 safe).
//
// Why this beats both pure busy-wait and POSIX sem_timedwait:
// - Producer hot path: when no consumer is sleeping (waiters == 0), notify()/notify_all()
//   executes ONE barrier + load with ZERO atomic RMWs and ZERO syscalls.
// - Consumer hot path: spins briefly (PAUSE loop, ~1-2 us) to absorb burst arrivals at
//   sub-microsecond latency without entering the kernel.
// - Consumer idle path: increments `waiters` (seq_cst), snapshots `seq`, caller re-checks
//   predicate (Dekker store-load ordering prevents lost wakeups for 1 or N waiters), then
//   sleeps via relative FUTEX_WAIT_PRIVATE (no clock_gettime syscall) at ~0% CPU.
class cAdaptiveWake {
public:
	cAdaptiveWake() {
		seq = 0;
		waiters = 0;
		#ifdef FREEBSD
		pthread_mutex_init(&mtx, NULL);
		pthread_cond_init(&cv, NULL);
		#endif
	}
	~cAdaptiveWake() {
		#ifdef FREEBSD
		pthread_cond_destroy(&cv);
		pthread_mutex_destroy(&mtx);
		#endif
	}

	inline void notify() {
		__sync_synchronize();
		if(ATOMIC_LOAD(waiters) > 0) {
			notify_slow(1);
		}
	}

	inline void notify_all() {
		__sync_synchronize();
		if(ATOMIC_LOAD(waiters) > 0) {
			notify_slow(0x7fffffff);
		}
	}

	// Register as a waiter with full seq_cst fence and return current generation token.
	// Caller MUST re-check the wait predicate after calling prepare_sleep()
	// and before calling sleep_if_marked()!
	inline uint32_t prepare_sleep() {
		__sync_add_and_fetch(&waiters, 1);
		return(ATOMIC_LOAD(seq));
	}

	inline void cancel_sleep() {
		__sync_sub_and_fetch(&waiters, 1);
	}

	inline void sleep_if_marked(uint32_t token, unsigned int timeout_us) {
		#ifndef FREEBSD
		if(ATOMIC_LOAD(seq) == token) {
			struct timespec ts;
			ts.tv_sec = timeout_us / 1000000U;
			ts.tv_nsec = (long)(timeout_us % 1000000U) * 1000L;
			syscall(SYS_futex, (int*)&seq, FUTEX_WAIT_PRIVATE, (int)token,
				timeout_us ? &ts : NULL, NULL, 0);
		}
		__sync_sub_and_fetch(&waiters, 1);
		#else
		pthread_mutex_lock(&mtx);
		if(ATOMIC_LOAD(seq) == token) {
			if(timeout_us) {
				struct timespec ts;
				clock_gettime(CLOCK_REALTIME, &ts);
				unsigned long long ns = (unsigned long long)ts.tv_nsec + (unsigned long long)timeout_us * 1000ULL;
				ts.tv_sec += ns / 1000000000ULL;
				ts.tv_nsec = (long)(ns % 1000000000ULL);
				pthread_cond_timedwait(&cv, &mtx, &ts);
			} else {
				pthread_cond_wait(&cv, &mtx);
			}
		}
		pthread_mutex_unlock(&mtx);
		__sync_sub_and_fetch(&waiters, 1);
		#endif
	}

private:
	void notify_slow(int wake_count) __attribute__((noinline, cold)) {
		#ifndef FREEBSD
		__sync_add_and_fetch(&seq, 1);
		syscall(SYS_futex, (int*)&seq, FUTEX_WAKE_PRIVATE, wake_count, NULL, NULL, 0);
		#else
		pthread_mutex_lock(&mtx);
		__sync_add_and_fetch(&seq, 1);
		if(wake_count == 1) {
			pthread_cond_signal(&cv);
		} else {
			pthread_cond_broadcast(&cv);
		}
		pthread_mutex_unlock(&mtx);
		#endif
	}

private:
	char _pad0[VM_CACHELINE_SIZE];
	volatile uint32_t seq;
	volatile int waiters;
	#ifdef FREEBSD
	pthread_mutex_t mtx;
	pthread_cond_t cv;
	#endif
	char _pad1[VM_CACHELINE_SIZE - sizeof(uint32_t) - sizeof(int)];
};

// 64-byte cache-line-isolated adaptive TTAS spinlock.
// Eliminates false sharing between adjacent locks and avoids immediate 10us kernel sleep
// on brief critical sections by spinning read-only before TAS, then yielding before sleeping.
struct cPaddedSpinLock {
	volatile int flag;
	char _pad[VM_CACHELINE_SIZE - sizeof(int)];

	cPaddedSpinLock() : flag(0) {}

	inline void init() {
		flag = 0;
	}

	inline void lock(unsigned int sleep_us = 10) {
		if(__sync_lock_test_and_set(&flag, 1) == 0) {
			return;
		}
		lock_slow(sleep_us);
	}

	inline void unlock() {
		__sync_lock_release(&flag);
	}

private:
	void lock_slow(unsigned int sleep_us) __attribute__((noinline, cold)) {
		unsigned int spins = 0;
		while(true) {
			// Read-only spin keeps cache line in Shared state (no MESI RFO storm)
			while(ATOMIC_LOAD(flag) != 0) {
				if(spins < 64) {
					__ASM_PAUSE;
				} else if(spins < 72) {
					sched_yield();
				} else if(sleep_us) {
					usleep(sleep_us);
				} else {
					__ASM_PAUSE;
				}
				++spins;
			}
			if(__sync_lock_test_and_set(&flag, 1) == 0) {
				return;
			}
		}
	}
};

// Distributed Reader-Writer Lock (Linux kernel brlock / percpu_rwsem pattern).
// Optimized for read-heavy hash tables (e.g. Calltable::calls_hash: 99.9% RTP reads, 0.1% SIP writes):
// - Readers own a dedicated 64-byte cache-line-isolated slot: ZERO shared cache-line writes,
//   ZERO atomic RMWs per packet (acquired once per 64-packet chunk), linear multi-core read scaling!
// - Writers set writer_waiting (full barrier) and drain active reader slots (~1-2 us max latency).
class cDistributedRWLock {
public:
	static const int MAX_READER_SLOTS = 32;

	struct sReaderSlot {
		volatile int active;
		char _pad[VM_CACHELINE_SIZE - sizeof(int)];
	};

	cDistributedRWLock() : writer_waiting(0), shared_readers(0) {
		writer_lock.init();
		for(int i = 0; i < MAX_READER_SLOTS; i++) {
			readers[i].active = 0;
		}
	}

	inline void init() {
		writer_lock.init();
		writer_waiting = 0;
		shared_readers = 0;
		for(int i = 0; i < MAX_READER_SLOTS; i++) {
			readers[i].active = 0;
		}
	}

	inline void lock_read_slot(int slot) {
		if(__builtin_expect(slot < 0 || slot >= MAX_READER_SLOTS, 0)) {
			lock_read_shared();
			return;
		}
		while(true) {
			while(ATOMIC_LOAD(writer_waiting) != 0) {
				__ASM_PAUSE;
			}
			VM_ATOMIC_STORE_RELAXED(readers[slot].active, 1);
			__sync_synchronize();
			if(__builtin_expect(ATOMIC_LOAD(writer_waiting) == 0, 1)) {
				return;
			}
			VM_ATOMIC_STORE_RELEASE(readers[slot].active, 0);
		}
	}

	inline void unlock_read_slot(int slot) {
		if(__builtin_expect(slot < 0 || slot >= MAX_READER_SLOTS, 0)) {
			unlock_read_shared();
			return;
		}
		__sync_lock_release(&readers[slot].active);
	}

	inline void lock_read_shared() {
		while(true) {
			while(ATOMIC_LOAD(writer_waiting) != 0) {
				__ASM_PAUSE;
			}
			__sync_add_and_fetch(&shared_readers, 1);
			if(__builtin_expect(ATOMIC_LOAD(writer_waiting) == 0, 1)) {
				return;
			}
			__sync_sub_and_fetch(&shared_readers, 1);
		}
	}

	inline void unlock_read_shared() {
		__sync_sub_and_fetch(&shared_readers, 1);
	}

	inline void lock_write() {
		writer_lock.lock(1);
		__sync_lock_test_and_set(&writer_waiting, 1);
		// Full fence required on weakly-ordered architectures (ARM64) for Dekker pairing
		// with lock_read_slot(): guarantees writer_waiting=1 is globally visible before
		// reading readers[i].active.
		__sync_synchronize();
		for(int i = 0; i < MAX_READER_SLOTS; i++) {
			unsigned spins = 0;
			while(ATOMIC_LOAD(readers[i].active) != 0) {
				if(spins < 32) {
					__ASM_PAUSE;
				} else {
					sched_yield();
				}
				++spins;
			}
		}
		unsigned spins = 0;
		while(ATOMIC_LOAD(shared_readers) != 0) {
			if(spins < 32) {
				__ASM_PAUSE;
			} else {
				sched_yield();
			}
			++spins;
		}
	}

	inline void unlock_write() {
		__sync_lock_release(&writer_waiting);
		writer_lock.unlock();
	}

private:
	cPaddedSpinLock writer_lock;
	char _pad_ww0[VM_CACHELINE_SIZE];
	volatile int writer_waiting;
	char _pad_ww1[VM_CACHELINE_SIZE - sizeof(int)];
	volatile int shared_readers;
	char _pad_sr[VM_CACHELINE_SIZE - sizeof(int)];
	sReaderSlot readers[MAX_READER_SLOTS];
};

// Thread-local cached fixed-size buffer pool for zero-copy storage handoffs
// (FileZipHandler -> AsyncClose -> ChunkBuffer -> Tar).
// Supports exact slab sizes 8 KB, 16 KB, and 32 KB. Pure C++98 + POSIX pthread_key_t,
// bounded global retention (no memory bloat), automatic cleanup on thread exit.
class cFixedBufferPool {
public:
	static const int NUM_BUCKETS = 3;
	static const int TLS_MAX = 32;
	static const int TLS_BATCH = 16;

	static inline int bucketIndex(size_t size) {
		if(size == 8192) return(0);
		if(size == 16384) return(1);
		if(size == 32768) return(2);
		return(-1);
	}

	static inline bool supports(size_t size) {
		return(bucketIndex(size) >= 0);
	}

	static inline char *alloc(size_t size, bool *from_pool) {
		int idx = bucketIndex(size);
		if(__builtin_expect(idx < 0, 0)) {
			if(from_pool) *from_pool = false;
			return(new char[size]);
		}
		if(from_pool) *from_pool = true;
		sTlsCache *tls = getTls();
		if(__builtin_expect(tls != NULL, 1)) {
			sTlsBucket &tb = tls->buckets[idx];
			if(__builtin_expect(tb.count > 0, 1)) {
				return(tb.items[--tb.count]);
			}
			char *refilled = refill_from_global(tb, idx);
			if(refilled) {
				return(refilled);
			}
		}
		return(new char[size]);
	}

	static inline void release(char *ptr, size_t size, bool from_pool) {
		if(!ptr) return;
		if(!from_pool) {
			delete [] ptr;
			return;
		}
		int idx = bucketIndex(size);
		if(__builtin_expect(idx < 0, 0)) {
			delete [] ptr;
			return;
		}
		sTlsCache *tls = getTls();
		if(__builtin_expect(tls != NULL, 1)) {
			sTlsBucket &tb = tls->buckets[idx];
			if(__builtin_expect(tb.count < TLS_MAX, 1)) {
				tb.items[tb.count++] = ptr;
				return;
			}
			spill_to_global(tb, idx, ptr);
			return;
		}
		delete [] ptr;
	}

private:
	struct sTlsBucket {
		char *items[TLS_MAX];
		int count;
	};
	struct sTlsCache {
		sTlsBucket buckets[NUM_BUCKETS];
	};
	struct sGlobalBucket {
		cPaddedSpinLock lock;
		void *head;
		unsigned count;
		char _pad[VM_CACHELINE_SIZE - sizeof(void*) - sizeof(unsigned)];
	};

	static char *refill_from_global(sTlsBucket &tb, int idx) __attribute__((noinline, cold)) {
		sGlobalBucket &gb = globalBuckets()[idx];
		gb.lock.lock(0);
		while(tb.count < TLS_BATCH && gb.head) {
			char *p = (char*)gb.head;
			gb.head = *(void**)p;
			--gb.count;
			tb.items[tb.count++] = p;
		}
		gb.lock.unlock();
		return(tb.count > 0 ? tb.items[--tb.count] : NULL);
	}

	static void spill_to_global(sTlsBucket &tb, int idx, char *ptr) __attribute__((noinline, cold)) {
		char *to_delete[TLS_BATCH];
		int del_count = 0;
		sGlobalBucket &gb = globalBuckets()[idx];
		const unsigned max_global = maxGlobalForBucket(idx);
		gb.lock.lock(0);
		for(int i = 0; i < TLS_BATCH; i++) {
			char *p = tb.items[--tb.count];
			if(gb.count < max_global) {
				*(void**)p = gb.head;
				gb.head = p;
				++gb.count;
			} else {
				to_delete[del_count++] = p;
			}
		}
		gb.lock.unlock();
		for(int i = 0; i < del_count; i++) {
			delete [] to_delete[i];
		}
		tb.items[tb.count++] = ptr;
	}

	static inline unsigned maxGlobalForBucket(int idx) {
		return(idx == 0 ? 2048U : 1024U);
	}

	static sGlobalBucket *globalBuckets() {
		static sGlobalBucket buckets[NUM_BUCKETS];
		return(buckets);
	}

	static pthread_key_t &tlsKey() {
		static pthread_key_t key;
		return(key);
	}

	static void tlsDestructor(void *arg) {
		sTlsCache *tls = (sTlsCache*)arg;
		if(!tls) return;
		sGlobalBucket *gbs = globalBuckets();
		for(int idx = 0; idx < NUM_BUCKETS; idx++) {
			sTlsBucket &tb = tls->buckets[idx];
			if(tb.count > 0) {
				char *to_delete[TLS_MAX];
				int del_count = 0;
				const unsigned max_global = maxGlobalForBucket(idx);
				gbs[idx].lock.lock(0);
				while(tb.count > 0) {
					char *p = tb.items[--tb.count];
					if(gbs[idx].count < max_global) {
						*(void**)p = gbs[idx].head;
						gbs[idx].head = p;
						++gbs[idx].count;
					} else {
						to_delete[del_count++] = p;
					}
				}
				gbs[idx].lock.unlock();
				for(int i = 0; i < del_count; i++) {
					delete [] to_delete[i];
				}
			}
		}
		free(tls);
	}

	static bool &tlsKeyValid() {
		static bool valid = false;
		return(valid);
	}

	static void initTlsKey() {
		tlsKeyValid() = (pthread_key_create(&tlsKey(), tlsDestructor) == 0);
	}

	static inline sTlsCache *getTls() {
		static pthread_once_t once = PTHREAD_ONCE_INIT;
		pthread_once(&once, initTlsKey);
		if(__builtin_expect(!tlsKeyValid(), 0)) {
			return(NULL);
		}
		sTlsCache *tls = (sTlsCache*)pthread_getspecific(tlsKey());
		if(!tls) {
			tls = (sTlsCache*)calloc(1, sizeof(sTlsCache));
			if(tls) {
				pthread_setspecific(tlsKey(), tls);
			}
		}
		return(tls);
	}
};

#endif // SYNC_MODERN_H
