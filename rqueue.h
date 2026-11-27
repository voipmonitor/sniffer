#ifndef RQUEUE_H
#define RQUEUE_H

#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <unistd.h>
#include <syslog.h>
#include <string>
#include <semaphore.h>
#include <time.h>

#include "heap_safe.h"
#include "sync.h"
#include "sync_modern.h"
#include "tools_global.h"


typedef volatile int v_int;
typedef volatile u_int32_t v_u_int32_t;

template<class typeItem>
class rqueue_quick {
public:
	rqueue_quick(size_t length,
		     unsigned int pushUsleep, unsigned int popUsleep,
		     volatile int *term_rqueue,
		     bool binaryBuffer) {
		this->length = length;
		this->pushUsleep = pushUsleep;
		this->popUsleep = popUsleep;
		this->term_rqueue = term_rqueue;
		this->binaryBuffer = binaryBuffer;
		buffer = new FILE_LINE(21001) typeItem[this->length + 1];
		free = new FILE_LINE(21002) v_int[this->length + 1];
		for(size_t i = 0; i < this->length; i++) {
			free[i] = 1;
		}
		readit = 0;
		writeit = 0;
		_sync_lock.init();
		useSemSync = false;
	}
	~rqueue_quick() {
		delete [] buffer;
		delete [] free;
	}
	void setUseSemSync(bool enable) {
		useSemSync = enable;
	}
	bool push(typeItem *item, bool waitForFree, bool useLock = false) {
		if(!waitForFree && ATOMIC_LOAD(free[writeit]) != 1) {
			return(false);
		}
		#if IS_ARM
		useLock = true;
		#endif
		if(useLock) lock();
		while(ATOMIC_LOAD(free[writeit]) != 1) {
			if(waitForFree) {
				if(term_rqueue && *term_rqueue) {
					if(useLock) unlock();
					return(false);
				}
				if(useLock) unlock();
				if(useSemSync) {
					for(int sp = 0; sp < 128 && ATOMIC_LOAD(free[writeit]) != 1; sp++) {
						__ASM_PAUSE;
					}
					if(ATOMIC_LOAD(free[writeit]) != 1) {
						uint32_t wake_tok = wake_free.prepare_sleep();
						if(ATOMIC_LOAD(free[writeit]) != 1 && !(term_rqueue && *term_rqueue)) {
							wake_free.sleep_if_marked(wake_tok, pushUsleep ? pushUsleep : 1000);
						} else {
							wake_free.cancel_sleep();
						}
					}
				} else {
					USLEEP(pushUsleep);
				}
				if(useLock) lock();
			} else {
				if(useLock) unlock();
				return(false);
			}
		}
		if(binaryBuffer) {
			memcpy(CAST_OBJ_TO_VOID(&buffer[writeit]), item, sizeof(typeItem));
		} else {
			buffer[writeit] = *item;
		}
		#if RQUEUE_SAFE
			__SYNC_NULL(free[writeit]);
			u_int32_t next_w = writeit + 1;
			if(next_w == length) next_w = 0;
			__SYNC_SET_TO(writeit, next_w);
		#else
			free[writeit] = 0;
			if((writeit + 1) == length) {
				writeit = 0;
			} else {
				writeit++;
			}
		#endif
		if(useLock) unlock();
		if(useSemSync) {
			wake_filled.notify();
		}
		return(true);
	}
	bool pop(typeItem *item, bool waitForFree, bool useLock = false) {
		#if IS_ARM
		useLock = true;
		#endif
		if(useLock) lock();
		while(ATOMIC_LOAD(free[readit]) != 0) {
			if(waitForFree) {
				if(term_rqueue && *term_rqueue) {
					if(useLock) unlock();
					return(false);
				}
				if(useLock) unlock();
				if(useSemSync) {
					for(int sp = 0; sp < 128 && ATOMIC_LOAD(free[readit]) != 0; sp++) {
						__ASM_PAUSE;
					}
					if(ATOMIC_LOAD(free[readit]) != 0) {
						uint32_t wake_tok = wake_filled.prepare_sleep();
						if(ATOMIC_LOAD(free[readit]) != 0 && !(term_rqueue && *term_rqueue)) {
							wake_filled.sleep_if_marked(wake_tok, popUsleep ? popUsleep : 1000);
						} else {
							wake_filled.cancel_sleep();
						}
					}
				} else {
					USLEEP(popUsleep);
				}
				if(useLock) lock();
			} else {
				if(useLock) unlock();
				return(false);
			}
		}
		if(binaryBuffer) {
			memcpy(CAST_OBJ_TO_VOID(item), &buffer[readit], sizeof(typeItem));
		} else {
			*item = buffer[readit];
		}
		#if RQUEUE_SAFE
			__SYNC_SET(free[readit]);
			u_int32_t next_r = readit + 1;
			if(next_r == length) next_r = 0;
			__SYNC_SET_TO(readit, next_r);
		#else
			free[readit] = 1;
			if((readit + 1) == length) {
				readit = 0;
			} else {
				readit++;
			}
		#endif
		if(useLock) unlock();
		if(useSemSync) {
			wake_free.notify();
		}
		return(true);
	}
	u_int8_t popq(typeItem *item, bool useLock = false) {
		#if IS_ARM
		useLock = true;
		#endif
		if(useLock) lock();
		if(ATOMIC_LOAD(free[readit]) != 0) {
			if(useLock) unlock();
			return(false);
		}
		*item = buffer[readit];
		#if RQUEUE_SAFE
			__SYNC_SET(free[readit]);
			u_int32_t next_r = readit + 1;
			if(next_r == length) next_r = 0;
			__SYNC_SET_TO(readit, next_r);
		#else
			free[readit] = 1;
			if((readit + 1) == length) {
				readit = 0;
			} else {
				readit++;
			}
		#endif
		if(useLock) unlock();
		if(useSemSync) {
			wake_free.notify();
		}
		return(true);
	}
	bool get(typeItem *item, bool useLock = false) {
		#if IS_ARM
		useLock = true;
		#endif
		if(useLock) lock();
		if(ATOMIC_LOAD(free[readit]) != 0) {
			if(useLock) unlock();
			return(false);
		}
		if(binaryBuffer) {
			memcpy(item, &buffer[readit], sizeof(typeItem));
		} else {
			*item = buffer[readit];
		}
		if(useLock) unlock();
		return(true);
	}
	void moveReadit(bool useLock = false) {
		#if IS_ARM
		useLock = true;
		#endif
		if(useLock) lock();
		#if RQUEUE_SAFE
			__SYNC_SET(free[readit]);
			u_int32_t next_r = readit + 1;
			if(next_r == length) next_r = 0;
			__SYNC_SET_TO(readit, next_r);
		#else
			free[readit] = 1;
			if((readit + 1) == length) {
				readit = 0;
			} else {
				readit++;
			}
		#endif
		if(useLock) unlock();
		if(useSemSync) {
			wake_free.notify();
		}
	}
	unsigned int wait_for_data(unsigned int timeout_us, unsigned int counter = (unsigned int)-1) {
		if(useSemSync) {
			if(ATOMIC_LOAD(free[readit]) == 0) return(0);
			for(int sp = 0; sp < 128 && ATOMIC_LOAD(free[readit]) != 0; sp++) __ASM_PAUSE;
			if(ATOMIC_LOAD(free[readit]) == 0) return(0);
			uint32_t wake_tok = wake_filled.prepare_sleep();
			if(ATOMIC_LOAD(free[readit]) != 0 && !(term_rqueue && *term_rqueue)) {
				u_int64_t t0 = getTimeUS();
				wake_filled.sleep_if_marked(wake_tok, timeout_us ? timeout_us : 1000);
				return((unsigned int)(getTimeUS() - t0));
			}
			wake_filled.cancel_sleep();
			return(0);
		}
		return(usleep(timeout_us, counter, __FILE__, __LINE__, NULL));
	}
	unsigned int wait_for_free(unsigned int timeout_us, unsigned int counter = (unsigned int)-1) {
		if(useSemSync) {
			if(ATOMIC_LOAD(free[writeit]) == 1) return(0);
			for(int sp = 0; sp < 128 && ATOMIC_LOAD(free[writeit]) != 1; sp++) __ASM_PAUSE;
			if(ATOMIC_LOAD(free[writeit]) == 1) return(0);
			uint32_t wake_tok = wake_free.prepare_sleep();
			if(ATOMIC_LOAD(free[writeit]) != 1 && !(term_rqueue && *term_rqueue)) {
				u_int64_t t0 = getTimeUS();
				wake_free.sleep_if_marked(wake_tok, timeout_us ? timeout_us : 1000);
				return((unsigned int)(getTimeUS() - t0));
			}
			wake_free.cancel_sleep();
			return(0);
		}
		return(usleep(timeout_us, counter, __FILE__, __LINE__, NULL));
	}
	void lock() {
		_sync_lock.lock(0);
	}
	void unlock() {
		_sync_lock.unlock();
	}
	size_t size() {
		u_int32_t _writeit = ATOMIC_LOAD(writeit);
		u_int32_t _readit = ATOMIC_LOAD(readit);
		return(_writeit > _readit ?
			_writeit - _readit :
		       _writeit < _readit ?
			_writeit + length - _readit :
			ATOMIC_LOAD(free[_writeit]) ? 0 : length);
	}
private:
	size_t length;
	bool binaryBuffer;
	unsigned int pushUsleep;
	unsigned int popUsleep;
	volatile int *term_rqueue;
	typeItem *buffer;
	v_int *free;
	bool useSemSync;
	char _pad_r[VM_CACHELINE_SIZE];
	v_u_int32_t readit;
	char _pad_w[VM_CACHELINE_SIZE];
	v_u_int32_t writeit;
	char _pad_l[VM_CACHELINE_SIZE];
	cPaddedSpinLock _sync_lock;
	cAdaptiveWake wake_free;
	cAdaptiveWake wake_filled;
};


#endif

