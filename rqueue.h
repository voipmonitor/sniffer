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
		_sync_lock = 0;
		useSemSync = false;
	}
	~rqueue_quick() {
		delete [] buffer;
		delete [] free;
		if(useSemSync) {
			sem_destroy(&sem_qring_free);
			sem_destroy(&sem_qring_filled);
		}
	}
	void setUseSemSync(bool enable) {
		if(enable && !useSemSync) {
			sem_init(&sem_qring_free, 0, length);
			sem_init(&sem_qring_filled, 0, 0);
			useSemSync = true;
		} else if(!enable && useSemSync) {
			sem_destroy(&sem_qring_free);
			sem_destroy(&sem_qring_filled);
			useSemSync = false;
		}
	}
	bool push(typeItem *item, bool waitForFree, bool useLock = false) {
		if(useSemSync) {
			if(waitForFree) {
				while(true) {
					if(term_rqueue && *term_rqueue) {
						return(false);
					}
					if(SEM_TIMEDWAIT_US(&sem_qring_free, pushUsleep) == 0) {
						break;
					}
				}
			} else {
				if(sem_trywait(&sem_qring_free) == -1) {
					return(false);
				}
			}
		} else if(!waitForFree && free[writeit] != 1) {
			return(false);
		}
		#if IS_ARM
		useLock = true;
		#endif
		if(useLock) lock();
		if(!useSemSync) {
			while(free[writeit] != 1) {
				if(waitForFree) {
					if(term_rqueue && *term_rqueue) {
						if(useLock) unlock();
						return(false);
					}
					if(useLock) unlock();
					USLEEP(pushUsleep);
					if(useLock) lock();
				} else {
					if(useLock) unlock();
					return(false);
				}
			}
		}
		if(binaryBuffer) {
			memcpy(CAST_OBJ_TO_VOID(&buffer[writeit]), item, sizeof(typeItem));
		} else {
			buffer[writeit] = *item;
		}
		#if RQUEUE_SAFE
			__SYNC_NULL(free[writeit]);
			__SYNC_INCR(writeit, length);
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
			sem_post(&sem_qring_filled);
		}
		return(true);
	}
	bool pop(typeItem *item, bool waitForFree, bool useLock = false) {
		if(useSemSync) {
			if(waitForFree) {
				while(true) {
					if(term_rqueue && *term_rqueue) {
						return(false);
					}
					if(SEM_TIMEDWAIT_US(&sem_qring_filled, popUsleep) == 0) {
						break;
					}
				}
			} else {
				if(sem_trywait(&sem_qring_filled) == -1) {
					return(false);
				}
			}
		}
		#if IS_ARM
		useLock = true;
		#endif
		if(useLock) lock();
		if(!useSemSync) {
			while(free[readit] != 0) {
				if(waitForFree) {
					if(term_rqueue && *term_rqueue) {
						if(useLock) unlock();
						return(false);
					}
					USLEEP(popUsleep);
				} else {
					if(useLock) unlock();
					return(false);
				}
			}
		}
		if(binaryBuffer) {
			memcpy(CAST_OBJ_TO_VOID(item), &buffer[readit], sizeof(typeItem));
		} else {
			*item = buffer[readit];
		}
		#if RQUEUE_SAFE
			__SYNC_SET(free[readit]);
			__SYNC_INCR(readit, length);
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
			sem_post(&sem_qring_free);
		}
		return(true);
	}
	u_int8_t popq(typeItem *item, bool useLock = false) {
		if(useSemSync) {
			if(sem_trywait(&sem_qring_filled) == -1) {
				return(false);
			}
		}
		#if IS_ARM
		useLock = true;
		#endif
		if(useLock) lock();
		if(free[readit] != 0) {
			if(useLock) unlock();
			if(useSemSync) {
				sem_post(&sem_qring_filled);
			}
			return(false);
		}
		*item = buffer[readit];
		#if RQUEUE_SAFE
			__SYNC_SET(free[readit]);
			__SYNC_INCR(readit, length);
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
			sem_post(&sem_qring_free);
		}
		return(true);
	}
	bool get(typeItem *item, bool useLock = false) {
		#if IS_ARM
		useLock = true;
		#endif
		if(useLock) lock();
		if(free[readit] != 0) {
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
			__SYNC_INCR(readit, length);
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
			sem_trywait(&sem_qring_filled);
			sem_post(&sem_qring_free);
		}
	}
	unsigned int wait_for_data(unsigned int timeout_us, unsigned int counter = (unsigned int)-1) {
		return(usleep(timeout_us, counter, __FILE__, __LINE__, useSemSync ? &sem_qring_filled : NULL));
	}
	unsigned int wait_for_free(unsigned int timeout_us, unsigned int counter = (unsigned int)-1) {
		return(usleep(timeout_us, counter, __FILE__, __LINE__, useSemSync ? &sem_qring_free : NULL));
	}
	void lock() {
		__SYNC_LOCK(this->_sync_lock);
	}
	void unlock() {
		__SYNC_UNLOCK(this->_sync_lock);
	}
	size_t size() {
		u_int32_t _writeit = writeit;
		u_int32_t _readit = readit;
		return(_writeit > _readit ?
			_writeit - _readit :
		       _writeit < _readit ?
			_writeit + length - _readit :
			free[_writeit] ? 0 : length);
	}
private:
	size_t length;
	bool binaryBuffer;
	unsigned int pushUsleep;
	unsigned int popUsleep;
	volatile int *term_rqueue;
	typeItem *buffer;
	v_int *free;
	v_u_int32_t readit;
	v_u_int32_t writeit;
	volatile int _sync_lock;
	bool useSemSync;
	sem_t sem_qring_free;
	sem_t sem_qring_filled;
};


#endif

