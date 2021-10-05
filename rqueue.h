#ifndef RQUEUE_H
#define RQUEUE_H

#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <unistd.h>
#include <syslog.h>
#include <string>

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
	}
	~rqueue_quick() {
		delete [] buffer;
		delete [] free;
	}
	bool push(typeItem *item, bool waitForFree, bool useLock = false) {
		if(useLock) lock();
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
		return(true);
	}
	bool pop(typeItem *item, bool waitForFree, bool useLock = false) {
		if(useLock) lock();
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
		return(true);
	}
	u_int8_t popq(typeItem *item) {
		if(free[readit] != 0) {
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
		return(true);
	}
	bool get(typeItem *item) {
		while(free[readit] != 0) {
			return(false);
		}
		if(binaryBuffer) {
			memcpy(item, &buffer[readit], sizeof(typeItem));
		} else {
			*item = buffer[readit];
		}
		return(true);
	}
	void moveReadit() {
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
};


#endif

