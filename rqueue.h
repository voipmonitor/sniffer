#ifndef RQUEUE_H
#define RQUEUE_H

#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <unistd.h>
#include <syslog.h>
#include <string>

#ifdef HAVE_LIBBOOST
#include <boost/lockfree/spsc_queue.hpp>
#endif


template<class typeItem>
class rqueue {
public:
	rqueue(size_t length = 100, size_t inc_length = 100, size_t limit_length = 0, bool binaryBuffer = false, 
	       bool clearBuff = false,bool clearAtPop = false) {
		this->length = length;
		this->inc_length = inc_length;
		this->limit_length = limit_length;
		this->binaryBuffer = binaryBuffer;
		this->clearBuff = clearBuff;
		this->clearAtPop = clearAtPop;
		if(this->length) {
			this->buffer = new typeItem[this->length];
			if(this->binaryBuffer && this->clearBuff) {
				memset(this->buffer, 0, this->length * sizeof(typeItem));
			}
		} else {
			this->buffer = NULL;
		}
		this->startIndex = 0;
		this->countItems = 0;
		this->_sync_lock = 0;
	}
	~rqueue() {
		delete [] this->buffer;
	}
	bool push(typeItem item, bool lock = false) {
		bool rslt = true;
		if(lock) {
			this->lock();
		}
		if(this->countItems < this->length) {
			this->buffer[(this->startIndex + this->countItems) % this->length] = item;
			++this->countItems;
		} else {
			if(this->inc_length && 
			   (!this->limit_length || (this->length + this->inc_length) < this->limit_length)) {
				this->incBuffer();
				this->buffer[(this->startIndex + this->countItems) % this->length] = item;
				++this->countItems;
			} else {
				rslt = false;
			}
		}
		if(lock) {
			this->unlock();
		}
		return(rslt);
	}
	bool push(typeItem *item, bool lock = false) {
		bool rslt = true;
		if(lock) {
			this->lock();
		}
		if(this->countItems >= this->length && this->inc_length && 
		   (!this->limit_length || (this->length + this->inc_length) < this->limit_length)) {
			this->incBuffer();
		}
		if(this->countItems < this->length) {
			size_t writePos = (this->startIndex + this->countItems) % this->length;
			if(this->binaryBuffer) {
				memcpy(&this->buffer[writePos], item, sizeof(typeItem));
			} else {
				this->buffer[writePos] = *item;
			}
			++this->countItems;
		} else {
			rslt = false;
		}
		if(lock) {
			this->unlock();
		}
		return(rslt);
	}
	typeItem* push_get_pointer() {
		typeItem *item = NULL;
		if(this->countItems < this->length) {
			item = &this->buffer[(this->startIndex + this->countItems) % this->length];
			++this->countItems;
		} else {
			if(this->inc_length && 
			   (!this->limit_length || (this->length + this->inc_length) < this->limit_length)) {
				this->incBuffer();
				item = &this->buffer[(this->startIndex + this->countItems) % this->length];
				++this->countItems;
			}
		}
		return(item);
	}
	typeItem pop(bool lock = false) {
		typeItem item;
		if(lock) {
			this->lock();
		}
		if(this->countItems) {
			item = this->buffer[this->startIndex];
			if(this->binaryBuffer && this->clearAtPop) {
				memset(&this->buffer[this->startIndex], 0, sizeof(typeItem));
			}
			++this->startIndex;
			--this->countItems;
			if(this->startIndex >= this->length) {
				this->startIndex = 0;
			}
		} else {
			if(this->binaryBuffer && this->clearAtPop) {
				memset(&item, 0, sizeof(item));
			}
		}
		if(lock) {
			this->unlock();
		}
		return(item);
	}
	bool pop(typeItem *item,bool lock = false) {
		bool rslt = true;
		if(lock) {
			this->lock();
		}
		if(this->countItems) {
			if(this->binaryBuffer) {
				memcpy(item, &this->buffer[this->startIndex], sizeof(typeItem));
			} else {
				*item = this->buffer[this->startIndex];
			}
			if(this->binaryBuffer && this->clearAtPop) {
				memset(&this->buffer[this->startIndex], 0, sizeof(typeItem));
			}
			++this->startIndex;
			--this->countItems;
			if(this->startIndex >= this->length) {
				this->startIndex = 0;
			}
		} else {
			if(this->binaryBuffer && this->clearAtPop) {
				memset(&item, 0, sizeof(item));
			}
			rslt = false;
		}
		if(lock) {
			this->unlock();
		}
		return(rslt);
	}
	typeItem* pop_get_pointer() {
		if(this->countItems) {
			typeItem* item = &this->buffer[this->startIndex];
			++this->startIndex;
			--this->countItems;
			if(this->startIndex >= this->length) {
				this->startIndex = 0;
			}
			return(item);
		}
		return(NULL);
	}
	size_t size() {
		return(this->countItems);
	}
	void incBuffer();
	void printBuffer();
	void lock() {
		while(__sync_lock_test_and_set(&this->_sync_lock, 1));
	}
	void unlock() {
		__sync_lock_release(&this->_sync_lock);
	}
	void _test();
	void _testPerf(bool useRqueue);
	void setName(const char *name) {
		this->name = name;
	}
private:
	typeItem *buffer;
	size_t length;
	size_t inc_length;
	size_t limit_length;
	bool binaryBuffer;
	bool clearBuff;
	bool clearAtPop;
	size_t startIndex;
	size_t countItems;
	volatile int _sync_lock;
	std::string name;
};


template <class typeItem>
void rqueue<typeItem>::incBuffer() {
	size_t newLength = this->length + this->inc_length;
	syslog(LOG_NOTICE, "increase size of rqueue %s from %lu to %lu", name.c_str(), this->length, newLength);
	typeItem *newBuffer = new typeItem[newLength];
	if(this->binaryBuffer) {
		if(this->clearBuff) {
			memset(newBuffer, 0, newLength * sizeof(typeItem));
		}
		if(this->countItems) {
			if(this->startIndex + this->countItems <= this->length) {
				memcpy(newBuffer, this->buffer + this->startIndex, 
					this->countItems * sizeof(typeItem));
			} else {
				memcpy(newBuffer, this->buffer + this->startIndex, 
					(this->length - this->startIndex) * sizeof(typeItem));
				memcpy(newBuffer + (this->length - this->startIndex), this->buffer,
					(this->countItems - (this->length - this->startIndex)) * sizeof(typeItem));
			}
		}
	} else {
		if(this->countItems) {
			if(this->startIndex + this->countItems <= this->length) {
				for(size_t i = 0; i < this->countItems; i++) {
					newBuffer[i] = this->buffer[i + this->startIndex];
				}
			} else {
				for(size_t i = 0; i < this->length - this->startIndex; i++) {
					newBuffer[i] = this->buffer[i + this->startIndex];
				}
				for(size_t i = 0; i < this->countItems - (this->length - this->startIndex); i++) {
					newBuffer[i + (this->length - this->startIndex)] = this->buffer[i];
				}
			}
		}
	}
	if(this->buffer) {
		delete [] this->buffer;
	}
	this->buffer = newBuffer;
	this->length = newLength;
	this->startIndex = 0;
}

template <class typeItem>
void rqueue<typeItem>::printBuffer() {
	for(size_t i = 0; i < this->length; i++) {
		if(i == this->startIndex) {
			std::cout << "S|";
		}
		if(i == (this->startIndex + this->countItems) % this->length) {
			std::cout << "<E|";
		}
		std::cout << this->buffer[i];
		std::cout << "; ";
	}
	std::cout << std::endl;
}


#include <queue>
#include <deque>

struct s_rqueue_testStruct {
	s_rqueue_testStruct(int i = 0) {
		this->i = i;
	};
	int i;
	char a[1000];
};

template <class typeItem>
void rqueue<typeItem>::_test() {
	bool usePointer = true;
	bool printRing = false;
	int testItem = 0;
	rqueue<int> testRing1(10, 10, false);
	std::queue<int> testQueue;
	for(int pass = 0; pass < 400; pass ++) {
		for(int i = 1; i <= 12 + pass * 5; i++) {
			if(usePointer) {
				*testRing1.push_get_pointer() = ++testItem;
			} else {
				testRing1.push(++testItem);
			}
			testQueue.push(testItem);
		}
		if(printRing) testRing1.printBuffer();
		for(int i = 1; i <= 5; i++) {
			if(usePointer) {
				testRing1.pop_get_pointer();
			} else {
				testRing1.pop();
			}
			testQueue.pop();
		}
		if(printRing) testRing1.printBuffer();
		for(int i = 1; i <= 3; i++) {
			if(usePointer) {
				*testRing1.push_get_pointer() = ++testItem;
			} else {
				testRing1.push(++testItem);
			}
			testQueue.push(testItem);
		}
		if(printRing) testRing1.printBuffer();
		for(int i = 1; i <= 10; i++) {
			if(usePointer) {
				testRing1.pop_get_pointer();
			} else {
				testRing1.pop();
			}
			testQueue.pop();
		}
		if(printRing) { testRing1.printBuffer(); std::cout << std::endl; }
		
	}
	std::cout << testRing1.size() << std::endl;
	if(testRing1.size() != testQueue.size()) {
		std::cout << "BAD SIZE !!!" << std::endl;
		exit(1);
	}
	int i;
	while(testRing1.size()) {
		if((i=testRing1.pop()) != testQueue.front()) {
			std::cout << "BAD CONTENT !!!" << std::endl;
			std::cout << i << std::endl;
			std::cout << testQueue.front() << std::endl;
			exit(1);
		}
		testQueue.pop();
	}
	std::cout << "OK" << std::endl;
}

template <class typeItem>
void rqueue<typeItem>::_testPerf(bool useRqueue) {
	if(useRqueue) {
		bool usePointer = true;
		s_rqueue_testStruct s;
		rqueue<s_rqueue_testStruct> testRing1(100*1000, 100*1000, false);
		for(int pass = 0; pass < 1000; pass++) {
			for(int i = 0; i < 100*1000; i++) {
				if(usePointer) {
					testRing1.lock();
					testRing1.push_get_pointer()->i = i;
					testRing1.unlock();
				} else {
					testRing1.push(i);
				}
			}
			for(int i = 0; i < 100*1000; i++) {
				if(usePointer) {
					testRing1.lock();
					testRing1.pop_get_pointer();
					testRing1.unlock();
				} else {
					testRing1.pop();
				}
			}
		}
	} else {
		s_rqueue_testStruct s;
		std::deque<s_rqueue_testStruct> testQueue;
		for(int pass = 0; pass < 1000; pass++) {
			for(int i = 0; i < 100*1000; i++) {
				testQueue.push_back(i);
			}
			for(int i = 0; i < 100*1000; i++) {
				s = testQueue.front();
				testQueue.pop_front();
			}
		}
	}
}



typedef volatile int v_int;
typedef volatile u_int32_t v_u_int32_t;

template<class typeItem>
class rqueue_quick {
public:
	rqueue_quick(size_t length,
		     unsigned int pushUsleep, unsigned int popUsleep,
		     int *terminating = NULL,
		     bool binaryBuffer = true) {
		this->length = length;
		this->pushUsleep = pushUsleep;
		this->popUsleep = popUsleep;
		this->terminating = terminating;
		this->binaryBuffer = binaryBuffer;
		buffer = new typeItem[this->length + 1];
		free = new v_int[this->length + 1];
		for(size_t i = 0; i < this->length; i++) {
			free[i] = 1;
		}
		readit = 0;
		writeit = 0;
	}
	~rqueue_quick() {
		delete [] buffer;
		delete [] free;
	}
	bool push(typeItem *item, bool waitForFree) {
		while(free[writeit] == 0) {
			if(waitForFree) {
				if(terminating && *terminating) {
					return(false);
				}
				usleep(pushUsleep);
			} else {
				return(false);
			}
		}
		if(binaryBuffer) {
			memcpy(&buffer[writeit], item, sizeof(typeItem));
		} else {
			buffer[writeit] = *item;
		}
		free[writeit] = 0;
		if((writeit + 1) == length) {
			writeit = 0;
		} else {
			writeit++;
		}
		return(true);
	}
	bool pop(typeItem *item, bool waitForFree) {
		while(free[readit] == 1) {
			if(waitForFree) {
				if(terminating && *terminating) {
					return(false);
				}
				usleep(popUsleep);
			} else {
				return(false);
			}
		}
		if(binaryBuffer) {
			memcpy(item, &buffer[readit], sizeof(typeItem));
		} else {
			*item = buffer[readit];
		}
		free[readit] = 1;
		if((readit + 1) == length) {
			readit = 0;
		} else {
			readit++;
		}
		return(true);
	}
	size_t size() {
		return(writeit >= readit ? writeit - readit : writeit + length - readit);
	}
private:
	size_t length;
	bool binaryBuffer;
	unsigned int pushUsleep;
	unsigned int popUsleep;
	int *terminating;
	typeItem *buffer;
	v_int *free;
	v_u_int32_t readit;
	v_u_int32_t writeit;
};


#ifdef HAVE_LIBBOOST
template<class typeItem>
class rqueue_quick_boost {
public:
	rqueue_quick_boost(unsigned int pushUsleep, unsigned int popUsleep,
			   int *terminating = NULL) {
		this->pushUsleep = pushUsleep;
		this->popUsleep = popUsleep;
		this->terminating = terminating;
	}
	bool push(typeItem *item, bool waitForFree) {
		while(!spsc_queue.push(*item)) {
			if(waitForFree) {
				if(terminating && *terminating) {
					return(false);
				}
				usleep(pushUsleep);
			} else {
				return(false);
			}
		}
		return(true);
	}
	bool pop(typeItem *item, bool waitForFree) {
		while(!spsc_queue.pop(*item)) {
			if(waitForFree) {
				if(terminating && *terminating) {
					return(false);
				}
				usleep(popUsleep);
			} else {
				return(false);
			}
		}
		return(true);
	}
private:
	boost::lockfree::spsc_queue<typeItem, boost::lockfree::capacity<20000> > spsc_queue;
	unsigned int pushUsleep;
	unsigned int popUsleep;
	int *terminating;
};
#else
template<class typeItem>
class rqueue_quick_boost : public rqueue_quick<typeItem> {
public:
	rqueue_quick_boost(unsigned int pushUsleep, unsigned int popUsleep,
			   int *terminating = NULL) 
	 : rqueue_quick<typeItem>(20000,
				  pushUsleep, popUsleep,
				  terminating,
				  true) {
	}
};
#endif


#endif

