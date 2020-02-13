#ifndef TOOLS_FIFO_BUFFER_H
#define TOOLS_FIFO_BUFFER_H


#include <string>

#include "tools.h"
#include "heap_safe.h"


class FifoBuffer {
public:
	class FifoBufferItem {
	public:
		FifoBufferItem(FifoBuffer *owner, u_int32_t length = 0) {
			this->owner = owner;
			this->buffer_length = this->getBufferLength(length);
			if(this->buffer_length) {
				this->buffer = new FILE_LINE(41001) u_char[this->buffer_length];
			} else {
				this->buffer = NULL;
			}
			this->length = 0;
			this->next = NULL;
		}
		~FifoBufferItem() {
			delete [] this->buffer;
		}
		FifoBufferItem *add(u_char *buffer, u_int32_t length, u_int32_t offset = 0) {
			if(offset >= length) {
				return(this);
			}
			if(!this->buffer) {
				this->buffer_length = this->getBufferLength(length - offset);
				this->buffer = new FILE_LINE(41002) u_char[this->buffer_length];
			}
			if(this->length < this->buffer_length) {
				if(length - offset <= this->buffer_length - this->length) {
					memcpy(this->buffer + this->length, buffer + offset, length - offset);
					this->length += length - offset;
					return(this);
				} else {
					memcpy(this->buffer + this->length, buffer + offset, this->buffer_length - this->length);
					offset += this->buffer_length - this->length;
					this->length = this->buffer_length;
				}
			}
			if(!this->next) {
				this->next = new FILE_LINE(41003) FifoBufferItem(this->owner, length - offset);
			}
			return(this->next->add(buffer, length, offset));
		}
		u_int32_t getBufferLength(u_int32_t length) {
			if(owner->min_item_buffer_length && length < owner->min_item_buffer_length) {
				length = owner->min_item_buffer_length;
			}
			if(owner->max_item_buffer_length && owner->max_item_buffer_length > owner->min_item_buffer_length &&
			   length > owner->max_item_buffer_length) {
				length = owner->max_item_buffer_length;
			}
			return(length);
		}
	public:
		u_int32_t buffer_length;
		u_char *buffer;
		u_int32_t length;
		FifoBufferItem *next;
		FifoBuffer *owner;
	};
public:
	FifoBuffer(const char *description = NULL) {
		if(description) {
			this->description = description;
		}
		this->first = NULL;
		this->min_item_buffer_length = 0;
		this->max_item_buffer_length = 0;
		this->max_size = 0;
		this->get_pos = 0;
		this->freed_pos = 0;
		this->disable = false;
		this->_sync = 0;
		this->_sync_master = 0;
		this->lastTimeErrMaxSize = 0;
		this->debug_out_file = NULL;
	}
	virtual ~FifoBuffer() {
		this->free();
		if(this->debug_out_file) {
			fclose(this->debug_out_file);
		}
	}
	bool add(u_char *buffer, u_int32_t size) {
		if(!size) {
			return(false);
		}
		lock();
		if(this->debug_out_file) {
			fwrite(buffer, size, 1, this->debug_out_file);
		}
		if(this->disable) {
			unlock();
			return(false);
		}
		if(this->max_size &&
		   this->size_all(false) + size > this->max_size) {
			u_int64_t actTime = getTimeMS();
			if(actTime - 1000 > this->lastTimeErrMaxSize) {
				syslog(LOG_ERR, "buffer '%s' is full", description.size() ? description.c_str() : "noname");
				this->lastTimeErrMaxSize = actTime;
			}
			unlock();
			return(false);
		}
		if(!this->first) {
			this->first = new FILE_LINE(41004) FifoBufferItem(this, size);
		}
		this->last(false)->add(buffer, size);
		unlock();
		return(true);
	}
	bool push(u_char *buffer, u_int32_t length) {
		return(add(buffer, length));
	}
	u_char *_get(u_int32_t *get_size, u_int32_t get_pos) {
		if(this->disable) {
			*get_size = 0;
			return(NULL);
		}
		u_int32_t all_size = this->_size(false);
		if(!all_size || get_pos > all_size - 1) {
			*get_size = 0;
			return(NULL);
		}
		u_int32_t size = all_size - get_pos;
		if(!*get_size ||
		   size < *get_size) {
			*get_size = size;
		}
		u_char *get_buffer = new FILE_LINE(41005) u_char[*get_size];
		u_int32_t _all_size = 0;
		u_int32_t _get_size = 0;
		FifoBufferItem *iter = this->first;
		while(iter && _get_size < *get_size) {
			if(_all_size + iter->length > get_pos) {
				u_int32_t _offset = _all_size < get_pos ? get_pos - _all_size : 0;
				u_int32_t _length = iter->length - _offset;
				if(_length > *get_size - _get_size) {
					_length = *get_size - _get_size;
				}
				memcpy(get_buffer + _get_size, iter->buffer + _offset, _length);
				_get_size += _length;
			}
			_all_size += iter->length;
			iter = iter->next;
		}
		return(get_buffer);
	}
	u_char *get(u_int32_t *get_size) {
		lock();
		u_char *get_buffer = _get(get_size, this->get_pos);
		if(!get_buffer) {
			return(NULL);
		}
		get_pos += *get_size;
		while(this->first && get_pos > this->first->length) {
			get_pos -= this->first->length;
			FifoBufferItem *deleteItem = this->first;
			this->first = this->first->next;
			delete deleteItem;
		}
		unlock();
		return(get_buffer);
	}
	u_char *pop(u_int32_t *pop_size) {
		return(get(pop_size));
	}
	u_char *get_from_pos(u_int32_t *get_size, u_int32_t get_pos) {
		lock();
		u_char *get_buffer = _get(get_size, get_pos - this->freed_pos);
		if(!get_buffer) {
			unlock();
			return(NULL);
		}
		unlock();
		return(get_buffer);
	}
	void free(bool useLock = true) {
		if(useLock) lock();
		while(this->first) {
			FifoBufferItem *deleteItem = this->first;
			this->first = this->first->next;
			delete deleteItem;
		}
		get_pos = 0;
		freed_pos = 0;
		if(useLock) unlock();
	}
	void free_pos(u_int32_t pos) {
		lock();
		if(pos > freed_pos) {
			pos -= freed_pos;
			while(this->first && pos >= this->first->length) {
				FifoBufferItem *deleteItem = this->first;
				this->first = this->first->next;
				this->freed_pos += deleteItem->length;
				pos -= deleteItem->length;
				delete deleteItem;
			}
		}
		unlock();
	}
	void clean() {
		free();
	}
	void clean_and_disable() {
		lock();
		free(false);
		this->disable = true;
		unlock();
	}
	void enable() {
		lock();
		this->disable = false;
		unlock();
	}
	bool is_enable() {
		return(!this->disable);
	}
	u_int32_t size_all(bool useLock = true) {
		return(this->_size(useLock));
	}
	u_int32_t size_all_with_freed_pos(bool useLock = true) {
		if(useLock) lock();
		u_int32_t size = this->_size(false); 
		size += this->freed_pos;
		if(useLock) unlock();
		return(size);
	}
	u_int32_t size_get(bool useLock = true) {
		if(useLock) lock();
		u_int32_t size = this->_size(false); 
		size -= this->get_pos;
		if(useLock) unlock();
		return(size);
	}
	u_int32_t _size(bool useLock = true) {
		if(useLock) lock();
		u_int32_t size = 0;
		FifoBufferItem *iter = this->first;
		while(iter) {
			size += iter->length;
			iter = iter->next;
		}
		if(useLock) unlock();
		return(size);
	}
	FifoBufferItem *last(bool useLock = true) {
		if(!this->first) {
			return(NULL);
		}
		if(useLock) lock();
		FifoBufferItem *last = this->first;
		while(last->next) {
			last = last->next;
		}
		if(useLock) unlock();
		return(last);
	}
	bool empty() {
		return(!this->first);
	}
	void setMinItemBufferLength(u_int32_t min_item_buffer_length) {
		this->min_item_buffer_length = min_item_buffer_length;
	}
	void setMaxItemBufferLength(u_int32_t max_item_buffer_length) {
		this->max_item_buffer_length = max_item_buffer_length;
	}
	void setMaxSize(u_int32_t max_size) {
		this->max_size = max_size;
	}
	void setDebugOut(const char *debug_out_filename) {
		this->debug_out_filename = debug_out_filename;
		this->debug_out_file = fopen(debug_out_filename, "w");
	}
	void lock() {
		while(__sync_lock_test_and_set(&this->_sync, 1)) USLEEP(20);
	}
	void unlock() {
		__sync_lock_release(&this->_sync);
	}
	void lock_master() {
		while(__sync_lock_test_and_set(&this->_sync_master, 1)) USLEEP(20);
	}
	void unlock_master() {
		__sync_lock_release(&this->_sync_master);
	}
private:
	std::string description;
	FifoBufferItem *first;
	u_int32_t min_item_buffer_length;
	u_int32_t max_item_buffer_length;
	u_int32_t max_size;
	u_int32_t get_pos;
	u_int32_t freed_pos;
	volatile bool disable;
	volatile int _sync;
	volatile int _sync_master;
	u_int64_t lastTimeErrMaxSize;
	std::string debug_out_filename;
	FILE *debug_out_file;
friend class FifoBufferItem;
};


#endif
