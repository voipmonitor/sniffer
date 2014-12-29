#ifndef TOOLS_DYNAMIC_BUFFER_H
#define TOOLS_DYNAMIC_BUFFER_H

#include <string.h>
#include <string>
#include <iostream>
#include <sys/types.h>
#include <algorithm>

class DynamicBuffer {
public:
	class DynamicBufferItem {
	public:
		DynamicBufferItem(DynamicBuffer *owner, u_int32_t length = 0) {
			this->owner = owner;
			this->buffer_length = this->getBufferLength(length);
			if(this->buffer_length) {
				this->buffer = new u_char[this->buffer_length];
			} else {
				this->buffer = NULL;
			}
			this->length = 0;
			this->next = NULL;
		}
		DynamicBufferItem *add(u_char *buffer, u_int32_t length, u_int32_t offset = 0) {
			if(offset >= length) {
				return(this);
			}
			if(!this->buffer) {
				this->buffer_length = this->getBufferLength(length - offset);
				this->buffer = new u_char[this->buffer_length];
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
				this->next = new DynamicBufferItem(this->owner, length - offset);
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
		DynamicBufferItem *next;
		DynamicBuffer *owner;
	};
public:
	DynamicBuffer() {
		this->first = NULL;
		this->last = NULL;
		this->min_item_buffer_length = 0;
		this->max_item_buffer_length = 0;
	}
	~DynamicBuffer() {
		this->free();
	}
	void add(u_char *buffer, u_int32_t length) {
		if(!length) {
			return;
		}
		if(!this->first) {
			this->first = new DynamicBufferItem(this, length);
			this->last = this->first;
		}
		this->last = this->last->add(buffer, length);
	}
	void free() {
		DynamicBufferItem *iter[2] = { this->first, NULL };
		while(iter[0]) {
			iter[1] = iter[0]->next;
			delete iter[0];
			iter[0] = iter[1];
		}
		this->first = NULL;
		this->last = NULL;
	}
	u_int32_t getSize() {
		u_int32_t size = 0;
		DynamicBufferItem *iter = this->first;
		while(iter) {
			size += iter->length;
			iter = iter->next;
		}
		return(size);
	}
	bool isEmpty() {
		return(!this->first);
	}
	void setMinItemBufferLength(u_int32_t min_item_buffer_length) {
		this->min_item_buffer_length = min_item_buffer_length;
	}
	void setMaxItemBufferLength(u_int32_t max_item_buffer_length) {
		this->max_item_buffer_length = max_item_buffer_length;
	}
	void cout(bool itemSeparator = false);
	u_char *getConcatBuffer();
	virtual void write(const char *fileName, int time) {}
private:
	DynamicBufferItem *first;
	DynamicBufferItem *last;
	u_int32_t min_item_buffer_length;
	u_int32_t max_item_buffer_length;
friend class DynamicBufferItem;
};

class DynamicBufferTar : public DynamicBuffer {
public:
	virtual void write(const char *fileName, int time);
};

#endif