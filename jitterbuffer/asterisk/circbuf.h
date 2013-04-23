#ifndef CIRCBUF_H
#define CIRCBUF_H
#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

/* circbuf */
typedef struct {
         size_t beg_index_, end_index_, size_, capacity_;
         char *data_;
} pvt_circbuf;

void circbuf_init(pvt_circbuf *pvt, size_t capacity);
void circbuf_destroy(pvt_circbuf *pvt);

size_t circbuf_size(pvt_circbuf *pvt);
size_t circbuf_capacity(pvt_circbuf *pvt);
// Return number of bytes written.
size_t circbuf_write(pvt_circbuf *pvt, const char *data, size_t bytes);
// Return number of bytes read.
size_t circbuf_read(pvt_circbuf *pvt, char *data, size_t bytes);
/* end */

#if defined(__cplusplus) || defined(c_plusplus)
}
#endif

#endif
