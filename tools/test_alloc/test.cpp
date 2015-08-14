#include <stdlib.h>


void test_alloc_speed() {
	unsigned ii = 1000000;
	for(int p = 0; p < 10; p++) {
		char **pointers = new char*[ii];
		for(unsigned i = 0; i < ii; i++) {
			pointers[i] = (char*)malloc(1000);
		}
		for(unsigned i = 0; i < ii; i++) {
			free(pointers[i]);
		}
		delete pointers;
	}
}


/*
extern "C" {
void* tc_malloc(size_t size);
void tc_free(void*);
}
void test_alloc_speed_tc() {
	unsigned ii = 1000000;
	for(int p = 0; p < 10; p++) {
		char **pointers = new char*[ii];
		for(unsigned i = 0; i < ii; i++) {
			pointers[i] = (char*)tc_malloc(1000);
		}
		for(unsigned i = 0; i < ii; i++) {
			tc_free(pointers[i]);
		}
		delete pointers;
	}
}
*/


int main() {
	test_alloc_speed();
	return(1);
}
