#ifndef MURMUR_HASH_H
#define MURMUR_HASH_H


#define MURMUR_HASH true


void MurmurHash3_x64_128 ( const void * key, const int len,
                           const uint32_t seed, void * out );


#endif //MURMUR_HASH_H
