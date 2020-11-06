#ifndef SYNC_H
#define SYNC_H


#define __SYNC_LOCK(vint) while(__sync_lock_test_and_set(&vint, 1)) {};
#define __SYNC_LOCK_USLEEP(vint, us_sleep) while(__sync_lock_test_and_set(&vint, 1)) { if(us_sleep) { USLEEP(us_sleep); } }
#define __SYNC_UNLOCK(vint) __sync_lock_release(&vint);

#define __SYNC_NULL(vint) __sync_and_and_fetch(&vint, 0);
#define __SYNC_SET(vint) __sync_add_and_fetch(&vint, 1);
#define __SYNC_SET_TO(vint, to) { __sync_and_and_fetch(&vint, 0); __sync_add_and_fetch(&vint, to); }
#define __SYNC_SET_TO_LOCK(vint, to, lock) { __SYNC_LOCK(lock); __SYNC_SET_TO(vint, to); __SYNC_UNLOCK(lock); }

#define __SYNC_INC(vint) __sync_add_and_fetch(&vint, 1);
#define __SYNC_DEC(vint) __sync_sub_and_fetch(&vint, 1);
#define __SYNC_ADD(vint, add) __sync_add_and_fetch(&vint, add);
#define __SYNC_INCR(vint, length) if((vint + 1) == length) { __SYNC_NULL(vint); } else { __SYNC_INC(vint); }


#endif //SYNC_H
