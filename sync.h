#ifndef SYNC_H
#define SYNC_H


#if defined(__x86_64__) || defined(__i386__)
	#define __ASM_PAUSE __asm__ volatile ("pause")
#else
	#define __ASM_PAUSE
#endif

#define __SYNC_LOCK_WHILE(vint) while(__sync_lock_test_and_set(&vint, 1))
#define __SYNC_LOCK_QUICK(vint) while(__sync_lock_test_and_set(&vint, 1));
#define __SYNC_LOCK(vint) while(__sync_lock_test_and_set(&vint, 1)) { __ASM_PAUSE; };
#define __SYNC_LOCK_USLEEP(vint, us_sleep) { if(us_sleep) { unsigned c = 0; while(__sync_lock_test_and_set(&vint, 1)) { USLEEP_C(us_sleep, c++); } } else { __SYNC_LOCK(vint); } }
#define __SYNC_UNLOCK(vint) __sync_lock_release(&vint);

#define __SYNC_NULL(vint) __sync_and_and_fetch(&vint, 0);
#define __SYNC_SET(vint) __sync_add_and_fetch(&vint, 1);
#define __SYNC_SET_TO(vint, to) { __sync_and_and_fetch(&vint, 0); __sync_add_and_fetch(&vint, to); }
#define __SYNC_SET_TO_LOCK(vint, to, lock) { __SYNC_LOCK(lock); __SYNC_SET_TO(vint, to); __SYNC_UNLOCK(lock); }

#define __SYNC_INC(vint) __sync_add_and_fetch(&vint, 1);
#define __SYNC_DEC(vint) __sync_sub_and_fetch(&vint, 1);
#define __SYNC_ADD(vint, add) __sync_add_and_fetch(&vint, add);
#define __SYNC_SUB(vint, sub) __sync_sub_and_fetch(&vint, sub);
#define __SYNC_INCR(vint, length) if((vint + 1) == length) { __SYNC_NULL(vint); } else { __SYNC_INC(vint); }

#if defined __ATOMIC_SEQ_CST
#define SAFE_ATOMIC_LOAD(vint) __atomic_load_n(&vint, __ATOMIC_SEQ_CST)
#else
#define SAFE_ATOMIC_LOAD(vint) (vint)
#endif

#if defined(__arm__) || defined(__aarch64__)
    #define IS_ARM true
#else
    #define IS_ARM false
#endif

#if IS_ARM
#define __SYNC_LOCK_ARM_ONLY(vint)  __SYNC_LOCK(vint)
#define __SYNC_UNLOCK_ARM_ONLY(vint)  __SYNC_UNLOCK(vint)
#define MEMORY_BARRIER_ARM __sync_synchronize()
#else
#define __SYNC_LOCK_ARM_ONLY(vint)
#define __SYNC_UNLOCK_ARM_ONLY(vint)
#define MEMORY_BARRIER_ARM
#endif

#endif //SYNC_H
