#ifndef TOOLS_INLINE_H
#define TOOLS_INLINE_H


#include <unistd.h>
#include <sys/syscall.h>

#ifdef FREEBSD
#include <sys/thr.h>
#endif


inline unsigned int get_unix_tid(void) {
	static __thread int tid = 0;
	if(tid) {
		return tid;
	}
#ifdef HAVE_PTHREAD_GETTHREADID_NP
	tid = pthread_getthreadid_np();
#elif defined(linux)
	tid = syscall(SYS_gettid);
#elif defined(__sun)
	tid = pthread_self();
#elif defined(__APPLE__)
	tid = mach_thread_self();
	mach_port_deallocate(mach_task_self(), tid);
#elif defined(__NetBSD__)
	tid = _lwp_self();
#elif defined(__FreeBSD__)
	long lwpid;
	thr_self( &lwpid );
	tid = lwpid;
#elif defined(__DragonFly__)
	tid = lwp_gettid();
#endif
	return tid;
}


#endif
