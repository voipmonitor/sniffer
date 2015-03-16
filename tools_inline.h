#ifndef TOOLS_INLINE_H
#define TOOLS_INLINE_H


#include <unistd.h>
#include <sys/syscall.h>


inline unsigned int get_unix_tid(void) {
	 int ret = -1;
#ifdef HAVE_PTHREAD_GETTHREADID_NP
	ret = pthread_getthreadid_np();
#elif defined(linux)
	ret = syscall(SYS_gettid);
#elif defined(__sun)
	ret = pthread_self();
#elif defined(__APPLE__)
	ret = mach_thread_self();
	mach_port_deallocate(mach_task_self(), ret);
#elif defined(__NetBSD__)
	ret = _lwp_self();
#elif defined(__FreeBSD__)
	long lwpid;
	thr_self( &lwpid );
	ret = lwpid;
#elif defined(__DragonFly__)
	ret = lwp_gettid();
#endif
	return ret;
}


#endif
