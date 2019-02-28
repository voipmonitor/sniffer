#ifndef TOOLS_DEFINE_H
#define TOOLS_DEFINE_H


#if ( defined( __FreeBSD__ ) || defined ( __NetBSD__ ) )
# ifndef FREEBSD
#  define FREEBSD
# endif
#else
# ifndef NO_FREEBSD
#  define NO_FREEBSD
# endif
#endif


#endif
