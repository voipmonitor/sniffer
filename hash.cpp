/* taken from libnids */

#include <sys/types.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

static u_char xor1[12];
static u_char perm[12];
static void
getrnd ()
{
	struct timeval s;
	u_int *ptr;
	int fd = open ("/dev/urandom", O_RDONLY);
	if (fd > 0)
		{
			read (fd, xor1, 12);
			read (fd, perm, 12);
			close (fd);
			return;
		}

	gettimeofday (&s, 0);
	srand (s.tv_usec);
	ptr = (u_int *) xor1;
	*ptr = rand ();
	*(ptr + 1) = rand ();
	*(ptr + 2) = rand ();
	ptr = (u_int *) perm;
	*ptr = rand ();
	*(ptr + 1) = rand ();
	*(ptr + 2) = rand ();


}
void
init_hash ()
{
	int i, n, j;
	int p[12];
	getrnd ();
	for (i = 0; i < 12; i++)
		p[i] = i;
	for (i = 0; i < 12; i++)
		{
			n = perm[i] % (12 - i);
			perm[i] = p[n];
			for (j = 0; j < 11 - n; j++)
				p[n + j] = p[n + j + 1];
		}
}

u_int
mkhash (u_int src, u_short sport, u_int dest, u_short dport)
{
	u_int res = 0;
	int i;
	u_char data[12];
	u_int *stupid_strict_aliasing_warnings=(u_int*)data;
	*stupid_strict_aliasing_warnings = src;
	*(u_int *) (data + 4) = dest;
	*(u_short *) (data + 8) = sport;
	*(u_short *) (data + 10) = dport;
	for (i = 0; i < 12; i++)
		res = ( (res << 8) + (data[perm[i]] ^ xor1[i])) % 0xff100f;
	return res;
}

