#include <stdio.h>
#include "rrd_call.h"
#include <locale.h>

int main()
{
	int res;
//	res = rrd_call("update latency_db.rrd --template pl:rtt N:0:15.734");
	res = rrd_call("");
//	printf("Navratova hodnota: %d\n",res);
}

