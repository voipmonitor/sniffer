#include <stdlib.h>
#include <string.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "cloud_router.h"


int parse_command(string cmd, int client, cCR_Client_response *cr_client) {
	cr_client->writeEnc((u_char*)"123456789\r\n", 11, "abcd");
	return(1);
}
