#include <iostream>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <unistd.h>
#include <string>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>

#include "voipmonitor.h"
#include "format_slinear.h"
#include "codec_alaw.h"
#include "tools.h"
#include "calltable.h"

#define BUFSIZE 1024

extern Calltable *calltable;
extern int opt_manager_port;
extern int calls;

using namespace std;

struct listening_worker_arg {
	Call *call;
	int fifo1r,fifo2r,fifoout;
};


/* 
 * this function runs as thread. It reads RTP audio data from call
 * and write it to output fifo. once output fifo is closed or is not 
 * opened, function will terminate. 
 *
 * input parameter is structure where call and fifo file descriptors
 * are provided
 *
*/
void *listening_worker(void *arguments) {
	struct listening_worker_arg *args = (struct listening_worker_arg*)arguments;

        int ret, ret1, ret2;
        unsigned char read1[1024];
        unsigned char read2[1024];
        struct timeval tv;
        int diff;

	int cfifo1 = args->call->fifo1;
	int cfifo2 = args->call->fifo2;

	getUpdDifTime(&tv);
	alaw_init();

        struct timeval tvwait;
        fd_set rfds;
	//printf("fd[%d]\n", args->call->fifo1);

	short int r1;
	short int r2;

	// if call is hanged hup it will set listening_worker_run in its destructor to 0
	int listening_worker_run = 1;
	int timeoutms = 2000;
	args->call->listening_worker_run = &listening_worker_run;

//	FILE *out = fopen("/tmp/test.raw", "w");
//	FILE *outa = fopen("/tmp/test.alaw", "w");

        while(1 && listening_worker_run) {
		tvwait.tv_sec = 0;
		tvwait.tv_usec = 1000*20; //20 ms
		FD_ZERO(&rfds);
		FD_SET(args->fifo2r, &rfds);
		ret = select(args->fifo2r + 1,&rfds, NULL, NULL, &tvwait);
                if (ret > 0) {
                        //reading
                        ret1 = read(args->fifo1r, read1, 160);
                        ret2 = read(args->fifo2r, read2, 160);
/*			if(ret == -1) {
				printf( "Error: %s\n", strerror( errno ) );
			//	break;
			}
*/
                        usleep(tvwait.tv_usec);
			diff = getUpdDifTime(&tv) / 1000;
			for(int i = 0; i < ret1; i++) {
				r1 = ALAW(read1[i]);
				r2 = ALAW(read2[i]);
				// mix r1+r2  => r1
	                        slinear_saturated_add((short int*)&r1, (short int*)&r2);
				ret2 = write(args->fifoout, &r1, 2); // .sln data 
				//fwrite(&r1, 1, 2, out);
			}
			if(ret2 == -1) {
				timeoutms -= 20;
				if(timeoutms <= 0) {
					// writing pipe were closed, stop
					break;
				}
			} else {
				timeoutms = 2000;
			}
                        //printf("diff [%d] [%d] reading [%d] ret2[%d:%d]\n", diff, (unsigned int)tvwait.tv_usec, ret, ret2, args->fifoout);
                } else if (ret == 0) {
                        //timeout
                        //printf("diff [%d] timeout\n", diff);
			// write 20ms silence 
			int16_t s = 0;
			//unsigned char sa = 255;
			for(int i = 0; i < 160; i++) {
				ret2 = write(args->fifoout, &s, 2);
				//fwrite(&s, 1, 2, out);
			}
			if(ret2 == -1) {
				timeoutms -= 20;
				// writing pipe were closed or not opened yet, stop after some time
				if(timeoutms <= 0) {
					//printf("writing pipe were closed, stop\n");
					break;
				}
			} else {
				timeoutms = 2000;
			}
                } else {
                        //error
                        //printf("diff [%d] error\n", diff);
			break;
                }
		
        }
	if(args->fifo1r)
		close(args->fifo1r);
	if(args->fifo2r)
		close(args->fifo2r);
	if(args->fifoout)
		close(args->fifoout);
	if(cfifo1)
		close(cfifo1);
	if(cfifo2)
		close(cfifo2);
	
	args->call->fifo1 = 0;
	args->call->fifo2 = 0;

	free(args);

	return 0;
}

void *manager_server(void *dummy) {
	sockaddr_in sockName;
	sockaddr_in clientInfo;
	int mainSocket;
	char buf[BUFSIZE];
	char sendbuf[BUFSIZE];
	int size;
	socklen_t addrlen;

	// Vytvorime soket - viz minuly dil
	if ((mainSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		cerr << "Cannot create manager tcp socket" << endl;
		return 0;
	}
	sockName.sin_family = AF_INET;
	sockName.sin_port = htons(opt_manager_port);
	sockName.sin_addr.s_addr = INADDR_ANY;
	if (bind(mainSocket, (sockaddr *)&sockName, sizeof(sockName)) == -1) {
		cerr << "Cannot bind manager to port " << opt_manager_port << endl;
		return 0;
	}
	// create queue with 100 connections max 
	if (listen(mainSocket, 100) == -1) {
		cerr << "Cannot create manager queue" << endl;
		return 0;
	}
	while(1) {
		addrlen = sizeof(clientInfo);
		int client = accept(mainSocket, (sockaddr*)&clientInfo, &addrlen);
		if (client == -1) {
			cerr << "Problem with accept client" <<endl;
			return 0;
		}
		//cout << "New manager connect from: " << inet_ntoa((in_addr)clientInfo.sin_addr) << endl;
		if ((size = recv(client, buf, BUFSIZE - 1, 0)) == -1) {
			cerr << "Error in receiving data" << endl;
			close(client);
			continue;
		}

		if(strstr(buf, "totalcalls") != NULL) {
			snprintf(sendbuf, BUFSIZE, "%d", calls);
			if ((size = send(client, sendbuf, sizeof(sendbuf), 0)) == -1){
				cerr << "Error sending data to client" << endl;
				close(client);
				continue;
			}
		} else if(strstr(buf, "listcalls") != NULL) {
			list<Call*>::iterator call;
			char *outbuf = (char*)malloc(1024*200*sizeof(char));
			if(outbuf == NULL) {
				syslog(LOG_NOTICE,"Cannot allocate memory\n");
				continue;
			}
			/* headers */
			sprintf(outbuf, "[[\"callreference\", \"callid\", \"callercodec\", \"calledcodec\", \"caller\", \"callername\", \"called\", \"calldate\", \"duration\", \"callerip\", \"calledip\"]");
			for (call = calltable->calls_list.begin(); call != calltable->calls_list.end(); ++call) {
				/* 
				 * caller 
				 * callername
				 * called
				 * calldate
				 * duration
				 * callerip htonl(sipcallerip)
				 * sipcalledip htonl(sipcalledip)
				*/
				//XXX: escape " or replace it to '
				sprintf(outbuf + strlen(outbuf), ",[\"%p\", \"%s\", \"%d\", \"%d\", \"%s\", \"%s\", \"%s\", \"%d\", \"%d\", \"%u\", \"%u\"]",
					*call, (*call)->call_id, (*call)->last_callercodec, (*call)->last_callercodec, (*call)->caller, 
					(*call)->callername, (*call)->called, (*call)->calltime(), (*call)->duration(), htonl((*call)->sipcallerip), 
					htonl((*call)->sipcalledip));
			}
			sprintf(outbuf + strlen(outbuf), "]");
			if ((size = send(client, outbuf, strlen(outbuf), 0)) == -1){
				cerr << "Error sending data to client" << endl;
				free(outbuf);
				close(client);
				continue;
			}
			free(outbuf);
			close(client);
			continue;
		/* listen callreference fifo */
		} else if(strstr(buf, "listen") != NULL) {
			char fifo[1024];
			char fifo1[1024];
			char fifo2[1024];
			char fifo3[1024];
			void *callreference;
			sscanf(buf, "listen %p %s", &callreference, fifo);
			//printf("listen %u %s\n", callreference, fifo);
			sprintf(fifo1, "%s.0", fifo);
			sprintf(fifo2, "%s.1", fifo);
			sprintf(fifo3, "%s.out", fifo);
			list<Call*>::iterator call;
			//XXX MUTEX!
			for (call = calltable->calls_list.begin(); call != calltable->calls_list.end(); ++call) {
				if(*call == callreference) {
					//cerr << "founded" << endl;
					//TODO handle returned values
					struct listening_worker_arg *args = (struct listening_worker_arg*)malloc(sizeof(listening_worker_arg));
					args->call = *call;
					umask(0000);
					mkfifo(fifo1, S_IWUSR | S_IRUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
					mkfifo(fifo2, S_IWUSR | S_IRUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
					args->fifo1r = open(fifo1, O_RDONLY | O_NONBLOCK);
					args->fifo2r = open(fifo2, O_RDONLY | O_NONBLOCK);
					args->fifoout = open(fifo3, O_WRONLY | O_NONBLOCK);

					(*call)->fifo1 = open(fifo1, O_WRONLY | O_NONBLOCK);
					(*call)->fifo2 = open(fifo2, O_WRONLY | O_NONBLOCK);

					pthread_t call_thread;
					pthread_create(&call_thread, NULL, listening_worker, (void *)args);
					continue;
				}
			}
			if ((size = send(client, "call not found", 14, 0)) == -1){
				cerr << "Error sending data to client" << endl;
				close(client);
				continue;
			}
			close(client);
			continue;
		} else if(strstr(buf, "reload") != NULL) {
			reload_config();
			if ((size = send(client, "reload ok", 9, 0)) == -1){
				cerr << "Error sending data to client" << endl;
				close(client);
				continue;
			}
			close(client);
			continue;
		} else if(strstr(buf, "quit") != NULL) {
			close(client);
			continue;
		} else {
			// Odeslu pozdrav
			if ((size = send(client, "command not found\n", 18, 0)) == -1){
				cerr << "Error sending data to client" << endl;
				close(client);
				continue;
			}
		}
		close(client);
	}
	close(mainSocket);
	return 0;
}
