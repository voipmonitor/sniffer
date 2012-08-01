#include <mysql++.h>
#include <cstdlib>
#include <iostream>
#include <string>
#include <cmath>
#include <map>
#include <vector>
#include <deque>
#include <deque>


#define FLAG_RTP	(1 << 0)
#define FLAG_NORTP      (1 << 1)
#define FLAG_SIP	(1 << 2)
#define FLAG_NOSIP      (1 << 3)
#define FLAG_REGISTER	(1 << 4)
#define FLAG_NOREGISTER	(1 << 5)
#define FLAG_GRAPH	(1 << 6)
#define FLAG_NOGRAPH    (1 << 7)
#define FLAG_WAV	(1 << 8)
#define FLAG_NOWAV      (1 << 9)

class IPfilter {
private:
	struct db_row {
		unsigned int ip;
		int mask;
		int direction;
		int rtp;
		int sip;
		int reg;
		int graph;
		int wav;
	};
        struct t_node {
		unsigned int ip;
		int mask;
		int direction;
		unsigned int flags;

                t_node *next;
        };
        t_node *first_node;

public: 
        IPfilter();
        ~IPfilter();

	int count;
        void load();
        void dump();
	int add_call_flags(unsigned int *flags, unsigned int saddr, unsigned int daddr);

};

class TELNUMfilter {
private:
	struct db_row {
		unsigned long long prefix;
		int direction;
		int rtp;
		int sip;
		int reg;
		int graph;
		int wav;
	};
	struct t_payload {
		char prefix[32];
		int direction;
		unsigned int ip;
		int mask;
		unsigned int flags;
	};
        struct t_node_tel {
                t_node_tel *nodes[10];
                t_payload *payload;
        };
        t_node_tel *first_node;
public: 
        TELNUMfilter();
        ~TELNUMfilter();

	int count;
        void load();
        void dump(t_node_tel *node = NULL);
	void add_payload(t_payload *payload);
	int add_call_flags(unsigned int *flags, char *telnum_src, char *telnum_dst);
};
