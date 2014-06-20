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
#define FLAG_SKIP       (1 << 10)
#define FLAG_NOSKIP     (1 << 11)
#define FLAG_SCRIPT     (1 << 12)
#define FLAG_NOSCRIPT   (1 << 13)
#define FLAG_AMOSLQO    (1 << 14)
#define FLAG_BMOSLQO    (1 << 15)
#define FLAG_ABMOSLQO   (1 << 16)
#define FLAG_NOMOSLQO   (1 << 17)
#define FLAG_HIDEMSG	(1 << 18)
#define FLAG_SHOWMSG	(1 << 19)

#define MAX_PREFIX 64

class IPfilter {
private:
	struct db_row {
		db_row() {
			ip = 0;
			mask = 0;
			direction = 0;
			rtp = 0;
			sip = 0;
			reg = 0;
			graph = 0;
			wav = 0;
			skip = 0;
			mos_lqo = 0;
			script = 0;
			hide_message = 0;
		}
		unsigned int ip;
		int mask;
		int direction;
		int rtp;
		int sip;
		int reg;
		int graph;
		int wav;
		int skip;
		int mos_lqo;
		int script;
		int hide_message;
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
		db_row() {
			memset(prefix, 0, sizeof(prefix));
			direction = 0;
			rtp = 0;
			sip = 0;
			reg = 0;
			graph = 0;
			wav = 0;
			skip = 0;
			mos_lqo = 0;
			script = 0;
			hide_message = 0;
		}
		char prefix[MAX_PREFIX];
		int direction;
		int rtp;
		int sip;
		int reg;
		int graph;
		int wav;
		int skip;
		int mos_lqo;
		int script;
		int hide_message;
	};
	struct t_payload {
		char prefix[MAX_PREFIX];
		int direction;
		unsigned int ip;
		int mask;
		unsigned int flags;
	};
        struct t_node_tel {
                t_node_tel *nodes[256];
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

class DOMAINfilter {
private:
	struct db_row {
		db_row() {
			direction = 0;
			rtp = 0;
			sip = 0;
			reg = 0;
			graph = 0;
			wav = 0;
			skip = 0;
			mos_lqo = 0;
			script = 0;
			hide_message = 0;
		}
		std::string domain;
		int direction;
		int rtp;
		int sip;
		int reg;
		int graph;
		int wav;
		int skip;
		int mos_lqo;
		int script;
		int hide_message;
	};
        struct t_node {
		std::string domain;
		int direction;
		unsigned int flags;
		t_node *next;
	};
	t_node *first_node;
public: 
	DOMAINfilter();
	~DOMAINfilter();

	int count;
	void load();
	void dump();
	int add_call_flags(unsigned int *flags, char *domain_src, char *domain_dst);

};
