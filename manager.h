#ifndef MANAGER_H
#define MANAGER_H

#include "config.h"
#include <string>
#include <vector>
#include <queue>
#include <sys/socket.h>
#include <sys/un.h>


void *manager_client(void *dummy);
void *manager_server(void *arg);
void *manager_ssh(void *dummy);
int Handle_pause_call(long long callref, int val);


struct sManagerServerArgs {
	sManagerServerArgs() {
		non_block = false;
		timeout = 0;
	}
	string file_socket;
	bool non_block;
	int timeout;
};

struct sManagerClientInfo : public sClientInfo {
	sManagerClientInfo(int handler = 0, vmIP ip = 0, bool file_socket = false)
	: sClientInfo(handler, ip) {
		this->file_socket = file_socket;
	}
	bool file_socket;
};


class ManagerClientThread {
public:
	ManagerClientThread(sClientInfo client, const char *type, const char *command, int commandLength = 0);
	virtual ~ManagerClientThread() {}
	void run();
	bool isFinished() { return(finished); }
	virtual bool parseCommand() = 0;
	virtual void onCall(int /*sipResponseNum*/, const char */*callerName*/, const char */*callerNum*/, const char */*calledNum*/,
			    vmIP /*sipSaddr*/, vmIP /*sipDaddr*/,
			    const char */*screenPopupFieldsString*/) {}
protected:
	void lock_responses() {
		__SYNC_LOCK(this->_sync_responses);
	}
	void unlock_responses() {
		__SYNC_UNLOCK(this->_sync_responses);
	}
protected:
	sClientInfo client;
	string type;
	string command;
	bool finished;
	std::queue<string> responses;
private:
	volatile int _sync_responses;
};

class ManagerClientThread_screen_popup : public ManagerClientThread {
public:
	struct RegexReplace {
		RegexReplace(const char *pattern, const char *replace) {
			this->pattern = pattern;
			this->replace = replace;
		}
		string pattern;
		string replace;
	};
public:
	ManagerClientThread_screen_popup(sClientInfo client, const char *command, int commandLength = 0);
	bool parseCommand();
	void onCall(int sipResponseNum, const char *callerName, const char *callerNum, const char *calledNum,
		    vmIP sipSaddr, vmIP sipDaddr,
		    const char *screenPopupFieldsString);
private:
	bool parseUserPassword();
	bool isNumericId(const char *id);
private:
	string username;
	string name;
	string dest_number;
	bool allow_change_settings;
	string profile_name;
	bool auto_popup;
	bool show_ip;
	string popup_on;
	bool non_numeric_caller_id;
	vector<RegexReplace> regex_replace_calling_number;
	vector<string> regex_check_calling_number;
	ListIP_wb src_ip;
	string app_launch;
	string app_launch_args_or_url;
	string status_line;
	string popup_title;
};

class ManagerClientThreads {
public:
	ManagerClientThreads();
	void add(ManagerClientThread *clientThread);
	void onCall(const char *call_id,
		    int sipResponseNum, const char *callerName, const char *callerNum, const char *calledNum,
		    vmIP sipSaddr, vmIP sipDaddr,
		    const char *screenPopupFieldsString);
	void cleanup();
	int getCount();
private:
	void lock_client_threads() {
		__SYNC_LOCK(this->_sync_client_threads);
	}
	void unlock_client_threads() {
		__SYNC_UNLOCK(this->_sync_client_threads);
	}
private: 
	std::vector<ManagerClientThread*> clientThreads;
	volatile int _sync_client_threads;
};

struct commandAndHelp {
	commandAndHelp(const char *command, const char *help, int notNeedAes = 0) {
		this->command = command;
		this->help = help;
		this->notNeedAes = notNeedAes;
	}
	const char *command;
	const char *help;
	int notNeedAes;
};

class Mgmt_params {
public:
	Mgmt_params(char *ibuf, int isize, sClientInfo iclient, cClient *ic_client, 
		    cAesKey *aes_key, const char *aes_cipher, ManagerClientThread **imanagerClientThread);
	~Mgmt_params();
	int sendString(const char *);
	int sendString(const char *, ssize_t);
	int sendString(string);
	int sendString(string *);
	int sendString(ostringstream *);
	int sendString(int);
	int sendFile(const char *fileName, u_int64_t tailMaxSize = 0);
	int sendConfigurationFile(const char *fileName, list<string> *hidePasswordForOptions = NULL);
	int sendPexecOutput(const char *cmd);
	int _send(const char *, ssize_t);
	int registerCommand(const char *cmd, const char *help, int notNeedAes = false);
	int registerCommand(struct commandAndHelp *);
	enum eTask {
		mgmt_task_na = 0,
		mgmt_task_DoInit = 1 << 0,
		mgmt_task_CheckNeedAes = 1 << 2
	};
	eTask task;
	int (*mgmtFce)(class Mgmt_params *params);
	bool zip;
	string command;
// vars for sendvm
	char *buf;
	int size;
	sClientInfo client;
	cClient *c_client;
	ManagerClientThread **managerClientThread;
	cAesKey aes_key;
	string aes_cipher;
	cAes *aes;
};

class cManagerAes {
public:
	static bool getAesKey(cAesKey *aes_key, bool force = false);
	static bool isAes(SimpleBuffer *buffer);
	static bool existsEnd(SimpleBuffer *buffer, int *endPos);
	static bool decrypt(SimpleBuffer *buffer, string *rslt, cAesKey *aes_key, string *aes_cipher);
	static bool notNeedAesForCommand(char *command, struct sMgmtCmdsReg *mgmtCmd = NULL);
private:
	static cAesKey aes_key;
	static u_int32_t aes_key_at;
};

void listening_master_lock();
void listening_master_unlock();
void listening_cleanup();
void listening_remove_worker(class Call *call);

void manager_parse_command_enable();
void manager_parse_command_disable();

#endif
