#ifndef MANAGER_H
#define MANAGER_H

#include <string>
#include <vector>
#include <queue>

void *manager_client(void *dummy);
void *manager_server(void *dummy);

class ManagerClientThread {
public:
	ManagerClientThread(int client, const char *type, const char *command, int commandLength = 0);
	void run();
	bool isFinished() { return(finished); }
	virtual bool parseCommand() = 0;
	virtual void onCall(int sipResponseNum, const char *callerName, const char *callerNum, const char *calledNum,
			    unsigned int sipSaddr, unsigned int sipDaddr) {}
protected:
	void lock_responses() {
		while(__sync_lock_test_and_set(&this->_sync_responses, 1));
	}
	void unlock_responses() {
		__sync_lock_release(&this->_sync_responses);
	}
protected:
	int client;
	string type;
	string command;
	bool finished;
	std::queue<string> responses;
private:
	volatile int _sync_responses;
};

class ManagerClientThread_screen_popup : public ManagerClientThread {
public:
	ManagerClientThread_screen_popup(int client, const char *command, int commandLength = 0);
	bool parseCommand();
	void onCall(int sipResponseNum, const char *callerName, const char *callerNum, const char *calledNum,
		    unsigned int sipSaddr, unsigned int sipDaddr);
private:
	bool parseUserPassword();
	bool isNumericId(const char *id);
private:
	string username;
	string name;
	string profile_name;
	bool auto_popup;
	bool show_ip;
	string popup_on;
	bool non_numeric_caller_id;
	string regex_calling_number;
	string app_launch;
	string app_launch_args_or_url;
};

class ManagerClientThreads {
public:
	ManagerClientThreads();
	void add(ManagerClientThread *clientThread);
	void onCall(int sipResponseNum, const char *callerName, const char *callerNum, const char *calledNum,
		    unsigned int sipSaddr, unsigned int sipDaddr);
	void cleanup();
	int getCount();
private:
	void lock_client_threads() {
		while(__sync_lock_test_and_set(&this->_sync_client_threads, 1));
	}
	void unlock_client_threads() {
		__sync_lock_release(&this->_sync_client_threads);
	}
private: 
	std::vector<ManagerClientThread*> clientThreads;
	volatile int _sync_client_threads;
};

#endif
