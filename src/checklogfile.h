#pragma once
#include "Database\src\sqlite3.h"
#include <iostream>
#include <deque>
#include <string>
#include <set>
#include <functional>
using namespace std;

#define FLAG_NORMAL_LOG 0
#define FLAG_PORT_SCAN 1
#define FLAG_SERVICE_ENUMERATION 2
#define FLAG_MS_FRONTPAGE_SERVER_EXTENSION_BUFFER_OVERFLOW 3
#define FLAG_MS_MESSAENGER_HEAP_OVERFLOW 4
#define FLAG_LSASS_RPC_BUFFER_OVERFLOW 5
#define FLAG_IPSWITCH_IMAIL_LDAP 6
#define FLAG_WINDOWS_NT_RETURN_INTO_LIBC 7
#define FLAG_WINDOWS_WORKSTATION_SERVICE_WKSSVC_LIBC 8
#define FLAG_MSMQ_HEAP_OVERFLOW 9
#define FLAG_PROFTPD_FILE_REMOTE_ROOT_EXPLOIT 10
#define FLAG_WFTPD_STAT_COMMAND_REMOTE_EXPLOIT 12
#define FLAG_PHATBOT_AGOBOT_GAOBOT_WORM 13
#define FLAG_DAMWARE_PROBE 14
#define FLAG_DOOMJUICE_WORM 15
#define FLAG_USER_DEFINED_RULE 100

#define NO_ERROR_CHECKPOINT 0
#define NO_INPUT_LINE_DATA -1
#define NO_INPUT_QUERY_DATE_DATA -2
#define NOT_OPEN_DATABASE -3
#define NO_INPUT_DATABASE_HANDLE -4

typedef struct {
	int displacement_value;
	string action;
	string protocol;
	string srcip;
	string dstip;
	string srcport;
	string dstport;
	string content_suspicious;
} user_rule_info;

class GetErrorMessage_CheckPoint 
{
private:
	string message_error;
	bool exist_error;

public:
	GetErrorMessage_CheckPoint();
	virtual ~GetErrorMessage_CheckPoint();
	void set_errorflag(const int &flag_input);
	bool is_exist_error() { return exist_error; };
	string get_message_error();
};

class CheckPoint_Line : public GetErrorMessage_CheckPoint
{
private:
	int data_line;
	int data_line_pattern3, data_line_pattern5;
	int flag_line_suspiciouspoint;
	int flag_error_checkpoint_line;
	bool flag_data_input;
	bool flag_start_pattern3, flag_start_pattern5;	
	bool flag_end_pattern3, flag_end_pattern5;
	string data_srcip, data_dstip, data_srcport, data_dstport;
	string data_srcip_pattern3, data_srcip_pattern5;
	string data_dstip_pattern3, data_dstip_paatern5;

	void data_clear();
public:
	CheckPoint_Line();
	~CheckPoint_Line();

	void set_logline_data(int line, deque<string> &input_data);
	int process_checkpoint_line();
	int process_checkpoint_line_pass1();	// Imeediately Check Pattern 9, 14.
	int process_checkpoint_line_pass2();	// Check Pattern 3, 5.
	int check_pass2_loginfo();
	void insert_suspiciousinfo_in_database(sqlite3 *handle_input);
	string output_message_error() { 
		set_errorflag(flag_error_checkpoint_line);
		if (is_exist_error()) {
			return get_message_error();
		}
		else {
			return NULL;
		}
	};
};

class CheckPoint_Query : public GetErrorMessage_CheckPoint
{
private:
	int flag_query_suspiciouspoint;
	int flag_error_checkpoint_query;
	bool flag_input_date;
	string name_database;
	string date_database;
	deque<string> data_find_line;
	deque<int> data_find_suspicious_info;
	sqlite3* handle_database;

	void insert_suspiciousinfo_in_database(sqlite3* handle_database);
public:
	CheckPoint_Query();
	~CheckPoint_Query();

	void process_get_checkpoint(sqlite3* handle_database); // Check Pattern 4,6,7,8,10,12

	string output_message_error() {
		set_errorflag(flag_error_checkpoint_query);
		if (is_exist_error()) {
			return get_message_error();
		}
		else {
			return NULL;
		}
	};
};

class CheckPoint_Multi_Condition : public GetErrorMessage_CheckPoint
{
private:
	int flag_query_suspiciouspoint;
	int flag_error_CheckPoint_Multi_Condition;
	set<string> data_logrepository;
	pair<set<string>::iterator, bool> check_duplicate;
	deque<string> data_loglocation;

	void insert_suspiciousinfo_in_database(sqlite3* handle_database);
public:
	CheckPoint_Multi_Condition();
	~CheckPoint_Multi_Condition();

	void process_checkpoint_multicondition(sqlite3* handle_database); // Check Pattern 1, 13
	string output_message_error() {
		set_errorflag(flag_error_CheckPoint_Multi_Condition);
		if (is_exist_error()) {
			return get_message_error();
		}
		else {
			return NULL;
		}
	};
};

class CheckPoint_UserDefined : public GetErrorMessage_CheckPoint
{
private:
	int flag_error_CheckPoint_UserDefined;
	user_rule_info information_rule;
	deque<string> data_find_line;

public:
	CheckPoint_UserDefined();
	~CheckPoint_UserDefined();
	void set_checkpoint_userdefined(user_rule_info input);
	void process_checkpoint_userdefined(sqlite3* handle_database);
	string output_message_error() {
		set_errorflag(flag_error_CheckPoint_UserDefined);
		if (is_exist_error()) {
			return get_message_error();
		}
		else {
			return NULL;
		}
	};
};
