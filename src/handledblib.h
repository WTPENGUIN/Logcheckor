#pragma once
#ifndef HANDLEDBLIB_H
#define HANDLEDBLIB_H
#include "Database\src\sqlite3.h"
#include <iostream>
#include <string>
#include <deque>
using namespace std;

#define MAX_PROTOCO_NUMBERING 30
#define MAX_SIZE_IP_DATA 5

#define STATE_NORMAL 0
#define NOT_INPUT_DATABASE_DATE -1
#define EMPTY_DBINFO -2
#define ERROR_NOT_DB_TABLE_CREATE -3
#define ERROR_NOT_OPEN_DATABASE -4
#define ERROR_NOT_INPUT_DATABASE_HANDLE -5
#define ERROR_NOT_COMMIT_NORMALLY -6
#define EMPTY_LOGINFO -7
#define EMPTY_TCPINFO -8
#define EMPTY_ICMPINFO -9
#define EMPTY_WARNINFO -10

class GetErrorMessage_Database
{
private:
	string message_error;
	bool exist_error;

public:
	GetErrorMessage_Database();
	virtual ~GetErrorMessage_Database();
	void set_errorflag(const int &flag_input);
	bool is_exist_error() { return exist_error; };
	string get_message_error();
};

class Set_DBinfo : public GetErrorMessage_Database
{
private:
	int errorflag_setdbinfo;
	string databasename;
	string date_data;

public:
	Set_DBinfo();
	~Set_DBinfo();

	void set_DBdate(string date);
	string get_DBdate();
	string get_DBname();
};

class Manage_DB_Connection : public GetErrorMessage_Database
{
private:
	Set_DBinfo data_DBinfo;
	sqlite3* handle_database;
	int errorflag_manageconnectiondb;
	char *errmsg_create_table;

public:
	Manage_DB_Connection();
	~Manage_DB_Connection();

	void set_dbinfo(Set_DBinfo dbinfo_input);
	sqlite3* get_handle_DBconnection();

	void createdbtable();
	void opendb();
	void closedb();
	void start_db_transaction();
	int end_db_transaction();
};

class Operate_DB
{
private:
	sqlite3_stmt *query_statement_info;
	int errorflag_operatedb;

	string message_error;
	bool exist_error;

public:
	Operate_DB();
	virtual ~Operate_DB();
	void insertdb(sqlite3* handle_input, string query_input);
	void set_errorflag(const int &flag_input);
	bool is_exist_error() { return exist_error; };
	string get_message_error() { return message_error;};
};


class Loginfo_Table : public Operate_DB
{
private:
	Manage_DB_Connection data_DB_connection;
	deque<string> loginfodata;

	const int loginfotable_attribute_amount;
	int errorflag_loginfotbl;
	int size_protocol;
	string insertquery_loginfo;
	string data_log_srcip[MAX_SIZE_IP_DATA], data_log_dstip[MAX_SIZE_IP_DATA];
	int data_amount_srcip[MAX_SIZE_IP_DATA], data_amount_dstip[MAX_SIZE_IP_DATA];

	sqlite3_stmt *query_statement_info;

	void makeinsertquery(deque<string> inputloginfo);
public:
	deque<string> data_log_protocol;
	deque<int> data_amount_protocol;
	string data_numbering[MAX_PROTOCO_NUMBERING];

	Loginfo_Table();
	~Loginfo_Table();

	void setDBconnection(Manage_DB_Connection InputConnection);
	int setloginfo(deque<string> inputloginfo);
	int insertdb_loginfo();
	void calculate_count();

	int get_size_protocol() { return size_protocol; };
	string *get_log_srcip() { return data_log_srcip; };
	string *get_log_dstip() { return data_log_dstip; };
	int *get_amount_srcip() { return data_amount_srcip; };
	int *get_amount_dstip() { return data_amount_dstip; };
	string output_message_error() {
		set_errorflag(errorflag_loginfotbl);
		if (is_exist_error()) {
			return get_message_error();
		}
		else {
			return NULL;
		}
	};
};

class TCPinfo_Table  : public Operate_DB
{
private:
	Manage_DB_Connection data_DB_connection;
	const int tcpinfotable_attribute_amount;
	string insertquery_tcpinfo;
	deque<string> tcpinfodata;
	int errorflag_tcpinfotbl;

	void makeinsertquery(deque<string> inputtcpinfo);

	sqlite3_stmt *query_statement_info;
public:
	TCPinfo_Table();
	~TCPinfo_Table();

	void setDBconnection(Manage_DB_Connection InputConnection);
	int settcpinfo(deque<string> inputtcpinfo);
	int insertdb_tcpinfo();
	string output_message_error() {
		set_errorflag(errorflag_tcpinfotbl);
		if (is_exist_error()) {
			return get_message_error();
		}
		else {
			return NULL;
		}
	};
};

class ICMPinfo_Table : public Operate_DB
{
private:
	Manage_DB_Connection data_DB_connection;
	const int icmpinfotable_attribute_amount;
	string insertquery_icmpinfo;
	deque<string> icmpinfodata;
	int errorflag_icmpinfotbl;

	void makeinsertquery(deque<string>inputicmpinfo);

	sqlite3_stmt *query_statement_info;
public:
	ICMPinfo_Table();
	~ICMPinfo_Table();

	void setDBconnection(Manage_DB_Connection InputConnection);
	int seticmpinfo( deque<string> inputicmpinfo);
	int insertdb_icmpinfo();
	string output_message_error() {
		set_errorflag(errorflag_icmpinfotbl);
		if (is_exist_error()) {
			return get_message_error();
		}
		else {
			return NULL;
		}
	};
};

class Warninfo_Table : public Operate_DB
{
private:
	Manage_DB_Connection data_DB_connection;
	const int warninfotable_attribute_amount;
	string insertquery_warninfo;
	deque<string> warninfodata;
	int errorflag_warninfotbl;

	void makeinsertquery(deque<string> inputwarninfo);

	sqlite3_stmt *query_statement_info;
public:
	Warninfo_Table();
	~Warninfo_Table();

	void setDBconnection(Manage_DB_Connection InputConnection);
	int setwarninfo(deque<string>inputwarninfo);
	int insertdb_warninfo();
	string output_message_error() {
		set_errorflag(errorflag_warninfotbl);
		if (is_exist_error()) {
			return get_message_error();
		}
		else {
			return NULL;
		}
	};
};

#endif // HANDLEDBLIB_H endif.
