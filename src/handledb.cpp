#include "handledblib.h"

GetErrorMessage_Database::GetErrorMessage_Database()
{
	exist_error = false;
}

GetErrorMessage_Database::~GetErrorMessage_Database()
{
	exist_error = false;
	message_error.clear();
}

void GetErrorMessage_Database::set_errorflag(const int &flag_input)
{
	switch (flag_input) {
	case ERROR_NOT_DB_TABLE_CREATE:
		message_error = "Error. Don't create database table.";
		exist_error = true;
		break;
	case ERROR_NOT_OPEN_DATABASE:
		message_error = "Error. Don't open database.";
		exist_error = true;
		break;
	case ERROR_NOT_COMMIT_NORMALLY:
		message_error = "Error. Don't commit query statements in database.";
		exist_error = true;
		break;
	default:
		message_error = "Not exist error. Database handling process normally in program.";
		exist_error = false;
		break;
	}
	return;
}

string GetErrorMessage_Database::get_message_error()
{
	return message_error;
}

Set_DBinfo::Set_DBinfo()
{
	errorflag_setdbinfo = STATE_NORMAL;
}

Set_DBinfo::~Set_DBinfo()
{
	errorflag_setdbinfo = STATE_NORMAL;
}

void Set_DBinfo::set_DBdate(string date)
{
	databasename = "./Database\\Win_Firewall_Log_";
	databasename.append(date);
	databasename.append(".db");
	date_data = date;
	return;
}

string Set_DBinfo::get_DBdate()
{
	return date_data;
}

string Set_DBinfo::get_DBname()
{
	return databasename;
}

sqlite3* Manage_DB_Connection::get_handle_DBconnection()
{
	return handle_database;
}

Manage_DB_Connection::Manage_DB_Connection()
{
	handle_database = NULL;
	errorflag_manageconnectiondb = STATE_NORMAL;
	errmsg_create_table = NULL;
}

Manage_DB_Connection::~Manage_DB_Connection()
{
	handle_database = NULL;
	errorflag_manageconnectiondb = STATE_NORMAL;
	errmsg_create_table = NULL;
}

void Manage_DB_Connection::set_dbinfo(Set_DBinfo dbinfo_input)
{
	data_DBinfo = dbinfo_input;
	return;
}

void Manage_DB_Connection::createdbtable()
{
	int query_executionflag;
	const char *createquery_loginfotbl = "CREATE TABLE IF NOT EXISTS LOGINFOTBL (Line INTEGER, Date DATE, Time TIME, Action VARCHAR(32), Protocol VARCAHR(16), SourceIP VARCAHR(32), DestinationIP VARCHAR(32), SourcePort INTEGER, DestinationPort INTEGER, Size INTEGER, PRIMARY KEY(Line));";
	const char *createquery_tcpinfotbl = "CREATE TABLE IF NOT EXISTS TCPINFOTBL (TCPLine INTEGER,TCPFlag VARCHAR(32), TCPSyn INTEGER, TCPAck INTEGER, TCPWin INTEGER, PRIMARY KEY(TCPLine));";
	const char *createquery_icmpinfotbl = "CREATE TABLE IF NOT EXISTS ICMPINFOTBL (ICMPLine INTEGER, ICMPType VARCHAR(16), ICMPCode VARCHAR(16), Info VARCHAR(32), Path VARCHAR(32), PRIMARY KEY(ICMPLine));";
	const char *createquery_warninfotbl = "CREATE TABLE IF NOT EXISTS WARNINFOTBL (WARNLine INTEGER, WARNFlag INTEGER, PRIMARY KEY(WARNLine));";

	try {
		query_executionflag = sqlite3_exec(handle_database, createquery_loginfotbl, NULL, NULL, &errmsg_create_table);
		if (query_executionflag) {
			throw ERROR_NOT_DB_TABLE_CREATE;
		}
		query_executionflag = sqlite3_exec(handle_database, createquery_tcpinfotbl, NULL, NULL, &errmsg_create_table);
		if (query_executionflag) {
			throw ERROR_NOT_DB_TABLE_CREATE;
		}
		query_executionflag = sqlite3_exec(handle_database, createquery_icmpinfotbl, NULL, NULL, &errmsg_create_table);
		if (query_executionflag) {
			throw ERROR_NOT_DB_TABLE_CREATE;
		}
		query_executionflag = sqlite3_exec(handle_database, createquery_warninfotbl, NULL, NULL, &errmsg_create_table);
		if (query_executionflag) {
			throw ERROR_NOT_DB_TABLE_CREATE;
		}
	}
	catch (int query_executionflag) {
		errorflag_manageconnectiondb = ERROR_NOT_DB_TABLE_CREATE;
		return;
	}
	return;
}

void Manage_DB_Connection::opendb()
{
	if (sqlite3_open((data_DBinfo.get_DBname()).c_str(), &handle_database) != SQLITE_OK) {
		errorflag_manageconnectiondb = ERROR_NOT_OPEN_DATABASE;
	}
	else {
		errorflag_manageconnectiondb = STATE_NORMAL;
	}
	return;
}

void Manage_DB_Connection::closedb()
{
	sqlite3_close(handle_database);
	errorflag_manageconnectiondb = STATE_NORMAL;
}

void Manage_DB_Connection::start_db_transaction()
{
	int state_transaction;
	state_transaction = SQLITE_BUSY;
	sqlite3_exec(handle_database, "BEGIN IMMEDIATE TRANSACTION;", NULL, NULL, NULL);

	return;
}

int Manage_DB_Connection::end_db_transaction()
{
	int end_transaction;
	end_transaction = SQLITE_OK;
	end_transaction = sqlite3_exec(handle_database, "COMMIT TRANSACTION;", NULL, NULL, NULL);

	if (end_transaction != SQLITE_OK) {
		return ERROR_NOT_COMMIT_NORMALLY;
	}
	return 0;
}

Operate_DB::Operate_DB()
{
	query_statement_info = NULL;
	errorflag_operatedb = STATE_NORMAL;
	exist_error = false;
}

Operate_DB::~Operate_DB()
{
	query_statement_info = NULL;
	errorflag_operatedb = STATE_NORMAL;
	exist_error = false;
	message_error.clear();
}

void Operate_DB::insertdb(sqlite3* handle_input, string query_insert)
{
	if (handle_input == NULL) {
		errorflag_operatedb = ERROR_NOT_INPUT_DATABASE_HANDLE;
	}

	sqlite3_prepare_v2(handle_input, query_insert.c_str(), -1, &query_statement_info, NULL);
	sqlite3_step(query_statement_info);
	sqlite3_finalize(query_statement_info);
	query_insert.clear();
	return;
}

void Operate_DB::set_errorflag(const int &flag_input)
{
	if (errorflag_operatedb != STATE_NORMAL) {
		message_error = "Error. Don't input database handle.";
		exist_error = true;
	}
	else {
		switch (flag_input) {
		case ERROR_NOT_INPUT_DATABASE_HANDLE:
			message_error = "Error. Don't input database handle.";
			exist_error = true;
			break;
		case EMPTY_TCPINFO:
			message_error = "Error. Empty inputed tcp information data.";
			exist_error = true;
			break;
		case EMPTY_LOGINFO:
			message_error = "Error. Empty inputed log information data.";
			exist_error = true;
			break;
		case EMPTY_ICMPINFO:
			message_error = "Error. Empty inputed icmp information data.";
			exist_error = true;
			break;
		case EMPTY_WARNINFO:
			message_error = "Error. Empty inputed warning information data.";
			exist_error = true;
			break;
		default:
			message_error = "Not exist error. CheckPoint process normally in program.";
			exist_error = false;
			break;
		}
		return;
	}
}

Loginfo_Table::Loginfo_Table() :loginfotable_attribute_amount(10)
{
	insertquery_loginfo = "";
	errorflag_loginfotbl = STATE_NORMAL;
	data_numbering[0] = "HOPOPT";
	data_numbering[1] = "ICMP";
	data_numbering[2] = "IGMP";
	data_numbering[3] = "GGP";
	data_numbering[4] = "IPv4";
	data_numbering[5] = "ST";
	data_numbering[6] = "TCP";
	data_numbering[7] = "CBT";
	data_numbering[8] = "EGP";
	data_numbering[9] = "IGP";
	data_numbering[10] = "BBN-RCC-MON";
	data_numbering[11] = "NVP-II";
	data_numbering[12]= "PUP";
	data_numbering[13] = "ARGUS";
	data_numbering[14] = "EMCON";
	data_numbering[15] = "XNET";
	data_numbering[16] = "CHAOS";
	data_numbering[17] = "UDP";
	data_numbering[18] = "MUX";
	data_numbering[19] = "DCN-MEAS";
	data_numbering[20] = "HMP";
	data_numbering[21] = "PRM";
	data_numbering[22] = "XNS-IDP";
	data_numbering[23] = "TRUNK-1";
	data_numbering[24] = "TRUNK-2";
	data_numbering[25] = "LEAF-1";
	data_numbering[26] = "LEAF-2";
	data_numbering[27] = "RDP";
	data_numbering[28] = "IRTP";
	data_numbering[29] = "ISO-TP4";
};

Loginfo_Table::~Loginfo_Table()
{
	insertquery_loginfo = "";
	errorflag_loginfotbl = STATE_NORMAL;
}

void Loginfo_Table::setDBconnection(Manage_DB_Connection InputConnection)
{
	data_DB_connection = InputConnection;
}

void Loginfo_Table::makeinsertquery(deque<string> inputloginfo)
{
	insertquery_loginfo = "INSERT INTO LOGINFOTBL VALUES (";

	for (int attr = 0; attr < loginfotable_attribute_amount; attr++) {
		insertquery_loginfo.append("\'");
		insertquery_loginfo.append(inputloginfo.front());
		inputloginfo.pop_front();
		insertquery_loginfo.append("\'");
		if (attr != loginfotable_attribute_amount - 1) {
			insertquery_loginfo.append(",");
		}
	}
	insertquery_loginfo.append(");");
}

int Loginfo_Table::setloginfo(deque<string> inputloginfo)
{
	if (inputloginfo.empty()) {
		return EMPTY_LOGINFO;
	}
	loginfodata = inputloginfo;

	return STATE_NORMAL;
}

int Loginfo_Table::insertdb_loginfo()
{
	makeinsertquery(loginfodata);
	insertdb(data_DB_connection.get_handle_DBconnection(), insertquery_loginfo);
	insertquery_loginfo.clear();
	return 0;
}

void Loginfo_Table::calculate_count()
{
	if (data_DB_connection.get_handle_DBconnection() == NULL) {
		errorflag_loginfotbl = ERROR_NOT_INPUT_DATABASE_HANDLE;
	}
	sqlite3_stmt *stmt_calcuate;
	string query_getsize_protocol = "SELECT COUNT(DISTINCT Protocol) FROM LOGINFOTBL";
	string query_getname_protocol = "SELECT DISTINCT Protocol FROM LOGINFOTBL;";
	string query_getamount_protocol = "SELECT COUNT(*) FROM LOGINFOTBL WHERE Protocol = \'";
	string query_get_sourceip = "SELECT SourceIP, COUNT(*) FROM LOGINFOTBL GROUP BY SourceIP ORDER BY 2 DESC LIMIT 5";
	string query_get_destinationip = "SELECT DestinationIP, COUNT(*) FROM LOGINFOTBL GROUP BY DestinationIP ORDER BY 2 DESC LIMIT 5";
	string repo_result;
	data_amount_protocol.clear();
	data_log_protocol.clear();

	sqlite3_prepare_v2(data_DB_connection.get_handle_DBconnection(), query_getsize_protocol.c_str(), -1, &stmt_calcuate, NULL);
	sqlite3_step(stmt_calcuate);
	repo_result = (char *)sqlite3_column_text(stmt_calcuate, 0);
	size_protocol = stoi(repo_result);
	sqlite3_finalize(stmt_calcuate);
	repo_result.clear();

	sqlite3_prepare_v2(data_DB_connection.get_handle_DBconnection(), query_getname_protocol.c_str(), -1, &stmt_calcuate, NULL);
	sqlite3_step(stmt_calcuate);
	for (int loop_query = 0; loop_query < size_protocol; loop_query++) {
		repo_result = (char *)sqlite3_column_text(stmt_calcuate, 0);
		data_log_protocol.push_back(repo_result);
		sqlite3_step(stmt_calcuate);
		repo_result.clear();
	}
	sqlite3_finalize(stmt_calcuate);

	for (int loop_query = 0; loop_query < size_protocol; loop_query++) {
		query_getamount_protocol.append(data_log_protocol.at(loop_query));
		query_getamount_protocol.append("\';");
		sqlite3_prepare_v2(data_DB_connection.get_handle_DBconnection(), query_getamount_protocol.c_str(), -1, &stmt_calcuate, NULL);
		sqlite3_step(stmt_calcuate);
		repo_result = (char *)sqlite3_column_text(stmt_calcuate, 0);
		data_amount_protocol.push_back(stol(repo_result));
		sqlite3_finalize(stmt_calcuate);
		repo_result.clear();
		query_getamount_protocol = "SELECT COUNT(*) FROM LOGINFOTBL WHERE Protocol = \'";
	}

	sqlite3_prepare_v2(data_DB_connection.get_handle_DBconnection(), query_get_sourceip.c_str(), -1, &stmt_calcuate, NULL);
	sqlite3_step(stmt_calcuate);
	for (int loop_query = 0; loop_query < MAX_SIZE_IP_DATA; loop_query++) {
		repo_result = (char *)sqlite3_column_text(stmt_calcuate, 0);
		data_log_srcip[loop_query] = repo_result;
		repo_result = (char *)sqlite3_column_text(stmt_calcuate, 1);
		data_amount_srcip[loop_query] = stoi(repo_result);
		sqlite3_step(stmt_calcuate);
		repo_result.clear();
	}
	sqlite3_finalize(stmt_calcuate);

	sqlite3_prepare_v2(data_DB_connection.get_handle_DBconnection(), query_get_destinationip.c_str(), -1, &stmt_calcuate, NULL);
	sqlite3_step(stmt_calcuate);
	for (int loop_query = 0; loop_query < MAX_SIZE_IP_DATA; loop_query++) {
		repo_result = (char *)sqlite3_column_text(stmt_calcuate, 0);
		data_log_dstip[loop_query] = repo_result;
		repo_result = (char *)sqlite3_column_text(stmt_calcuate, 1);
		data_amount_dstip[loop_query] = stoi(repo_result);
		sqlite3_step(stmt_calcuate);
		repo_result.clear();
	}
	sqlite3_finalize(stmt_calcuate);
}

TCPinfo_Table::TCPinfo_Table() : tcpinfotable_attribute_amount(5)
{
	insertquery_tcpinfo = "";
	errorflag_tcpinfotbl = STATE_NORMAL;
}

TCPinfo_Table::~TCPinfo_Table()
{
	insertquery_tcpinfo = "";
	errorflag_tcpinfotbl = STATE_NORMAL;
}

void TCPinfo_Table::makeinsertquery(deque<string> inputtcpinfo)
{
	insertquery_tcpinfo = "INSERT INTO TCPINFOTBL VALUES (";

	for (int attr = 0; attr < tcpinfotable_attribute_amount; attr++) {
		insertquery_tcpinfo.append("\'");
		insertquery_tcpinfo.append(inputtcpinfo.front());
		inputtcpinfo.pop_front();
		insertquery_tcpinfo.append("\'");
		if (attr != tcpinfotable_attribute_amount - 1) {
			insertquery_tcpinfo.append(",");
		}
	}
	insertquery_tcpinfo.append(");");
}

void TCPinfo_Table::setDBconnection(Manage_DB_Connection InputConnection)
{
	data_DB_connection = InputConnection;
}

int TCPinfo_Table::settcpinfo(deque<string> inputtcpinfo)
{
	if (inputtcpinfo.empty()) {
		return EMPTY_TCPINFO;
	}

	tcpinfodata = inputtcpinfo;
	return STATE_NORMAL;
}

int TCPinfo_Table::insertdb_tcpinfo()
{
	makeinsertquery(tcpinfodata);
	insertdb(data_DB_connection.get_handle_DBconnection(), insertquery_tcpinfo);
	insertquery_tcpinfo.clear();
	return 0;
}

ICMPinfo_Table::ICMPinfo_Table() : icmpinfotable_attribute_amount(5)
{
	insertquery_icmpinfo = "";
	errorflag_icmpinfotbl = STATE_NORMAL;
}
ICMPinfo_Table::~ICMPinfo_Table()
{
	insertquery_icmpinfo = "";
	errorflag_icmpinfotbl = STATE_NORMAL;
}

void ICMPinfo_Table::makeinsertquery(deque<string>inputicmpinfo)
{
	insertquery_icmpinfo = "INSERT INTO ICMPINFOTBL VALUES (";

	for (int attr = 0; attr < icmpinfotable_attribute_amount; attr++) {
		insertquery_icmpinfo.append("\'");
		insertquery_icmpinfo.append(inputicmpinfo.front());
		inputicmpinfo.pop_front();
		insertquery_icmpinfo.append("\'");
		if (attr != icmpinfotable_attribute_amount - 1) {
			insertquery_icmpinfo.append(",");
		}
	}
	insertquery_icmpinfo.append(");");
}

void ICMPinfo_Table::setDBconnection(Manage_DB_Connection InputConnection)
{
	data_DB_connection = InputConnection;
}

int ICMPinfo_Table::seticmpinfo(deque<string> inputicmpinfo)
{
	if (inputicmpinfo.empty()) {
		return EMPTY_ICMPINFO;
	}

	icmpinfodata = inputicmpinfo;
	return STATE_NORMAL;
}

int ICMPinfo_Table::insertdb_icmpinfo()
{
	makeinsertquery(icmpinfodata);
	insertdb(data_DB_connection.get_handle_DBconnection(), insertquery_icmpinfo);
	insertquery_icmpinfo.clear();
	return 0;
}

Warninfo_Table::Warninfo_Table() : warninfotable_attribute_amount(2)
{
	insertquery_warninfo = "";
	errorflag_warninfotbl = STATE_NORMAL;
}

Warninfo_Table::~Warninfo_Table()
{
	insertquery_warninfo = "";
	errorflag_warninfotbl = STATE_NORMAL;
}

void Warninfo_Table::makeinsertquery(deque<string> inputwarninfo)
{
	insertquery_warninfo = "INSERT INTO WARNINFOTBL VALUES (";

	for (int attr = 0; attr < warninfotable_attribute_amount; attr++) {
		insertquery_warninfo.append("\'");
		insertquery_warninfo.append(inputwarninfo.front());
		inputwarninfo.pop_front();
		insertquery_warninfo.append("\'");
		if (attr != warninfotable_attribute_amount - 1) {
			insertquery_warninfo.append(",");
		}
	}
	insertquery_warninfo.append(");");
}

void Warninfo_Table::setDBconnection(Manage_DB_Connection InputConnection)
{
	data_DB_connection = InputConnection;
}

int Warninfo_Table::setwarninfo( deque<string>inputwarninfo)
{
	if (inputwarninfo.empty()) {
		return EMPTY_WARNINFO;
	}

	warninfodata = inputwarninfo;
	return STATE_NORMAL;
}

int Warninfo_Table::insertdb_warninfo()
{

	makeinsertquery(warninfodata);
	insertdb(data_DB_connection.get_handle_DBconnection(), insertquery_warninfo);
	return 0;
}
