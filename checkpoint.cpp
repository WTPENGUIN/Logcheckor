#include "checklogfile.h"
#include "Database\src\sqlite3.h"

GetErrorMessage_CheckPoint::GetErrorMessage_CheckPoint()
{
	exist_error = false;
}

GetErrorMessage_CheckPoint::~GetErrorMessage_CheckPoint()
{
	exist_error = false;
	message_error.clear();
}

void GetErrorMessage_CheckPoint::set_errorflag(const int &flag_input)
{
	switch (flag_input) {
	case NO_INPUT_LINE_DATA:
		message_error = "Error. Don't input log line data.";
		exist_error = true;
		break;
	case NO_INPUT_QUERY_DATE_DATA:
		message_error = "Error. Don't input query data.";
		exist_error = true;
		break;
	case NOT_OPEN_DATABASE:
		message_error = "Error. Don't open database.";
		exist_error = true;
		break;
	case NO_INPUT_DATABASE_HANDLE:
		message_error = "Error. Don't input database handle.";
		exist_error = true;
		break;
	default:
		message_error = "Not exist error. CheckPoint process normally in program.";
		exist_error = false;
		break;
	}
	return;
}

string GetErrorMessage_CheckPoint::get_message_error()
{
	return message_error;
}

void CheckPoint_Line::data_clear()
{
	data_srcip_pattern3.clear();
	data_srcip_pattern5.clear();
	data_dstip_pattern3.clear();
	data_dstip_paatern5.clear();
}

CheckPoint_Line::CheckPoint_Line()
{
	flag_line_suspiciouspoint = FLAG_NORMAL_LOG;
	flag_error_checkpoint_line = NO_ERROR_CHECKPOINT;
	flag_start_pattern3 = false;
	flag_start_pattern5 = false;
	flag_end_pattern3 = false;
	flag_end_pattern5 = false;
	flag_data_input = false;
}

CheckPoint_Line::~CheckPoint_Line()
{
	flag_line_suspiciouspoint = FLAG_NORMAL_LOG;
	flag_error_checkpoint_line = NO_ERROR_CHECKPOINT;
	flag_start_pattern3 = false;
	flag_start_pattern5 = false;
	flag_end_pattern3 = false;
	flag_end_pattern5 = false;
	flag_data_input = false;
	data_line_pattern3 = NULL;
	data_line_pattern5 = NULL;
	data_clear();
}

void CheckPoint_Line::set_logline_data(int line, deque<string> &input_data)
{
	data_line = line;
	data_srcip = input_data.at(5);
	data_dstip = input_data.at(6);
	data_srcport = input_data.at(7);
	data_dstport = input_data.at(8);
	flag_data_input = true;
}

int CheckPoint_Line::process_checkpoint_line()
{
	if (flag_data_input != true) {
		return NO_INPUT_LINE_DATA;
	}

	flag_line_suspiciouspoint = process_checkpoint_line_pass1();
	if (flag_line_suspiciouspoint != FLAG_NORMAL_LOG) {
		return flag_line_suspiciouspoint;
	}
	flag_line_suspiciouspoint = process_checkpoint_line_pass2();

	return flag_line_suspiciouspoint;
}

int CheckPoint_Line::process_checkpoint_line_pass1()
{
	if (data_srcport == "1356" && data_dstport == "2101") {	// Search Pattern 9
		return FLAG_MSMQ_HEAP_OVERFLOW;
	}
	if (data_srcport == "220" && data_dstport == "21") {	// Search Pattern 14
		return FLAG_DAMWARE_PROBE;
	}
	return FLAG_NORMAL_LOG;
}

int CheckPoint_Line::process_checkpoint_line_pass2()
{
	if (data_dstport == "80") {
		data_line_pattern3 = data_line;
		data_srcip_pattern3 = data_srcip;
		data_dstip_pattern3 = data_dstip;
		flag_start_pattern3 = true;
	}
	if (data_dstport == "445") {
		data_line_pattern5 = data_line;
		data_srcip_pattern5 = data_srcip;
		data_dstip_paatern5 = data_dstip;
		flag_start_pattern5 = true;
	}
	if (flag_start_pattern3 == true && data_dstport == "9999") {
		flag_start_pattern3 = false;
		flag_end_pattern3 = true;
		data_clear();
		return FLAG_MS_FRONTPAGE_SERVER_EXTENSION_BUFFER_OVERFLOW;
	}
	if (flag_start_pattern5 == true && data_dstport == "4444") {
		flag_start_pattern5 = false;
		flag_end_pattern3 = true;
		data_clear();
		return FLAG_LSASS_RPC_BUFFER_OVERFLOW;
	}

	return FLAG_NORMAL_LOG;
}

int CheckPoint_Line::check_pass2_loginfo()
{
	if (flag_line_suspiciouspoint == FLAG_MS_FRONTPAGE_SERVER_EXTENSION_BUFFER_OVERFLOW) {
		return data_line_pattern3;
	}
	if (flag_line_suspiciouspoint == FLAG_LSASS_RPC_BUFFER_OVERFLOW) {
		return data_line_pattern5;
	}
	return 0;
}

void CheckPoint_Line::insert_suspiciousinfo_in_database(sqlite3* handle_input)
{
	string query_insert_suspiciousinfo = "INSERT INTO WARNINFOTBL VALUES (";
	sqlite3_stmt *query_stmt_insertdb;

	if (flag_end_pattern3 == true) {
		query_insert_suspiciousinfo.append("\'");
		query_insert_suspiciousinfo.append(to_string(data_line_pattern3));
		query_insert_suspiciousinfo.append("\',\'");
		query_insert_suspiciousinfo.append(to_string(flag_line_suspiciouspoint));
		query_insert_suspiciousinfo.append("\');");
		sqlite3_prepare_v2(handle_input, query_insert_suspiciousinfo.c_str(), -1, &query_stmt_insertdb, NULL);
		sqlite3_step(query_stmt_insertdb);
		sqlite3_finalize(query_stmt_insertdb);
		query_insert_suspiciousinfo.clear();
		flag_end_pattern3 = false;
	}
	if (flag_end_pattern5 == true) {
		query_insert_suspiciousinfo.append("\'");
		query_insert_suspiciousinfo.append(to_string(data_line_pattern5));
		query_insert_suspiciousinfo.append("\',\'");
		query_insert_suspiciousinfo.append(to_string(flag_line_suspiciouspoint));
		query_insert_suspiciousinfo.append("\');");
		sqlite3_prepare_v2(handle_input, query_insert_suspiciousinfo.c_str(), -1, &query_stmt_insertdb, NULL);
		sqlite3_step(query_stmt_insertdb);
		sqlite3_finalize(query_stmt_insertdb);
		query_insert_suspiciousinfo.clear();
		flag_end_pattern5 = false;
	}
	if (flag_line_suspiciouspoint != FLAG_NORMAL_LOG) {
		query_insert_suspiciousinfo = "INSERT INTO WARNINFOTBL VALUES (";

		query_insert_suspiciousinfo.append("\'");
		query_insert_suspiciousinfo.append(to_string(data_line));
		query_insert_suspiciousinfo.append("\',\'");
		query_insert_suspiciousinfo.append(to_string(flag_line_suspiciouspoint));
		query_insert_suspiciousinfo.append("\');");

		sqlite3_prepare_v2(handle_input, query_insert_suspiciousinfo.c_str(), -1, &query_stmt_insertdb, NULL);
		sqlite3_step(query_stmt_insertdb);
		sqlite3_finalize(query_stmt_insertdb);
		query_insert_suspiciousinfo.clear();
	}

	return;
}

void CheckPoint_Query::insert_suspiciousinfo_in_database(sqlite3* handle_database)
{
	string query_insert_suspiciousinfo = "INSERT INTO WARNINFOTBL VALUES (";

	if (handle_database == NULL) {
		flag_error_checkpoint_query = NO_INPUT_DATABASE_HANDLE;
		return;
	}

	while (!data_find_line.empty() && !data_find_suspicious_info.empty()) {
		query_insert_suspiciousinfo = "INSERT INTO WARNINFOTBL VALUES (";
		sqlite3_stmt *query_stmt_insertdb;

		query_insert_suspiciousinfo.append("\'");
		query_insert_suspiciousinfo.append(data_find_line.at(0));
		data_find_line.pop_front();
		query_insert_suspiciousinfo.append("\',\'");
		query_insert_suspiciousinfo.append(to_string(data_find_suspicious_info.at(0)));
		data_find_suspicious_info.pop_front();
		query_insert_suspiciousinfo.append("\');");

		sqlite3_prepare_v2(handle_database, query_insert_suspiciousinfo.c_str(), -1, &query_stmt_insertdb, NULL);
		sqlite3_step(query_stmt_insertdb);
		sqlite3_finalize(query_stmt_insertdb);
		query_insert_suspiciousinfo.clear();
	}

	return;
}

CheckPoint_Query::CheckPoint_Query()
{
	flag_query_suspiciouspoint = FLAG_NORMAL_LOG;
	flag_error_checkpoint_query = NO_INPUT_QUERY_DATE_DATA;
}

CheckPoint_Query::~CheckPoint_Query()
{
	flag_query_suspiciouspoint = FLAG_NORMAL_LOG;
	flag_error_checkpoint_query = NO_INPUT_QUERY_DATE_DATA;
}

void CheckPoint_Query::process_get_checkpoint(sqlite3* handle_database)
{
	if (handle_database == NULL) {
		flag_error_checkpoint_query = NO_INPUT_DATABASE_HANDLE;
		return;
	}

	// Pattern 4 Search
	string query_pattern4 = "SELECT former.Line,latter.Line FROM (SELECT * FROM LOGINFOTBL WHERE Protocol = \"TCP\" AND DestinationPort = 135) as former, (SELECT * FROM LOGINFOTBL WHERE Protocol = \"TCP\" AND DestinationPort = 9191) as latter WHERE former.SourceIP = latter.SourceIP AND former.DestinationIP = latter.DestinationIP;";
	sqlite3_stmt *query_stmt_pattern4;
	sqlite3_prepare_v2(handle_database, query_pattern4.c_str(), -1, &query_stmt_pattern4, NULL);
	while (sqlite3_step(query_stmt_pattern4) == SQLITE_ROW) {
		data_find_line.push_back((char *)sqlite3_column_text(query_stmt_pattern4,0));
		data_find_suspicious_info.push_back(FLAG_MS_MESSAENGER_HEAP_OVERFLOW);
		data_find_line.push_back((char *)sqlite3_column_text(query_stmt_pattern4,1));
		data_find_suspicious_info.push_back(FLAG_MS_MESSAENGER_HEAP_OVERFLOW);
	}
	sqlite3_finalize(query_stmt_pattern4);

	// Pattern 6 Search
	string query_pattern6 = "SELECT former.Line,latter.Line FROM (SELECT * FROM LOGINFOTBL WHERE Protocol = \"TCP\" AND DestinationPort = 389) as former, (SELECT * FROM LOGINFOTBL WHERE Protocol = \"TCP\" AND DestinationPort = 31337) as latter WHERE former.SourceIP = latter.SourceIP AND former.DestinationIP = latter.DestinationIP;";
	sqlite3_stmt *query_stmt_pattern6;
	sqlite3_prepare_v2(handle_database, query_pattern6.c_str(), -1, &query_stmt_pattern6, NULL);
	while (sqlite3_step(query_stmt_pattern6) == SQLITE_ROW) {
		data_find_line.push_back((char *)sqlite3_column_text(query_stmt_pattern6, 0));
		data_find_suspicious_info.push_back(FLAG_IPSWITCH_IMAIL_LDAP);
		data_find_line.push_back((char *)sqlite3_column_text(query_stmt_pattern6, 1));
		data_find_suspicious_info.push_back(FLAG_IPSWITCH_IMAIL_LDAP);
	}
	sqlite3_finalize(query_stmt_pattern6);

	// Pattern 7 Search
	string query_pattern7 = "SELECT former.Line,latter.Line FROM (SELECT * FROM LOGINFOTBL WHERE Protocol = \"TCP\" AND DestinationPort = 135) as former, (SELECT * FROM LOGINFOTBL WHERE Protocol = \"TCP\" AND DestinationPort = 7175) as latter WHERE former.SourceIP = latter.SourceIP AND former.DestinationIP = latter.DestinationIP;";
	sqlite3_stmt *query_stmt_pattern7;
	sqlite3_prepare_v2(handle_database, query_pattern7.c_str(), -1, &query_stmt_pattern7, NULL);
	while (sqlite3_step(query_stmt_pattern7) == SQLITE_ROW) {
		data_find_line.push_back((char *)sqlite3_column_text(query_stmt_pattern7, 0));
		data_find_suspicious_info.push_back(FLAG_WINDOWS_NT_RETURN_INTO_LIBC);
		data_find_line.push_back((char *)sqlite3_column_text(query_stmt_pattern7, 1));
		data_find_suspicious_info.push_back(FLAG_WINDOWS_NT_RETURN_INTO_LIBC);
	}
	sqlite3_finalize(query_stmt_pattern7);

	// Pattern 8 Search
	string query_pattern8 = "SELECT former.Line,latter.Line FROM (SELECT * FROM LOGINFOTBL WHERE DestinationPort = 24876) as former, (SELECT * FROM LOGINFOTBL) as latter WHERE former.SourceIP = latter.DestinationIP AND former.DestinationIP = latter.SourceIP AND former.SourcePort = latter.DestinationPort;";
	sqlite3_stmt *query_stmt_pattern8;
	sqlite3_prepare_v2(handle_database, query_pattern8.c_str(), -1, &query_stmt_pattern8, NULL);
	while (sqlite3_step(query_stmt_pattern8) == SQLITE_ROW) {
		data_find_line.push_back((char *)sqlite3_column_text(query_stmt_pattern8, 0));
		data_find_suspicious_info.push_back(FLAG_WINDOWS_WORKSTATION_SERVICE_WKSSVC_LIBC);
		data_find_line.push_back((char *)sqlite3_column_text(query_stmt_pattern8, 1));
		data_find_suspicious_info.push_back(FLAG_WINDOWS_WORKSTATION_SERVICE_WKSSVC_LIBC);
	}
	sqlite3_finalize(query_stmt_pattern8);

	// Pattern 10 Search
	string query_pattern10 = "SELECT former.Line,latter.Line FROM (SELECT * FROM LOGINFOTBL WHERE DestinationPort = 21) as former, (SELECT * FROM LOGINFOTBL WHERE SourcePort = 20 AND DestinationPort = 34568) as latter WHERE former.SourceIP = latter.DestinationIP AND former.DestinationIP = latter.SourceIP;";
	sqlite3_stmt *query_stmt_pattern10;
	sqlite3_prepare_v2(handle_database, query_pattern10.c_str(), -1, &query_stmt_pattern10, NULL);
	while (sqlite3_step(query_stmt_pattern10) == SQLITE_ROW) {
		data_find_line.push_back((char *)sqlite3_column_text(query_stmt_pattern10, 0));
		data_find_suspicious_info.push_back(FLAG_PROFTPD_FILE_REMOTE_ROOT_EXPLOIT);
		data_find_line.push_back((char *)sqlite3_column_text(query_stmt_pattern10, 1));
		data_find_suspicious_info.push_back(FLAG_PROFTPD_FILE_REMOTE_ROOT_EXPLOIT);
	}
	sqlite3_finalize(query_stmt_pattern10);

	// Pattern 12 Search
	string query_pattern12 = "SELECT former.Line,latter.Line FROM (SELECT * FROM LOGINFOTBL WHERE Protocol = \"TCP\" AND DestinationPort = 21) as former, (SELECT * FROM LOGINFOTBL WHERE Protocol = \"TCP\" AND DestinationPort = 19800) as latter WHERE former.SourceIP = latter.SourceIP AND former.DestinationIP = latter.DestinationIP;";
	sqlite3_stmt *query_stmt_pattern12;
	sqlite3_prepare_v2(handle_database, query_pattern12.c_str(), -1, &query_stmt_pattern12, NULL);
	while (sqlite3_step(query_stmt_pattern12) == SQLITE_ROW) {
		data_find_line.push_back((char *)sqlite3_column_text(query_stmt_pattern12, 0));
		data_find_suspicious_info.push_back(FLAG_WFTPD_STAT_COMMAND_REMOTE_EXPLOIT);
		data_find_line.push_back((char *)sqlite3_column_text(query_stmt_pattern12, 1));
		data_find_suspicious_info.push_back(FLAG_WFTPD_STAT_COMMAND_REMOTE_EXPLOIT);
	}
	sqlite3_finalize(query_stmt_pattern12);

	insert_suspiciousinfo_in_database(handle_database);
	return;
}

void CheckPoint_Multi_Condition::insert_suspiciousinfo_in_database(sqlite3* handle_database)
{
	while (!data_loglocation.empty()) {
		string query_insert_suspiciousinfo = "INSERT INTO WARNINFOTBL VALUES (";
		sqlite3_stmt *query_stmt_insertdb;
		query_insert_suspiciousinfo.append("\'");
		query_insert_suspiciousinfo.append(data_loglocation.at(0));
		query_insert_suspiciousinfo.append("\',\'");
		query_insert_suspiciousinfo.append(to_string(flag_query_suspiciouspoint));
		query_insert_suspiciousinfo.append("\');");
		data_loglocation.pop_front();

		sqlite3_prepare_v2(handle_database, query_insert_suspiciousinfo.c_str(), -1, &query_stmt_insertdb, NULL);
		sqlite3_step(query_stmt_insertdb);
		sqlite3_finalize(query_stmt_insertdb);
		query_insert_suspiciousinfo.clear();
	}
}

CheckPoint_Multi_Condition::CheckPoint_Multi_Condition()
{
	flag_query_suspiciouspoint = FLAG_NORMAL_LOG;
	flag_error_CheckPoint_Multi_Condition = NO_ERROR_CHECKPOINT;
}

CheckPoint_Multi_Condition::~CheckPoint_Multi_Condition()
{
	flag_query_suspiciouspoint = FLAG_NORMAL_LOG;
	flag_error_CheckPoint_Multi_Condition = NO_ERROR_CHECKPOINT;
}

void CheckPoint_Multi_Condition::process_checkpoint_multicondition(sqlite3* handle_database)
{
	if (handle_database == NULL) {
		flag_error_CheckPoint_Multi_Condition = NO_INPUT_DATABASE_HANDLE;
		return;
	}

	sqlite3_stmt *stmt_check_multicondition;
	string query_portscan = "select * from (select * from LOGINFOTBL as A where A.Protocol = \'TCP\' and A.DestinationPort in (\'21\',\'23\',\'79\',\'110\',\'111\',\'135\',\'512\',\'513\',\'514\',\'1433\',\'1434\',\'32771\') union select * from LOGINFOTBL as B where B.Protocol = \'UDP\' and B.DestinationPort in (\'135\',\'161\',\'1433\',\'1434\',\'32771\')) order by SourceIP ASC, DestinationIP ASC";
	string query_worm = "SELECT * FROM (SELECT * FROM LOGINFOTBL WHERE Protocol = 'TCP' AND DestinationPort IN (\'80\',\'135\',\'139\',\'445\',\'3127\')) ORDER BY SourceIP ASC, DestinationIP ASC;";
	string current_srcip, current_dstip, repo_column_field;
	bool flag_change_ip = false;
	int flag_row, amount_portscanlog = 0, amount_wormlog = 0;
	flag_query_suspiciouspoint = FLAG_NORMAL_LOG;

	sqlite3_prepare_v2(handle_database, query_portscan.c_str(), -1, &stmt_check_multicondition, NULL);
	flag_row = sqlite3_step(stmt_check_multicondition);
	if (flag_row == SQLITE_ROW) {
		current_srcip = (char *)sqlite3_column_text(stmt_check_multicondition, 5);
		current_dstip = (char *)sqlite3_column_text(stmt_check_multicondition, 6);
	}
	while (flag_row == SQLITE_ROW) {
		if (current_srcip != (char *)sqlite3_column_text(stmt_check_multicondition, 5) || current_dstip != (char *)sqlite3_column_text(stmt_check_multicondition, 6)) {
			flag_change_ip = true;
		}

		if (flag_change_ip == true) {
			flag_change_ip = false;
			if (amount_portscanlog > 4) {
				flag_query_suspiciouspoint = FLAG_PORT_SCAN;
				insert_suspiciousinfo_in_database(handle_database);
				flag_query_suspiciouspoint = FLAG_NORMAL_LOG;;
				data_loglocation.erase(data_loglocation.begin(), data_loglocation.end());
			}
			data_loglocation.erase(data_loglocation.begin(), data_loglocation.end());
			amount_portscanlog = 0;
		}
		repo_column_field = (char *)sqlite3_column_text(stmt_check_multicondition, 0);
		current_srcip = (char *)sqlite3_column_text(stmt_check_multicondition, 5);
		current_dstip = (char *)sqlite3_column_text(stmt_check_multicondition, 6);
		data_loglocation.push_front(repo_column_field);
		amount_portscanlog++;
		flag_row = sqlite3_step(stmt_check_multicondition);
	}

	if (amount_portscanlog > 4) {
		flag_query_suspiciouspoint = FLAG_PORT_SCAN;
		insert_suspiciousinfo_in_database(handle_database);
		flag_query_suspiciouspoint = FLAG_NORMAL_LOG;;
	}
	data_loglocation.erase(data_loglocation.begin(), data_loglocation.end());
	amount_portscanlog = 0;
	flag_change_ip = false;
	sqlite3_finalize(stmt_check_multicondition);

	sqlite3_prepare_v2(handle_database, query_worm.c_str(), -1, &stmt_check_multicondition, NULL);
	flag_row = sqlite3_step(stmt_check_multicondition);
	if (flag_row == SQLITE_ROW) {
		current_srcip = (char *)sqlite3_column_text(stmt_check_multicondition, 5);
		current_dstip = (char *)sqlite3_column_text(stmt_check_multicondition, 6);
	}
	while (flag_row == SQLITE_ROW) {
		if (current_srcip != (char *)sqlite3_column_text(stmt_check_multicondition, 5) || current_dstip != (char *)sqlite3_column_text(stmt_check_multicondition, 6)) {
			flag_change_ip = true;
		}
		if (flag_change_ip == true) {
			if (amount_wormlog > 4) {
				flag_query_suspiciouspoint = FLAG_PHATBOT_AGOBOT_GAOBOT_WORM;
				insert_suspiciousinfo_in_database(handle_database);
				flag_query_suspiciouspoint = FLAG_NORMAL_LOG;
			}
			data_loglocation.erase(data_loglocation.begin(), data_loglocation.end());
			data_logrepository.erase(data_logrepository.begin(), data_logrepository.end());
			amount_wormlog = 0;
			flag_change_ip = false;
		}
		
		repo_column_field = (char *)sqlite3_column_text(stmt_check_multicondition, 0);
		current_srcip = (char *)sqlite3_column_text(stmt_check_multicondition, 5);
		current_dstip = (char *)sqlite3_column_text(stmt_check_multicondition, 6);
		data_loglocation.push_front(repo_column_field);
		repo_column_field = (char *)sqlite3_column_text(stmt_check_multicondition, 8);
		check_duplicate = data_logrepository.insert(repo_column_field);
		if (true == check_duplicate.second) {
			amount_wormlog++;
		}
		flag_row = sqlite3_step(stmt_check_multicondition);
	}

	if (amount_wormlog > 4) {
		flag_query_suspiciouspoint = FLAG_PHATBOT_AGOBOT_GAOBOT_WORM;
		insert_suspiciousinfo_in_database(handle_database);
		flag_query_suspiciouspoint = FLAG_NORMAL_LOG;
	}
	data_loglocation.erase(data_loglocation.begin(), data_loglocation.end());
	data_logrepository.erase(data_logrepository.begin(), data_logrepository.end());
	amount_wormlog = 0;
	sqlite3_finalize(stmt_check_multicondition);

	return;
}

CheckPoint_UserDefined::CheckPoint_UserDefined()
{
	flag_error_CheckPoint_UserDefined = NO_ERROR_CHECKPOINT;
}

CheckPoint_UserDefined::~CheckPoint_UserDefined()
{
	flag_error_CheckPoint_UserDefined = NO_ERROR_CHECKPOINT;
}

void CheckPoint_UserDefined::process_checkpoint_userdefined(sqlite3* handle_database)
{
	if (handle_database == NULL) {
		flag_error_CheckPoint_UserDefined = NO_INPUT_DATABASE_HANDLE;
		return;
	}

	string query_search_rule = "SELECT Line FROM LOGINFOTBL WHERE ";
	string query_insert_suspiciousinfo;
	sqlite3_stmt *query_stmt_search_rule;
	bool flag_add_condition = false;

	if (information_rule.action != "-") {
		query_search_rule.append("Action = ");
		query_search_rule.append("\"");
		query_search_rule.append(information_rule.action);
		query_search_rule.append("\"");
		flag_add_condition = true;
	}
	if (information_rule.protocol != "-") {
		if (flag_add_condition == true) {
			query_search_rule.append(" AND ");
		}
		query_search_rule.append("Protocol = ");
		query_search_rule.append("\"");
		query_search_rule.append(information_rule.protocol);
		query_search_rule.append("\"");
		flag_add_condition = true;
	}
	if (information_rule.srcip != "-") {
		if (flag_add_condition == true) {
			query_search_rule.append(" AND ");
		}
		query_search_rule.append("SourceIP = ");
		query_search_rule.append("\"");
		query_search_rule.append(information_rule.srcip);
		query_search_rule.append("\"");
		flag_add_condition = true;
	}
	if (information_rule.dstip != "-") {
		if (flag_add_condition == true) {
			query_search_rule.append(" AND ");
		}
		query_search_rule.append("DestinationIP = ");
		query_search_rule.append("\"");
		query_search_rule.append(information_rule.dstip);
		query_search_rule.append("\"");
		flag_add_condition = true;
	}
	if (information_rule.srcport != "-") {
		if (flag_add_condition == true) {
			query_search_rule.append(" AND ");
		}
		query_search_rule.append("SourcePort = ");
		query_search_rule.append(information_rule.srcport);
		flag_add_condition = true;
	}
	if (information_rule.dstport != "-") {
		if (flag_add_condition == true) {
			query_search_rule.append(" AND ");
		}
		query_search_rule.append("DestinationPort = ");
		query_search_rule.append(information_rule.dstport);
		flag_add_condition = true;
	}
	query_search_rule.append(";");

	sqlite3_prepare_v2(handle_database, query_search_rule.c_str(), -1, &query_stmt_search_rule, NULL);
	while (sqlite3_step(query_stmt_search_rule) == SQLITE_ROW) {
		data_find_line.push_back((char *)sqlite3_column_text(query_stmt_search_rule, 0));
	}
	sqlite3_finalize(query_stmt_search_rule);

	while (!data_find_line.empty()) {
		query_insert_suspiciousinfo = "INSERT INTO WARNINFOTBL VALUES (";
		sqlite3_stmt *query_stmt_insertdb;

		query_insert_suspiciousinfo.append("\'");
		query_insert_suspiciousinfo.append(data_find_line.at(0));
		data_find_line.pop_front();
		query_insert_suspiciousinfo.append("\',\'");
		query_insert_suspiciousinfo.append(to_string(FLAG_USER_DEFINED_RULE + information_rule.displacement_value));
		query_insert_suspiciousinfo.append("\');");

		sqlite3_prepare_v2(handle_database, query_insert_suspiciousinfo.c_str(), -1, &query_stmt_insertdb, NULL);
		sqlite3_step(query_stmt_insertdb);
		sqlite3_finalize(query_stmt_insertdb);
		query_insert_suspiciousinfo.clear();
	}

	return;
}

void CheckPoint_UserDefined::set_checkpoint_userdefined(user_rule_info input)
{
	information_rule.displacement_value = input.displacement_value;
	information_rule.action = input.action;
	information_rule.protocol = input.protocol;
	information_rule.srcip = input.srcip;
	information_rule.dstip = input.dstip;
	information_rule.srcport = input.srcport;
	information_rule.dstport = input.dstport;
	information_rule.content_suspicious = input.content_suspicious;
}