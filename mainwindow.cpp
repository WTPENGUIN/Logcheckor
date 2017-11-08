#include <iostream>
#include <Windows.h>
#include <cstring>
#include "mainwindow.h"

MainWindow::MainWindow()
{
	QSplashScreen *splash_logcheckor = new QSplashScreen;
	Qt::Alignment bottomRight = Qt::AlignRight | Qt::AlignBottom;
	splash_logcheckor->setPixmap(QPixmap("./start.jpg").scaled(720, 480, Qt::IgnoreAspectRatio, Qt::FastTransformation));
	splash_logcheckor->resize(720, 480);
	splash_logcheckor->show();

	splash_logcheckor->showMessage(QObject::tr("Reading Logcheckor metadata..."), bottomRight, Qt::white);
	Sleep(2);
	reading_metadata_program();
	reading_metadata_rule();
	if (read_logfile(logstream)) {
		flag_failure_readlog = false;
		splash_logcheckor->showMessage(QObject::tr("Read and Processing Log data..."), bottomRight, Qt::white);
		processing_logfile();
	}
	else {
		flag_failure_readlog = true;
	}
	splash_logcheckor->showMessage(QObject::tr("Make GUI Screen..."), bottomRight, Qt::white);
	Sleep(2);
	create_actions();
	create_menus();
	if (flag_failure_readlog == false) {
		splash_logcheckor->showMessage(QObject::tr("Back up log data automatically..."), bottomRight, Qt::white);
		Sleep(2);
		processing_backup_log(flag_option_autobackup);
	}
	splash_logcheckor->showMessage(QObject::tr("Start Logcheckor..."), bottomRight, Qt::white);
	Sleep(2);
	allocate_widget_in_mainwindow();
	splash_logcheckor->close();
	delete splash_logcheckor;
	setWindowTitle(tr("LogChecker"));
}

void MainWindow::reading_metadata_program()
{
	ifstream file_metadata;
	string metadata_stream;
	string string_flag;
	size_t start_postion;

	file_metadata.open("./Data\\logcheckor_meta.dat", ios::binary);
	if (file_metadata.is_open() == false) {
		flag_option_autobackup = true;
		flag_option_defaultkey = true;
		flag_option_default_encryption = true;
		for (int init_key = 0; init_key < LENGTH_KEY; init_key++) {
			encrypt_key[init_key] = '\0';
			decrypt_key[init_key] = '\0';
		}
		return;
	}

	getline(file_metadata, metadata_stream);
	start_postion = metadata_stream.find(" ");
	start_postion++;
	string_flag = metadata_stream.substr(start_postion);
	flag_option_autobackup = stoi(string_flag);

	getline(file_metadata, metadata_stream);
	start_postion = metadata_stream.find(" ");
	start_postion++;
	string_flag = metadata_stream.substr(start_postion);
	flag_option_default_encryption = stoi(string_flag);

	getline(file_metadata, metadata_stream);
	start_postion = metadata_stream.find(" ");
	start_postion++;
	string_flag = metadata_stream.substr(start_postion);
	flag_option_defaultkey = stoi(string_flag);

	getline(file_metadata, metadata_stream);
	if (!file_metadata.eof()) {
		for (int copy = 0; copy < LENGTH_KEY; copy++) {
			encrypt_key[copy] = metadata_stream.at(copy);
		}
		encrypt_key[LENGTH_KEY] = '\0';

		getline(file_metadata, metadata_stream);
		for (int copy = 0; copy < LENGTH_KEY; copy++) {
			decrypt_key[copy] = metadata_stream.at(copy);
		}
		decrypt_key[LENGTH_KEY] = '\0';
	}	

	file_metadata.close();
	//std::remove("./Data\\logcheckor_meta.dat");


	return;
}

void MainWindow::reading_metadata_rule()
{
	rule_count = 0;

	ifstream stream_rule_metadata;
	string string_user_rule;
	string delimiter = "\n";
	int rule_column_index = 0;
	int rule_row_index = 0;
	rule_count = 0;

	stream_rule_metadata.open("./Data\\user_rule_metadata.dat", std::ios::binary);
	if (stream_rule_metadata.is_open() == false) {
		rule_count = 0;
		stream_rule_metadata.close();
		return;
	}

	getline(stream_rule_metadata, string_user_rule);
	rule_count = stoi(string_user_rule);
	if (rule_count == 0) {
		stream_rule_metadata.close();
		return;
	}

	while (!stream_rule_metadata.eof()) {
		getline(stream_rule_metadata, string_user_rule);
RULE_ROW_NEXT_PHASE:
		if (string_user_rule.length() == 0) {
			break;
		}
		switch (rule_column_index) {
			case 0:
				define_rule[rule_row_index].displacement_value = stoi(string_user_rule);
				rule_column_index++;
				continue;
			case 1:
				define_rule[rule_row_index].action = string_user_rule;
				rule_column_index++;
				continue;
			case 2:
				define_rule[rule_row_index].protocol = string_user_rule;
				rule_column_index++;
				continue;
			case 3:
				define_rule[rule_row_index].srcip = string_user_rule;
				rule_column_index++;
				continue;
			case 4:
				define_rule[rule_row_index].dstip = string_user_rule;
				rule_column_index++;
				continue;
			case 5:
				define_rule[rule_row_index].srcport = string_user_rule;
				rule_column_index++;
				continue;
			case 6:
				define_rule[rule_row_index].dstport = string_user_rule;
				rule_column_index++;
				continue;
			case 7:
				define_rule[rule_row_index].content_suspicious = string_user_rule;
				rule_column_index++;
				continue;
			default:
				rule_column_index = 0;
				rule_row_index++;
				goto RULE_ROW_NEXT_PHASE;
		}
	}
	stream_rule_metadata.close();
}

void MainWindow::writing_metadata()
{
	ofstream file_metadata;
	file_metadata.open("./Data\\logcheckor_meta.dat", ios::binary);
	string write_option_backup = "option_backup ";
	string write_option_encryption = "option_encryption ";
	string write_cipher_key = "option_cipher_key ";

	file_metadata.write(write_option_backup.c_str(), write_option_backup.length());
	file_metadata << flag_option_autobackup  <<"\n";
	file_metadata.write(write_option_encryption.c_str(), write_option_encryption.length());
	file_metadata << flag_option_default_encryption << "\n";
	file_metadata.write(write_cipher_key.c_str(), write_cipher_key.length());
	file_metadata << flag_option_defaultkey;
	if (strlen(encrypt_key) > 0) {
		file_metadata << "\n"<< encrypt_key;
	}
	if (strlen(decrypt_key) > 0) {
		file_metadata << "\n" << decrypt_key;
	}
	file_metadata.close();
}

void MainWindow::create_actions()
{
	action_readlog = new QAction(tr("&Load"));
	connect(action_readlog, SIGNAL(triggered()), this, SLOT(clicked_menu_load()));
	action_exit = new QAction(tr("E&xit"));
	connect(action_exit, SIGNAL(triggered()), this, SLOT(clicked_menu_exit()));
	action_user_rule = new QAction(tr("Add User Rule"));
	connect(action_user_rule, SIGNAL(triggered()), this, SLOT(clicked_tool_user_rule()));
	action_compress = new QAction(tr("&Compress"));
	connect(action_compress, SIGNAL(triggered()), this, SLOT(clicked_tool_compress()));
	action_decompress = new QAction(tr("&Deompress"));
	connect(action_decompress, SIGNAL(triggered()), this, SLOT(clicked_tool_decompress()));
	action_encryption_option = new QAction(tr("&Encryption_Option"));
	connect(action_encryption_option, SIGNAL(triggered()), this, SLOT(clicked_tool_encryption_option()));
	action_make_report = new QAction(tr("&Reporting"));
	connect(action_make_report, SIGNAL(triggered()), this, SLOT(clicked_tool_make_report()));
	action_convert_logdata = new QAction(tr("Con&vert Data"));
	connect(action_convert_logdata, SIGNAL(triggered()), this, SLOT(clicked_tool_convert_logdata()));
	action_control_panel = new QAction(tr("Control &Panel"));
	connect(action_control_panel, SIGNAL(triggered()), this, SLOT(clicked_tool_control_panel()));
	action_cmd = new QAction(tr("c&md -ARP"));
	connect(action_cmd, SIGNAL(triggered()), this, SLOT(clicked_tool_cmd()));
	action_aboutus = new QAction(tr("About &Us"));
	connect(action_aboutus, SIGNAL(triggered()), this, SLOT(clicked_help_aboutus()));
}

void MainWindow::create_menus()
{
	menu_main = menuBar()->addMenu(tr("&Menu"));
	menu_main->addAction(action_readlog);
	menu_main->addSeparator();
	menu_main->addAction(action_exit);

	menu_tool = menuBar()->addMenu(tr("&Tool"));
	menu_tool->addAction(action_user_rule);
	menu_tool->addAction(action_compress);
	menu_tool->addAction(action_decompress);
	menu_tool->addAction(action_encryption_option);
	menu_tool->addAction(action_make_report);
	menu_tool->addAction(action_convert_logdata);
	menu_tool->addSeparator();
	menu_tool->addAction(action_control_panel);
	menu_tool->addAction(action_cmd);

	menu_help = menuBar()->addMenu(tr("&Help"));
	menu_help->addAction(action_aboutus);
}


void MainWindow::create_tree_information()
{
	QStringList filters_fileformat;
	filters_fileformat << "*.db" << "*.des";
	QString path_master = "./Database\\";
	filemodel_directory = new QFileSystemModel(this);
	filemodel_directory->setFilter(QDir::NoDotAndDotDot | QDir::Files);
	filemodel_directory->setRootPath(path_master);
	filemodel_directory->setNameFilters(filters_fileformat);
	tree_datapath->setModel(filemodel_directory);
	tree_datapath->setRootIndex(filemodel_directory->index(path_master));
	tree_datapath->hideColumn(1);
	tree_datapath->hideColumn(2);
	tree_datapath->hideColumn(3);
	tree_datapath->hideColumn(4);
}

void MainWindow::allocate_widget_in_mainwindow()
{
	tree_datapath = new QTreeView();
	create_tree_information();
	connect(tree_datapath, SIGNAL(doubleClicked(QModelIndex)), this, SLOT(doubleclicked_treeview_item()));

	main_tab = new QTabWidget();
	tab_information = new TabInformation();
	tab_suspicious_report = new TabSuspiciousReport();
	tab_loginfo = new TabLogInfo();

	if (flag_failure_readlog == false) {
		tab_information->setTabInformation(loginfo_data);
		tab_suspicious_report->setTabSuspiciousReport(loginfo_data,define_rule ,log_db_connection, rule_count);
		tab_loginfo->setTabLogInfo(log_db_connection);
	}
	
	main_tab->addTab(tab_information, tr("Information"));
	main_tab->addTab(tab_suspicious_report, tr("Report"));
	main_tab->addTab(tab_loginfo, tr("Log data"));


	QHBoxLayout *layout_main = new QHBoxLayout;
	layout_main->addWidget(tree_datapath);
	layout_main->addWidget(main_tab);

	QWidget *widget_main = new QWidget;
	widget_main->setLayout(layout_main);
	setCentralWidget(widget_main);
}

bool MainWindow::read_logfile(ifstream& inputstream)
{
	inputstream.open("C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log.old");
	if (inputstream.is_open()) {
//		file_will_deleted.push_back("C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log.old");
		flag_logfile_isold = true;
		return true;
	}
	else {
		inputstream.close();
		inputstream.open("C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log");
		if (inputstream.is_open()) {
//			file_will_deleted.push_back("C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log");
			flag_logfile_isold = false;
			return true;
		}
		else {
			return false;
		}
	}

	if (inputstream.fail()) {
		return false;
	}
}

void MainWindow::processing_logfile()
{
	bool calculate_first = false;
	string string_logstream;
	string delimiters = " ";
	string date_firstday;
	string::size_type tokenloc_start;
	string::size_type tokenloc_last;
	deque<string> loginfo, tcpinfo, icmpinfo;
	int line_count = 1;
	int loginfo_count = 0, tcpinfo_count = 0;

	for (int i = 0; i < 6; i++) {
		getline(logstream, string_logstream);
	}

	getline(logstream, string_logstream);
	tokenloc_start = string_logstream.find_first_not_of(delimiters, 0);
	tokenloc_last = string_logstream.find_first_of(delimiters, tokenloc_start);
	loginfo.push_front(to_string(line_count));
	tcpinfo.push_front(to_string(line_count));
	icmpinfo.push_front(to_string(line_count));
	while (string::npos != tokenloc_last || string::npos != tokenloc_start) {
		if (loginfo_count < 9) {
			loginfo.push_back(string_logstream.substr(tokenloc_start, tokenloc_last - tokenloc_start));
			tokenloc_start = string_logstream.find_first_not_of(delimiters, tokenloc_last);
			tokenloc_last = string_logstream.find_first_of(delimiters, tokenloc_start);
			loginfo_count++;
		}
		else {
			if (tcpinfo_count < 4) {
				tcpinfo.push_back(string_logstream.substr(tokenloc_start, tokenloc_last - tokenloc_start));
				tokenloc_start = string_logstream.find_first_not_of(delimiters, tokenloc_last);
				tokenloc_last = string_logstream.find_first_of(delimiters, tokenloc_start);
				tcpinfo_count++;
			}
			else {
				icmpinfo.push_back(string_logstream.substr(tokenloc_start, tokenloc_last - tokenloc_start));
				tokenloc_start = string_logstream.find_first_not_of(delimiters, tokenloc_last);
				tokenloc_last = string_logstream.find_first_of(delimiters, tokenloc_start);
			}
		}
	}

	log_date_info.set_DBdate(loginfo.at(1));
	log_db_connection.set_dbinfo(log_date_info);
	log_db_connection.opendb();
	log_db_connection.createdbtable();
	filename_database.push_back(log_date_info.get_DBname());

	loginfo_data.setloginfo(loginfo);
	loginfo_data.setDBconnection(log_db_connection);
	loginfo_data.insertdb_loginfo();
	tcpinfo_data.settcpinfo(tcpinfo);
	tcpinfo_data.setDBconnection(log_db_connection);
	tcpinfo_data.insertdb_tcpinfo();
	icmpinfo_data.seticmpinfo(icmpinfo);
	icmpinfo_data.setDBconnection(log_db_connection);
	icmpinfo_data.insertdb_icmpinfo();
	Line_checker.set_logline_data(line_count, loginfo);
	Line_checker.process_checkpoint_line();
	Line_checker.insert_suspiciousinfo_in_database(log_db_connection.get_handle_DBconnection());
	line_count++;

	loginfo_count = 0;
	tcpinfo_count = 0;
	loginfo.erase(loginfo.begin(), loginfo.end());
	tcpinfo.erase(tcpinfo.begin(), tcpinfo.end());
	icmpinfo.erase(icmpinfo.begin(), icmpinfo.end());

	log_db_connection.start_db_transaction();

	while (!logstream.eof()) {
		getline(logstream, string_logstream);
		tokenloc_start = string_logstream.find_first_not_of(delimiters, 0);
		tokenloc_last = string_logstream.find_first_of(delimiters, tokenloc_start);

		if (string_logstream.length() <= 1) {
			break;
		}

		loginfo.push_front(to_string(line_count));
		tcpinfo.push_front(to_string(line_count));
		icmpinfo.push_front(to_string(line_count));
		while (string::npos != tokenloc_last || string::npos != tokenloc_start) {
			if (loginfo_count < 9) {
				loginfo.push_back(string_logstream.substr(tokenloc_start, tokenloc_last - tokenloc_start));
				tokenloc_start = string_logstream.find_first_not_of(delimiters, tokenloc_last);
				tokenloc_last = string_logstream.find_first_of(delimiters, tokenloc_start);
				loginfo_count++;
			}
			else {
				if (tcpinfo_count < 4) {
					tcpinfo.push_back(string_logstream.substr(tokenloc_start, tokenloc_last - tokenloc_start));
					tokenloc_start = string_logstream.find_first_not_of(delimiters, tokenloc_last);
					tokenloc_last = string_logstream.find_first_of(delimiters, tokenloc_start);
					tcpinfo_count++;
				}
				else {
					icmpinfo.push_back(string_logstream.substr(tokenloc_start, tokenloc_last - tokenloc_start));
					tokenloc_start = string_logstream.find_first_not_of(delimiters, tokenloc_last);
					tokenloc_last = string_logstream.find_first_of(delimiters, tokenloc_start);
				}
			}
		}

		if (log_date_info.get_DBdate() != loginfo.at(1)) {
			if (calculate_first == false) {
				loginfo_data.calculate_count();
				date_firstday = log_date_info.get_DBdate();
				calculate_first = true;
			}
			Query_checker.process_get_checkpoint(log_db_connection.get_handle_DBconnection());
			Multicondition_checker.process_checkpoint_multicondition(log_db_connection.get_handle_DBconnection());
			for (int check_rule_count = 0; check_rule_count < rule_count; check_rule_count++) {
				Userdefined_checker.set_checkpoint_userdefined(define_rule[check_rule_count]);
				Userdefined_checker.process_checkpoint_userdefined(log_db_connection.get_handle_DBconnection());
			}
			log_db_connection.end_db_transaction();
			log_db_connection.closedb();

			log_date_info.set_DBdate(loginfo.at(1));
			log_db_connection.set_dbinfo(log_date_info);
			log_db_connection.opendb();
			log_db_connection.createdbtable();
			filename_database.push_back(log_date_info.get_DBname());
			line_count = 1;

			log_db_connection.start_db_transaction();
		}
	
		loginfo_data.setloginfo(loginfo);
		loginfo_data.setDBconnection(log_db_connection);
		loginfo_data.insertdb_loginfo();
		tcpinfo_data.settcpinfo(tcpinfo);
		tcpinfo_data.setDBconnection(log_db_connection);
		tcpinfo_data.insertdb_tcpinfo();
		icmpinfo_data.seticmpinfo(icmpinfo);
		icmpinfo_data.setDBconnection(log_db_connection);
		icmpinfo_data.insertdb_icmpinfo();

		Line_checker.set_logline_data(line_count, loginfo);
		Line_checker.process_checkpoint_line();
		Line_checker.insert_suspiciousinfo_in_database(log_db_connection.get_handle_DBconnection());
		line_count++;
		loginfo_count = 0;
		tcpinfo_count = 0;
		loginfo.erase(loginfo.begin(), loginfo.end());
		tcpinfo.erase(tcpinfo.begin(), tcpinfo.end());
		icmpinfo.erase(icmpinfo.begin(), icmpinfo.end());
	}

	if (calculate_first == false) {
		loginfo_data.calculate_count();
		date_firstday = log_date_info.get_DBdate();
	}

	Query_checker.process_get_checkpoint(log_db_connection.get_handle_DBconnection());
	Multicondition_checker.process_checkpoint_multicondition(log_db_connection.get_handle_DBconnection());
	for (int check_rule_count = 0; check_rule_count < rule_count; check_rule_count++) {
		Userdefined_checker.set_checkpoint_userdefined(define_rule[check_rule_count]);
		Userdefined_checker.process_checkpoint_userdefined(log_db_connection.get_handle_DBconnection());
	}
	log_db_connection.end_db_transaction();
	log_db_connection.closedb();
	log_date_info.set_DBdate(date_firstday);
	log_db_connection.set_dbinfo(log_date_info);
	log_db_connection.opendb();
	logstream.close();
}

void MainWindow::processing_backup_log(bool flag_auto)
{
	if (flag_auto == false) {
		return;
	}
// Compress algorithm devloper choice.
/*
	string string_backup_filename = "./Backup\\";
	string string_metadata_filename = "./Backup\\";
	string_backup_filename.append(log_date_info.get_DBdate());
	string_backup_filename.append(".lzw");
	string_metadata_filename.append(log_date_info.get_DBdate());
	string_metadata_filename.append(".mtd");

	typedef void(*dll_prepare_resource)();
	typedef void(*dll_open_compress_file)(char*, const char *);
	typedef void(*dll_compress)();
	typedef void(*dll_close_compress_resource)();
	typedef void(*dll_write_metadata)(const char *);
	typedef void(*dll_release_resource)();
	QLibrary library_compress("./compress.dll");
	library_compress.load();

	dll_prepare_resource _prepare_resource = (dll_prepare_resource)library_compress.resolve("prepare_resource");
	dll_open_compress_file _open_compress_file = (dll_open_compress_file)library_compress.resolve("open_compress_file");
	dll_compress _compress = (dll_compress)library_compress.resolve("compress");
	dll_close_compress_resource _close_compress_resource = (dll_close_compress_resource)library_compress.resolve("close_compress_resource");
	dll_write_metadata _write_metadata = (dll_write_metadata)library_compress.resolve("write_metadata");
	dll_release_resource _release_resource = (dll_release_resource)library_compress.resolve("release_resoure");

	_prepare_resource();
	if (flag_logfile_isold == true) {
		_open_compress_file("C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log.old", string_backup_filename.c_str());
	}
	else {
		_open_compress_file("C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log", string_backup_filename.c_str());
	}
	_compress();
	_close_compress_resource();
	_write_metadata(string_metadata_filename.c_str());
	_release_resource();
	library_compress.unload();
*/
	return;
}


/*========================================= [ SLOT Implementation Part ] ========================================= */
void MainWindow::clicked_menu_load()
{
	QString string_load_path;
	string_load_path = QFileDialog::getOpenFileName(this, tr("Select File(Compress Mode)"), "C:\\Windows\\System32\\LogFiles\\Firewall\\", tr("Log File(*.log *.log.old)"));
	if (string_load_path.length() > 0) {
		log_db_connection.closedb();
		logstream.open((string_load_path.toStdString()));
		processing_logfile();

		tab_information->setTabInformation(loginfo_data);
		tab_suspicious_report->setTabSuspiciousReport(loginfo_data,define_rule ,log_db_connection, rule_count);
		tab_loginfo->setTabLogInfo(log_db_connection);
	}
	return;
}

void MainWindow::clicked_menu_exit()
{
	log_db_connection.closedb();

	Encryption encryption_auto;
	char *ptr_defaultkey;
	char *argument_origianl_file, *argument_encrypted_file;
	string name_encrypted_file;

	if (flag_option_default_encryption == true && flag_failure_readlog == false) {
		while (!filename_database.empty()) {
			name_encrypted_file = filename_database.front().substr(0, filename_database.front().length() - 3);
			name_encrypted_file.append(".des");
			argument_origianl_file = new char[filename_database.front().length() + 1];
			for (int copy = 0; copy < filename_database.front().length(); copy++) {
				argument_origianl_file[copy] = filename_database.front().at(copy);
			}
			argument_origianl_file[filename_database.front().length()] = '\0';
			argument_encrypted_file = new char[name_encrypted_file.length() + 2];
			for (int copy = 0; copy < name_encrypted_file.length(); copy++) {
				argument_encrypted_file[copy] = name_encrypted_file.at(copy);
			}
			argument_encrypted_file[filename_database.front().length() + 1] = '\0';


			if (strlen(encrypt_key) > 0) {
				encryption_auto.file_encrypt(argument_origianl_file, argument_encrypted_file, encrypt_key);
			}
			else {
				ptr_defaultkey = encryption_auto.get_defaultkey();
				for (int copy = 0; copy < LENGTH_KEY; copy++) {
					encrypt_key[copy] = *(ptr_defaultkey + copy);
				}
				encrypt_key[LENGTH_KEY] = '\0';
				encryption_auto.file_encrypt(argument_origianl_file, argument_encrypted_file, encrypt_key);
				ptr_defaultkey = encryption_auto.get_decryptkey(encrypt_key);
				for (int copy = 0; copy < LENGTH_KEY; copy++) {
					decrypt_key[copy] = *(ptr_defaultkey + copy);
				}
				decrypt_key[LENGTH_KEY] = '\0';
			}

			std::remove(filename_database.front().c_str());
			filename_database.pop_front();
		}
		delete[] argument_origianl_file;
		delete[] argument_encrypted_file;
	}

	while (!file_will_deleted.empty()) {
		std::remove(file_will_deleted.front().c_str());
		file_will_deleted.pop_front();
	}

	writing_metadata();
	this->close();
}

void MainWindow::clicked_tool_user_rule()
{
	Dialog_User_Firewall_Rule dialog_userfirwall(this);
	dialog_userfirwall.resize(1280,700);
	dialog_userfirwall.exec();
}

void MainWindow::clicked_tool_compress()
{
/* Compress Algorithm user choice.
	QString string_repo_path;
	QString string_compress_path, string_name_compress, string_name_metadata;
	QByteArray array_compress_path, array_name_compress, array_name_metadata;
	string_compress_path = QFileDialog::getOpenFileName(this, tr("Select File(Compress Mode)"), "C:\\Windows\\System32\\LogFiles\\Firewall\\", tr("Log File(*.log *.log.old)"));
	if (string_compress_path.length() != 0) {
		string_repo_path = string_compress_path;
		string_repo_path.replace(".log.old", "");
		string_repo_path.replace(".log", "");
		string_name_compress = string_repo_path;
		string_name_compress.append(".lzw");
		string_repo_path = string_compress_path;
		string_repo_path.replace(".log.old", "");
		string_repo_path.replace(".log", "");
		string_name_metadata = string_repo_path;
		string_name_metadata.append(".metadata");
		array_compress_path.append(string_compress_path);
		array_name_compress.append(string_name_compress);
		array_name_metadata.append(string_name_metadata);

		typedef void(*dll_prepare_resource)();
		typedef void(*dll_open_compress_file)(char*, char *);
		typedef void(*dll_compress)();
		typedef void(*dll_close_compress_resource)();
		typedef void(*dll_write_metadata)(char *);
		typedef void(*dll_release_resource)();
		QLibrary library_compress("./compress.dll");
		library_compress.load();

		dll_prepare_resource _prepare_resource = (dll_prepare_resource)library_compress.resolve("prepare_resource");
		dll_open_compress_file _open_compress_file = (dll_open_compress_file)library_compress.resolve("open_compress_file");
		dll_compress _compress = (dll_compress)library_compress.resolve("compress");
		dll_close_compress_resource _close_compress_resource = (dll_close_compress_resource)library_compress.resolve("close_compress_resource");
		dll_write_metadata _write_metadata = (dll_write_metadata)library_compress.resolve("write_metadata");
		dll_release_resource _release_resource = (dll_release_resource)library_compress.resolve("release_resoure");

		_prepare_resource();
		_open_compress_file(array_compress_path.data(), array_name_compress.data());
		_compress();
		_close_compress_resource();
		_write_metadata(array_name_metadata.data());
		_release_resource();
		library_compress.unload();
	}
*/
	return;
}

void MainWindow::clicked_tool_decompress()
{
/* Compress Algorithm user choice.
	QString string_repo_path;
	QString string_decompress_path, string_name_decompress, string_name_metadata;
	QByteArray array_decompress_path, array_name_decompress, array_name_metadata;
	string_decompress_path = QFileDialog::getOpenFileName(this, tr("Select File(Decompressed Mode)"), "./Backup", tr("Compressed File(*.lzw)"));
	if (string_decompress_path.length() != 0) {
		string_repo_path = string_decompress_path;
		string_repo_path.replace(".lzw", "");
		string_name_decompress = string_repo_path;
		string_name_decompress.append("_rev.log");
		string_repo_path = string_decompress_path;
		string_repo_path.replace(".lzw", "");
		string_name_metadata = string_repo_path;
		string_name_metadata.append(".mtd");
		array_decompress_path.append(string_decompress_path);
		array_name_decompress.append(string_name_decompress);
		array_name_metadata.append(string_name_metadata);

		typedef void(*dll_prepare_resource)();
		typedef void(*dll_open_expand_file)(char*, char *);
		typedef void(*dll_expand)();
		typedef void(*dll_close_expand_resource)();
		typedef void(*dll_read_metadata)(char *);
		typedef void(*dll_release_resource)();
		QLibrary library_compress("compress.dll");
		library_compress.load();

		dll_prepare_resource _prepare_resource = (dll_prepare_resource)library_compress.resolve("prepare_resource");
		dll_open_expand_file _open_exapnd_file = (dll_open_expand_file)library_compress.resolve("open_expand_file");
		dll_read_metadata _read_metadata = (dll_read_metadata)library_compress.resolve("read_metadata");
		dll_expand _expand = (dll_expand)library_compress.resolve("expand");
		dll_close_expand_resource _close_expand_resource = (dll_close_expand_resource)library_compress.resolve("close_expand_resource");
		dll_release_resource _release_resource = (dll_release_resource)library_compress.resolve("release_resoure");

		_prepare_resource();
		_open_exapnd_file(array_decompress_path.data(), array_name_decompress.data());
		_read_metadata(array_name_metadata.data());
		_expand();
		_close_expand_resource();
		_release_resource();
		library_compress.unload();
	}
*/
	return;
}

void MainWindow::clicked_tool_encryption_option()
{
	Dialog_Encryption_Option encryption_optiondialog(flag_option_default_encryption, flag_option_defaultkey);

	if (encryption_optiondialog.exec() == QDialog::Accepted) {
		flag_option_default_encryption = encryption_optiondialog.get_encryption_flag();
		flag_option_defaultkey = encryption_optiondialog.get_defaultkey_flag();
	}
}

void MainWindow::clicked_tool_make_report()
{
	QString string_name_savefile;
	QString data_write_copy;
	QTableWidgetItem *data_table_cell;
	int row_copy, column_copy;

	string_name_savefile = QFileDialog::getSaveFileName(this, tr("Designate Reporting File"), "./", tr("CSV(*.csv);; TXT(*.txt)"));

	if (string_name_savefile.mid(string_name_savefile.length() - 4) == QString(".csv")) {
		QFile reportfile_csv(string_name_savefile);
		row_copy = tab_suspicious_report->get_suspicious_table()->rowCount();
		column_copy = tab_suspicious_report->get_suspicious_table()->columnCount();
		data_write_copy += "Line, Date, SourceIP, DestinaitionIP, Protocol, Warning Message\n";
		for (int row = 0; row < row_copy; row++) {
			for (int column = 0; column < column_copy; column++) {
				data_table_cell = tab_suspicious_report->get_suspicious_table()->item(row, column);
				data_write_copy += data_table_cell->text();
				data_write_copy += ", ";
			}
			data_write_copy += "\n";
		}
		
		if (reportfile_csv.open(QIODevice::WriteOnly)) {
			QTextStream targetfile(&reportfile_csv);
			targetfile << data_write_copy;
			reportfile_csv.close();
		}
	}
	else if (string_name_savefile.mid(string_name_savefile.length() - 4) == QString(".txt")) {
		QFile reportfile_txt(string_name_savefile);
		row_copy = tab_suspicious_report->get_suspicious_table()->rowCount();
		column_copy = tab_suspicious_report->get_suspicious_table()->columnCount();
		data_write_copy += "Line\tDate\tSourceIP\tDestinaitionIP\tProtocol\tWarning Message\n";
		for (int row = 0; row < row_copy; row++) {
			for (int column = 0; column < column_copy; column++) {
				data_table_cell = tab_suspicious_report->get_suspicious_table()->item(row, column);
				data_write_copy += data_table_cell->text();
				data_write_copy += "\t";
			}
			data_write_copy += "\n";
		}

		if (reportfile_txt.open(QIODevice::WriteOnly)) {
			QTextStream targetfile(&reportfile_txt);
			targetfile << data_write_copy;
			reportfile_txt.close();
		}
	}
	return;
}

void MainWindow::clicked_tool_convert_logdata()
{
	QString string_name_savefile;
	QString data_write_copy;
	QTableWidgetItem *data_table_cell;
	int row_copy, column_copy;

	string_name_savefile = QFileDialog::getSaveFileName(this, tr("Designate Reporting File"), "./", tr("CSV(*.csv);; TXT(*.txt)"));

	if (string_name_savefile.mid(string_name_savefile.length() - 4) == QString(".csv")) {
		QFile reportfile_csv(string_name_savefile);
		row_copy = tab_loginfo->get_loginfo_table()->rowCount();
		column_copy = tab_loginfo->get_loginfo_table()->columnCount();
		data_write_copy += "Date, Time, Action, Protocol, SourceIP, DestinaitionIP, SourcePort, DestinationPort, Size\n";
		for (int row = 0; row < row_copy; row++) {
			for (int column = 0; column < column_copy; column++) {
				data_table_cell = tab_loginfo->get_loginfo_table()->item(row, column);
				data_write_copy += data_table_cell->text();
				data_write_copy += ", ";
			}
			data_write_copy += "\n";
		}

		if (reportfile_csv.open(QIODevice::WriteOnly)) {
			QTextStream targetfile(&reportfile_csv);
			targetfile << data_write_copy;
			reportfile_csv.close();
		}
	}
	else if (string_name_savefile.mid(string_name_savefile.length() - 4) == QString(".txt")) {
		QFile reportfile_txt(string_name_savefile);
		row_copy = tab_loginfo->get_loginfo_table()->rowCount();
		column_copy = tab_loginfo->get_loginfo_table()->columnCount();
		data_write_copy += "Date\tTime\tAction\tProtocol\tSourceIP\tDestinaitionIP\tSourcePort\tDestinationPort\tSize\n";
		for (int row = 0; row < row_copy; row++) {
			for (int column = 0; column < column_copy; column++) {
				data_table_cell = tab_loginfo->get_loginfo_table()->item(row, column);
				data_write_copy += data_table_cell->text();
				data_write_copy += "\t";
			}
			data_write_copy += "\n";
		}

		if (reportfile_txt.open(QIODevice::WriteOnly)) {
			QTextStream targetfile(&reportfile_txt);
			targetfile << data_write_copy;
			reportfile_txt.close();
		}
	}
	return;
}

void MainWindow::clicked_tool_control_panel()
{
	WinExec("control.exe", SW_SHOW);
	return;
}

void MainWindow::clicked_tool_cmd()
{
	ShellExecute(NULL, L"open", L"cmd.exe", L"/K arp -a", L"C:\\", SW_SHOW);
	return;
}

void MainWindow::clicked_help_aboutus()
{
	Dialog_Aboutus *aboutus_dialog;
	aboutus_dialog = new Dialog_Aboutus;

	aboutus_dialog->show();
	aboutus_dialog->raise();
	aboutus_dialog->activateWindow();
	return;
}

void MainWindow::doubleclicked_treeview_item()
{
	Encryption decryption_auto;
	char *encrypted_data_path, *decrypted_data_path;

	QModelIndex index_current_data = tree_datapath->currentIndex();
	QVariant current_data = tree_datapath->model()->data(index_current_data);
	QString current_data_path, current_file_date;
	if (flag_failure_readlog == true) 
	{
		current_data_path = "./Database\\";
	}
	current_data_path += current_data.toString();
	current_file_date = current_data.toString();
	current_file_date.replace("./Database\\", "");
	current_file_date.replace(".des", "");
	current_file_date.replace(".db", "");
	current_file_date.replace("Win_Firewall_Log_", "");
	string std_string_data_path = current_data_path.toStdString();
	string temp_data_path = current_data_path.toStdString();
	string data_file_date = current_file_date.toStdString();
	std_string_data_path = std_string_data_path.substr(std_string_data_path.length() - 4, std_string_data_path.length());
	
	if (std_string_data_path == ".des") {
		std_string_data_path = "./Database\\"; 
		std_string_data_path.append(current_data_path.toStdString());
		encrypted_data_path = new char[std_string_data_path.length() + 1];
		for (int copy = 0; copy < std_string_data_path.length(); copy++) {
			encrypted_data_path[copy] = std_string_data_path.at(copy);
		}
		encrypted_data_path[std_string_data_path.length()] = '\0';
		temp_data_path = temp_data_path.substr(0, temp_data_path.length() - 4);
		temp_data_path.append(".db");
		string temp_path = temp_data_path;
		temp_data_path = "./Database\\";
		temp_data_path.append(temp_path);
		file_will_deleted.push_back(temp_data_path);
		decrypted_data_path = new char[temp_data_path.length() + 1];
		for (int copy = 0; copy < temp_data_path.length(); copy++) {
			decrypted_data_path[copy] = temp_data_path.at(copy);
		}
		decrypted_data_path[temp_data_path.length()] = '\0';

		decryption_auto.file_decrypt(encrypted_data_path, decrypted_data_path,decrypt_key);

		delete[] encrypted_data_path;
		delete[] decrypted_data_path;
	}

	log_db_connection.closedb();
	log_date_info.set_DBdate(data_file_date);
	log_db_connection.set_dbinfo(log_date_info);
	log_db_connection.opendb();
	loginfo_data.setDBconnection(log_db_connection);
	loginfo_data.calculate_count();

	tab_information->setTabInformation(loginfo_data);
	tab_suspicious_report->setTabSuspiciousReport(loginfo_data, define_rule ,log_db_connection, rule_count);
	tab_loginfo->setTabLogInfo(log_db_connection);
}

TabInformation::TabInformation(QWidget *parent) : QWidget(parent)
{
	series_protocol = new QtCharts::QPieSeries();
	label_protocol = new QLabel(tr("Protocol List"));
	list_protocol = new QListWidget;

	series_srcip = new QtCharts::QPieSeries();
	label_srcip = new QLabel(tr("SourceIP List(MAX 5)"));
	list_srcip = new QListWidget;

	series_dstip = new QtCharts::QPieSeries();
	label_dstip = new QLabel(tr("DestinationIP List(MAX 5)"));
	list_dstip = new QListWidget;

	chart_protocol = new QtCharts::QChart();
	chartview_protocol = new QtCharts::QChartView();
	chart_srcip = new QtCharts::QChart();
	chartview_srcip = new QtCharts::QChartView();
	chart_dstip = new QtCharts::QChart();
	chartview_dstip = new QtCharts::QChartView();

	layout_protocol_information = new QVBoxLayout;
	layout_protocol_information->addWidget(label_protocol);
	layout_protocol_information->addWidget(list_protocol);

	layout_protocol = new QHBoxLayout;
	layout_protocol->addWidget(chartview_protocol);
	layout_protocol->addLayout(layout_protocol_information);

	layout_srcip_information = new QVBoxLayout;
	layout_srcip_information->addWidget(label_srcip);
	layout_srcip_information->addWidget(list_srcip);

	layout_srcip = new QHBoxLayout;
	layout_srcip->addWidget(chartview_srcip);
	layout_srcip->addLayout(layout_srcip_information);

	layout_dstip_information = new QVBoxLayout;
	layout_dstip_information->addWidget(label_dstip);
	layout_dstip_information->addWidget(list_dstip);

	layout_dstip = new QHBoxLayout;
	layout_dstip->addWidget(chartview_dstip);
	layout_dstip->addLayout(layout_dstip_information);

	mainlayout = new QVBoxLayout;
	mainlayout->addLayout(layout_protocol);
	mainlayout->addLayout(layout_srcip);
	mainlayout->addLayout(layout_dstip);
	setLayout(mainlayout);
}

void TabInformation::setTabInformation(Loginfo_Table &input_loginfo)
{
	string name_color[6] = { "red", "cyan", "yellow", "magenta","blue","lightGray" };
	int amount_data = 0;

	series_protocol->clear();
	series_srcip->clear();
	series_dstip->clear();
	list_protocol->clear();
	list_srcip->clear();
	list_dstip->clear();

	for (int sum_loop = 0; sum_loop < input_loginfo.get_size_protocol(); sum_loop++) {
		amount_data += input_loginfo.data_amount_protocol.at(sum_loop);
	}
	for (int loop_protocol = 0; loop_protocol < input_loginfo.get_size_protocol(); loop_protocol++) {
		double percent_protocol = ((double)(input_loginfo.data_amount_protocol.at(loop_protocol) / (double)amount_data) * 100);
		series_protocol->append(QString::fromStdString(input_loginfo.data_log_protocol.at(loop_protocol)), (int)percent_protocol);
		list_protocol->addItem(QString::fromStdString(input_loginfo.data_log_protocol.at(loop_protocol)));
	}

	QColor color;
	for (int i = 0; i < series_protocol->count(); i++) {
		color = QColor::QColor(name_color[i].c_str());
		series_protocol->slices().at(i)->setBrush(color);

	}

	chart_protocol->addSeries(series_protocol);
	chart_protocol->setTitle("Protocol Statics");
	chart_protocol->legend()->setAlignment(Qt::AlignRight);

	chartview_protocol->setChart(chart_protocol);
	chartview_protocol->setRenderHint(QPainter::Antialiasing);
	amount_data = 0;

	for (int sum_loop = 0; sum_loop < MAX_SIZE_IP_DATA; sum_loop++) {
		amount_data += *(input_loginfo.get_amount_srcip() + sum_loop);
	}
	for (int loop_srcip = 0; loop_srcip < MAX_SIZE_IP_DATA; loop_srcip++) {
		double percent_scrip = (((double)*(input_loginfo.get_amount_srcip() + loop_srcip) / (double)amount_data) * 100);
		series_srcip->append(QString::fromStdString(*(input_loginfo.get_log_srcip() + loop_srcip)), (int)percent_scrip);
		list_srcip->addItem(QString::fromStdString(*(input_loginfo.get_log_srcip() + loop_srcip)));
	}

	for (int i = 0; i < series_srcip->count(); i++) {
		color = QColor::QColor(name_color[i].c_str());
		series_srcip->slices().at(i)->setBrush(color);

	}

	chart_srcip->addSeries(series_srcip);
	chart_srcip->setTitle("SourceIP Statics");
	chart_srcip->legend()->setAlignment(Qt::AlignRight);

	chartview_srcip->setChart(chart_srcip);
	chartview_srcip->setRenderHint(QPainter::Antialiasing);
	amount_data = 0;

	for (int sum_loop = 0; sum_loop < MAX_SIZE_IP_DATA; sum_loop++) {
		amount_data += *(input_loginfo.get_amount_dstip() + sum_loop);
	}
	for (int loop_dstip = 0; loop_dstip < MAX_SIZE_IP_DATA; loop_dstip++) {
		double percent_dstip = (((double)*(input_loginfo.get_amount_dstip() + loop_dstip) / amount_data) * 100);
		series_dstip->append(QString::fromStdString(*(input_loginfo.get_log_dstip() + loop_dstip)), (int)percent_dstip);
		list_dstip->addItem(QString::fromStdString(*(input_loginfo.get_log_dstip() + loop_dstip)));
	}

	for (int i = 0; i < series_dstip->count(); i++) {
		color = QColor::QColor(name_color[i].c_str());
		series_dstip->slices().at(i)->setBrush(color);

	}

	chart_dstip->addSeries(series_dstip);
	chart_dstip->setTitle("DestinationIP Statics");
	chart_dstip->legend()->setAlignment(Qt::AlignRight);

	chartview_dstip->setChart(chart_dstip);
	chartview_dstip->setRenderHint(QPainter::Antialiasing);

	layout_protocol_information->addWidget(label_protocol);
	layout_protocol_information->addWidget(list_protocol);

	layout_protocol->addWidget(chartview_protocol);
	layout_protocol->addLayout(layout_protocol_information);

	layout_srcip_information->addWidget(label_srcip);
	layout_srcip_information->addWidget(list_srcip);

	layout_srcip->addWidget(chartview_srcip);
	layout_srcip->addLayout(layout_srcip_information);

	layout_dstip_information->addWidget(label_dstip);
	layout_dstip_information->addWidget(list_dstip);

	layout_dstip->addWidget(chartview_dstip);
	layout_dstip->addLayout(layout_dstip_information);

	mainlayout->addLayout(layout_protocol);
	mainlayout->addLayout(layout_srcip);
	mainlayout->addLayout(layout_dstip);
	setLayout(mainlayout);
}

TabSuspiciousReport::TabSuspiciousReport(QWidget *parent) : QWidget(parent)
{
	table_suspicious = new QTableWidget();

	layout_main = new QVBoxLayout;
	layout_main->addWidget(table_suspicious);
	setLayout(layout_main);
}

void TabSuspiciousReport::setTabSuspiciousReport(Loginfo_Table &input_loginfo, user_rule_info *userule_info, Manage_DB_Connection &connection_database, int rule_count_input)
{
	int flag_table_row, amount_warninfo = 0;
	int flag_warninfo = -1;
	int index_row_warninfo = 0;
	sqlite3_stmt *query_get_warninfo;
	string query_amount_warninfo = "select COUNT(*) from WARNINFOTBL;";
	string query_warninfo = "select * from WARNINFOTBL;";
	string query_loginfo = "select Date, SourceIP, DestinationIP, Protocol from LOGINFOTBL as LOGTBL, WARNINFOTBL as WARNTBL WHERE LOGTBL.Line = WARNTBL.WARNLine ORDER BY WARNLine ASC;";
	string repo_temp_result;
	string message_warninfo;

	sqlite3_prepare_v2(connection_database.get_handle_DBconnection(), query_amount_warninfo.c_str(), -1, &query_get_warninfo, NULL);
	sqlite3_step(query_get_warninfo);
	repo_temp_result = (char *)sqlite3_column_text(query_get_warninfo, 0);
	amount_warninfo = stoi(repo_temp_result);
	repo_temp_result.clear();
	sqlite3_finalize(query_get_warninfo);

	table_suspicious->setColumnCount(6);
	table_suspicious->setRowCount(amount_warninfo);
	table_suspicious->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
	table_suspicious->setHorizontalHeaderLabels(QString("Line ;Date ;SourceIP ;DestinaitionIP ;Protocol ;Warning Message").split(";"));

	sqlite3_prepare_v2(connection_database.get_handle_DBconnection(), query_warninfo.c_str(), -1, &query_get_warninfo, NULL);
	flag_table_row = sqlite3_step(query_get_warninfo);
	while (flag_table_row == SQLITE_ROW) {
		repo_temp_result = (char *)sqlite3_column_text(query_get_warninfo, 1);
		flag_warninfo = stoi(repo_temp_result);
		message_warninfo = get_message_warning(flag_warninfo, userule_info , rule_count_input);
		repo_temp_result = (char *)sqlite3_column_text(query_get_warninfo, 0);
		table_suspicious->setItem(index_row_warninfo, 0, new QTableWidgetItem(QString::fromStdString(repo_temp_result)));
		table_suspicious->setItem(index_row_warninfo, 5, new QTableWidgetItem(QString::fromStdString(message_warninfo)));
		flag_table_row = sqlite3_step(query_get_warninfo);
		index_row_warninfo++;
		repo_temp_result.clear();
		flag_warninfo = -1;
	}
	sqlite3_finalize(query_get_warninfo);

	index_row_warninfo = 0;
	sqlite3_prepare_v2(connection_database.get_handle_DBconnection(), query_loginfo.c_str(), -1, &query_get_warninfo, NULL);
	flag_table_row = sqlite3_step(query_get_warninfo);
	while (flag_table_row == SQLITE_ROW) {
		repo_temp_result = (char *)sqlite3_column_text(query_get_warninfo, 0);
		table_suspicious->setItem(index_row_warninfo, 1, new QTableWidgetItem(QString::fromStdString(repo_temp_result)));
		repo_temp_result = (char *)sqlite3_column_text(query_get_warninfo, 1);
		table_suspicious->setItem(index_row_warninfo, 2, new QTableWidgetItem(QString::fromStdString(repo_temp_result)));
		repo_temp_result = (char *)sqlite3_column_text(query_get_warninfo, 2);
		table_suspicious->setItem(index_row_warninfo, 3, new QTableWidgetItem(QString::fromStdString(repo_temp_result)));
		repo_temp_result = (char *)sqlite3_column_text(query_get_warninfo, 3);
		table_suspicious->setItem(index_row_warninfo, 4, new QTableWidgetItem(QString::fromStdString(repo_temp_result)));
		flag_table_row = sqlite3_step(query_get_warninfo);
		index_row_warninfo++;
		repo_temp_result.clear();
	}
	sqlite3_finalize(query_get_warninfo);
	table_suspicious->horizontalHeader()->setStretchLastSection(true);
	layout_main->addWidget(table_suspicious);
	setLayout(layout_main);
}


QTableWidget* TabSuspiciousReport::get_suspicious_table()
{
	return table_suspicious;
}

string TabSuspiciousReport::get_message_warning(int flag_type_warn, user_rule_info *userule_info, int rule_count_input)
{
	string message_return;
	switch (flag_type_warn) {
	case 1:
		message_return = "This log warns of port scan attempts.";
		return message_return;
	case 2:
		message_return = "This log warns of service enumeration attempts.";
		return message_return;
	case 3:
		message_return = "This log warns \'MS frontpage server extension buffer overflow\' attempts.";
		return message_return;
	case 4:
		message_return = "This log warns \'MS messagner heap overflow\' attempts.";
		return message_return;
	case 5:
		message_return = "This log warns \'LSASS.DLL RPC buffer overflow\' attempts.";
		return message_return;
	case 6:
		message_return = "This log warns \'IPswitch IMAIL LDAP remote attack\' attempts.";
		return message_return;
	case 7:
		message_return = "This log warns \'Windows XP/2000 return into Libc attack\' attempts.";
		return message_return;
	case 8:
		message_return = "This log warns \'Windows Workstation service WKSSVC Libc attack\' attempts.";
		return message_return;
	case 9:
		message_return = "This log warns \'MSMQ heap overflow attack\' attempts.";
		return message_return;
	case 10:
		message_return = "This log warns \'ProFTPD ASCII file remote rooot exploit attack\' attempts.";
		return message_return;
	case 11:
		message_return = "This log warns ";
		return message_return;
	case 12:
		message_return = "This log warns \'WFTPD STAT command remote exploit attack\' attempts.";
		return message_return;
	case 13:
		message_return = "This log warns \'Phatbot/Agobot/Gaobot worm attack\'";
		return message_return;
	case 14:
		message_return = "This log warns \'Dameware Probe attack\'";
		return message_return;
	case 15:
		message_return = "This log warns \'Doomjuice worm attack\'";
	default:
		goto CHECK_USER_DEFINE_RULE;
		break;
	}
CHECK_USER_DEFINE_RULE:
	if (flag_type_warn >= 100) {
		for (int search_type = 0; search_type < rule_count_input; search_type++) {
			if (flag_type_warn == userule_info[search_type].displacement_value + FLAG_USER_DEFINED_RULE) {
				message_return = userule_info[search_type].content_suspicious;
				return message_return;
			}
		}
		message_return = "This suspicious information which is defined is deleted by user.";
		return message_return;
	}
	else {
		message_return = "This log warns unknown attack attempts.";
		return message_return;
	}
}

TabLogInfo::TabLogInfo(QWidget *parent) : QWidget(parent)
{
	table_loginfo = new QTableWidget();

	layout_main = new QVBoxLayout;
	layout_main->addWidget(table_loginfo);
	setLayout(layout_main);
}

void TabLogInfo::setTabLogInfo(Manage_DB_Connection &connection_database)
{
	sqlite3_stmt *stmt_getloginfo;
	string query_amount_loginfo = "select COUNT(*) from LOGINFOTBL;";
	string query_get_loginfo = "select * from LOGINFOTBL;";
	string repo_temp_result;
	int amount_loginfo;
	int flag_table_row;
	int index_row_loginfo = 0;

	sqlite3_prepare_v2(connection_database.get_handle_DBconnection(), query_amount_loginfo.c_str(), -1, &stmt_getloginfo, NULL);
	sqlite3_step(stmt_getloginfo);
	repo_temp_result = (char *)sqlite3_column_text(stmt_getloginfo, 0);
	amount_loginfo = stoi(repo_temp_result);
	repo_temp_result.clear();
	sqlite3_finalize(stmt_getloginfo);

	table_loginfo->setColumnCount(9);
	table_loginfo->setRowCount(amount_loginfo);
	table_loginfo->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
	table_loginfo->setHorizontalHeaderLabels(QString("Date ;Time ;Action ;Protocol ;SourceIP ;DestinaitionIP ;SourcePort ;DestinationPort ;Size").split(";"));
	table_loginfo->hideColumn(8);

	sqlite3_prepare_v2(connection_database.get_handle_DBconnection(), query_get_loginfo.c_str(), -1, &stmt_getloginfo, NULL);
	flag_table_row = sqlite3_step(stmt_getloginfo);
	while (flag_table_row == SQLITE_ROW) {
		for (int column_number = 1; column_number < 10; column_number++) {
			repo_temp_result = (char *)sqlite3_column_text(stmt_getloginfo, column_number);
			table_loginfo->setItem(index_row_loginfo, column_number - 1, new QTableWidgetItem(QString::fromStdString(repo_temp_result)));
			repo_temp_result.clear();
		}
		flag_table_row = sqlite3_step(stmt_getloginfo);
		index_row_loginfo++;
		repo_temp_result.clear();
	}
	sqlite3_finalize(stmt_getloginfo);

	table_loginfo->horizontalHeader()->setStretchLastSection(true);
	layout_main->addWidget(table_loginfo);
	setLayout(layout_main);
}

QTableWidget* TabLogInfo::get_loginfo_table()
{
	return table_loginfo;
}
