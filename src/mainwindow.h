#pragma once
#ifndef MAINWINDOW_H
#define MAINWINDOW_H
#include <QtWidgets>
#include <qfiledialog.h>
#include <qfilesystemmodel.h>
#include <qlibrary.h>
#include <QtCharts/qchart.h>
#include <QtCharts/qchartview.h>
#include <QtCharts/qpieslice.h>
#include <QtCharts/qpieseries.h>
#include <string>
#include <fstream>
#include <deque>
#include "handledblib.h"
#include "checklogfile.h"
#include "cipher.h"
#include "dialog.h"

#define LOG_MAXIMUM_COUNT 30

class QAction;
class QFileDialog;
class QFileSystemModel;
class QLabel;
class QListWidget;
class QLibrary;
class QTabWidget;
class QTableWidget;
class QTreeView;
class QWidget;
class QSplashScreen;
class QtCharts::QPieSeries;
class QtCharts::QChart;
class QtCharts::QChartView;

class TabInformation : public QWidget
{
	Q_OBJECT

public:
	TabInformation(QWidget *parent = 0);
	void setTabInformation(Loginfo_Table &input_info);

private:
	QtCharts::QChart *chart_protocol;
	QtCharts::QChart *chart_srcip;
	QtCharts::QChart *chart_dstip;

	QtCharts::QChartView *chartview_protocol;
	QtCharts::QChartView *chartview_srcip;
	QtCharts::QChartView *chartview_dstip;

	QtCharts::QPieSeries *series_protocol;
	QtCharts::QPieSeries *series_srcip;
	QtCharts::QPieSeries *series_dstip;

	QLabel *label_protocol;
	QLabel *label_srcip;
	QLabel *label_dstip;

	QVBoxLayout *layout_protocol_information;
	QVBoxLayout *layout_srcip_information;
	QHBoxLayout *layout_protocol;
	QHBoxLayout *layout_srcip;
	QVBoxLayout *layout_dstip_information;
	QHBoxLayout *layout_dstip;
	QVBoxLayout *mainlayout;

	QListWidget *list_protocol;
	QListWidget *list_srcip;
	QListWidget *list_dstip;
};

class TabSuspiciousReport : public QWidget
{
	Q_OBJECT

public:
	TabSuspiciousReport(QWidget *parent = 0);
	void setTabSuspiciousReport(Loginfo_Table &input_info, user_rule_info *userule_info, Manage_DB_Connection &connection_database, int rule_count_input);
	QTableWidget *get_suspicious_table();

private slots:

private:
	string get_message_warning(int flag_type_warn, user_rule_info *userule_info, int rule_count_input);
	QTableWidget *table_suspicious;
	QVBoxLayout *layout_main;
};

class TabLogInfo : public QWidget
{
	Q_OBJECT

public:
	TabLogInfo(QWidget *parent = 0);
	void setTabLogInfo(Manage_DB_Connection &connection_database);
	QTableWidget *get_loginfo_table();

private slots:

private:
	QTableWidget *table_loginfo;
	QVBoxLayout *layout_main;
};

class MainWindow : public QMainWindow
{
	Q_OBJECT;

public:
	MainWindow();

	Set_DBinfo log_date_info;
	Manage_DB_Connection log_db_connection;
	Loginfo_Table loginfo_data;
	TCPinfo_Table tcpinfo_data;
	ICMPinfo_Table icmpinfo_data;

	CheckPoint_Line Line_checker;
	CheckPoint_Query Query_checker;
	CheckPoint_Multi_Condition Multicondition_checker;
	CheckPoint_UserDefined Userdefined_checker;
	
private slots:
	void clicked_menu_load();
	void clicked_menu_exit();
	void clicked_tool_user_rule();
	void clicked_tool_compress();
	void clicked_tool_decompress();
	void clicked_tool_encryption_option();
	void clicked_tool_make_report();
	void clicked_tool_convert_logdata();
	void clicked_tool_control_panel();
	void clicked_tool_cmd();
	void clicked_help_aboutus();
	void doubleclicked_treeview_item();

private:
	char encrypt_key[5];
	char decrypt_key[5];
	deque<string> filename_database;
	deque<string> file_will_deleted;
	user_rule_info define_rule[MAX_USER_RULE];
	int rule_count;

	void create_actions();
	void create_menus();
	void create_tree_information();

	bool read_logfile(ifstream& inputstream);
	void reading_metadata_program();
	void reading_metadata_rule();
	void writing_metadata();
	void processing_logfile();
	void processing_backup_log(bool flag_auto);
	void allocate_widget_in_mainwindow();

	bool flag_logfile_isold;
	bool flag_failure_readlog;
	bool flag_option_autobackup;
	bool flag_option_default_encryption;
	bool flag_option_defaultkey;

	QAction *action_readlog;
	QAction *action_exit;
	QAction *action_user_rule;
	QAction *action_compress;
	QAction *action_decompress;
	QAction *action_encryption_option;
	QAction *action_make_report;
	QAction *action_convert_logdata;
	QAction *action_control_panel;
	QAction *action_cmd;
	QAction *action_aboutus;

	QFileSystemModel *filemodel_directory;

	QTreeView *tree_datapath;
	QTabWidget *main_tab;

	TabSuspiciousReport *tab_suspicious_report;
	TabLogInfo *tab_loginfo;
	TabInformation *tab_information;
	
	QMenu *menu_main;
	QMenu *menu_tool;
	QMenu *menu_help;
	
	ifstream logstream;
};

#endif // !MAINWINDOW_H
