#pragma once
#ifndef DIALOG_H
#define DIALOG_H
#include <QtWidgets>
#include <qdialog.h>
#include <qlineedit.h>
#include <iostream>
#include <fstream>
#include <string>
#define MAX_USER_RULE 30
#define MAX_USER_RULE_COLUMN 8
using namespace std;

class QComboBox;
class QCheckBox;
class QDialog;
class QFileDialog;
class QLabel;
class QLineEdit;
class QTableWidget;
class QPushButton;

class Dialog_Encryption_Option : public QDialog
{
	Q_OBJECT;

public:
	Dialog_Encryption_Option(bool flag_encryption = true, bool flag_defaultkey = true, QWidget *parent = 0);
	QString get_input_key();
	bool get_encryption_flag();
	bool get_defaultkey_flag();

private slots:
	void enable_ok_button(const QString &text);
	void enable_edit_key();
	void clicked_box_encryption();
	void clicked_box_defaultkey();

private:
	bool flag_dialog_encryption;
	bool flag_dialog_defaultkey;

	QComboBox *combobox_encrypt_algorithm;
	QCheckBox *checkbox_default_encrypt;
	QCheckBox *checkbox_default_key;

	QLabel *label_encrypt_algorithm;
	QLabel *label_default_encrypt;
	QLabel *label_default_key;
	QLabel *label_edit_input_key;

	QLineEdit *edit_input_key;

	QPushButton *button_change_ok;
	QPushButton *button_cancel;
};

class Dialog_User_Set_Rule : public QDialog
{
	Q_OBJECT

public:
	Dialog_User_Set_Rule(QWidget *parent = 0);
	void get_user_rule(QString *info);

private slots:
	void click_box_action();
	void click_box_protocol();
	void click_box_sourceip();
	void click_box_destinationip();
	void click_box_sourceport();
	void click_box_destinationport();
	void click_box_name_rule();

private:
	QLabel *label_action;
	QLabel *label_protocol;
	QLabel *label_sourceip;
	QLabel *label_destinationip;
	QLabel *label_sourceport;
	QLabel *label_destinationport;
	QLabel *label_name_rule;

	QLineEdit *edit_sourceip;
	QLineEdit *edit_destinationip;
	QLineEdit *edit_sourceport;
	QLineEdit *edit_destinationport;
	QLineEdit *edit_protocol;
	QLineEdit *edit_action;
	QLineEdit *edit_name_rule;

	QCheckBox *check_sourceip;
	QCheckBox *check_destinationip;
	QCheckBox *check_sourceport;
	QCheckBox *check_destinationport;
	QCheckBox *check_protocol;
	QCheckBox *check_action;
	QCheckBox *check_name_rule;

	QPushButton *button_addrule;
	QPushButton *button_cancel;
};

class Dialog_User_Firewall_Rule : public QDialog
{
	Q_OBJECT

public:
	Dialog_User_Firewall_Rule(QWidget *parent = 0);
	QTableWidget *get_user_firewall_rule_info();

private slots:
	void clicked_addrule_button();
	void clicked_delete_button();
	void reject();

private:
	void reading_metadata();
	void writing_metadata();

	ifstream read_metadata;
	ofstream write_metadata;
	int size_user_rule;
	int index_table_row , index_table_column;
	int current_rule_displacement;

	QPushButton *button_addrule;
	QPushButton *button_close;
	QPushButton *button_delete;

	QTableWidget *table_user_firewall_rule;
	QHBoxLayout *layout_button;
	QHBoxLayout *layout_table;
	QVBoxLayout *layout_main;
};

class Dialog_Aboutus : public QDialog
{
	Q_OBJECT

public:
	Dialog_Aboutus(QWidget *parent = 0);
private:
	QLabel *label_message_content;
	QLabel *label_message_developer;
	QLabel *label_message_contact;

	QPushButton *button_ok;
};
#endif