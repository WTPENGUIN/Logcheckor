#include "dialog.h"

Dialog_Encryption_Option::Dialog_Encryption_Option(bool flag_encryption ,bool flag_defaultkey, QWidget *parent) : QDialog(parent)
{
	flag_dialog_encryption = flag_encryption;
	flag_dialog_defaultkey = flag_defaultkey;
	combobox_encrypt_algorithm = new QComboBox;
	combobox_encrypt_algorithm->addItem("Default Algorithm");
	combobox_encrypt_algorithm->sizeHint();

	checkbox_default_encrypt= new QCheckBox;
	if (flag_encryption == true) {
		checkbox_default_encrypt->setChecked(true);
	}
	else {
		checkbox_default_encrypt->setChecked(false);
	}
	checkbox_default_key = new QCheckBox;
	if (flag_defaultkey == true) {
		checkbox_default_key->setChecked(true);
	}
	else {
		checkbox_default_key->setChecked(false);
	}

	label_encrypt_algorithm = new QLabel(tr("Select Encryption algorithm : "));
	label_default_encrypt = new QLabel(tr("Defalut Encryption Check : "));
	label_default_key = new QLabel(tr("Default Cipher key Check : "));
	label_edit_input_key = new QLabel(tr("Input New Key(4 character)"));

	edit_input_key = new QLineEdit;
	label_edit_input_key->setBuddy(edit_input_key);
	edit_input_key->setEnabled(false);

	button_change_ok = new QPushButton(tr("OK"));
	if (flag_defaultkey == true) {
		button_change_ok->setEnabled(true);
	}
	else {
		button_change_ok->setEnabled(false);
	}
	button_change_ok->setDefault(true);
	button_cancel = new QPushButton(tr("Cancel"));

	connect(button_change_ok, SIGNAL(clicked()), this, SLOT(accept()));
	connect(button_cancel, SIGNAL(clicked()), this, SLOT(reject()));
	connect(checkbox_default_key, SIGNAL(clicked()), this, SLOT(enable_edit_key()));
	connect(checkbox_default_encrypt, SIGNAL(clicked()), this, SLOT(clicked_box_encryption()));
	connect(checkbox_default_key, SIGNAL(clicked()), this, SLOT(clicked_box_defaultkey()));
	connect(edit_input_key, SIGNAL(textChanged(const QString &)), this, SLOT(enable_ok_button(const QString &)));

	QHBoxLayout *layout_algorithm = new QHBoxLayout;
	layout_algorithm->addWidget(label_encrypt_algorithm);
	layout_algorithm->addWidget(combobox_encrypt_algorithm);

	QHBoxLayout *layout_edit_key = new QHBoxLayout;
	layout_edit_key->addWidget(label_edit_input_key);
	layout_edit_key->addWidget(edit_input_key);

	QHBoxLayout *layout_box_encrypt = new QHBoxLayout;
	layout_box_encrypt->addWidget(label_default_encrypt);
	layout_box_encrypt->addWidget(checkbox_default_encrypt);

	QHBoxLayout *layout_box_setkey = new QHBoxLayout;
	layout_box_setkey->addWidget(label_default_key);
	layout_box_setkey->addWidget(checkbox_default_key);

	QHBoxLayout *layout_button = new QHBoxLayout;
	layout_button->addStretch();
	layout_button->addWidget(button_change_ok);
	layout_button->addWidget(button_cancel);

	QVBoxLayout *layout_main = new QVBoxLayout;
	layout_main->addLayout(layout_algorithm);
	layout_main->addLayout(layout_edit_key);
	layout_main->addLayout(layout_box_encrypt);
	layout_main->addLayout(layout_box_setkey);
	layout_main->addLayout(layout_button);
	setLayout(layout_main);
	setWindowTitle(tr("Setting Encryption Option"));

	return;
}

QString Dialog_Encryption_Option::get_input_key()
{
	return edit_input_key->text();
}

bool Dialog_Encryption_Option::get_encryption_flag()
{
	return flag_dialog_encryption;
}

bool Dialog_Encryption_Option::get_defaultkey_flag()
{
	return flag_dialog_defaultkey;
}

void Dialog_Encryption_Option::enable_ok_button(const QString &text)
{
	if (edit_input_key->isEnabled() == true) {
		button_change_ok->setEnabled(!text.isEmpty() && text.length() == 4);
	}
	else {
		button_change_ok->setEnabled(true);
	}
}

void Dialog_Encryption_Option::enable_edit_key()
{
	edit_input_key->setEnabled(checkbox_default_key->isChecked() == false);
	button_change_ok->setEnabled(checkbox_default_key->isChecked() == true);
}

void Dialog_Encryption_Option::clicked_box_encryption()
{
	if (flag_dialog_encryption == true) {
		flag_dialog_encryption = false;
	}
	else {
		flag_dialog_encryption = true;
	}
}

void Dialog_Encryption_Option::clicked_box_defaultkey()
{
	if (flag_dialog_defaultkey == true) {
		flag_dialog_defaultkey = false;
	}
	else {
		flag_dialog_defaultkey = true;
	}
}

Dialog_User_Set_Rule::Dialog_User_Set_Rule(QWidget *parent) : QDialog(parent)
{
	label_action = new QLabel(tr("Action : "));
	label_protocol = new QLabel(tr("Protocol : "));
	label_sourceip = new QLabel(tr("SourceIP : "));
	label_destinationip = new QLabel(tr("DestinationIP : "));
	label_sourceport = new QLabel(tr("Source Port : "));
	label_destinationport = new QLabel(tr("Destination Port : "));
	label_name_rule = new QLabel(tr("Rule description : "));

	edit_action = new QLineEdit;
	edit_action->setEnabled(false);
	label_action->setBuddy(edit_action);
	edit_protocol = new QLineEdit;
	edit_protocol->setEnabled(false);
	label_protocol->setBuddy(edit_protocol);
	edit_sourceip = new QLineEdit;
	edit_sourceip->setEnabled(false);
	label_sourceip->setBuddy(edit_sourceip);
	edit_destinationip = new QLineEdit;
	edit_destinationip->setEnabled(false);
	label_destinationip->setBuddy(edit_destinationip);
	edit_sourceport = new QLineEdit;
	edit_sourceport->setEnabled(false);
	label_sourceport->setBuddy(edit_sourceport);
	edit_destinationport = new QLineEdit;
	edit_destinationport->setEnabled(false);
	label_destinationport->setBuddy(edit_destinationport);
	edit_name_rule = new QLineEdit;
	edit_name_rule->setEnabled(false);
	label_name_rule->setBuddy(edit_name_rule);

	check_action = new QCheckBox;
	check_action->setChecked(false);
	check_protocol = new QCheckBox;
	check_protocol->setChecked(false);
	check_sourceip = new QCheckBox;
	check_sourceip->setChecked(false);
	check_destinationip = new QCheckBox;
	check_destinationip->setChecked(false);
	check_sourceport = new QCheckBox;
	check_sourceport->setChecked(false);
	check_destinationport = new QCheckBox;
	check_destinationport->setChecked(false);
	check_name_rule = new QCheckBox;
	check_name_rule->setChecked(false);


	button_addrule = new QPushButton(tr("Add"));
	button_cancel = new QPushButton(tr("Cancel"));

	connect(button_addrule, SIGNAL(clicked()), this, SLOT(accept()));
	connect(button_cancel, SIGNAL(clicked()), this, SLOT(reject()));
	connect(check_action, SIGNAL(clicked()), this, SLOT(click_box_action()));
	connect(check_protocol, SIGNAL(clicked()), this, SLOT(click_box_protocol()));
	connect(check_sourceip, SIGNAL(clicked()), this, SLOT(click_box_sourceip()));
	connect(check_destinationip, SIGNAL(clicked()), this, SLOT(click_box_destinationip()));
	connect(check_sourceport, SIGNAL(clicked()), this, SLOT(click_box_sourceport()));
	connect(check_destinationport, SIGNAL(clicked()), this, SLOT(click_box_destinationport()));
	connect(check_name_rule, SIGNAL(clicked()), this, SLOT(click_box_name_rule()));
	connect(check_name_rule, SIGNAL(clicked()), this, SLOT(click_box_name_rule(current_list)));

	QHBoxLayout *layout_action = new QHBoxLayout;
	layout_action->addWidget(label_action);
	layout_action->addWidget(edit_action);
	layout_action->addWidget(check_action);

	QHBoxLayout *layout_protocol = new QHBoxLayout;
	layout_protocol->addWidget(label_protocol);
	layout_protocol->addWidget(edit_protocol);
	layout_protocol->addWidget(check_protocol);

	QHBoxLayout *layout_sourceip = new QHBoxLayout;
	layout_sourceip->addWidget(label_sourceip);
	layout_sourceip->addWidget(edit_sourceip);
	layout_sourceip->addWidget(check_sourceip);

	QHBoxLayout *layout_desinationip = new QHBoxLayout;
	layout_desinationip->addWidget(label_destinationip);
	layout_desinationip->addWidget(edit_destinationip);
	layout_desinationip->addWidget(check_destinationip);

	QHBoxLayout *layout_sourceport = new QHBoxLayout;
	layout_sourceport->addWidget(label_sourceport);
	layout_sourceport->addWidget(edit_sourceport);
	layout_sourceport->addWidget(check_sourceport);

	QHBoxLayout *layout_destinationport = new QHBoxLayout;
	layout_destinationport->addWidget(label_destinationport);
	layout_destinationport->addWidget(edit_destinationport);
	layout_destinationport->addWidget(check_destinationport);

	QHBoxLayout *layout_name_rule = new QHBoxLayout;
	layout_name_rule->addWidget(label_name_rule);
	layout_name_rule->addWidget(edit_name_rule);
	layout_name_rule->addWidget(check_name_rule);

	QHBoxLayout *layout_button = new QHBoxLayout;
	layout_button->addStretch();
	layout_button->addWidget(button_addrule);
	layout_button->addWidget(button_cancel);

	QVBoxLayout *layout_main = new QVBoxLayout;
	layout_main->addLayout(layout_action);
	layout_main->addLayout(layout_protocol);
	layout_main->addLayout(layout_sourceip);
	layout_main->addLayout(layout_desinationip);
	layout_main->addLayout(layout_sourceport);
	layout_main->addLayout(layout_destinationport);
	layout_main->addLayout(layout_name_rule);
	layout_main->addLayout(layout_button);
	setLayout(layout_main);
	setWindowTitle(tr("Set user defined suspicious firewall Rule"));
}

void Dialog_User_Set_Rule::get_user_rule(QString *ruleinfo)
{
	int index = 0;
	if (edit_action->text().length() == 0) {
		*(ruleinfo + index) = "-";
	}
	else {
		*(ruleinfo + index) = edit_action->text();
	}
	index++;

	if (edit_protocol->text().length() == 0) {
		*(ruleinfo + index) = "-";
	}
	else {
		*(ruleinfo + index) = edit_protocol->text();
	}
	index++;

	if (edit_sourceip->text().length() == 0) {
		*(ruleinfo + index) = "-";
	}
	else {
		*(ruleinfo + index) = edit_sourceip->text();
	}
	index++;

	if (edit_destinationip->text().length() == 0) {
		*(ruleinfo + index) = "-";
	}
	else {
		*(ruleinfo + index) = edit_destinationip->text();
	}
	index++;

	if (edit_sourceport->text().length() == 0) {
		*(ruleinfo + index) = "-";
	}
	else {
		*(ruleinfo + index) = edit_sourceport->text();
	}
	index++;

	if (edit_destinationport->text().length() == 0) {
		*(ruleinfo + index) = "-";
	}
	else {
		*(ruleinfo + index) = edit_destinationport->text();
	}
	index++;

	if (edit_name_rule->text().length() == 0) {
		*(ruleinfo + index) = "User defined log information which is suspicious.";
	}
	else {
		*(ruleinfo + index) = edit_name_rule->text();
	}
	index++;
}

void Dialog_User_Set_Rule::click_box_action()
{
	edit_action->setEnabled(check_action->isChecked() == true);
}

void Dialog_User_Set_Rule::click_box_protocol()
{
	edit_protocol->setEnabled(check_protocol->isChecked() == true);
}

void Dialog_User_Set_Rule::click_box_sourceip()
{
	edit_sourceip->setEnabled(check_sourceip->isChecked() == true);
}

void Dialog_User_Set_Rule::click_box_destinationip()
{
	edit_destinationip->setEnabled(check_destinationip->isChecked() == true);
}

void Dialog_User_Set_Rule::click_box_sourceport()
{
	edit_sourceport->setEnabled(check_sourceport->isChecked() == true);
}

void Dialog_User_Set_Rule::click_box_destinationport()
{
	edit_destinationport->setEnabled(check_destinationport->isChecked() == true);
}

void Dialog_User_Set_Rule::click_box_name_rule()
{
	edit_name_rule->setEnabled(check_name_rule->isChecked() == true);
}

Dialog_User_Firewall_Rule::Dialog_User_Firewall_Rule(QWidget *parent) : QDialog(parent)
{
	table_user_firewall_rule = new QTableWidget();
	table_user_firewall_rule->setRowCount(0);
	table_user_firewall_rule->setColumnCount(8);
	table_user_firewall_rule->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
	table_user_firewall_rule->setHorizontalHeaderLabels(QString("Index ;Action ;Protocol ;SourceIP ;DestinaitionIP ;SourcePort ;DestinationPort ;Rule Information").split(";"));
	table_user_firewall_rule->hideColumn(0);
	reading_metadata();
	table_user_firewall_rule->horizontalHeader()->setStretchLastSection(true);

	button_addrule = new QPushButton(tr("Add Rule"));
	button_close = new QPushButton(tr("Close"));
	button_delete = new QPushButton(tr("Delete"));

	connect(button_addrule, SIGNAL(clicked()), this, SLOT(clicked_addrule_button()));
	connect(button_delete, SIGNAL(clicked()), this, SLOT(clicked_delete_button()));
	connect(button_close, SIGNAL(clicked()), this, SLOT(reject()));

	layout_button = new QHBoxLayout;
	layout_button->addStretch();
	layout_button->addWidget(button_addrule);
	layout_button->addWidget(button_delete);
	layout_button->addWidget(button_close);

	layout_table = new QHBoxLayout;
	layout_table->addWidget(table_user_firewall_rule);
	table_user_firewall_rule->adjustSize();

	layout_main = new QVBoxLayout;
	layout_main->addLayout(layout_table);
	layout_main->addLayout(layout_button);
	setLayout(layout_main);
	setWindowTitle("View User Defined Suspicious Rule");
}

QTableWidget* Dialog_User_Firewall_Rule::get_user_firewall_rule_info()
{
	return table_user_firewall_rule;
}

void Dialog_User_Firewall_Rule::reading_metadata()
{
	string string_user_rule;
	string delimiter = "\n";
	unsigned int count_column = 0;
	index_table_row = 0;
	index_table_column = 0;
	size_user_rule = 0;
	current_rule_displacement = 0;

	read_metadata.open("./Data\\user_rule_metadata.dat", std::ios::binary);
	if (read_metadata.is_open() == false) {
		size_user_rule = 0;
		index_table_row = 0;
		index_table_column = 0;
		current_rule_displacement = 0;
		read_metadata.close();
		return;
	}

	getline(read_metadata, string_user_rule);
	size_user_rule = stoi(string_user_rule);
	if (size_user_rule == MAX_USER_RULE) {
		button_addrule->setEnabled(false);
	}
	if (size_user_rule <= 0) {
		size_user_rule = 0;
		index_table_row = 0;
		index_table_column = 0;
		current_rule_displacement = 0;
		read_metadata.close();
		return;
	}

	while (!read_metadata.eof()) {
		getline(read_metadata, string_user_rule);
		if (string_user_rule.length() == 0) {
			break;
		}
		table_user_firewall_rule->insertRow(index_table_row);
		table_user_firewall_rule->setItem(index_table_row, index_table_column, new QTableWidgetItem(QString::fromStdString(string_user_rule)));
		if (current_rule_displacement  < stoi(string_user_rule)) {
			current_rule_displacement = stoi(string_user_rule);
		}
		index_table_column++;

		for (int repeat_col_count = 0; repeat_col_count < 7; repeat_col_count++) {
			getline(read_metadata, string_user_rule);
			table_user_firewall_rule->setItem(index_table_row, index_table_column, new QTableWidgetItem(QString::fromStdString(string_user_rule)));
			index_table_column++;
		}
		index_table_row++;
		index_table_column = 0;
	}
	read_metadata.close();
	return;
}

void Dialog_User_Firewall_Rule::writing_metadata()
{
	write_metadata.open("./Data\\user_rule_metadata.dat", ios::binary | ios::trunc);
	write_metadata << size_user_rule << "\n";
	for (int table_row = 0; table_row < table_user_firewall_rule->rowCount(); table_row++) {
		for (int table_column = 0; table_column < table_user_firewall_rule->columnCount(); table_column++) {
			write_metadata << table_user_firewall_rule->item(table_row, table_column)->text().toStdString() << "\n";
		}
	}
	write_metadata.close();
}

void Dialog_User_Firewall_Rule::clicked_addrule_button()
{
	QString result_ruleinfo[7];
	Dialog_User_Set_Rule dialog_userrule(this);
	index_table_column = 0;

	if (dialog_userrule.exec() == QDialog::Accepted) {
		dialog_userrule.get_user_rule(result_ruleinfo);
		table_user_firewall_rule->insertRow(index_table_row);
		table_user_firewall_rule->setItem(index_table_row, index_table_column, new QTableWidgetItem(QString::number(current_rule_displacement +1)));
		current_rule_displacement++;
		index_table_column++;
		if (result_ruleinfo[index_table_column -1].length() != 0) {
			table_user_firewall_rule->setItem(index_table_row, index_table_column, new QTableWidgetItem(result_ruleinfo[index_table_column - 1]));
		}
		else {
			table_user_firewall_rule->setItem(index_table_row, index_table_column, new QTableWidgetItem("-"));
		}
		index_table_column++;
		if (result_ruleinfo[index_table_column - 1].length() != 0) {
			table_user_firewall_rule->setItem(index_table_row, index_table_column, new QTableWidgetItem(result_ruleinfo[index_table_column - 1]));
		}
		else {
			table_user_firewall_rule->setItem(index_table_row, index_table_column, new QTableWidgetItem("-"));
		}
		index_table_column++;
		if (result_ruleinfo[index_table_column - 1].length() != 0) {
			table_user_firewall_rule->setItem(index_table_row, index_table_column, new QTableWidgetItem(result_ruleinfo[index_table_column - 1]));
		}
		else {
			table_user_firewall_rule->setItem(index_table_row, index_table_column, new QTableWidgetItem("-"));
		}
		index_table_column++;
		if (result_ruleinfo[index_table_column - 1].length() != 0) {
			table_user_firewall_rule->setItem(index_table_row, index_table_column, new QTableWidgetItem(result_ruleinfo[index_table_column - 1]));
		}
		else {
			table_user_firewall_rule->setItem(index_table_row, index_table_column, new QTableWidgetItem("-"));
		}
		index_table_column++;
		if (result_ruleinfo[index_table_column - 1].length() != 0) {
			table_user_firewall_rule->setItem(index_table_row, index_table_column, new QTableWidgetItem(result_ruleinfo[index_table_column - 1]));
		}
		else {
			table_user_firewall_rule->setItem(index_table_row, index_table_column, new QTableWidgetItem("-"));
		}
		index_table_column++;
		if (result_ruleinfo[index_table_column - 1].length() != 0) {
			table_user_firewall_rule->setItem(index_table_row, index_table_column, new QTableWidgetItem(result_ruleinfo[index_table_column - 1]));
		}
		else {
			table_user_firewall_rule->setItem(index_table_row, index_table_column, new QTableWidgetItem("-"));
		}
		index_table_column++;
		if (result_ruleinfo[index_table_column - 1].length() != 0) {
			table_user_firewall_rule->setItem(index_table_row, index_table_column, new QTableWidgetItem(result_ruleinfo[index_table_column - 1]));
		}
		else {
			table_user_firewall_rule->setItem(index_table_row, index_table_column, new QTableWidgetItem("User defined log information which is suspicious."));
		}
		index_table_column = 0;
		size_user_rule++;
		if (size_user_rule > MAX_USER_RULE) {
			button_addrule->setEnabled(false);
		}
	}
}

void Dialog_User_Firewall_Rule::clicked_delete_button()
{
	int select_row = table_user_firewall_rule->selectionModel()->currentIndex().row();
	table_user_firewall_rule->removeRow(select_row);
	size_user_rule--;
}

void Dialog_User_Firewall_Rule::reject()
{
	writing_metadata();
	table_user_firewall_rule->clear();
	QDialog::reject();
}

Dialog_Aboutus::Dialog_Aboutus(QWidget *parent) : QDialog(parent)
{
	label_message_content = new QLabel(tr("This program is used to anlayze windows firewall .log file.\n This program contains SQLite, QT Library and LZW source for Nielson.\n\n"));
	label_message_developer = new QLabel(tr("Developer : YoungJung Kim (Undergraduated ChungBuk National University major in Computer Engineering)\n"));
	label_message_contact = new QLabel(tr("Contect Developer : seestarland@gmail.com\n"));

	button_ok = new QPushButton(tr("OK"));
	button_ok->setDefault(true);
	connect(button_ok, SIGNAL(clicked()), this, SLOT(close()));

	QVBoxLayout *layout_main = new QVBoxLayout;
	layout_main->addWidget(label_message_content);
	layout_main->addWidget(label_message_developer);
	layout_main->addWidget(label_message_contact);
	layout_main->addWidget(button_ok);
	setLayout(layout_main);
	setWindowTitle("About LogCheckor");
}
