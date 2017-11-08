#include <QtWidgets/QApplication>
#include "mainwindow.h"
#include "dialog.h"
int main(int argc, char *argv[])
{
	QApplication applicaiton_logcheckor(argc, argv);
	QIcon icon_logcheckor("./icon.ico");
	MainWindow mainwindow_logcheckor;
	applicaiton_logcheckor.setWindowIcon(icon_logcheckor);
	applicaiton_logcheckor.setStyle("windowsxp");
	mainwindow_logcheckor.showMaximized();
	return applicaiton_logcheckor.exec();
}