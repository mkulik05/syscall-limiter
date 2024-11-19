#pragma once

#include <QDialog>
#include <QLabel>
#include <QTextEdit>
#include <QVBoxLayout>

class ProcOutputDialog : public QDialog {
    Q_OBJECT

public:
    ProcOutputDialog(QString proc_name, std::string log_path, QWidget *parent);

private:
    QLabel *l_stdout;
    QTextEdit *edit_out;
    QLabel *l_stderr;
    QTextEdit *edit_err;
};
