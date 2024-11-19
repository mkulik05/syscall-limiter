
#include "ProcOutputW.h"

#include <QTimer>

#include <QScrollBar>

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>

std::string readFileToString(const std::string& filename) {
    std::ifstream file(filename);
    if (!file) {
        return "";
    }

    std::ostringstream ss;
    ss << file.rdbuf();
    return ss.str();    
}

ProcOutputDialog::ProcOutputDialog(QString proc_name, std::string log_path, QWidget *parent = nullptr) : QDialog(parent) {
    QVBoxLayout *layout = new QVBoxLayout(this);

    l_stdout = new QLabel("stdout:", this);
    layout->addWidget(l_stdout);

    edit_out = new QTextEdit(this);
    edit_out->setReadOnly(true);
    layout->addWidget(edit_out);

    l_stderr = new QLabel("stderr:", this);
    layout->addWidget(l_stderr);

    edit_err = new QTextEdit(this);
    edit_err->setReadOnly(true);
    layout->addWidget(edit_err);

    edit_out->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    edit_err->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);

    setLayout(layout);
    setWindowTitle(proc_name + " logs");
    resize(600, 400);

    std::string sstdout = readFileToString(log_path + ".out");
    std::string sstderr = readFileToString(log_path + ".err");

    edit_out->setText(QString::fromStdString(sstdout));
    edit_err->setText(QString::fromStdString(sstderr));

    QTimer* timer = new QTimer();
    timer->setInterval(500);
    connect(timer, &QTimer::timeout, this, [=]() {
        int currentOutScroll = edit_out->verticalScrollBar()->value();
        int currentErrScroll = edit_err->verticalScrollBar()->value();

        std::string sstdout = readFileToString(log_path + ".out");
        std::string sstderr = readFileToString(log_path + ".err");

        edit_out->setText(QString::fromStdString(sstdout));
        edit_err->setText(QString::fromStdString(sstderr));

        edit_out->verticalScrollBar()->setValue(currentOutScroll);
        edit_err->verticalScrollBar()->setValue(currentErrScroll);
    });
    timer->start();
}
