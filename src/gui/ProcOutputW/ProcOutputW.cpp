#include "ProcOutputW.h"

#include <QTimer>
#include <QScrollBar>
#include <QPushButton>
#include <QClipboard>
#include <QApplication>
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

    QHBoxLayout *stdoutLayout = new QHBoxLayout();
        
    l_stdout = new QLabel("stdout:", this);
    stdoutLayout->addWidget(l_stdout);

    stdoutLayout->addStretch(); 

    QPushButton *copyOutButton = new QPushButton("Copy", this);
    stdoutLayout->addWidget(copyOutButton);

    layout->addLayout(stdoutLayout);

    edit_out = new QTextEdit(this);
    edit_out->setReadOnly(true);
    layout->addWidget(edit_out);

    QHBoxLayout *stderrLayout = new QHBoxLayout(); 

    l_stderr = new QLabel("stderr:", this);
    stderrLayout->addWidget(l_stderr);

    stderrLayout->addStretch(); 

    QPushButton *copyErrButton = new QPushButton("Copy", this);
    stderrLayout->addWidget(copyErrButton);

    layout->addLayout(stderrLayout);

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

    connect(copyOutButton, &QPushButton::clicked, this, [=]() {
        QClipboard *clipboard = QApplication::clipboard();
        clipboard->setText(edit_out->toPlainText());
    });

    connect(copyErrButton, &QPushButton::clicked, this, [=]() {
        QClipboard *clipboard = QApplication::clipboard();
        clipboard->setText(edit_err->toPlainText());
    });

    QTimer* timer = new QTimer();
    timer->setInterval(500);
    connect(timer, &QTimer::timeout, this, [=]() {
        std::string newStdout = readFileToString(log_path + ".out");
        std::string newStderr = readFileToString(log_path + ".err");

        if (edit_out->toPlainText() != QString::fromStdString(newStdout)) {
            edit_out->setPlainText(QString::fromStdString(newStdout));
            edit_out->moveCursor(QTextCursor::End);
        }
        if (edit_err->toPlainText() != QString::fromStdString(newStderr)) {
            edit_err->setPlainText(QString::fromStdString(newStderr));
            edit_err->moveCursor(QTextCursor::End); 
        }
    });
    timer->start();
}