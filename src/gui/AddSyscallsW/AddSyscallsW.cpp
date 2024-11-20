#include <QVBoxLayout>
#include <QPushButton>
#include <QHBoxLayout>
#include <QLineEdit>
#include <QKeyEvent>
#include <QMessageBox>
#include<QDebug>

#include "AddSyscallsW.h"

AddSyscallsW::AddSyscallsW(QWidget *parent, QStringList syscalls) : QDialog(parent) {
    setWindowTitle("Select Items");

    QVBoxLayout *layout = new QVBoxLayout(this);

    comboBox = new QComboBox(this);
    comboBox->setEditable(true);
    comboBox->addItems(syscalls); 
    comboBox->setInsertPolicy(QComboBox::NoInsert);
    comboBox->lineEdit()->clear();
    layout->addWidget(comboBox);

    listWidget = new QListWidget(this);
    layout->addWidget(listWidget);

    QHBoxLayout *buttonLayout = new QHBoxLayout();
    QPushButton *okButton = new QPushButton("OK", this);
    QPushButton *cancelButton = new QPushButton("Cancel", this);
    buttonLayout->addWidget(okButton);
    buttonLayout->addWidget(cancelButton);
    layout->addLayout(buttonLayout);

    connect(okButton, &QPushButton::clicked, this, &AddSyscallsW::accept);
    connect(cancelButton, &QPushButton::clicked, this, &AddSyscallsW::reject);
    connect(comboBox->lineEdit(), &QLineEdit::returnPressed, this, &AddSyscallsW::checkAndAdd);
    connect(listWidget, &QListWidget::itemDoubleClicked, this, &AddSyscallsW::removeItem);
    connect(comboBox, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &AddSyscallsW::addItemFromComboBox);

    setLayout(layout);
}

void AddSyscallsW::addItemFromComboBox() {
    QString text = comboBox->currentText();
    if (!text.isEmpty() && listWidget->findItems(text, Qt::MatchExactly).isEmpty()) {
        listWidget->addItem(text);
    }
}

AddSyscallsW::AddSyscallsW(QWidget *parent, QStringList syscalls, QVector<QString> presented_elements) : AddSyscallsW(parent, syscalls)  {
    for (int i = 0; i < presented_elements.size(); i++) {
        listWidget->addItem(presented_elements[i]);
    }
}

QVector<QString> AddSyscallsW::getSelections() const {
    QVector<QString> selections;
    for (int i = 0; i < listWidget->count(); ++i) {
        selections.append(listWidget->item(i)->text());
    }
    return selections;
}

void AddSyscallsW::checkAndAdd() {
    QString text = comboBox->currentText();
    if (!text.isEmpty() && !listWidget->findItems(text, Qt::MatchExactly).isEmpty()) {
        return; 
    }
    if (comboBox->findText(text) != -1) { 
        listWidget->addItem(text);
        comboBox->lineEdit()->clear();
    }
}

void AddSyscallsW::removeItem(QListWidgetItem *item) {
    delete item;
}


void AddSyscallsW::keyPressEvent(QKeyEvent *event) {
    if (comboBox->hasFocus() && event->key() == Qt::Key_Return) {
        QString text = comboBox->currentText();
        if (!comboBox->findText(text)) {
            event->ignore();
            return;
        }
    } else {
        QDialog::keyPressEvent(event); 
    }
}