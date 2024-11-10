#pragma once

#include <QApplication>
#include <QPushButton>
#include <QTableWidget>
#include <QVBoxLayout>
#include <QWidget>
#include <QDialog>
#include <QLineEdit>
#include <QFormLayout>
#include <QHeaderView>
#include <QTableWidgetItem>
#include <QComboBox>
#include <QLabel>
#include <QStringList>
#include <QTextEdit>
#include <QVector>
#include <QString>

struct RuleInfoGui {
    QVector<int> syscalls;
    bool restrict_all;
    QString path_info;
};

class AddProcessDialog : public QDialog {

public:
    AddProcessDialog(QWidget *parent);
    AddProcessDialog(QWidget *parent, QString name, QString path, QVector<RuleInfoGui> rules);

    void addRule();

    void AddRuleRow(QString &message);

    QString getName() const;
    QString getProgPath() const;
    QVector<RuleInfoGui> getRules() const;


   
private:
    void TableCellDoubleClicked(int row, int column);
    QLineEdit *progNameEdit;
    QLineEdit *progPathEdit;
    std::vector<QLabel*> syscallsSels;      
    std::vector<QComboBox*> ruleTypeSels; 
    std::vector<QLineEdit*> restrictPath; 
    QTableWidget *rulesTable;
    QStringList elements;             
};