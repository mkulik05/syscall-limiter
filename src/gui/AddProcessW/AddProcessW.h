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


#include "../ProcessInfo.h"

class AddProcessDialog : public QDialog {
Q_OBJECT
public:
    AddProcessDialog(QWidget *parent);
    AddProcessDialog(QWidget *parent, ProcessInfo& process_info);

    void addRule();

    void AddRuleRow(QString &message);

    QString getName() const;
    QString getProgPath() const;
    QVector<RuleInfoGui> getRules() const;
    int getMaxMem() const;
    int getMaxTime() const;

private slots:
    void checkAndAccept();
   
private:
    void TableCellDoubleClicked(int row, int column);
    QLineEdit *progNameEdit;
    QLineEdit *progPathEdit;
    
    QLineEdit *progMaxMemEdit;
    QLineEdit *progMaxTimeEdit;
    std::vector<QLabel*> syscallsSels;      
    std::vector<QComboBox*> ruleTypeSels; 
    std::vector<QLineEdit*> restrictPath; 
    QTableWidget *rulesTable;
    QStringList elements;             
};