#ifndef SELECTIONDIALOG_H
#define SELECTIONDIALOG_H

#include <QDialog>
#include <QComboBox>
#include <QListWidget>
#include <QVector>

class AddSyscallsW : public QDialog {

public:
    AddSyscallsW(QWidget *parent, QStringList syscalls);
    AddSyscallsW(QWidget *parent, QStringList syscalls, QVector<QString> presented_elements);
    QVector<QString> getSelections() const;

private:
    void checkAndAdd();
    void removeItem(QListWidgetItem *item);
    void keyPressEvent(QKeyEvent *event) override;
    

private:
    QComboBox *comboBox;
    QListWidget *listWidget;
};

#endif // SELECTIONDIALOG_H