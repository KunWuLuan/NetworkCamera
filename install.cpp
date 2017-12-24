#include <iostream>	// cin,cout��
#include <iomanip>	// setw��
#include <mysql.h>	// mysql����
#include <fstream>
#include <string.h>
using namespace std;
#define u "1552157"
#define p "401001"
#define install_file "install.sql"
int main(int argc, char* argv[])
{
    MYSQL     *mysql;
    MYSQL_RES *result;
    MYSQL_ROW  row;

    /* ��ʼ�� mysql ������ʧ�ܷ���NULL */
    if ((mysql = mysql_init(NULL))==NULL) {
      cout << "mysql_init failed" << endl;
      return -1;
      }
    /* �������ݿ⣬ʧ�ܷ���NULL
       1��mysqldû����
       2��û��ָ�����Ƶ����ݿ���� */
    if (mysql_real_connect(mysql,"localhost","root", "root123","demo",0, NULL, 0)==NULL) {
      cout << "mysql_real_connect failed(" << mysql_error(mysql) << ")" << endl;
      return -1;
      }
    /* �����ַ���������������ַ����룬��ʹ/etc/my.cnf������Ҳ���� */
    mysql_set_character_set(mysql, "gbk");

    string cmd;
    fstream infile;
    infile.open(install_file,ios::in);
    if(0==infile.is_open())
    {
        cout<<"Fail to open command file to set database"<<endl;
        return -1;
    }
    while(!infile.eof())
    {
        getline(infile,cmd,'\n');
        if(sizeof(cmd)==0)
            continue;
        /* ���в�ѯ���ɹ�����0�����ɹ���0
           1����ѯ�ַ��������﷨����
           2����ѯ�����ڵ����ݱ� */
        if (mysql_query(mysql, cmd)) {
        	cout << "mysql_query failed(" << mysql_error(mysql) << ")" << endl;
        	return -1;
        	}
        /* �ͷ�result */
        mysql_free_result(result);
    }
    /* �ر��������� */
    mysql_close(mysql);

    return 0;
}
