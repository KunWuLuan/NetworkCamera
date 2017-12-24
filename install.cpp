#include <iostream>	// cin,cout等
#include <iomanip>	// setw等
#include <mysql.h>	// mysql特有
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

    /* 初始化 mysql 变量，失败返回NULL */
    if ((mysql = mysql_init(NULL))==NULL) {
      cout << "mysql_init failed" << endl;
      return -1;
      }
    /* 连接数据库，失败返回NULL
       1、mysqld没运行
       2、没有指定名称的数据库存在 */
    if (mysql_real_connect(mysql,"localhost","root", "root123","demo",0, NULL, 0)==NULL) {
      cout << "mysql_real_connect failed(" << mysql_error(mysql) << ")" << endl;
      return -1;
      }
    /* 设置字符集，否则读出的字符乱码，即使/etc/my.cnf中设置也不行 */
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
        /* 进行查询，成功返回0，不成功非0
           1、查询字符串存在语法错误
           2、查询不存在的数据表 */
        if (mysql_query(mysql, cmd)) {
        	cout << "mysql_query failed(" << mysql_error(mysql) << ")" << endl;
        	return -1;
        	}
        /* 释放result */
        mysql_free_result(result);
    }
    /* 关闭整个连接 */
    mysql_close(mysql);

    return 0;
}
