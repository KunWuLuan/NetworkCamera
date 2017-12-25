#include<sstream>
#include<string>
#include<iostream>
using namespace std;
class sql_ctl{
public:
    MYSQL myCont;
    MYSQL_RES *result;
    MYSQL_ROW sql_row;
    int res;
public:
    int Sql_error;
    sql_ctl();
    ~sql_ctl();
    int connect(string username,string password,string host,int port,string table);
    int confirm(const string& username,const string& password);
    int signup(const string& username,const string& password,const string& cid);
    int cameraList(const string& username,string* list,int& count);
    int changePwd(const string& username,const string& exPwd,const string& newPwd);
    void query(string query_str);
};
const string table1_rows_str[]={"username","password"};//Array of row data
enum table1_rows_enu{user,pwd};
const string table2_rows_str[]={"username","cid"};
enum table2_rows_enu{user1,cid};