#define database "sdfafas"
#define table1 "user_pwd"
#define table2 "user_camera"
#include<mysql.h>
#include "SqlCtl.h"
using namespace std;
/*Function to decoding EncryptedText*/
void decoding(const string& EncryptedText,string& ClearText)
{
    ClearText=EncryptedText;
}
/*Function to encoding ClearText*/
void encoding(const string& ClearText,string& EncryptedText)
{
    EncryptedText=ClearText;
}
sql_ctl::sql_ctl()
{
    mysql_init(&myCont);
}
sql_ctl::~sql_ctl()
{
    if (result != NULL)
        mysql_free_result(result);
    mysql_close(&myCont);
}
/*Function to change password.*/
int sql_ctl::changePwd(const string& username,const string& exPwd,const string& newPwd)
{
	cout<<"Start to changePwd"<<endl;
    string query_str;
    query_str=string("select password from ")+string(table1)+string(" where user=\"")+string(username)+string("\";");
    res=mysql_query(&myCont,query_str.c_str());
    if(!res)
        return 0;
    result = mysql_store_result(&myCont);
    sql_row=mysql_fetch_row(result);
    string password=sql_row[0];
    if(password==exPwd)
    {
        query_str=string("update ")+string(table1)+string(" set password=\"")+string(newPwd)+string("\" where username=\"")+string(username)+string("\";");
        mysql_query(&myCont,query_str.c_str());
        return 1;
    }
    mysql_free_result(result);
    return 0;
}
int sql_ctl::connect(string username,string password,string host,int port,string table)
{
    return (mysql_real_connect(&myCont, host.c_str(), username.c_str(), password.c_str(), table.c_str(), 0, NULL, 0)==NULL)?0:1;
}
/*Functions to query data from database
  Num of result will be stored in res while result will be stored in result.
  You can use "while (sql_row = mysql_fetch_row(result))" to obtain data from
  result.
  If error, Sql_error wil be set.*/
void sql_ctl::query(string query_str)
{
	  cout<<"Start to query "<<query_str<<endl;
      res=mysql_query(&myCont, query_str.c_str());
      if (!res)
        if ((result = mysql_store_result(&myCont))==NULL) {
            Sql_error=1;
			cout << "mysql_store_result failed" << endl;
    	}
		else
			cout << "select return " << (int)mysql_num_rows(result) << " records" << endl;
      else
          Sql_error=1;
	  cout<<"End query "<< Sql_error<<endl;
}
/*Functions to verify user identity.
  para:
    username:string of username.
    password:string of password
  Note:
    At the end of the function, result will be released.
    */
int sql_ctl::confirm(const string& username,const string& password)
{
	  cout<<"Start to confirm"<<endl;
      table1_rows_enu d=pwd;
      string target_pwd,cleartext;
      string query_str="select password from ";
	  query_str+=table1;
	  query_str+=" where username=\"";
	  query_str+=username;
	  query_str+="\";";
      query(query_str);
	  if(Sql_error==1){
		  cout << "mysql_query failed(" << mysql_error(&myCont) << ")" << endl;
		  return -1;
	  }
      //get data
      sql_row=mysql_fetch_row(result);
      if(NULL==sql_row)
          return 0;
      target_pwd=sql_row[0];
      //decoding
      decoding(target_pwd,cleartext);
      //free result
      mysql_free_result(result);
      //confirm
	  cout<<"Finish confirm"<<endl;
      if (password==cleartext)
          return 1;
      return 0;
}
/*Function to handle request of signup of new user*/
int sql_ctl::signup(const string& username,const string& password,const string& cid)
{
      string query_str="select password from ";
	  query_str+=table1;
	  query_str+=" where username=\"";
	  query_str+=username;
	  query_str+="\";";
      query(query_str);
      //get data
      unsigned int num_fields;
      num_fields = mysql_num_fields(result);
      if(num_fields>0)
          return 0;
      mysql_free_result(result);
      string encoded;
      encoding(password,encoded);
      stringstream sstr;
      sstr<<"insert into "<<table1<<" ("<<table1_rows_str[0]<<','<<table1_rows_str[1]<<") values "
          <<"(\""<<username<<"\",\""<<encoded<<"\");";
      sstr>>query_str;
      sstr.clear();
      query(query_str);
      if(Sql_error==1){
          mysql_free_result(result);
          return 0;
      }
      mysql_free_result(result);
      sstr<<"insert into "<<table2<<" ("<<table2_rows_str[0]<<','<<table2_rows_str[1]<<") values "
          <<"(\""<<username<<"\",\""<<cid<<"\");";
      sstr>>query_str;
      sstr.clear();
      query(query_str);
      if(Sql_error==1){
          mysql_free_result(result);
          return 0;
      }
      mysql_free_result(result);
      return 1;
}
/*Function to obtain camera list from database.
  Input parameter: username
  Output parameter:list,count
  list:array of camera that user have bound
  count:number of cameras
*/
int sql_ctl::cameraList(const string& username,string* list,int& count)
{
	  cout<<"Start to query cameraList"<<endl;
      string query_str;
      query_str="select cid from ";
	  query_str+=table2;
	  query_str+=" where ";
	  query_str+=table1_rows_str[0];
	  query_str+="=\"";
	  query_str+=username;
	  query_str+="\";";
      query(query_str);
      if(Sql_error==1)
          return 0;
      count=mysql_num_fields(result);
      list=new string[count];
      string* head=list;
      while((sql_row=mysql_fetch_row(result)))
      {
          (*head)=sql_row[1];
		  head++;
      }
      return 1;
}
