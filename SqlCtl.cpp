#define database "sdfafas"
#define table1 "user_pwd"
#define table2 "user_camera"
const string table1_rows_str[]={"user","pwd"};//Array of row data
enum table1_rows_enu{user,pwd};
const string table1_rows_str[]={"user","cid"};
enum table1_rows_enu{user,cid};

#include<sstream>
class sql_ctl{
    MYSQL myCont;
    MYSQL_RES *result;
    MYSQL_ROW sql_row;
    int res;
public
    int Sql_error;
    sql_ctl();
    ~sql_ctl();
    int connect(string* username,string* password,string* host,int* port,char* table);
    int confirm(const string& username,const string& password);
    int signup(const string& username,const string& password,const string& cid);
    void query(char* query_str);
}
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
int sql_ctl::connect(string* username,string* password,string* host,int* port,char* table)
{
    return mysql_real_connect(&myCont, host->c_str(), user->c_str(), pswd->c_str(), table, *port, NULL, 0);
}
/*Functions to query data from database
  Num of result will be stored in res while result will be stored in result.
  You can use "while (sql_row = mysql_fetch_row(result))" to obtain data from
  result.
  If error, Sql_error wil be set.*/
void sql_ctl::query(char* query_str)
{
      res=mysql_query(&myCont, query_str);
      if (!res)
          result = mysql_store_result(&myCont);
      else
          Sql_error=1;
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
      table1_rows_enu d=pwd;
      string target_pwd,cleartext;
      string query_str="select pwd from "+table1+" where username="+username+";";
      query(query_str);
      //get data
      sql_row=mysql_fetch_row(result);
      if(NULL==sql_row)
          return 0;
      target_pwd=sql_row[d];
      //decoding
      decoding(target_pwd,cleartext);
      //free result
      mysql_free_result(result);
      //confirm
      if (password==cleartext)
          return 1;
      return 0;
}
/*Function to handle request of signup of new user*/
int sql_ctl::signup(const string& username,const string& password,const string& cid)
{
      string query_str="select pwd from "+table1+" where username="+username+";";
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
      stringstream sstr;
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
