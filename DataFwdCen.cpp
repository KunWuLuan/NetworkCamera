#include <iostream>	// cin,cout等
#include <iomanip>	// setw等
#include <mysql.h>	// mysql特有
#include <stdlib.h>
#include <stdio.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/stat.h>   
#include <sys/prctl.h>  
#include <getopt.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <fstream>
#include "SqlCtl.h"
#define CLNTNUM 10						//最多10个用户
#define CAMNUM 10						//最多10个摄像头
using namespace std;

char BUF[100000];						//接收缓冲区
int place;								//某个客户端放置的位置
int sndLen, rcvLen;
char ipAddr[INET_ADDRSTRLEN];
string loginHtml;
string errorUserHtml;					//虽然比起loginHtml只是多了报错的一句话,
										//但是为了减少文本处理(要计算长度)
										//采取另外读取一个文件
string camListHtml;
string temp;
sql_ctl mariaDB;

struct CLNT
{
	int sock;							//用户每次点击网页可能在变
	int port;
	/*用户名和密码不一定存在,新用户可能还没有注册*/
	string username;					//登录的用户名 查数据库要用
	string password;					//登录的密码
	char ipAddr[INET_ADDRSTRLEN];		//标记用户ip
	bool identified;					//标记用户是否经过了本地认证
	int cameraNum;						//摄像头编号(不是摄像头的socket)
										//某个用户正在访问的摄像头数据
	bool isWatching;					//已经在看了,没有绑定这一操作
	int numOfCam;
	//string *camList;			
	string camList[2];
}clnt[CLNTNUM];

struct CAMERA
{
	int sock;
	char ipAddr[INET_ADDRSTRLEN];		//标记ip
	int port;							//端口号
	char nickName[20];
	int timer;							//常连接心跳计时
}cam[CAMNUM];

short tryCnt = 0;	//尝试连接次数 3 次都失败,服务器死亡,本地作简单退出处理

/*初始化为守护进程*/
bool InitDaemon()
{
	pid_t pid;
	//1) 屏蔽一些控制终端操作的信号
	signal(SIGTTOU, SIG_IGN);
	signal(SIGTTIN, SIG_IGN);
	signal(SIGTSTP, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	//2) 在后台运行
	if (pid = fork()) { // 父进程  
		exit(0); //结束父进程，子进程继续  
	}
	else if (pid < 0) { // 出错  
		perror("fork");
		exit(EXIT_FAILURE);
	}

	//8) 处理SIGCHLD信号 使之不会产生僵尸进程
	signal(SIGCHLD, SIG_IGN);		//父进程不处理子进程退出

	return 0;
}

void InitHtml()
{
	ifstream in("login.html",ios::in);
	while (getline(in, temp))
	{
		loginHtml += temp;
		loginHtml += '\n';
	}
	in.close();
	temp = "HTTP/1.1 200 OK\r\n";
	temp += "Server: Apache/2.4.6 (Red Hat Enterprise Linux) PHP/5.4.16\r\n";
	temp += "X-Powered-By: PHP/5.4.16\r\n";
	temp += "Content-Length: ";
	char contentLen[10];
	sprintf(contentLen, "%d", loginHtml.length());
	temp += contentLen;
	temp += "\r\n";
	//temp += "Keep-Alive: timeout=5, max=100\r\n";
	//temp += "Connection: Keep-Alive\r\n";
	temp += "Content-Type: text/html; charset=gbk\r\n";
	temp += "\r\n";
	temp += loginHtml;
	loginHtml = temp;
	
	ifstream in1("erroUser.html", ios::in);
	while (getline(in1, temp))
	{
		loginHtml += temp;
		loginHtml += '\n';
	}
	in1.close();
	temp = "HTTP/1.1 200 OK\r\n";
	temp += "Server: Apache/2.4.6 (Red Hat Enterprise Linux) PHP/5.4.16\r\n";
	temp += "X-Powered-By: PHP/5.4.16\r\n";
	temp += "Content-Length: ";
	sprintf(contentLen, "%d", errorUserHtml.length());
	temp += contentLen;
	temp += "\r\n";
	//temp += "Keep-Alive: timeout=5, max=100\r\n";
	//temp += "Connection: Keep-Alive\r\n";
	temp += "Content-Type: text/html; charset=gbk\r\n";
	temp += "\r\n";
	temp += errorUserHtml;
	errorUserHtml = temp;

}

void ConnTable1()
{
	//连接用户认证表
	mariaDB.connect("root", "1002.lkj555", "localhost",  0, "demo");
}

void ConnTable2()
{
	//连接用户信息表
}

/*设为阻塞非阻塞*/
bool SetBlock(int sock, bool isblock)
{
	int re = 0;
	int flags = fcntl(sock, F_GETFL, 0);
	if (flags < 0)
		return false;
	if (isblock)
		flags = flags & ~O_NONBLOCK;
	else
		flags = flags | O_NONBLOCK;

	re = fcntl(sock, F_SETFL, flags);
	if (re != 0)
		return false;
	return true;
}

/*连接本地数据库
bool ConDataBase(MYSQL *mysql)
{
	/* 初始化 mysql 变量，失败返回NULL 
	if ((mysql = mysql_init(NULL)) == NULL) {
		cout << "mysql_init failed" << endl;
		return 0;
	}

	/* 连接数据库，失败返回NULL
	1、mysqld没运行
	2、没有指定名称的数据库存在 
	if (mysql_real_connect(mysql, "localhost", "root", "1002.lkj555", "demo", 0, NULL, 0) == NULL) {
		cout << "mysql_real_connect failed(" << mysql_error(mysql) << ")" << endl;
		return 0;
	}

	/* 设置字符集，否则读出的字符乱码，即使/etc/my.cnf中设置也不行 
	mysql_set_character_set(mysql, "gbk");

	return 1; 
}*/

/*心跳检测主动发一次hello*/
void IsAlive()
{
}

void Timer(int sig)
{
	int i;
	for (i = 0; i < CAMNUM; i++)
		if (ipAddr[0] != '*')
			cam[i].timer++;
}

void SetTimer()
{
	//设置心跳计时器
	struct itimerval val;
	val.it_value.tv_sec = 1;		//1秒后启用定时器
	val.it_value.tv_usec = 0;

	val.it_interval.tv_sec = 1;		//定时器间隔为1秒
	val.it_interval.tv_usec = 0;
	if (setitimer(ITIMER_REAL, &val, NULL) < 0)
	{
		cout << "设置定时器失败" << endl;
		exit(0);
	}
	signal(SIGALRM, Timer);
}

int SearchEmpty(bool flag)
{
	int i;
	if (flag = 0)
	{
		for (i = 0; i < CLNTNUM; i++)
			if (clnt[i].ipAddr[0] == '*')
				return i;
		return -1;	//标记满了

	}
	else
	{
		for (i = 0; i < CAMNUM; i++)
			if (cam[i].ipAddr[0] == '*')
				return i;
		return -1;
	}
}

int SearchPlace(char *ipAddr,bool flag,int port = -1)
{
	//根据ip地址查看用户是否已经访问过了转发中心
	//返回用户信息
	int i;
	if (flag == 0)
	{
		for (i = 0; i < CLNTNUM; i++)
			if (strncmp(clnt[i].ipAddr, ipAddr, strlen(ipAddr)) == 0)
				return i;
		return -1;
	}
	else
	{
		for (i = 0; i < CAMNUM; i++)
			if (strncmp(cam[i].ipAddr, ipAddr, strlen(ipAddr)) == 0 && cam[i].port == port)
				return i;
		return -1;
	}
}

bool IsGet()
{
	//判断收到的是不是get包 请求页面
	cout << "判断收到的是不是get包" << endl;
	if (strstr(BUF, "GET /"))
		return 1;
	return 0;
}

bool IsPost()
{
	//判断收到的是不是post包 操作
	cout << "判断收到的是不是post包" << endl;
	if (strstr(BUF, "POST / HTTP/1.1"))
		return 1;
	return 0;

}

void InitBind(int &sock,const char * ipAddr,const int port)
{
	if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
	{
		cout << "create socket failed" << endl;
		exit(0);
	}

	//端口复用
	int reuse = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

	//初始化地址信息
	struct sockaddr_in Addr;
	bzero(&Addr, sizeof(Addr));
	Addr.sin_family = AF_INET;
	Addr.sin_addr.s_addr = inet_addr(ipAddr);
	Addr.sin_port = htons(port);

	//将本地地址绑定到所创建的套接字上
	if (bind(sock, (struct sockaddr *)&Addr, sizeof(Addr)) == -1)
	{
		cout << "bind socket failed" << endl;
		perror("bind");
		exit(0);
	}
}

bool Accept(int & sock, int & connect_fd, 
		struct sockaddr_in &connect_addr, socklen_t &connect_len)
{
	connect_fd = accept(sock,
		(struct sockaddr*)&connect_addr, &connect_len);
	inet_ntop(AF_INET, &(connect_addr.sin_addr), ipAddr, sizeof(ipAddr));
	cout << ipAddr << "发起连接" << endl;
	if (connect_fd == -1)
	{
		if (errno == 11)		//时钟中断可能会导致这个问题
			return 0;
		else
		{
			cout << "accept failed" << endl;
			exit(1);
		}
	}
	return 1;
}

void RecordCam(struct sockaddr_in &addr,int connect_fd)
{
	place = SearchEmpty(1);
	inet_ntop(AF_INET, &(addr.sin_addr), cam[place].ipAddr, sizeof(cam[place].ipAddr));
	cout << "连接的摄像头ip为:" << cam[place].ipAddr << endl;
	cam[place].port = ntohs(addr.sin_port);
	cam[place].sock = connect_fd;
}

bool IsCam(int sock)
{
	int i;
	for (i = 0; i < CAMNUM; i++)
		if (cam[i].sock == sock)
			return 1;
	return 0;
}

int CamToUser(int cameraNum)
{
	int i;
	for (i = 0; i < CLNTNUM; i++)
		if (clnt[i].cameraNum == cameraNum)
			return i;
	return -1;	//不应该出现这种情况
}

void SendIdentifyWeb(int sock,bool flag = 0)
{
	temp = loginHtml;
	if (flag == true)
		temp = errorUserHtml;

	sndLen = send(sock, temp.c_str(), temp.length(), 0);
	cout << "发送的html长度为"<< sndLen << endl;
}

bool UserIdentify(int clntPlace)
{
	/*认证失败直接告知信息,认证成功则将所有该用户绑定的摄像头信息返回给用户*/
	cout << "进行用户认证中" << endl;
	string username, password;
	char *ptr;
	ptr = strstr(BUF, "username=");
	ptr = ptr + 9;
	int i;
	for (i = 0;ptr[i] != '&'; i++)
		username += ptr[i];
	i += 10;
	for (; ptr[i] != '&'; i++)
		password += ptr[i];
	
	cout << "username:" << username << endl;
	cout << "password:" << password << endl;
	clnt[clntPlace].username = username;
	clnt[clntPlace].password = password;
	/*这里要调数据库进行对比*/
	/*连接认证表*/
	ConnTable1();
	/* 设置字符集，否则读出的字符乱码，即使/etc/my.cnf中设置也不行 */
	mysql_set_character_set(&mariaDB.myCont, "gbk");
	if (mariaDB.confirm(username, password) == 1)
	{
		/*如果认证通过,推送该用户绑定的摄像头的网页*/
		clnt[clntPlace].identified = 1;
		return 1;
	}
	/*认证失败,推送失败告知网页*/
	return 0;
}

void SendCamList(int sock,bool flag = 0,int clntPlace = -1)
{
	/*从数据库获取用户摄像头数据*/
	int numOfCam = 2;
	string table2_row[2] = { "192.168.80.230:5000",
		"192.168.80.230:6000" };	//最外层表示第几个摄像头然后 0为username 1为cid

	clnt[clntPlace].numOfCam = 2;
	clnt[clntPlace].camList[0] = table2_row[0];
	clnt[clntPlace].camList[1] = table2_row[1];

	ifstream in("camList.html", ios::in);
	while (getline(in, temp))
	{
		if (temp == "<!替换模板>")
			break;
		camListHtml += temp;
		camListHtml += '\n';
	}
	int i;
	char num = '1';	//在此假定用户不超过9个摄像头
	for (i = 0; i < numOfCam; i++, num++)
	{
		camListHtml += "<tr>\r\n <td>";
		camListHtml += table2_row[i];
		camListHtml += "</td>\r\n <form action=\"\" method=\"post\">\r\n";
		camListHtml += "<td><input type = \"submit\" name = \"CamNum";
		camListHtml += num;	//用来判断用户选择了哪个摄像头
		camListHtml += "$\" value = \"确认\" > </td>\r\n </form>\r\n </tr>\r\n";
	}
	if(flag == true)
		camListHtml += "<script>alert('所选择的摄像头未连接,请另选');</script>\r\n";
	getline(in, temp);
	while (getline(in, temp))
	{
		camListHtml += temp;
		camListHtml += '\n';
	}
	in.close();
	temp = "HTTP/1.1 200 OK\r\n";
	temp += "Server: Apache/2.4.6 (Red Hat Enterprise Linux) PHP/5.4.16\r\n";
	temp += "X-Powered-By: PHP/5.4.16\r\n";
	temp += "Content-Length: ";
	char contentLen[10];
	sprintf(contentLen, "%d", camListHtml.length());
	temp += contentLen;
	temp += "\r\n";
	//temp += "Keep-Alive: timeout=5, max=100\r\n";
	//temp += "Connection: Keep-Alive\r\n";
	temp += "Content-Type: text/html; charset=gbk\r\n";
	temp += "\r\n";
	temp += camListHtml;
	cout << "camListWeb" << endl;
	//cout << temp << endl;
	sndLen = send(sock, temp.c_str(), temp.length(), 0);
}

void GetCamInfo(int sock,int clntPlace)
{
	//向对应socket的摄像头服务器发送摄像头信息请求get包
	string Get;
	Get = "GET / HTTP/1.1\r\n";
	Get += "Host: ";
	Get += clnt[clntPlace].ipAddr;
	char Len[10];
	sprintf(Len, "%d", clnt[clntPlace].port);
	Get += Len;
	Get += "\r\n";
	Get += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0\r\n";
	Get += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n";
	Get += "Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2\r\n";
	Get += "Accept-Encoding: gzip, deflate\r\n";
	Get += "Connection: keep-alive\r\n";
	Get += "Upgrade-Insecure-Requests: 1\r\n";
	sndLen = send(sock, Get.c_str(), Get.length(), 0);
}

void BindCam(int clntPlace)
{
	char *ptr = strstr(BUF, "CamNum");
	ptr += 6;
	int camNum = ptr[0] - '0';
	/*从该用户的摄像头列表中找对应摄像头的ip+port*/
	cout << "camNum="<<camNum << endl;
	cout << clnt[clntPlace].camList[camNum - 1] << endl;
	string cid = clnt[clntPlace].camList[camNum - 1];
	cout << "还没挂" << endl;
	const char*p_cid = cid.c_str();
	cout << p_cid << endl;
	int i = 0;
	for (; p_cid[i] != ':'; i++)
		ipAddr[i] = p_cid[i];
	ipAddr[i] = '\0';
	cout << ipAddr << endl;
	i++;
	char c_port[10];
	int j;
	for (j = 0; p_cid[i] != '\0'; i++, j++)
		c_port[j] = p_cid[i];
	c_port[j] = '\0';
	cout << c_port << endl;
	int port = atoi(c_port);
	place = SearchPlace(ipAddr, 1, port);
	if (place < 0)
	{
		SendCamList(clnt[clntPlace].sock, 1);
	}
	else
	{
		clnt[clntPlace].cameraNum = place;
		clnt[clntPlace].isWatching = 1;
		cout << "绑定的摄像头ip为" << cam[place].ipAddr << endl;
		GetCamInfo(cam[place].sock,clntPlace);	//之后将会开始数据转发
	}
}

int main(int argc, char* argv[])
{
	int i;
	InitDaemon();

	InitHtml();

	//一个提供给客户连接,一个提供给每个摄像头服务器连接
	int sockForClnt, sockForCam;
	InitBind(sockForClnt, "192.168.80.230", 5555);
	InitBind(sockForCam,  "192.168.80.230", 8888);
	SetBlock(sockForClnt, 0);			//设为非阻塞
	SetBlock(sockForCam, 0);			//设为非阻塞

	//监听开放给客户的端口
	if (listen(sockForClnt, CLNTNUM) == -1)
	{
		cout << "listen socket failed" << endl;
		exit(0);
	}
	cout << "开始监听客户端连接" << endl;
	//监听开放给摄像头服务器的端口
	if (listen(sockForCam, CAMNUM) == -1)
	{
		cout << "listen socket failed" << endl;
		exit(0);
	}
	cout << "开始监听摄像头连接" << endl;
	//初始化客户端信息
	for (i = 0; i < CLNTNUM; i++)
	{
		clnt[i].ipAddr[0] = '*';
		clnt[i].identified = 0;
		clnt[i].cameraNum = -1;
		clnt[i].isWatching = 0;
	}
	//初始化摄像头信息
	for (i = 0; i < CAMNUM; i++)
	{
		cam[i].ipAddr[0] = '*';
		cam[i].timer = -1;
	}
	//strcpy(cam[0].ipAddr, "192.168.80.230");
	//cam[0].port = 5000;
	//SetTimer();

	fd_set rfd;
	fd_set rfdb;	//备份
	int res;
	int maxfd = max(sockForClnt,sockForCam);;
	struct timeval timeout;
	FD_ZERO(&rfdb);
	FD_SET(sockForClnt, &rfdb);
	FD_SET(sockForCam,  &rfdb);
	//连接的信息
	int connect_fd;
	struct sockaddr_in connect_addr;
	socklen_t connect_len;
	char connect_ip[INET_ADDRSTRLEN];
	//cout << "接受客户端的socket为" << sockForClnt << endl;
	//cout << "接受摄像头的socket为" << sockForCam << endl;
	//cout << "maxfd " << maxfd << endl;
	while (1)
	{
		rfd = rfdb;
		timeout.tv_sec = 20;
		timeout.tv_usec = 0;
		res = select(maxfd + 1, &rfd, NULL, NULL, &timeout);
		if (res == 0)
		{
			cout << "超时" << endl;
			continue;
		}
		connect_len = sizeof(connect_addr);
		if (res > 0)
		{
			for (i = 3; i <= maxfd; i++)
			{
				if (FD_ISSET(i, &rfd))
				{
					cout << i << "可读" << endl;
					sleep(1);
					if (i == sockForCam)
					{
						/*某个摄像头加入常连接*/
						if (!Accept(sockForCam, connect_fd, connect_addr, connect_len))
							continue;
						SetBlock(connect_fd, 0);
						/*记录下此摄像头的信息*/
						RecordCam(connect_addr, connect_fd);
						/*加入描述符集*/
						FD_SET(connect_fd, &rfdb);
						if (maxfd < connect_fd)
							maxfd = connect_fd;
					}
					else if (i == sockForClnt)
					{
						/*某个用户发起了连接*/
						/*bug?一旦用户访问了,就一直占坑（不是占sock而是占记录）*/
						if (!Accept(sockForClnt, connect_fd, connect_addr, connect_len))
							continue;
						SetBlock(connect_fd, 0);
						/*判断该用户是否已经经过了认证,
						 *网页请求一定时间会自动断开,
						 *这里不用cookie来记录用户状态*/
						if (maxfd < connect_fd)
							maxfd = connect_fd;
						FD_SET(connect_fd, &rfdb);
						place = SearchPlace(ipAddr, 0);
						if (place >= 0)
						{
							/*该用户已经连接过,不过网页服务器自动断开了连接而已,
							 *在这里只需要更新保存的socket
							 */
							clnt[place].sock = connect_fd;
							clnt[place].port = connect_addr.sin_port;
							cout << "该客户已经连接" << endl;
						}
						else
						{
							/*标记该用户的信息,需要认证*/
							place = SearchEmpty(0);
							if (place < 0)
								continue;	//不管了,容纳的用户满了
							clnt[place].sock = connect_fd;
							strcpy(clnt[place].ipAddr, ipAddr);
							cout << "place=" << place << endl;
							cout << clnt[place].ipAddr << endl;
						}
						cout << "客户端连接" << connect_fd << endl;
					}
					else
					{
						rcvLen = recv(i, BUF, sizeof(BUF), 0);
						cout << "读到的包为：" << endl;
						cout << BUF << endl;
						/*得到发来信息的sock的ip及其端口号*/
						res = getpeername(i, (struct sockaddr*)&connect_addr, &connect_len);
						inet_ntop(AF_INET, &(connect_addr.sin_addr), ipAddr, sizeof(ipAddr));
						if (IsCam(i))
						{
							/*摄像头i发送过来信息*/
							place = SearchPlace(ipAddr, 1, ntohs(connect_addr.sin_port));
							cam[place].timer = 0;
							if (strncmp(BUF, "hello",5) == 0)
							{
								/*心跳包*/
								continue;
							}
							/*非心跳包直接转给相应用户即可*/
							/*这里假定只有一个用户正在访问这个摄像头*/
							place = CamToUser(place);
							sndLen = send(clnt[place].sock, BUF, sizeof(BUF), 0);
						}
						else
						{
							/*用户i发送过来信息*/
							place = SearchPlace(ipAddr, 0);
							if (rcvLen == 0)
							{
								cout << ipAddr << "主动关闭" << endl;
								close(clnt[place].sock);
								continue;
							}
							if (!clnt[place].identified)
							{
								/*没有经过认证*/
								if (IsGet())
								{
									cout << "是get包" << endl;
									/*推送认证网页*/
									SendIdentifyWeb(i,0);
									continue;
								}
								else if (IsPost())
								{
									cout << "是post包" << endl;
									/*进行用户认证*/
									if (UserIdentify(place) == true)
									{
										cout << "认证通过" << endl;
										SendCamList(i,0,place);
									}
									else
										SendIdentifyWeb(i,1);
									continue;
								}
								cout << "居然既不是post也不是get？" << endl;
								continue;
							}
							else
							{
								/*已经通过了认证,看用户是否已经选择了摄像头 POST包*/
								/*如果用户已经选择了摄像头*/
								/*回放还是直播归摄像头服务器处理,这里只做简单转发*/
								/*必然是post包*/
								if (IsPost() && !clnt[place].isWatching)
								{
									/*根据用户的选择,绑定相应的摄像头*/
									/*向对应的摄像头服务器发送get包*/
									/*摄像头回包的时候因为用户已经绑定*/
									/*所以也知道该往哪里转发*/
									cout << "绑定摄像头" << endl;
									BindCam(place);
								}
								else
								{
									/*找到该用户选择的摄像头,转发*/
									place = clnt[place].cameraNum;
									sndLen = send(cam[place].sock, BUF, sizeof(BUF), 0);
								}
							}
						}
					}
				}
			}
		}
	}
    return 0;
}