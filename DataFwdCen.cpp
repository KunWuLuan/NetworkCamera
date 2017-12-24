#include <iostream>	// cin,cout��
#include <iomanip>	// setw��
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
#define CLNTNUM 10						//���10���û�
#define CAMNUM 10						//���10������ͷ
using namespace std;

char BUF[100000];						//���ջ�����
int place;								//ĳ���ͻ��˷��õ�λ��
int sndLen, rcvLen;
char ipAddr[INET_ADDRSTRLEN];
string loginHtml;

struct CLNT
{
	int sock;							//�û�ÿ�ε����ҳ�����ڱ�
	char ipAddr[INET_ADDRSTRLEN];		//����û�
	bool identified;					//����û��Ƿ񾭹��˱�����֤
	int cameraNum;						//����ͷ���(��������ͷ��socket)
										//ĳ���û����ڷ��ʵ�����ͷ����
	bool isWatching;					//�Ѿ��ڿ���,û�а���һ����
}clnt[CLNTNUM];

struct CAMERA
{
	int sock;
	char ipAddr[INET_ADDRSTRLEN];		//���ip
	int port;							//�˿ں�
	char nickName[20];
	int timer;							//������������ʱ
}cam[CAMNUM];

short tryCnt = 0;	//�������Ӵ��� 3 �ζ�ʧ��,����������,���������˳�����

/*��ʼ��Ϊ�ػ�����*/
bool InitDaemon()
{
	pid_t pid;
	//1) ����һЩ�����ն˲������ź�
	signal(SIGTTOU, SIG_IGN);
	signal(SIGTTIN, SIG_IGN);
	signal(SIGTSTP, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	//2) �ں�̨����
	if (pid = fork()) { // ������  
		exit(0); //���������̣��ӽ��̼���  
	}
	else if (pid < 0) { // ����  
		perror("fork");
		exit(EXIT_FAILURE);
	}

	//8) ����SIGCHLD�ź� ʹ֮���������ʬ����
	signal(SIGCHLD, SIG_IGN);		//�����̲������ӽ����˳�

	return 0;
}

void InitLogin()
{
	ifstream in("login.html",ios::in);
	string temp;
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
	int len = loginHtml.length();
	sprintf(contentLen, "%d", loginHtml.length());
	temp += contentLen;
	temp += "\r\n";
	//temp += "Keep-Alive: timeout=5, max=100\r\n";
	//temp += "Connection: Keep-Alive\r\n";
	temp += "Content-Type: text/html; charset=gbk\r\n";
	temp += "\r\n";
	temp += loginHtml;

	loginHtml = temp;
	cout << loginHtml << endl;
}

/*��Ϊ����������*/
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

/*���ӱ������ݿ�
bool ConDataBase(MYSQL *mysql)
{
	/* ��ʼ�� mysql ������ʧ�ܷ���NULL 
	if ((mysql = mysql_init(NULL)) == NULL) {
		cout << "mysql_init failed" << endl;
		return 0;
	}

	/* �������ݿ⣬ʧ�ܷ���NULL
	1��mysqldû����
	2��û��ָ�����Ƶ����ݿ���� 
	if (mysql_real_connect(mysql, "localhost", "root", "1002.lkj555", "demo", 0, NULL, 0) == NULL) {
		cout << "mysql_real_connect failed(" << mysql_error(mysql) << ")" << endl;
		return 0;
	}

	/* �����ַ���������������ַ����룬��ʹ/etc/my.cnf������Ҳ���� 
	mysql_set_character_set(mysql, "gbk");

	return 1; 
}*/

/*�������������һ��hello*/
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
	//����������ʱ��
	struct itimerval val;
	val.it_value.tv_sec = 1;		//1������ö�ʱ��
	val.it_value.tv_usec = 0;

	val.it_interval.tv_sec = 1;		//��ʱ�����Ϊ1��
	val.it_interval.tv_usec = 0;
	if (setitimer(ITIMER_REAL, &val, NULL) < 0)
	{
		cout << "���ö�ʱ��ʧ��" << endl;
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
		return -1;	//�������

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
	//����ip��ַ�鿴�û��Ƿ��Ѿ����ʹ���ת������
	//�����û���Ϣ
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
	//�ж��յ����ǲ���get�� ����ҳ��
	cout << "�ж��յ����ǲ���get��" << endl;
	if (strstr(BUF, "GET /"))
		return 1;
	return 0;
}

bool IsPost()
{
	//�ж��յ����ǲ���post�� ����
	cout << "�ж��յ����ǲ���post��" << endl;
	if (strstr(BUF, "POST / HTTP/ 1.1"))
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

	//�˿ڸ���
	int reuse = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

	//��ʼ����ַ��Ϣ
	struct sockaddr_in Addr;
	bzero(&Addr, sizeof(Addr));
	Addr.sin_family = AF_INET;
	Addr.sin_addr.s_addr = inet_addr(ipAddr);
	Addr.sin_port = htons(port);

	//�����ص�ַ�󶨵����������׽�����
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
	cout << ipAddr << "��������" << endl;
	sleep(5);
	if (connect_fd == -1)
	{
		if (errno == 11)		//ʱ���жϿ��ܻᵼ���������
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
	cout << "���ӵ�����ͷipΪ:" << cam[place].ipAddr << endl;
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
	return -1;	//��Ӧ�ó����������
}

void SendIdentifyWeb(int sock)
{
	sndLen = send(sock, loginHtml.c_str(), loginHtml.length(), 0);
	cout << "���͵�html����Ϊ"<< sndLen << endl;
}

void UserIdentify(int sock)
{
	/*��֤ʧ��ֱ�Ӹ�֪��Ϣ,��֤�ɹ������и��û��󶨵�����ͷ��Ϣ���ظ��û�*/
}

void BindCam(int clntPlace)
{

}

int main(int argc, char* argv[])
{
	int i;
	InitDaemon();

	InitLogin();

	//һ���ṩ���ͻ�����,һ���ṩ��ÿ������ͷ����������
	int sockForClnt, sockForCam;
	InitBind(sockForClnt, "192.168.80.230", 5555);
	InitBind(sockForCam,  "192.168.80.230", 8888);
	SetBlock(sockForClnt, 0);			//��Ϊ������
	SetBlock(sockForCam, 0);			//��Ϊ������

	//�������Ÿ��ͻ��Ķ˿�
	if (listen(sockForClnt, CLNTNUM) == -1)
	{
		cout << "listen socket failed" << endl;
		exit(0);
	}
	cout << "��ʼ�����ͻ�������" << endl;
	//�������Ÿ�����ͷ�������Ķ˿�
	if (listen(sockForCam, CAMNUM) == -1)
	{
		cout << "listen socket failed" << endl;
		exit(0);
	}
	cout << "��ʼ��������ͷ����" << endl;
	//��ʼ���ͻ�����Ϣ
	for (i = 0; i < CLNTNUM; i++)
	{
		clnt[i].ipAddr[0] = '*';
		clnt[i].identified = 0;
		clnt[i].cameraNum = -1;
		clnt[i].isWatching = 0;
	}
	//��ʼ������ͷ��Ϣ
	for (i = 0; i < CAMNUM; i++)
	{
		cam[i].ipAddr[0] = '*';
		cam[i].timer = 0;
	}
	//SetTimer();

	fd_set rfd;
	fd_set rfdb;	//����
	int res;
	int maxfd = max(sockForClnt,sockForCam);;
	struct timeval timeout;
	FD_ZERO(&rfdb);
	FD_SET(sockForClnt, &rfdb);
	FD_SET(sockForCam,  &rfdb);
	//���ӵ���Ϣ
	int connect_fd;
	struct sockaddr_in connect_addr;
	socklen_t connect_len;
	char connect_ip[INET_ADDRSTRLEN];
	cout << "���ܿͻ��˵�socketΪ" << sockForClnt << endl;
	cout << "��������ͷ��socketΪ" << sockForCam << endl;
	cout << "maxfd " << maxfd << endl;
	while (1)
	{
		rfd = rfdb;
		timeout.tv_sec = 3;
		timeout.tv_usec = 0;
		res = select(maxfd + 1, &rfd, NULL, NULL, &timeout);
		if (res == 0)
		{
			cout << "��ʱ" << endl;
			continue;
		}
		connect_len = sizeof(connect_addr);
		if (res > 0)
		{
			for (i = 3; i <= maxfd; i++)
			{
				if (FD_ISSET(i, &rfd))
				{
					cout << i << "�ɶ�" << endl;
					sleep(1);
					if (i == sockForCam)
					{
						/*ĳ������ͷ���볣����*/
						if (!Accept(sockForCam, connect_fd, connect_addr, connect_len))
							continue;
						SetBlock(connect_fd, 0);
						/*��¼�´�����ͷ����Ϣ*/
						RecordCam(connect_addr, connect_fd);
						/*������������*/
						FD_SET(connect_fd, &rfdb);
						if (maxfd < connect_fd)
							maxfd = connect_fd;
					}
					else if (i == sockForClnt)
					{
						/*ĳ���û�����������*/
						/*bug?һ���û�������,��һֱռ�ӣ�����ռsock����ռ��¼��*/
						if (!Accept(sockForClnt, connect_fd, connect_addr, connect_len))
							continue;
						SetBlock(connect_fd, 0);
						/*�жϸ��û��Ƿ��Ѿ���������֤,
						 *��ҳ����һ��ʱ����Զ��Ͽ�,
						 *���ﲻ��cookie����¼�û�״̬*/
						if (maxfd < connect_fd)
							maxfd = connect_fd;
						FD_SET(connect_fd, &rfdb);
						place = SearchPlace(ipAddr, 0);
						if (place >= 0)
						{
							/*���û��Ѿ����ӹ�,������ҳ�������Զ��Ͽ������Ӷ���,
							 *������ֻ��Ҫ���±����socket
							 */
							clnt[place].sock = connect_fd;
							cout << "�ÿͻ��Ѿ�����" << endl;
						}
						else
						{
							/*��Ǹ��û�����Ϣ,��Ҫ��֤*/
							place = SearchEmpty(0);
							clnt[place].sock = connect_fd;
							strcpy(clnt[place].ipAddr, ipAddr);
							cout << "place=" << place << endl;
							cout << clnt[place].ipAddr << endl;
						}
						cout << "�ͻ�������" << connect_fd << endl;
					}
					else
					{
						cout << BUF << endl;
						rcvLen = recv(i, BUF, sizeof(BUF), 0);
						/*�õ�������Ϣ��sock��ip����˿ں�*/
						res = getpeername(i, (struct sockaddr*)&connect_addr, &connect_len);
						inet_ntop(AF_INET, &(connect_addr.sin_addr), ipAddr, sizeof(ipAddr));
						if (IsCam(i))
						{
							/*����ͷi���͹�����Ϣ*/
							place = SearchPlace(ipAddr, 1, ntohs(connect_addr.sin_port));
							cam[place].timer = 0;
							if (strncmp(BUF, "hello",5) == 0)
							{
								/*������*/
								continue;
							}
							/*��������ֱ��ת����Ӧ�û�����*/
							/*����ٶ�ֻ��һ���û����ڷ����������ͷ*/
							place = CamToUser(place);
							sndLen = send(clnt[place].sock, BUF, sizeof(BUF), 0);
						}
						else
						{
							/*�û�i���͹�����Ϣ*/
							place = SearchPlace(ipAddr, 0);
							if (rcvLen == 0)
							{
								close(clnt[place].sock);
								continue;
							}
							if (!clnt[place].identified)
							{
								/*û�о�����֤*/
								if (IsGet())
								{
									/*������֤��ҳ*/
									SendIdentifyWeb(i);
									continue;
								}
								else if (IsPost())
								{
									/*�����û���֤*/
									UserIdentify(i);
									continue;
								}
								cout << "��Ȼ�Ȳ���postҲ����get��" << endl;
								continue;
							}
							else
							{
								/*�Ѿ�ͨ������֤,���û��Ƿ��Ѿ�ѡ��������ͷ POST��*/
								/*����û��Ѿ�ѡ��������ͷ*/
								/*�طŻ���ֱ��������ͷ����������,����ֻ����ת��*/
								if (IsPost() && !clnt[place].isWatching)
								{
									/*�����û���ѡ��,����Ӧ������ͷ*/
									/*���Ӧ������ͷ����������get��*/
									/*����ͷ�ذ���ʱ����Ϊ�û��Ѿ���*/
									/*����Ҳ֪����������ת��*/
									BindCam(place);
								}
								else
								{
									/*�ҵ����û�ѡ�������ͷ,ת��*/
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