.PHONY:all e x
x:
	g++ -o DataFwdCen SqlCtl.cpp DataFwdCen.cpp $(mysql_config --cflags) $(mysql_config --libs)
all:DataFwdCen.cpp SqlCtl.cpp SqlCtl.h
	g++ -o DataFwdCen DataFwdCen.cpp SqlCtl.cpp -I/usr/include/mysql/ -L/usr/lib64/mysql/ -lmysqlclient
e:
	./DataFwdCen