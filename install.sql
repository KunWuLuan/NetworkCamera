drop table if exists user_pwd;
create table user_pwd(username char(9) not null,password char(25) not null,primary key(username));

drop table if exists user_camera;
create table user_camera (username char(9) not null,cameraid char(40) not null,primary key(username));
