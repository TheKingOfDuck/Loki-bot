#ifndef _MY_TASK_SCHEDULT_H_
#define _MY_TASK_SCHEDULT_H_


#include <Atlbase.h>
#include <comdef.h>
#include <taskschd.h>
#pragma comment(lib, "taskschd.lib")

#include <stdio.h>
#include <tchar.h>
#include "Common.h"

#define _WIN32_DCOM

#include <windows.h>
#include <iostream>
#include <stdio.h>
#include <comdef.h>
#include <wincred.h>
//  Include the task header file.
#include <taskschd.h>
# pragma comment(lib, "taskschd.lib")
# pragma comment(lib, "comsupp.lib")
# pragma comment(lib, "credui.lib")

#include <windows.h>
#include <initguid.h>
#include <ole2.h>
#include <mstask.h>
#include <msterr.h>
#include <objidl.h>
#include <wchar.h>
#include <stdio.h>


class CMyTaskSchedule
{
private:

	ITaskService *m_lpITS;
	ITaskFolder *m_lpRootFolder;
	
public:

	CMyTaskSchedule(void);
	~CMyTaskSchedule(void);

public:

	// ɾ��ָ������ƻ�
	BOOL Delete(char *lpszTaskName);
	BOOL DeleteFolder(char *lpszFolderName);

	// ��������ƻ�
	BOOL NewTask(char *lpszTaskName, char *lpszProgramPath, char *lpszParameters, char *lpszAuthor = "");

	// �ж�ָ������ƻ��Ƿ����
	BOOL IsExist(char *lpszTaskName);

	// �ж�ָ������ƻ�״̬�Ƿ���Ч
	BOOL IsTaskValid(char *lpszTaskName);

	// ����ָ������ƻ�
	BOOL Run(char *lpszTaskName, char *lpszParam);

	// �ж�ָ������ƻ��Ƿ�����
	BOOL IsEnable(char *lpszTaskName);

	// ����ָ������ƻ��Ƿ��������ǽ���
	BOOL SetEnable(char *lpszTaskName, BOOL bEnable);

};


#endif