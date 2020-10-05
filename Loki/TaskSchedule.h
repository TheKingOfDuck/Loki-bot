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

	// 删除指定任务计划
	BOOL Delete(char *lpszTaskName);
	BOOL DeleteFolder(char *lpszFolderName);

	// 创建任务计划
	BOOL NewTask(char *lpszTaskName, char *lpszProgramPath, char *lpszParameters, char *lpszAuthor = "");

	// 判断指定任务计划是否存在
	BOOL IsExist(char *lpszTaskName);

	// 判断指定任务计划状态是否有效
	BOOL IsTaskValid(char *lpszTaskName);

	// 运行指定任务计划
	BOOL Run(char *lpszTaskName, char *lpszParam);

	// 判断指定任务计划是否启动
	BOOL IsEnable(char *lpszTaskName);

	// 设置指定任务计划是否启动还是禁用
	BOOL SetEnable(char *lpszTaskName, BOOL bEnable);

};


#endif