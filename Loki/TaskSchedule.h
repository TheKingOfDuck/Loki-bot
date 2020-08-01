#ifndef _MY_TASK_SCHEDULT_H_
#define _MY_TASK_SCHEDULT_H_


#include <Atlbase.h>
#include <comdef.h>
#include <taskschd.h>
#pragma comment(lib, "taskschd.lib")


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