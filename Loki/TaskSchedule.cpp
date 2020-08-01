#include "stdafx.h"
#include "TaskSchedule.h"


void ShowError(char *lpszText, DWORD dwErrCode)
{
	char szErr[MAX_PATH] = { 0 };
	::wsprintf(szErr, "%s Error!\nError Code Is:0x%08x\n", lpszText, dwErrCode);
}


CMyTaskSchedule::CMyTaskSchedule(void)
{
	m_lpITS = NULL;
	m_lpRootFolder = NULL;
	// ��ʼ��COM
	HRESULT hr = ::CoInitialize(NULL);
	HRESULT hr2 = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (FAILED(hr))
	{
		ShowError("CoInitialize", hr);
	}
	// ����һ���������Task Service��ʵ��
	hr = ::CoCreateInstance(CLSID_TaskScheduler,
		NULL,
		CLSCTX_INPROC_SERVER,
		IID_ITaskService,
		(LPVOID *)(&m_lpITS));
	if (FAILED(hr))
	{
		ShowError("CoCreateInstance", hr);
	}
	// ���ӵ��������Task Service��
	hr = m_lpITS->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
	if (FAILED(hr))
	{
		ShowError("ITaskService::Connect", hr);
	}
	// ��ȡRoot Task Folder��ָ�룬���ָ��ָ�������ע�������
	hr = m_lpITS->GetFolder(_bstr_t("\\"), &m_lpRootFolder);
	if (FAILED(hr))
	{
		ShowError("ITaskService::GetFolder", hr);
	}
}


CMyTaskSchedule::~CMyTaskSchedule(void)
{
	if (m_lpITS)
	{
		m_lpITS->Release();
	}
	if (m_lpRootFolder)
	{
		m_lpRootFolder->Release();
	}
	// ж��COM
	::CoUninitialize();
}


BOOL CMyTaskSchedule::Delete(char *lpszTaskName)
{
	if (NULL == m_lpRootFolder)
	{
		return FALSE;
	}
	CComVariant variantTaskName(NULL);
	variantTaskName = lpszTaskName;
	HRESULT hr = m_lpRootFolder->DeleteTask(variantTaskName.bstrVal, 0);
	if (FAILED(hr))
	{
		return FALSE;
	}

	return TRUE;
}


BOOL CMyTaskSchedule::DeleteFolder(char *lpszFolderName)
{
	if (NULL == m_lpRootFolder)
	{
		return FALSE;
	}
	CComVariant variantFolderName(NULL);
	variantFolderName = lpszFolderName;
	HRESULT hr = m_lpRootFolder->DeleteFolder(variantFolderName.bstrVal, 0);
	if (FAILED(hr))
	{
		return FALSE;
	}

	return TRUE;
}


BOOL CMyTaskSchedule::NewTask(char *lpszTaskName, char *lpszProgramPath, char *lpszParameters, char *lpszAuthor)
{
	if (NULL == m_lpRootFolder)
	{
		return FALSE;
	}
	// ���������ͬ�ļƻ�������ɾ��
	Delete(lpszTaskName);
	// �����������������������
	ITaskDefinition *pTaskDefinition = NULL;
	HRESULT hr = m_lpITS->NewTask(0, &pTaskDefinition);
	if (FAILED(hr))
	{
		ShowError("ITaskService::NewTask", hr);
		return FALSE;
	}

	/* ����ע����Ϣ */
	IRegistrationInfo *pRegInfo = NULL;
	CComVariant variantAuthor(NULL);
	variantAuthor = lpszAuthor;

	hr = pTaskDefinition->get_RegistrationInfo(&pRegInfo);
	if (FAILED(hr))
	{
		ShowError("pTaskDefinition::get_RegistrationInfo", hr);
		return FALSE;
	}
	// ����������Ϣ
	hr = pRegInfo->put_Description(variantAuthor.bstrVal);
	pRegInfo->Release();

	/* ���õ�¼���ͺ�����Ȩ�� */
	IPrincipal *pPrincipal = NULL;
	hr = pTaskDefinition->get_Principal(&pPrincipal);
	if (FAILED(hr))
	{
		ShowError("pTaskDefinition::get_Principal", hr);
		return FALSE;
	}
	// ���õ�¼����
	hr = pPrincipal->put_LogonType(TASK_LOGON_INTERACTIVE_TOKEN);
	// ��������Ȩ��
	// ���Ȩ��
	hr = pPrincipal->put_RunLevel(TASK_RUNLEVEL_HIGHEST);
	pPrincipal->Release();

	/* ����������Ϣ */
	ITaskSettings *pSettting = NULL;
	hr = pTaskDefinition->get_Settings(&pSettting);
	if (FAILED(hr))
	{
		ShowError("pTaskDefinition::get_Settings", hr);
		return FALSE;
	}


	// ����������Ϣ
	hr = pSettting->put_StopIfGoingOnBatteries(VARIANT_FALSE);
	hr = pSettting->put_DisallowStartIfOnBatteries(VARIANT_FALSE);
	hr = pSettting->put_AllowDemandStart(VARIANT_TRUE);
	hr = pSettting->put_StartWhenAvailable(VARIANT_TRUE);
	hr = pSettting->put_MultipleInstances(TASK_INSTANCES_PARALLEL);
	pSettting->Release();

	/* ����ִ�ж��� */
	IActionCollection *pActionCollect = NULL;
	hr = pTaskDefinition->get_Actions(&pActionCollect);
	if (FAILED(hr))
	{
		ShowError("pTaskDefinition::get_Actions", hr);
		return FALSE;
	}
	IAction *pAction = NULL;
	// ����ִ�в���
	hr = pActionCollect->Create(TASK_ACTION_EXEC, &pAction);
	pActionCollect->Release();

	/* ����ִ�г���·���Ͳ��� */
	CComVariant variantProgramPath(NULL);
	CComVariant variantParameters(NULL);
	IExecAction *pExecAction = NULL;
	hr = pAction->QueryInterface(IID_IExecAction, (PVOID *)(&pExecAction));
	if (FAILED(hr))
	{
		pAction->Release();
		ShowError("IAction::QueryInterface", hr);
		return FALSE;
	}
	pAction->Release();
	// ���ó���·���Ͳ���
	variantProgramPath = lpszProgramPath;
	variantParameters = lpszParameters;
	pExecAction->put_Path(variantProgramPath.bstrVal);
	pExecAction->put_Arguments(variantParameters.bstrVal);
	pExecAction->Release();

	/* ������������ʵ���û���½������ */
	ITriggerCollection *pTriggers = NULL;
	hr = pTaskDefinition->get_Triggers(&pTriggers);
	if (FAILED(hr))
	{
		ShowError("pTaskDefinition::get_Triggers", hr);
		return FALSE;
	}
	//start

	//end
	ITrigger* pTrigger = NULL;

	// 1�û���¼ʱ����
	hr = pTriggers->Create(TASK_TRIGGER_LOGON, &pTrigger);
	if (FAILED(hr))
	{
		ShowError("ITriggerCollection::Create", hr);
		return FALSE;
	}

	//�ս�ʱ��
	//hr = pTrigger->put_EndBoundary(_bstr_t(L"2099-05-02T12:05:00"));
	//if (FAILED(hr))
	//	printf("\nCannot put the end boundary: %x", hr);
	//1

	
	//2����������ִ��
	hr = pTriggers->Create(TASK_TRIGGER_REGISTRATION, &pTrigger);
	pTriggers->Release();
	if (FAILED(hr))
	{
		printf("\nCannot create a TASK_TRIGGER_REGISTRATION trigger: %x", hr);
		return 1;
	}
	//2

	//3������ʱִ��
	hr = m_lpITS->GetFolder(_bstr_t(L"\\"), &m_lpRootFolder);
	if (FAILED(hr))
	{
		printf("Cannot get Root Folder pointer: %x", hr);
		m_lpITS->Release();
		CoUninitialize();
		return 1;
	}
	m_lpITS->Release();  // COM clean up.  Pointer is no longer used.
	if (FAILED(hr))
	{
		printf("Failed to CoCreate an instance of the TaskService class: %x", hr);
		m_lpRootFolder->Release();
		CoUninitialize();
		return 1;
	}

	hr = pTaskDefinition->get_Triggers(&pTriggers);
	if (FAILED(hr))
	{
		printf("\nCannot get trigger collection: %x", hr);
		m_lpRootFolder->Release();
		pTaskDefinition->Release();
		CoUninitialize();
		return 1;
	}

	hr = pTriggers->Create(TASK_TRIGGER_DAILY, &pTrigger);
	pTriggers->Release();
	if (FAILED(hr)) {
		m_lpRootFolder->Release();
		pTaskDefinition->Release();
		CoUninitialize();
		return 1;
	}

	IDailyTrigger* pDailyTrigger = NULL;
	hr = pTrigger->QueryInterface(
		IID_IDailyTrigger, (void**)&pDailyTrigger);
	pTrigger->Release();
	if (FAILED(hr)) {
		m_lpRootFolder->Release();
		pTaskDefinition->Release();
		CoUninitialize();
		return 1;
	}

	hr = pDailyTrigger->put_Id(_bstr_t(L"Trigger"));
	hr = pDailyTrigger->put_StartBoundary(_bstr_t(L"2018-11-30T12:13:14"));//
	//  Set the time when the trigger is deactivated.
	//hr = pDailyTrigger->put_EndBoundary(_bstr_t(L"2099-01-01T12:00:00"));//
	//hr = pDailyTrigger->put_DaysInterval((short)1);//
	if (FAILED(hr)) {
		m_lpRootFolder->Release();
		pDailyTrigger->Release();
		pTaskDefinition->Release();
		CoUninitialize();
		return 1;
	}

	// Add a repetition to the trigger so that it repeats
	// five times.
	IRepetitionPattern* pRepetitionPattern = NULL;
	hr = pDailyTrigger->get_Repetition(&pRepetitionPattern);
	pDailyTrigger->Release();
	if (FAILED(hr)) {
		m_lpRootFolder->Release();
		pTaskDefinition->Release();
		CoUninitialize();
		return 1;
	}

	//hr = pRepetitionPattern->put_Duration(_bstr_t(L"PT1440M"));//
	//if (FAILED(hr)) {
	//	m_lpRootFolder->Release();
	//	pRepetitionPattern->Release();
	//	pTaskDefinition->Release();
	//	CoUninitialize();
	//	return 1;
	//}

	hr = pRepetitionPattern->put_Interval(_bstr_t(L"PT30M"));//
	pRepetitionPattern->Release();
	if (FAILED(hr)) {
		printf("\nCannot put repetition interval: %x", hr);
		m_lpRootFolder->Release();
		pTaskDefinition->Release();
		CoUninitialize();
		return 1;
	}
	//3



	

	// 4 ϵͳ����ʱ������
	hr = pTriggers->Create(TASK_TRIGGER_BOOT, &pTrigger);
	pTrigger->Release();
	if (FAILED(hr))
	{
		printf("\nCannot create the trigger: %x", hr);
		m_lpRootFolder->Release();
		pTaskDefinition->Release();
		CoUninitialize();
		return 1;
	}

	//CoolCat

	//CoolCat


	/* ע������ƻ�  */
	IRegisteredTask *pRegisteredTask = NULL;
	CComVariant variantTaskName(NULL);
	variantTaskName = lpszTaskName;
	hr = m_lpRootFolder->RegisterTaskDefinition(variantTaskName.bstrVal,
		pTaskDefinition,
		TASK_CREATE_OR_UPDATE,
		_variant_t(),
		_variant_t(),
		TASK_LOGON_INTERACTIVE_TOKEN,
		_variant_t(""),
		&pRegisteredTask);


	if (FAILED(hr))
	{
		pTaskDefinition->Release();
		ShowError("ITaskFolder::RegisterTaskDefinition", hr);
		return FALSE;
	}
	pTaskDefinition->Release();
	pRegisteredTask->Release();

	return TRUE;
}


BOOL CMyTaskSchedule::IsExist(char *lpszTaskName)
{
	if (NULL == m_lpRootFolder)
	{
		return FALSE;
	}
	HRESULT hr = S_OK;
	CComVariant variantTaskName(NULL);
	CComVariant variantEnable(NULL);
	variantTaskName = lpszTaskName;                     // ����ƻ�����
	IRegisteredTask *pRegisteredTask = NULL;
	// ��ȡ����ƻ�
	hr = m_lpRootFolder->GetTask(variantTaskName.bstrVal, &pRegisteredTask);
	if (FAILED(hr) || (NULL == pRegisteredTask))
	{
		return FALSE;
	}
	pRegisteredTask->Release();

	return TRUE;
}


BOOL CMyTaskSchedule::IsTaskValid(char *lpszTaskName)
{
	if (NULL == m_lpRootFolder)
	{
		return FALSE;
	}
	HRESULT hr = S_OK;
	CComVariant variantTaskName(NULL);
	CComVariant variantEnable(NULL);
	variantTaskName = lpszTaskName;                     // ����ƻ�����
	IRegisteredTask *pRegisteredTask = NULL;
	// ��ȡ����ƻ�
	hr = m_lpRootFolder->GetTask(variantTaskName.bstrVal, &pRegisteredTask);
	if (FAILED(hr) || (NULL == pRegisteredTask))
	{
		return FALSE;
	}
	// ��ȡ����״̬
	TASK_STATE taskState;
	hr = pRegisteredTask->get_State(&taskState);
	if (FAILED(hr))
	{
		pRegisteredTask->Release();
		return FALSE;
	}
	pRegisteredTask->Release();
	// ��Ч
	if (TASK_STATE_DISABLED == taskState)
	{
		return FALSE;
	}

	return TRUE;
}


BOOL CMyTaskSchedule::Run(char *lpszTaskName, char *lpszParam)
{
	if (NULL == m_lpRootFolder)
	{
		return FALSE;
	}
	HRESULT hr = S_OK;
	CComVariant variantTaskName(NULL);
	CComVariant variantParameters(NULL);
	variantTaskName = lpszTaskName;
	variantParameters = lpszParam;

	// ��ȡ����ƻ�
	IRegisteredTask *pRegisteredTask = NULL;
	hr = m_lpRootFolder->GetTask(variantTaskName.bstrVal, &pRegisteredTask);
	if (FAILED(hr) || (NULL == pRegisteredTask))
	{
		return FALSE;
	}
	// ����
	hr = pRegisteredTask->Run(variantParameters, NULL);
	if (FAILED(hr))
	{
		pRegisteredTask->Release();
		return FALSE;
	}
	pRegisteredTask->Release();

	return TRUE;
}


BOOL CMyTaskSchedule::IsEnable(char *lpszTaskName)
{
	if (NULL == m_lpRootFolder)
	{
		return FALSE;
	}
	HRESULT hr = S_OK;
	CComVariant variantTaskName(NULL);
	CComVariant variantEnable(NULL);
	variantTaskName = lpszTaskName;                     // ����ƻ�����
	IRegisteredTask *pRegisteredTask = NULL;
	// ��ȡ����ƻ�
	hr = m_lpRootFolder->GetTask(variantTaskName.bstrVal, &pRegisteredTask);
	if (FAILED(hr) || (NULL == pRegisteredTask))
	{
		return FALSE;
	}
	// ��ȡ�Ƿ��Ѿ�����
	pRegisteredTask->get_Enabled(&variantEnable.boolVal);
	pRegisteredTask->Release();
	if (ATL_VARIANT_FALSE == variantEnable.boolVal)
	{
		return FALSE;
	}

	return TRUE;
}


BOOL CMyTaskSchedule::SetEnable(char *lpszTaskName, BOOL bEnable)
{
	if (NULL == m_lpRootFolder)
	{
		return FALSE;
	}
	HRESULT hr = S_OK;
	CComVariant variantTaskName(NULL);
	CComVariant variantEnable(NULL);
	variantTaskName = lpszTaskName;                     // ����ƻ�����
	variantEnable = bEnable;                            // �Ƿ�����
	IRegisteredTask *pRegisteredTask = NULL;
	// ��ȡ����ƻ�
	hr = m_lpRootFolder->GetTask(variantTaskName.bstrVal, &pRegisteredTask);
	if (FAILED(hr) || (NULL == pRegisteredTask))
	{
		return FALSE;
	}
	// �����Ƿ�����
	pRegisteredTask->put_Enabled(variantEnable.boolVal);
	pRegisteredTask->Release();

	return TRUE;
}

