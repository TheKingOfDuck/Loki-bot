#define _WIN32_DCOM

#include <Lmcons.h>
#include <comdef.h>
#include <taskschd.h>
#include <string>


#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")

//------------------------------------------

#include "TaskSchedule.h"
#include <SDKDDKVer.h>





void ShowError(char *lpszText, DWORD dwErrCode)
{
	char szErr[MAX_PATH] = { 0 };
	::wsprintf(szErr, "%s Error!\nError Code Is:0x%08x\n", lpszText, dwErrCode);
}


CMyTaskSchedule::CMyTaskSchedule(void)
{
	m_lpITS = NULL;
	m_lpRootFolder = NULL;
	// 初始化COM
	HRESULT hr = ::CoInitialize(NULL);
	//HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	//HRESULT hr2 = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (FAILED(hr))
	{
		ShowError("CoInitialize", hr);
	}
	// 创建一个任务服务（Task Service）实例
	hr = ::CoCreateInstance(CLSID_TaskScheduler,
		NULL,
		CLSCTX_INPROC_SERVER,
		IID_ITaskService,
		(LPVOID *)(&m_lpITS));
	if (FAILED(hr))
	{
		ShowError("CoCreateInstance", hr);
	}
	// 连接到任务服务（Task Service）
	hr = m_lpITS->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
	if (FAILED(hr))
	{
		ShowError("ITaskService::Connect", hr);
	}
	// 获取Root Task Folder的指针，这个指针指向的是新注册的任务
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
	// 卸载COM
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


const DWORD USERNAME_DOMAIN_LEN = DNLEN + UNLEN + 2;
const DWORD USERNAME_LEN = UNLEN + 1;

BOOL CMyTaskSchedule::NewTask(char* lpszTaskName, char* lpszProgramPath, char* lpszParameters, char* lpszAuthor)
{
	bool isAdmin = Common::isAdmin();

	if (isAdmin)
	{

		if (NULL == m_lpRootFolder)
		{
			return FALSE;
		}
		// 如果存在相同的计划任务，则删除
		Delete(lpszTaskName);
		// 创建任务定义对象来创建任务
		ITaskDefinition* pTaskDefinition = NULL;
		HRESULT hr = m_lpITS->NewTask(0, &pTaskDefinition);
		if (FAILED(hr))
		{
			ShowError("ITaskService::NewTask", hr);
			return FALSE;
		}

		/* 设置注册信息 */
		IRegistrationInfo* pRegInfo = NULL;
		CComVariant variantAuthor(NULL);
		variantAuthor = lpszAuthor;

		hr = pTaskDefinition->get_RegistrationInfo(&pRegInfo);
		if (FAILED(hr))
		{
			ShowError("pTaskDefinition::get_RegistrationInfo", hr);
			return FALSE;
		}
		// 设置作者信息
		hr = pRegInfo->put_Description(variantAuthor.bstrVal);
		pRegInfo->Release();

		/* 设置登录类型和运行权限 */
		IPrincipal* pPrincipal = NULL;
		hr = pTaskDefinition->get_Principal(&pPrincipal);
		if (FAILED(hr))
		{
			ShowError("pTaskDefinition::get_Principal", hr);
			return FALSE;
		}
		//// 设置登录类型
		hr = pPrincipal->put_LogonType(TASK_LOGON_INTERACTIVE_TOKEN);
		//hr = pPrincipal->put_UserId(L"desktop\\xuanjian");
		//// 设置运行权限
		//// 最高权限
		//hr = pPrincipal->put_RunLevel(TASK_RUNLEVEL_LUA);
		hr = pPrincipal->put_RunLevel(TASK_RUNLEVEL_HIGHEST);

		pPrincipal->Release();

		/* 设置其他信息 */
		ITaskSettings* pSettting = NULL;
		hr = pTaskDefinition->get_Settings(&pSettting);
		if (FAILED(hr))
		{
			ShowError("pTaskDefinition::get_Settings", hr);
			return FALSE;
		}


		// 设置其他信息
		hr = pSettting->put_StopIfGoingOnBatteries(VARIANT_FALSE);
		hr = pSettting->put_DisallowStartIfOnBatteries(VARIANT_FALSE);
		hr = pSettting->put_AllowDemandStart(VARIANT_TRUE);
		hr = pSettting->put_StartWhenAvailable(VARIANT_TRUE);
		hr = pSettting->put_MultipleInstances(TASK_INSTANCES_PARALLEL);
		pSettting->Release();

		/* 创建执行动作 */
		IActionCollection* pActionCollect = NULL;
		hr = pTaskDefinition->get_Actions(&pActionCollect);
		if (FAILED(hr))
		{
			ShowError("pTaskDefinition::get_Actions", hr);
			return FALSE;
		}
		IAction* pAction = NULL;
		// 创建执行操作
		hr = pActionCollect->Create(TASK_ACTION_EXEC, &pAction);
		pActionCollect->Release();

		/* 设置执行程序路径和参数 */
		CComVariant variantProgramPath(NULL);
		CComVariant variantParameters(NULL);
		IExecAction* pExecAction = NULL;
		hr = pAction->QueryInterface(IID_IExecAction, (PVOID*)(&pExecAction));
		if (FAILED(hr))
		{
			pAction->Release();
			ShowError("IAction::QueryInterface", hr);
			return FALSE;
		}
		pAction->Release();
		// 设置程序路径和参数
		variantProgramPath = lpszProgramPath;
		variantParameters = lpszParameters;
		pExecAction->put_Path(variantProgramPath.bstrVal);
		pExecAction->put_Arguments(variantParameters.bstrVal);
		pExecAction->Release();

		/* 创建触发器，实现用户登陆自启动 */
		ITriggerCollection* pTriggers = NULL;
		hr = pTaskDefinition->get_Triggers(&pTriggers);
		if (FAILED(hr))
		{
			ShowError("pTaskDefinition::get_Triggers", hr);
			return FALSE;
		}
		//start

		//end
		ITrigger* pTrigger = NULL;

		// 1用户登录时启动
		hr = pTriggers->Create(TASK_TRIGGER_LOGON, &pTrigger);
		if (FAILED(hr))
		{
			ShowError("ITriggerCollection::Create", hr);
			return FALSE;
		}

		//终结时间
		//hr = pTrigger->put_EndBoundary(_bstr_t(L"2099-05-02T12:05:00"));
		//if (FAILED(hr))
		//	printf("\nCannot put the end boundary: %x", hr);
		//1


		//2创建后立即执行
		hr = pTriggers->Create(TASK_TRIGGER_REGISTRATION, &pTrigger);
		pTriggers->Release();
		if (FAILED(hr))
		{
			printf("\nCannot create a TASK_TRIGGER_REGISTRATION trigger: %x", hr);
			return 1;
		}
		//2

		//3创建后定时执行
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





		// 4 系统启动时就运行
		//hr = pTriggers->Create(TASK_TRIGGER_BOOT, &pTrigger);
		//pTrigger->Release();
		//if (FAILED(hr))
		//{
		//	printf("\nCannot create the trigger: %x", hr);
		//	m_lpRootFolder->Release();
		//	pTaskDefinition->Release();
		//	CoUninitialize();
		//	return 1;
		//}

		//	//CoolCat

		//	//CoolCat


			/* 注册任务计划  */
		IRegisteredTask* pRegisteredTask = NULL;
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
			//ShowError("ITaskFolder::RegisterTaskDefinition", hr);
			return FALSE;
		}
		pTaskDefinition->Release();
		pRegisteredTask->Release();

		return TRUE;
	}
	else
	{

		//  ------------------------------------------------------

		CHAR username_domain[USERNAME_DOMAIN_LEN];
		CHAR username[USERNAME_LEN];

		if (!GetEnvironmentVariable(_T("USERNAME"), username, USERNAME_LEN))
		{
			printf("Getting username failed");
		}
		if (!GetEnvironmentVariable(_T("USERDOMAIN"), username_domain, USERNAME_DOMAIN_LEN))
		{
			printf("Getting the user's domain failed");
		}
		strcat(username_domain, "\\");
		strcat(username_domain, username);

		//========================================================

		// 创建任务定义对象来创建任务
		//ITaskDefinition* pTaskDefinition = NULL;
		//HRESULT hr = m_lpITS->NewTask(0, &pTaskDefinition);
		//if (FAILED(hr))
		//{
		//	ShowError("ITaskService::NewTask", hr);
		//	return FALSE;
		//}
		//HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);

		if (NULL == m_lpRootFolder)
		{
			return FALSE;
		}
		// 如果存在相同的计划任务，则删除
		Delete(lpszTaskName);
		// 创建任务定义对象来创建任务
		ITaskDefinition* pTaskDefinition = NULL;
		HRESULT hr = m_lpITS->NewTask(0, &pTaskDefinition);
		if (FAILED(hr))
		{
			ShowError("ITaskService::NewTask", hr);
			return FALSE;
		}

		  //Set general COM security levels.
		hr = CoInitializeSecurity(
			NULL,
			-1,
			NULL,
			NULL,
			RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
			RPC_C_IMP_LEVEL_IMPERSONATE,
			NULL,
			0,
			NULL);

		if (FAILED(hr))
		{
			printf("\nCoInitializeSecurity failed: %x", hr);
			CoUninitialize();
			return 1;
		}

		//  Create an instance of the Task Service. 
		//========================================================

		ITaskService* pService = NULL;
		hr = CoCreateInstance(CLSID_TaskScheduler,
			NULL,
			CLSCTX_INPROC_SERVER,
			IID_ITaskService,
			(void**)&pService);
		if (FAILED(hr))
		{
			printf("Failed to create an instance of ITaskService: %x", hr);
			CoUninitialize();
			return 1;
		}

		//  Connect to the task service.
		hr = pService->Connect(_variant_t(), _variant_t(),
			_variant_t(), _variant_t());
		if (FAILED(hr))
		{
			printf("ITaskService::Connect failed: %x", hr);
			pService->Release();
			CoUninitialize();
			return 1;
		}

		//  ------------------------------------------------------
		//  Get the pointer to the root task folder.  This folder will hold the
		//  new task that is registered.
		ITaskFolder* pRootFolder = NULL;
		hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
		if (FAILED(hr))
		{
			printf("Cannot get Root folder pointer: %x", hr);
			pService->Release();
			CoUninitialize();
			return 1;
		}

		//  If the same task exists, remove it.
		pRootFolder->DeleteTask(_bstr_t(lpszTaskName), 0);

		//  Create the task definition object to create the task.
		ITaskDefinition* pTask = NULL;
		hr = pService->NewTask(0, &pTask);


		//  Add the time trigger to the task.

		ITrigger* pTrigger = NULL;


		//  Add an action to the task.    
		IActionCollection* pActionCollection = NULL;

		//  Get the task action collection pointer.
		hr = pTask->get_Actions(&pActionCollection);
		if (FAILED(hr))
		{
			printf("\nCannot get Task collection pointer: %x", hr);
			pRootFolder->Release();
			pTask->Release();
			CoUninitialize();
			return 1;
		}

		//  Create the action, specifying that it is an executable action.
		IAction* pAction = NULL;
		hr = pActionCollection->Create(TASK_ACTION_EXEC, &pAction);
		pActionCollection->Release();
		if (FAILED(hr))
		{
			printf("\nCannot create the action: %x", hr);
			pRootFolder->Release();
			pTask->Release();
			CoUninitialize();
			return 1;
		}

		IExecAction* pExecAction = NULL;
		//  QI for the executable task pointer.
		hr = pAction->QueryInterface(
			IID_IExecAction, (void**)&pExecAction);
		pAction->Release();
		if (FAILED(hr))
		{
			printf("\nQueryInterface call failed for IExecAction: %x", hr);
			pRootFolder->Release();
			pTask->Release();
			CoUninitialize();
			return 1;
		}

		//  Set the path of the executable to lpszProgramPath.
		hr = pExecAction->put_Path(_bstr_t(lpszProgramPath));
		pExecAction->Release();
		if (FAILED(hr))
		{
			printf("\nCannot put action path: %x", hr);
			pRootFolder->Release();
			pTask->Release();
			CoUninitialize();
			return 1;
		}


		//add

		 /* 创建触发器，实现用户登陆自启动 */
		ITriggerCollection* pTriggers = NULL;
		hr = pTask->get_Triggers(&pTriggers);
		if (FAILED(hr))
		{
			return FALSE;
		}

		//==========================================================================

		// 1用户登录时启动

		ILogonTrigger* pLogonTrigger = NULL;
		hr = pTriggers->Create(TASK_TRIGGER_LOGON, &pTrigger);

		hr = pTrigger->QueryInterface(
			IID_ILogonTrigger, (void**)&pLogonTrigger);
		pTrigger->Release();

		hr = pLogonTrigger->put_Id(_bstr_t(L"Trigger1"));

		hr = pLogonTrigger->put_Delay(_bstr_t(L"PT03S"));

		hr = pLogonTrigger->put_UserId(_bstr_t(username_domain));
		pLogonTrigger->Release();


		//2创建后立即执行
		hr = pTriggers->Create(TASK_TRIGGER_REGISTRATION, &pTrigger);
		pTriggers->Release();
		if (FAILED(hr))
		{
			printf("\nCannot create a TASK_TRIGGER_REGISTRATION trigger: %x", hr);
			return 1;
		}
		//2

		//3创建后定时执行
		hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
		if (FAILED(hr))
		{
			printf("Cannot get Root Folder pointer: %x", hr);
			pService->Release();
			CoUninitialize();
			return 1;
		}

		pService->Release();  // COM clean up.  Pointer is no longer used.

		if (FAILED(hr))
		{
			printf("Failed to CoCreate an instance of the TaskService class: %x", hr);
			pRootFolder->Release();
			CoUninitialize();
			return 1;
		}

		hr = pTask->get_Triggers(&pTriggers);
		if (FAILED(hr))
		{
			printf("\nCannot get trigger collection: %x", hr);
			pRootFolder->Release();
			pTask->Release();
			CoUninitialize();
			return 1;
		}

		hr = pTriggers->Create(TASK_TRIGGER_DAILY, &pTrigger);
		pTriggers->Release();
		if (FAILED(hr)) {
			pRootFolder->Release();
			pTask->Release();
			CoUninitialize();
			return 1;
		}

		IDailyTrigger* pDailyTrigger = NULL;
		hr = pTrigger->QueryInterface(
			IID_IDailyTrigger, (void**)&pDailyTrigger);
		pTrigger->Release();
		if (FAILED(hr)) {
			pRootFolder->Release();
			pTask->Release();
			CoUninitialize();
			return 1;
		}

		hr = pDailyTrigger->put_Id(_bstr_t(L"Trigger"));
		hr = pDailyTrigger->put_StartBoundary(_bstr_t(L"2018-11-30T12:13:14"));//
		//  Set the time when the trigger is deactivated.
		//hr = pDailyTrigger->put_EndBoundary(_bstr_t(L"2099-01-01T12:00:00"));//
		//hr = pDailyTrigger->put_DaysInterval((short)1);//
		if (FAILED(hr)) {
			pRootFolder->Release();
			pDailyTrigger->Release();
			pTask->Release();
			CoUninitialize();
			return 1;
		}

		// Add a repetition to the trigger so that it repeats
		// five times.
		IRepetitionPattern* pRepetitionPattern = NULL;
		hr = pDailyTrigger->get_Repetition(&pRepetitionPattern);
		pDailyTrigger->Release();
		if (FAILED(hr)) {
			pRootFolder->Release();
			pTask->Release();
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
			pRootFolder->Release();
			pTask->Release();
			CoUninitialize();
			return 1;
		}
		//3


		//==============================================================

		IRegisteredTask* pRegisteredTask = NULL;
		hr = pRootFolder->RegisterTaskDefinition(
			_bstr_t(lpszTaskName),
			pTask,
			TASK_CREATE_OR_UPDATE,
			_variant_t(),
			_variant_t(),
			TASK_LOGON_INTERACTIVE_TOKEN,
			_variant_t(L""),
			&pRegisteredTask);
		if (FAILED(hr))
		{
			printf("\nError saving the Task : %x", hr);
			pRootFolder->Release();
			pTask->Release();
			CoUninitialize();
			return false;
		}

		printf("\n Success! Task successfully registered. ");

		//  Clean up.
		pRootFolder->Release();
		pTask->Release();
		pRegisteredTask->Release();
		CoUninitialize();

		return true;

	}
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
	variantTaskName = lpszTaskName;                     // 任务计划名称
	IRegisteredTask *pRegisteredTask = NULL;
	// 获取任务计划
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
	variantTaskName = lpszTaskName;                     // 任务计划名称
	IRegisteredTask *pRegisteredTask = NULL;
	// 获取任务计划
	hr = m_lpRootFolder->GetTask(variantTaskName.bstrVal, &pRegisteredTask);
	if (FAILED(hr) || (NULL == pRegisteredTask))
	{
		return FALSE;
	}
	// 获取任务状态
	TASK_STATE taskState;
	hr = pRegisteredTask->get_State(&taskState);
	if (FAILED(hr))
	{
		pRegisteredTask->Release();
		return FALSE;
	}
	pRegisteredTask->Release();
	// 无效
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

	// 获取任务计划
	IRegisteredTask *pRegisteredTask = NULL;
	hr = m_lpRootFolder->GetTask(variantTaskName.bstrVal, &pRegisteredTask);
	if (FAILED(hr) || (NULL == pRegisteredTask))
	{
		return FALSE;
	}
	// 运行
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
	variantTaskName = lpszTaskName;                     // 任务计划名称
	IRegisteredTask *pRegisteredTask = NULL;
	// 获取任务计划
	hr = m_lpRootFolder->GetTask(variantTaskName.bstrVal, &pRegisteredTask);
	if (FAILED(hr) || (NULL == pRegisteredTask))
	{
		return FALSE;
	}
	// 获取是否已经启动
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
	variantTaskName = lpszTaskName;                     // 任务计划名称
	variantEnable = bEnable;                            // 是否启动
	IRegisteredTask *pRegisteredTask = NULL;
	// 获取任务计划
	hr = m_lpRootFolder->GetTask(variantTaskName.bstrVal, &pRegisteredTask);
	if (FAILED(hr) || (NULL == pRegisteredTask))
	{
		return FALSE;
	}
	// 设置是否启动
	pRegisteredTask->put_Enabled(variantEnable.boolVal);
	pRegisteredTask->Release();

	return TRUE;
}

