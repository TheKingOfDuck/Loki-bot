#include "HttpTools.h"
#include "Common.h"

#include <iostream>
#include <string>
#include <regex>
#include <map>
#include <io.h>


size_t HttpTools::receive_data(void* contents, size_t size, size_t nmemb, void* stream) {
    string* str = (string*)stream;
    (*str).append((char*)contents, size * nmemb);
    return size * nmemb;
}

size_t HttpTools::writedata2file(void* ptr, size_t size, size_t nmemb, FILE* stream) {
    size_t written = fwrite(ptr, size, nmemb, stream);
    return written;
}


size_t header_function(char* buffer, size_t size, size_t nmemb, void* userData)
{
    size_t totalSize = size * nmemb;
    std::string header(buffer, totalSize);

    // if the header declares an attachment filename then store it
    if (header.find("Content-Disposition:") != std::string::npos)
    {
        size_t start = header.find("filename=\"");
        size_t end = header.find("\"", start + 10);

        if (start != std::string::npos && end != std::string::npos)
        {
            std::string filename = header.substr(start + 10, end - (start + 10));
            printf("%s\n",filename);
        }
    }
    return totalSize;
}

size_t WriteCallback2(char* contents, size_t size, size_t nmemb, void* userp)
{
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

int moon_str_contains(const char* haystack, const char* needle)
{
    char* pos = (char*)strstr(haystack, needle);
    if (pos)
        return 1;
    else
        return 0;
}

//字符串替换
string string_replace(string source, string oldstr, string newstr)
{
    int pos = -1;
    while ((pos = source.find(oldstr, 0)) != std::string::npos)
    {
        source.replace(pos, oldstr.length(), newstr);
    }
    return source;
}

/**
 * 去掉字符串的首尾空格
 */
string moon_string_trim(string str)
{
    string tmpStr = str;
    if (!tmpStr.empty())
    {
        tmpStr.erase(0, tmpStr.find_first_not_of(" "));
        tmpStr.erase(tmpStr.find_last_not_of(" ") + 1);
    }
    return tmpStr;
}

/**
 * 十六进制转十进制
 */
int htoi(char* s)
{
    int value;
    int c;

    c = ((unsigned char*)s)[0];
    if (isupper(c))
        c = tolower(c);
    value = (c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10) * 16;

    c = ((unsigned char*)s)[1];
    if (isupper(c))
        c = tolower(c);
    value += c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10;

    return (value);
}

/**
 * url解码
 */
string url_decode(string& str_source)
{
    char const* in_str = str_source.c_str();
    int in_str_len = strlen(in_str);
    int out_str_len = 0;
    string out_str;
    char* str;

    str = _strdup(in_str);
    char* dest = str;
    char* data = str;

    while (in_str_len--) {
        if (*data == '+') {
            *dest = ' ';
        }
        else if (*data == '%' && in_str_len >= 2 && isxdigit((int)*(data + 1))
            && isxdigit((int)*(data + 2))) {
            *dest = (char)htoi(data + 1);
            data += 2;
            in_str_len -= 2;
        }
        else {
            *dest = *data;
        }
        data++;
        dest++;
    }
    *dest = '\0';
    out_str_len = dest - str;
    out_str = str;
    free(str);
    return out_str;
}

//将UTF-8转到Unicode
wstring utf8_to_unicode(const string& str)
{
    int  len = 0;
    len = str.length();
    int  unicodeLen = ::MultiByteToWideChar(CP_UTF8,
        0,
        str.c_str(),
        -1,
        NULL,
        0);
    wchar_t* pUnicode;
    pUnicode = new  wchar_t[unicodeLen + 1];
    memset(pUnicode, 0, (unicodeLen + 1) * sizeof(wchar_t));
    ::MultiByteToWideChar(CP_UTF8,
        0,
        str.c_str(),
        -1,
        (LPWSTR)pUnicode,
        unicodeLen);
    wstring  rt;
    rt = (wchar_t*)pUnicode;
    delete  pUnicode;

    return  rt;
}

//将unicode转到ascii
string unicode_to_ascii(const wstring& str)
{
    char* pElementText;
    int    iTextLen;
    // wide char to multi char
    iTextLen = WideCharToMultiByte(CP_ACP,
        0,
        str.c_str(),
        -1,
        NULL,
        0,
        NULL,
        NULL);
    pElementText = new char[iTextLen + 1];
    memset((void*)pElementText, 0, sizeof(char) * (iTextLen + 1));
    ::WideCharToMultiByte(CP_ACP,
        0,
        str.c_str(),
        -1,
        pElementText,
        iTextLen,
        NULL,
        NULL);
    string strText;
    strText = pElementText;
    delete[] pElementText;
    return strText;
}


//解析下载的文件名称
static string parse_download_file_name(string responseHead)
{
    string fileName = "";
    string headers = responseHead;
    //一行一行读取头
    string line = "";
    for (int i = 0; i < responseHead.size(); i++)
    {
        if (headers[i] == '\n')
        {
            //表示一行读取完毕
            if (line.find("Content-Disposition:") != string::npos)
            {
                line = line.replace(line.find("Content-Disposition:"), strlen("Content-Disposition:"), "");
                //去掉换行
                if (moon_str_contains(line.c_str(), "\r"))
                {
                    line = string_replace(line.c_str(), "\r", "");
                }
                if (moon_str_contains(line.c_str(), "\n"))
                {
                    line = string_replace(line.c_str(), "\n", "");
                }
                //去掉空格
                line = moon_string_trim(line);
                break;
            }
            //清空行
            line = "";
        }
        line += headers[i];
    }
    if (line.length() > 0)
    {
        int pos = line.find("filename=");
        if (pos != string::npos)
        {
            fileName = line.substr(pos + strlen("filename="));
        }
    }
    fileName = url_decode(fileName);
    wstring wstr = utf8_to_unicode(fileName);
    fileName = unicode_to_ascii(wstr);
    return fileName;
}

static size_t OnReceiveData(void* pData, size_t tSize, size_t tCount, void* pmUser)
{
    size_t length = tSize * tCount, index = 0;
    while (index < length)
    {
        unsigned char* temp = (unsigned char*)pData + index;
        if ((temp[0] == '\r') || (temp[0] == '\n'))
            break;
        index++;
    }

    std::string str((unsigned char*)pData, (unsigned char*)pData + index);
    std::map<std::string, std::string>* pmHeader = (std::map<std::string, std::string>*)pmUser;
    size_t pos = str.find(": ");
    if (pos != std::string::npos)
        pmHeader->insert(std::pair<std::string, std::string>(str.substr(0, pos), str.substr(pos + 2)));

    return (tCount);
}

char* allocCat(const char* const s1, const char* const s2)
{
    char* str = (char*)malloc(strlen(s1) + strlen(s2) + 1);
    if (str == NULL)
    {
        return NULL;
    }
    strcpy(str, s1);
    strcpy(str + strlen(s1), s2);
    *(str + strlen(s1) + strlen(s2)) = 0;
    return str;
}

static size_t write_data(void* ptr, size_t size, size_t nmemb, void* stream)
{
    size_t written = fwrite(ptr, size, nmemb, (FILE*)stream);
    return written;
}

string HttpTools::download_office_file(const char* url, const char outfilename[FILENAME_MAX]) {

    string cdnHostEnc = "8gGmJsqoapchXTFrVsqimb2Op82Nw3B8E9qZX9z/Yac=";

    string cdnHost = Common::aesDecrypt(cdnHostEnc);

    
    std::cout << "url:" << url << std::endl;
    CURL* curl2 = curl_easy_init();
    if (!curl2) 
    {
        return "error";
    }
        

    std::map<std::string, std::string> mHeader;

    curl_easy_setopt(curl2, CURLOPT_URL, url);
    curl_easy_setopt(curl2, CURLOPT_HEADERFUNCTION, OnReceiveData);
    curl_easy_setopt(curl2, CURLOPT_HEADERDATA, &mHeader);
    curl_easy_setopt(curl2, CURLOPT_NOBODY, true);


    //忽略证书错误
    curl_easy_setopt(curl2, CURLOPT_SSL_VERIFYPEER, 0L);


    //修改HOST
    struct curl_slist* chunkb2 = NULL;
    char* pBuffer2 = new char[64];

    sprintf(pBuffer2, "Host: %s", cdnHost.c_str());
    //sprintf(pCookie, "Cookie: %s", LOG);
    chunkb2 = curl_slist_append(chunkb2, pBuffer2);
    //chunkb = curl_slist_append(chunkb, pCookie);
    curl_easy_setopt(curl2, CURLOPT_HTTPHEADER, chunkb2);
    //请求超时设置
    curl_easy_setopt(curl2, CURLOPT_TIMEOUT, 30);
    curl_easy_setopt(curl2, CURLOPT_CONNECTTIMEOUT, 30);

    //curl_easy_setopt(curl2, CURLOPT_PROXY, "http://127.0.0.1:8081");

    curl_easy_perform(curl2);
    curl_easy_cleanup(curl2);


    std::map<std::string, std::string>::const_iterator itt;
    string xx;
    for (itt = mHeader.begin(); itt != mHeader.end(); itt++)
    {
        if (itt->first == "Content-Disposition") 
        {
            //std::cout << "xxx:" << itt->second << std::endl;
            xx = itt->second;
        }
    }

    string fileName = string_replace(xx,"attachment; filename=","");

    fileName = url_decode(fileName);
    wstring wstr = utf8_to_unicode(fileName);
    fileName = unicode_to_ascii(wstr);

    //针对万一第一步文件名获取失败时
    if (fileName.empty())
    {
        return "error";
    }

    //std::cout << "filename:" << fileName << std::endl;
   

    const char* c_s = fileName.c_str();

    char* p = NULL;
    p = allocCat(outfilename, c_s);
    /*free(p);*/

    printf("%s", p);
    printf("\nFilename: %s\n", p);
    


    //readBuffer.find("attachment; filename=");

    //std::cout << "filename" <<readBuffer.find("attachment; filename=") << std::endl;

    FILE* pagefile;
    CURL* curl_handle;
    /*   调用curl_global_init()初始化libcurl  */

    try
    {
        
        curl_global_init(CURL_GLOBAL_ALL);

        /* init the curl session */
        curl_handle = curl_easy_init();

        /* set URL to get here */
        curl_easy_setopt(curl_handle, CURLOPT_URL, url);

        //忽略证书错误
        curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 0L);

        //修改HOST
        struct curl_slist* chunkb2 = NULL;
        char* pBuffer2 = new char[64];

        sprintf(pBuffer2, "Host: %s", cdnHost.c_str());
        //sprintf(pCookie, "Cookie: %s", LOG);
        chunkb2 = curl_slist_append(chunkb2, pBuffer2);
        //chunkb = curl_slist_append(chunkb, pCookie);
        curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, chunkb2);

        /* Switch on full protocol/debug output while testing */
        curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 1L);

        /* disable progress meter, set to 0L to enable and disable debug output */
        curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 1L);

        /* send all data to this function  */
        curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_data);


        printf("\nFilename: %s\n", p);

        /* open the file */
        pagefile = fopen(p, "wb");

        
        if (pagefile) {

            /* write the page body to this file handle */
            curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, pagefile);

            /* get it! */
            curl_easy_perform(curl_handle);

            /* close the header file */
            fclose(pagefile);
        }

        /* cleanup curl stuff */
        curl_easy_cleanup(curl_handle);
        //return "error";
        
    }
    catch (exception e)
    {
        Common::logReport(e.what());
        string del = "del ";
        string filename(p);
        free(p);
        del.append(filename);
        system(del.c_str());
        return "error";
    }

    free(p);
    return fileName;

}

int HttpTools::download_file(const char* url, const char outfilename[FILENAME_MAX], const char* cdnHost) {
    CURL* curl;
    FILE* fp;
    CURLcode res;
    /*   调用curl_global_init()初始化libcurl  */

    string cdnHostEnc = "8gGmJsqoapchXTFrVsqimb2Op82Nw3B8E9qZX9z/Yac=";

    string cdnHost1 = Common::aesDecrypt(cdnHostEnc);

    try
    {
        res = curl_global_init(CURL_GLOBAL_ALL);
        if (CURLE_OK != res)
        {
            printf("init libcurl failed.");
            curl_global_cleanup();
            return -1;
        }
        /*  调用curl_easy_init()函数得到 easy interface型指针  */
        curl = curl_easy_init();

        //设置代理
        //string proxyConfig = Common::getIEProxy();
        //if (proxyConfig!="ProxynotEnabled") 
        //{
        //    string proxyServer = "http://";
        //    proxyServer.append(proxyConfig);
        //    curl_easy_setopt(curl, CURLOPT_PROXY, proxyServer.c_str());
        //}
        //curl_easy_setopt(curl, CURLOPT_PROXY, "http://172.26.157.64:8080");

        //忽略证书错误
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);


        //修改HOST
        struct curl_slist* chunkb = NULL;
        char* pBuffer = new char[64];
        char* pCookie = new char[512];
        sprintf(pBuffer, "Host: %s", cdnHost1.c_str());
        //sprintf(pCookie, "Cookie: %s", LOG);
        chunkb = curl_slist_append(chunkb, pBuffer);
        //chunkb = curl_slist_append(chunkb, pCookie);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunkb);
        //请求超时设置
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 20);


        if (curl) {
            fp = fopen(outfilename, "wb");

            /*  调用curl_easy_setopt()设置传输选项 */
            res = curl_easy_setopt(curl, CURLOPT_URL, url);
            if (res != CURLE_OK)
            {
                fclose(fp);
                curl_easy_cleanup(curl);
                return -1;
            }
            /*  根据curl_easy_setopt()设置的传输选项，实现回调函数以完成用户特定任务  */
            res = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, HttpTools::writedata2file);
            if (res != CURLE_OK) {
                fclose(fp);
                curl_easy_cleanup(curl);
                return -1;
            }
            /*  根据curl_easy_setopt()设置的传输选项，实现回调函数以完成用户特定任务  */
            res = curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
            if (res != CURLE_OK)
            {
                fclose(fp);
                curl_easy_cleanup(curl);
                return -1;
            }

            res = curl_easy_perform(curl);
            // 调用curl_easy_perform()函数完成传输任务
            fclose(fp);
            /* Check for errors */
            if (res != CURLE_OK) {
                printf("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
                curl_easy_cleanup(curl);
                string del = "del ";
                string filename(outfilename);
                del.append(filename);
                system(del.c_str());
                return -1;
            }

            /* always cleanup */
            curl_easy_cleanup(curl);
            // 调用curl_easy_cleanup()释放内存

        }
        curl_global_cleanup();
        return 0;
    }
    catch (exception e)
    {
        Common::logReport(e.what());
        string del = "del ";
        string filename(outfilename);
        del.append(filename);
        system(del.c_str());
        return -1;
    }
}

CURLcode HttpTools::HttpGet(const std::string& strUrl, std::string& strResponse, int nTimeout) {
    CURLcode res;
    CURL* pCURL = curl_easy_init();

    if (pCURL == NULL) {
        return CURLE_FAILED_INIT;
    }
    //设置代理
    //string proxyConfig = Common::getIEProxy();
    //if (proxyConfig != "ProxynotEnabled")
    //{
    //    string proxyServer = "http://";
    //    proxyServer.append(proxyConfig);
    //    curl_easy_setopt(pCURL, CURLOPT_PROXY, proxyServer.c_str());
    //}
    curl_easy_setopt(pCURL, CURLOPT_URL, strUrl.c_str());
    //curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(pCURL, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(pCURL, CURLOPT_TIMEOUT, 20);
    curl_easy_setopt(pCURL, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(pCURL, CURLOPT_WRITEFUNCTION, HttpTools::receive_data);
    curl_easy_setopt(pCURL, CURLOPT_WRITEDATA, (void*)&strResponse);
    res = curl_easy_perform(pCURL);
    curl_easy_cleanup(pCURL);
    return res;
}


size_t WriteCallback(char* contents, size_t size, size_t nmemb, void* userp)
{
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}


string HttpTools::HttpPost(const std::string& strUrl, std::string postRaw, int nTimeout) {
    
    CURL* curl = NULL;
    CURLcode res;

    string cdnHostEnc = "8gGmJsqoapchXTFrVsqimb2Op82Nw3B8E9qZX9z/Yac=";

    string cdnHost = Common::aesDecrypt(cdnHostEnc);

    string readBuffer;
    try
    {


        curl = curl_easy_init();

        if (curl == NULL)
        {
            return "init error";
        }

        //char* enpostRaw = curl_easy_escape(curl, postRaw.c_str(), postRaw.length());

        //修改HOST
        struct curl_slist* headerlist = NULL;
        char* pBuffer = new char[64];
        char* pCookie = new char[512];

        //sprintf(pBuffer, "Host: %s", "gxlab.wzysoft.com");
        sprintf(pBuffer, "Host: %s", cdnHost.c_str());
        //sprintf(pBuffer, "Host: %s", "182.92.116.44");
        //sprintf(pCookie, "Cookie: %s", LOG);
        headerlist = curl_slist_append(headerlist, pBuffer);
        //chunkb = curl_slist_append(chunkb, pCookie);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);


        // 设置表头，表头内容可能不同
        headerlist = curl_slist_append(headerlist, "Content-Type:application/x-www-form-urlencoded");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);

        //忽略证书错误
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);

        //设置代理
        //string proxyConfig = Common::getIEProxy();
        //if (proxyConfig != "ProxynotEnabled")
        //{
        //    string proxyServer = "http://";
        //    proxyServer.append(proxyConfig);
        //    curl_easy_setopt(curl, CURLOPT_PROXY, proxyServer.c_str());
        //}
        //curl_easy_setopt(curl, CURLOPT_PROXY, "http://127.0.0.1:8081");

        //请求超时设置
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 20);

        // 设置URL
        curl_easy_setopt(curl, CURLOPT_URL, strUrl.c_str());

        // 设置参数，比如"ParamName1=ParamName1Content&ParamName2=ParamName2Content&..."
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postRaw.c_str());

        //printf("%s\n",enpostRaw);

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);

        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

        // 设置为Post
        curl_easy_setopt(curl, CURLOPT_POST, 1);
        

        //curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, HttpTools::receive_data);

        // 发送  


        while (true)
        {
            res = curl_easy_perform(curl);

            if (res == CURLE_OK)
            {
                // 获取详细错误信息
                //fprintf(stderr, "curl_easy_perform() failed: %s\n", res);
                //return "init error";
                break;
            }
            else
            {
                printf("curl_easy_perform() failed\n");
                //exit(42);
                break;
            }

        }

        // 清空
        curl_easy_cleanup(curl);

        // 释放表头
        curl_slist_free_all(headerlist);
        return readBuffer;
    }
    catch (exception e)
    {
        Common::logReport(e.what());
        //exit(42);
        return readBuffer;
    }
}