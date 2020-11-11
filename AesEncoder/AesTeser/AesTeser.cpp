// AesTeser.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include "AES.h"
#include "Base64.h"
#include "Common.h"
#include <iostream>
#include <ctime>

using namespace std;

int main(int argc, char** argv)
{
	//string str1 = "255.255.255.255";
	//cout << "加密前:" << str1 << endl;
	//string str2 = aesEncrypt(str1);
	//cout << "加密后:" << str2 << endl;
	//string str3 = aesDecrypt(str2);
	//cout << "解密后:" << str3 << endl;


	string ips[2] = { "123.123.123.123","127.0.0.1"};

	string cdnHost[1] = {"x"};

	cout << aesEncrypt("x") << endl;

	

	//for (auto ip :ips) {
	//	cout << aesEncrypt(ip) << endl;
	//}

	//string ips_enc[1] = { "4Bsjb7fC1xRcxpBdZNWneg=="};
	//int iplength = sizeof(ips_enc) / sizeof(ips_enc[0]);
	//

	//for (auto ip : ips_enc) {
	//	cout << aesDecrypt(ip) << endl;
	//}
	//cout << ips_enc[2] << endl;

	//cout << iplength << endl;

	//srand((unsigned)time(NULL));
	//for (int i = 0; i < 30; i++) {
	//	cout << aesDecrypt(ips_enc[(rand() % (iplength + 1))]) << endl;
	//}

}


// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
