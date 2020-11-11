#pragma once
#include <string>
#include <iostream>
#include "AES.h"
#include "Base64.h"

std::string aesEncrypt(const string& strSrc);
std::string aesDecrypt(const string& strSrc);