#ifndef __COMMON_H_
#define __COMMON_H_

#define WINDOW		1
#define LINUX		0

#define IP_BUF_SIZE		128
#define BUF_SIZE		1024

#define ESC				27

#if WINDOW
#include <WinSock2.h>
#include <WS2tcpip.h>

#include <Windows.h>

#pragma comment(lib, "Ws2_32.lib")

#include <openssl/ssl.h>
#include <openssl/err.h>

#pragma comment(lib, "F:\\openssl\\openssl_dev\\lib\\VC\\x64\\MT\\libcrypto.lib")
#pragma comment(lib, "F:\\openssl\\openssl_dev\\lib\\VC\\x64\\MT\\libssl.lib")
#endif


#include <iostream>

#endif
