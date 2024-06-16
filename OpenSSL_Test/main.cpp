#include <iostream>

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#pragma comment(lib, "F:\\openssl\\openssl_dev\\lib\\VC\\x64\\MT\\libcrypto.lib")
#pragma comment(lib, "F:\\openssl\\openssl_dev\\lib\\VC\\x64\\MT\\libssl.lib")

using namespace std;

int main() {
	cout << "openssl_test start" << endl;

	const char* openSSLver = SSLeay_version(SSLEAY_VERSION);
	cout << "Oepn SSL Version : " << openSSLver << endl;

	cout << "oepnssl_test end" << endl;
	
	return 0;
}

