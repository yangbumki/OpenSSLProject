#pragma once

#include "../headers/common.h"

using namespace std;

typedef class TLS_CLIENT {
private:
	bool connectStatus = false;
//socket val
	char serverIP[IP_BUF_SIZE] = { 0, };
	unsigned int serverPort;

#if WINDOW
	WSADATA wsaData;
	SOCKET serverSocket;
	sockaddr_in serverAddress;
	HANDLE translateThreadHandle = NULL;
#endif

//socket function
	bool SetServerConfig(const char* ip) {
		if (connectStatus) {
			cerr << "Aleady connect server" << endl;
			return false;
		}

		memset(serverIP, 0, IP_BUF_SIZE);
		strcpy_s(serverIP, strlen(ip)+1, ip);
		return true;
	}
	bool InitSocket() {
		auto result = WSAStartup(MAKEWORD(2, 2), &wsaData);
		if (result < 0) {
			cerr << "Failed to WSAStartup" << endl;
			return false;
		}

		return true;
	}
	static DWORD WINAPI TranslateThreadFunction(void* args) {
		CLIENT* client = (CLIENT*)args;
		SSL* ssl = nullptr;

		ssl = SSL_new(client->ctx);

		SSL_set_fd(ssl, client->serverSocket);
		auto result = SSL_connect(ssl);
		if (result <= 0) {
			cerr << "Failed to ssl-connect" << endl;
			return -1;
		}

		client->ShowCert(ssl);

		const char* msg = "Hello, SSL Server!";
		char recvBuffer[BUF_SIZE] = { 0, };

		while (client->connectStatus) {
			Sleep(1000);

			result = SSL_write(ssl, msg, strlen(msg));
			if (result <= 0) {
				cerr << "Failed to write" << endl;
				continue;
			}

			result = SSL_read(ssl, recvBuffer, BUF_SIZE);
			if (result <= 0) {
				cerr << "Failed to read" << endl;
				continue;
			}

			cout << "---RECV DATA START---" << endl;
			cout << recvBuffer << endl;
			cout << "---RECV DATA END---" << endl<<endl;
		}

		SSL_shutdown(ssl);
		SSL_free(ssl);

		return 0;
	}
//ssl val
	SSL_CTX* ctx;

//ssl function
	bool InitializeSSL() {
		SSL_load_error_strings();
		OpenSSL_add_ssl_algorithms();

		ctx = SSL_CTX_new(TLS_client_method());
		if (!ctx) {
			cerr << "Failed to new ctx" << endl;
			return false;
		}
	}
	void ShowCert(SSL* ssl) {
		X509* cert = SSL_get_peer_certificate(ssl);
		if (!cert) {
			cerr<< "Failed to load certificate" << endl;
			X509_free(cert);
			return;
		}
		char* line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		std::cout << "Server certificate : " << line << endl;

		OPENSSL_free(line);
		X509_free(cert);
	}

public:
	TLS_CLIENT(const char* ip, const unsigned int port)
		:serverPort(port) {
		//IP ERROR 검사 코드 들어가야 된다.
		if (!SetServerConfig(ip)) exit(1);
		if (!InitializeSSL()) exit(1);
		if (!InitSocket()) exit(1);
	}
	~TLS_CLIENT() {
		connectStatus = FALSE;
#if WINDOW
		WaitForSingleObject(translateThreadHandle, INFINITE);
		CloseHandle(translateThreadHandle);

		WSACleanup();
		closesocket(serverSocket);
#endif
		EVP_cleanup();
		if (ctx) SSL_CTX_free(ctx);
	}

#if WINDOW
	bool ConnectServer() {
		if (connectStatus) {
			cerr << "Aleady connect server" << endl;
			return false;
		}

		serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (serverSocket == INVALID_SOCKET) {
			cerr << "Failed to create socket" << endl;
			return false;
		}

		memset(&serverAddress, 0, sizeof(sockaddr_in));

		inet_pton(AF_INET,serverIP,&serverAddress.sin_addr);
		serverAddress.sin_port = htons(serverPort);
		serverAddress.sin_family = AF_INET;

		auto result = connect(serverSocket, (sockaddr*)&serverAddress, sizeof(sockaddr));
		if (result == INVALID_SOCKET) {
			cerr << "Failed to connect server" << endl;
			return false;
		}

		connectStatus = TRUE;

		this->translateThreadHandle = CreateThread(NULL, NULL, this->TranslateThreadFunction, this, NULL, 0);
		if (translateThreadHandle == NULL) {
			cerr << "Failed to create thread" << endl;
			return false;
		}

		return true;
	}
#endif
}CLIENT;