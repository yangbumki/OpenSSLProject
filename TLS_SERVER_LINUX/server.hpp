#pragma once

#include "../headers/common.h"

using namespace std;

typedef class TLS_SERVER {
	typedef enum SERVER_STATUS {
		UNREADY = -1,
		READY,
		START,
		STOP
	}SERVERSTAT;
private:
	int serverStatus = UNREADY;

//ssl val
	SSL_CTX* ctx = nullptr;
    const char* crtPath = "../CERT/server.crt";
    const char* keyPath = "../CERT/server.key";
	
// socket val
	unsigned int serverPort = 0;
#if WINDOW
	WSADATA wsaData;
	SOCKET serverSocket;
	SOCKET clientSocket;
	sockaddr_in serverAddress;
	HANDLE translateThreadHandle;
#endif

#if LINUX
    int serverSocket;
	int clientSocket;
	sockaddr_in serverAddress;
	pthread_t translateThreadHandle;
#endif

	bool InitializeSSL() {
		SSL_load_error_strings();
		OpenSSL_add_ssl_algorithms();

		ctx = SSL_CTX_new(TLS_server_method());
		if (!ctx) {
			cerr << "Failed to create ctx" << endl;
			return false;
		}

		if (!SSL_CTX_use_certificate_file(ctx, crtPath, SSL_FILETYPE_PEM)) {
			cerr << "Failed to load .crt" << endl;
			return false;
		}
		if (!SSL_CTX_use_PrivateKey_file(ctx, keyPath, SSL_FILETYPE_PEM)) {
			cerr << "Failed to load .key" << endl;
			return false;
		}

		return true;
	}
	void ShowCert(SSL* ssl) {
		X509* cert = SSL_get_peer_certificate(ssl);
		if (!cert) {
			cout << "Failed to read cert" << endl;
			X509_free(cert);
			return;
		}

		char* line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		cout << "Client Certificate : " << line << endl;

		OPENSSL_free(line);
		X509_free(cert);
	}

#if WINDOW
	bool InitServer() {
		if (serverStatus != SERVERSTAT::UNREADY) {
			cerr << "Aleady Initialize server" << endl;
			return false;
		}

		auto result = WSAStartup(MAKEWORD(2, 2), &wsaData);
		if (result < 0) {
			cerr << "Failed to WSAStartup" << endl;
			return false;
		}

		serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (serverSocket == INVALID_SOCKET) {
			cerr << "Failed to creater socket" << endl;
			return false;
		}

		memset(&serverAddress, 0, sizeof(sockaddr_in));
		serverAddress.sin_family = AF_INET;
		serverAddress.sin_port = htons(serverPort);
		serverAddress.sin_addr.S_un.S_addr = htonl(INADDR_ANY);

		result = bind(serverSocket, (sockaddr*)&serverAddress, sizeof(sockaddr));
		if (result == INVALID_SOCKET) {
			cerr << "Failed to bind address" << endl;
			return false;
		}

		result = listen(serverSocket, 0);
		if (result == INVALID_SOCKET) {
			cerr << "Failed to listen server" << endl;
			return false;
		}

		serverStatus = SERVERSTAT::READY;

		return true;
	}
	static DWORD WINAPI TranslateThreadFunction(void* args) {
		SERVER* server = (SERVER*)args;
		SSL* ssl = nullptr;
		char buffer[BUF_SIZE] = { 0, };

		ssl = SSL_new(server->ctx);
		if (ssl == nullptr) {
			cerr << "Failed to SSL_new" << endl;
			return -1;
		}

		SSL_set_fd(ssl, server->clientSocket);

		auto result = SSL_accept(ssl);
		if (result <= 0) {
			cerr << "Failed to SSL_accept" << endl;
			SSL_free(ssl);
			return -1;
		}

		server->ShowCert(ssl);

		while (server->serverStatus == SERVERSTAT::START) {
			result = SSL_read(ssl, buffer, BUF_SIZE);
			if (result <= 0) {
				cout << "Failed to read ssl-data" << endl;
				continue;
			}

			cout << "Received : " << buffer << endl;

			result = SSL_write(ssl, buffer, BUF_SIZE);
			if (result < 0) {
				cout << "Failed to write ssl-data" << endl;
			}
		}

		SSL_free(ssl);
		return 0;
	}
#endif

#if LINUX
bool InitServer() {
	if(serverStatus != SERVERSTAT::UNREADY) {
		cerr<<"Failed to initialize server"<<endl;
		return false;
	}

	serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(serverSocket < 0) {
		cerr<<"Failed to create socket"<<endl;
		return false;
	}
	
	memset(&serverAddress, 0, sizeof(sockaddr_in));
	
	serverAddress.sin_family = AF_INET;
	serverAddress.sin_port = htons(this->serverPort);
	serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);

	auto result = bind(serverSocket, (sockaddr*)&serverAddress, sizeof(sockaddr_in));
	if(result < 0) {
		cerr<<"Failed to bind"<<endl;
		return false;
	}

	result = listen(serverSocket, 0);
	if(result < 0) {
		cerr<<"Failed to listen"<<endl;
		return false;
	}
	
	serverStatus = SERVERSTAT::READY;

	return true;
}
static void* TranslateThreadFunction(void* args) {
    TLS_SERVER* server = (TLS_SERVER*)args;
    SSL* ssl = nullptr;
    char buffer[BUF_SIZE] = {0,};

    ssl = SSL_new(server->ctx);
    if(ssl == nullptr) {
        cerr<<"Failed to SSL_new"<<endl;
        exit(1);
    }

    SSL_set_fd(ssl, server->clientSocket);

    auto result = SSL_accept(ssl);
    if(result <= 0) {
        cerr<<"Failed to SSL_accept"<<endl;
        exit(1);
    }

    server->ShowCert(ssl);

    while(server->serverStatus == SERVERSTAT::START) {
        result = SSL_read(ssl, buffer, BUF_SIZE);
        if(result <= 0) {
            cerr<<"Failed to read ssl-data"<<endl;
            server->serverStatus = SERVERSTAT::STOP;
            continue;
        }

        cout << "---RECIVED START---"<<endl;
        cout<<buffer<<endl;
        cout<<"---RECIVED END---"<<endl<<endl;

        result  = SSL_write(ssl, buffer, BUF_SIZE);
        if(result <= 0) {
            cerr<<"Failed to write ssl-data"<<endl;
            server->serverStatus = SERVERSTAT::STOP;
            continue;
        }
    }

    SSL_free(ssl);

    return 0;
}
#endif

public:
	TLS_SERVER(int port = 8986) 
		:serverPort(port) {
		
		cout << "---SERVER INITIALIZE START---" << endl;
		if (!InitializeSSL()) exit(1);
		if (!InitServer()) exit(1);
		cout << "---SERVER INITIALIZE END---" << endl;

	}
	~TLS_SERVER() {
		serverStatus = SERVERSTAT::STOP;
#if WINDOW
		WaitForSingleObject(translateThreadHandle, INFINITE);

		WSACleanup();
		closesocket(serverSocket);
		closesocket(clientSocket);
		CloseHandle(translateThreadHandle);
#endif

		EVP_cleanup();
		if (ctx) SSL_CTX_free(ctx);
	}

#if WINDOW
	bool OpenServer() {
		if (serverStatus != SERVERSTAT::READY) {
			cerr << "Failed to Open Server" << endl;
			return false;
		}

		sockaddr_in clientAddress;
		int caSize = sizeof(sockaddr_in);
		memset(&clientAddress, 0, caSize);

		clientSocket = accept(serverSocket, (sockaddr*)&clientAddress, &caSize);
		if (clientSocket == INVALID_SOCKET) {
			cerr << "Failed to accept client" << endl;
			return false;
		}

		char ipBuffer[IP_BUF_SIZE] = { 0, };

		cout << "---CLIENT INFO START---" << endl;
		cout << "IP : " << inet_ntop(AF_INET, &clientAddress.sin_addr, ipBuffer, IP_BUF_SIZE) << endl;
		cout << "PORT : " << ntohs(clientAddress.sin_port) << endl;
		cout << "---CLIENT INFO END---" << endl;

		serverStatus = SERVERSTAT::START;

		this->translateThreadHandle = CreateThread(NULL, NULL, this->TranslateThreadFunction, this, NULL, 0);
		if (translateThreadHandle == NULL) {
			cout << "Failed to create thread" << endl;
			return false;
		}

		return true;
	}
#endif

#if LINUX
    bool OpenServer() {
        if(serverStatus != SERVERSTAT::READY) {
            cerr<<"Failed to open server"<<endl;
            return false;
        }

        sockaddr_in clientAddress;
        socklen_t size = sizeof(sockaddr_in);

        memset(&clientAddress, 0, sizeof(sockaddr_in));

        clientSocket = accept(serverSocket, (sockaddr*)&clientAddress, &size);
        if(clientSocket < 0) {
            cerr<<"Failed to create client-socket"<<endl;
            return false;
        }

        char ipBuffer[IP_BUF_SIZE] = { 0, };

		cout << "---CLIENT INFO START---" << endl;
		cout << "IP : " << inet_ntop(AF_INET, &clientAddress.sin_addr, ipBuffer, IP_BUF_SIZE) << endl;
		cout << "PORT : " << ntohs(clientAddress.sin_port) << endl;
		cout << "---CLIENT INFO END---" << endl;

        serverStatus = SERVERSTAT::START;

        pthread_create(&translateThreadHandle, NULL, this->TranslateThreadFunction, this);

        return true;
    }
#endif
}SERVER;