#include "server.hpp"
#include "sqlite3.hpp"



int main() {
	SERVER server;
	BGYDB db;

	server.OpenServer();

	while(1) {
		sleep(1000);
	}

	return 0;
}