#include "server.hpp"

#include <conio.h>

int main() {
	SERVER server;

	server.OpenServer();

	while (true) {
		if (_kbhit()) {
			if (_getch() == ESC) break;
		}
	}

	return 0;
}