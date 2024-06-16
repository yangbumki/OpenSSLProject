#include "client.hpp"

#include <conio.h>

int main() {

	CLIENT client("192.168.56.110", 8986);

	client.ConnectServer();

	while (true) {
		if (_kbhit()) {
			if (_getch() == ESC) break;
		}
	}

	return 0;
}