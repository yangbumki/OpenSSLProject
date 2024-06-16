#pragma once

#include "../headers/common.h"

#include <../include/sqlite3.h>

using namespace std;

typedef class BGY_DB {
private:
    sqlite3* sql = nullptr;

    public:
    BGY_DB() {
        
    }
    ~BGY_DB() {

    }

}BGYDB;