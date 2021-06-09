#pragma once
#include <ntifs.h>

#define print_success_message( ... ) DbgPrintEx(0,0, "[+] " __VA_ARGS__);
#define print_error_message( ... ) DbgPrintEx(0,0, "[-] " __VA_ARGS__);