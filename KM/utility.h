#pragma once
#include <ntifs.h>
#include "structs.h"

namespace utility
{
	PVOID get_system_routine_address(LPCWSTR routine_name);
	PVOID get_system_module_export(LPCWSTR module_name, LPCSTR routine_name);
	PVOID get_system_module_base(LPCWSTR module_name);
}