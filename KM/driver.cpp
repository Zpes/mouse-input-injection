#include "includes.h"

NTSTATUS driver_entry()
{
	print_success_message("driver loaded");
	//PVOID target_function = utility::get_system_module_export(L"win32k.sys", "_win32kstub_NtUserInjectMouseInput");
	
	UNICODE_STRING target_function_name;
	RtlInitUnicodeString(&target_function_name, L"NtUserInjectMouseInput");
	PVOID target_function = MmGetSystemRoutineAddress(&target_function_name);

	if (!target_function)
	{
		print_error_message("could not find target function -> %p", target_function);
		return STATUS_UNSUCCESSFUL;
	}

	print_success_message("found target function -> %p", target_function);

	return STATUS_SUCCESS;
}