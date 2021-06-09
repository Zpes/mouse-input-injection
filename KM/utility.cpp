#include "utility.h"

PVOID utility::get_system_routine_address(LPCWSTR routine_name)
{
	UNICODE_STRING name;
	RtlInitUnicodeString(&name, routine_name);
	return MmGetSystemRoutineAddress(&name);
}

PVOID utility::get_system_module_export(LPCWSTR module_name, LPCSTR routine_name)
{
	PVOID lpModule = get_system_module_base(module_name);

	if (!lpModule)
		return NULL;

	return RtlFindExportedRoutineByName(lpModule, routine_name);
}

PVOID utility::get_system_module_base(LPCWSTR module_name)
{
	PVOID module_base = NULL;

	__try {

		PLIST_ENTRY module_list = reinterpret_cast<PLIST_ENTRY>(get_system_routine_address(L"PsLoadedModuleList"));

		if (!module_list)
			return NULL;

		UNICODE_STRING name;
		RtlInitUnicodeString(&name, module_name);

		for (PLIST_ENTRY link = module_list; link != module_list->Blink; link = link->Flink)
		{
			LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(link, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

			if (RtlEqualUnicodeString(&entry->BaseDllName, &name, TRUE))
			{
				module_base = entry->DllBase;
				break;
			}
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		module_base = NULL;
	}

	return module_base;
}