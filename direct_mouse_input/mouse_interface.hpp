#pragma once
#include <windows.h>
#include <iostream>
#include "pragma.h"

#include "defines.h"

class mouse_interface
{
private:
	bool(*NtUserInjectMouseInput)(InjectedInputMouseInfo*, int) = nullptr;

public:
	mouse_interface()
	{
		LoadLibrary("user32.dll");
		HMODULE win32u = LoadLibrary("win32u.dll");

		if (!win32u)
		{
			printf_s("[-] could not find win32u -> %p\n", win32u);
			return;
		}

		printf_s("[+] found win32u -> %p\n", win32u);

		void* NtUserInjectMouseInputAddress = (void*)GetProcAddress(win32u, "NtUserInjectMouseInput");

		if (!NtUserInjectMouseInputAddress)
		{
			printf_s("[-] could not find NtUserInjectMouseInput -> %p\n", win32u);
			return;
		}

		*(void**)&NtUserInjectMouseInput = NtUserInjectMouseInputAddress;

		printf_s("[+] found NtUserInjectMouseInput -> %p\n", NtUserInjectMouseInputAddress);
	}

	bool left_down(int x = 0, int y = 0)
	{
		InjectedInputMouseInfo temp = {};
		temp.mouse_options = InjectedInputMouseOptions::left_down;
		temp.move_direction_x = x;
		temp.move_direction_y = y;
		return NtUserInjectMouseInput(&temp, 1);
	}

	bool left_up(int x = 0, int y = 0)
	{
		InjectedInputMouseInfo temp{};
		temp.mouse_options = InjectedInputMouseOptions::left_up;
		temp.move_direction_x = x;
		temp.move_direction_y = y;
		return NtUserInjectMouseInput(&temp, 1);
	}

	bool right_down(int x = 0, int y = 0)
	{
		InjectedInputMouseInfo temp{};
		temp.mouse_options = InjectedInputMouseOptions::right_down;
		temp.move_direction_x = x;
		temp.move_direction_y = y;
		return NtUserInjectMouseInput(&temp, 1);
	}

	bool right_up(int x = 0, int y = 0)
	{
		InjectedInputMouseInfo temp{};
		temp.mouse_options = InjectedInputMouseOptions::right_up;
		temp.move_direction_x = x;
		temp.move_direction_y = y;
		return NtUserInjectMouseInput(&temp, 1);
	}
};
