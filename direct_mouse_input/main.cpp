#include "includes.h"

BOOLEAN WINAPI main()
{
	mouse_interface custom_mouse_interface = mouse_interface();

	custom_mouse_interface.left_down();

	while (1);
}