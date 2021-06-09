#pragma once
#include <windows.h>

// https://docs.microsoft.com/en-us/uwp/api/windows.ui.input.preview.injection.injectedinputmouseoptions?view=winrt-20348
enum InjectedInputMouseOptions
{
    left_up = 4,
    left_down = 2,
    right_up = 8,
    right_down = 16
};

struct InjectedInputMouseInfo
{
    int move_direction_x; // 10 would move the mouse from the current position +10 on the X, same withe the Y
    int move_direction_y;
    unsigned int mouse_data;
    InjectedInputMouseOptions mouse_options;
    unsigned int time_offset_in_miliseconds;
    void* extra_info;
};