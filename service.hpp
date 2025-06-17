#pragma once
#include <Windows.h>
#include <string>

namespace service {
	bool RegisterAndStart(const std::wstring& driver_path, std::wstring driver_name);
	bool StopAndRemove(const std::wstring& driver_name);
};