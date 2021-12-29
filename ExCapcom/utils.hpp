#pragma once
#include <Windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <vector>
#include <string>
#pragma comment(lib, "ntdll")

namespace utils
{
	typedef struct _RTL_PROCESS_MODULE_INFORMATION
	{
		HANDLE Section;         // Not filled in
		PVOID MappedBase;
		PVOID ImageBase;
		ULONG ImageSize;
		ULONG Flags;
		USHORT LoadOrderIndex;
		USHORT InitOrderIndex;
		USHORT LoadCount;
		USHORT OffsetToFileName;
		UCHAR  FullPathName[256];
	} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

	typedef struct _RTL_PROCESS_MODULES
	{
		ULONG NumberOfModules;
		RTL_PROCESS_MODULE_INFORMATION Modules[1];
	} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

	uintptr_t get_kernel_module(const char* kmodule)
	{
		NTSTATUS status = 0x0;
		ULONG bytes = 0;
		std::vector<uint8_t> data;
		unsigned long required = 0;


		while ((status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, data.data(), (ULONG)data.size(), &required)) == STATUS_INFO_LENGTH_MISMATCH) {
			data.resize(required);
		}

		if (!NT_SUCCESS(status))
			return 0;

		auto modules = reinterpret_cast<PRTL_PROCESS_MODULES>(data.data());
		for (unsigned i = 0; i < modules->NumberOfModules; ++i)
		{
			const auto& driver = modules->Modules[i];
			const auto image_base = reinterpret_cast<uintptr_t>(driver.ImageBase);
			std::string base_name = reinterpret_cast<char*>((uintptr_t)driver.FullPathName + driver.OffsetToFileName);
			const auto offset = base_name.find_last_of(".");

			if (kmodule == base_name
				or !_stricmp(base_name.c_str(), kmodule))
				return reinterpret_cast<uintptr_t>(driver.ImageBase);

			if (offset != base_name.npos)
				base_name = base_name.erase(offset, base_name.size() - offset);

			if (kmodule == base_name
				or !_stricmp(base_name.c_str(), kmodule))
				return reinterpret_cast<uintptr_t>(driver.ImageBase);
		}

		return 0;
	}
}