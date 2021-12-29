#pragma once
#include <Windows.h>
#include <cstdint>
#include "kcontrol.hpp"
#include "utils.hpp"

namespace MapHelper
{
	bool LoadPEFile(const wchar_t* szPath, PBYTE& outBuffer)
	{
		HANDLE hFile = CreateFileW(szPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

		if (hFile == INVALID_HANDLE_VALUE)
			return false;

		DWORD FileSize = GetFileSize(hFile, NULL);
		outBuffer = new BYTE[FileSize];

		if (!outBuffer)
		{
			CloseHandle(hFile);
			return false;
		}

		if (!ReadFile(hFile, outBuffer, FileSize, NULL, NULL))
		{
			delete[] outBuffer;
			CloseHandle(hFile);
			return false;
		}

		CloseHandle(hFile);

		return true;
	}

	namespace PEHelper
	{
		DWORD GetPESize(PVOID pe_)
		{
			IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)pe_;
			IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((uint64_t)(dos)+(uint64_t)(dos->e_lfanew));

			return nt->OptionalHeader.SizeOfImage;
		}

		IMAGE_SECTION_HEADER* GetSectionHeader(PVOID pe_, const char* sec_name)
		{
			IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)pe_;
			IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((uint64_t)(dos)+(uint64_t)(dos->e_lfanew));

			IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
			for (int i = 0; i < nt->FileHeader.NumberOfSections; i++)
			{
				if (strncmp((const char*)sec[i].Name, sec_name, 8) == 0)
					return &sec[i];
			}
			return 0;
		}

		uint64_t GetSectionAddress(PVOID pe_, const char* sec_name)
		{
			IMAGE_SECTION_HEADER* sec = GetSectionHeader(pe_, sec_name);
			if (sec)
				return sec->VirtualAddress;

			return 0;
		}

		uint64_t GetSectionSize(PVOID pe_, const char* sec_name)
		{
			IMAGE_SECTION_HEADER* sec = GetSectionHeader(pe_, sec_name);
			if (sec)
				return sec->SizeOfRawData;

			return 0;
		}
	}

	void MapSections(PVOID pImageBuffer, PVOID buffer)
	{
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
		PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)pImageBuffer + pDosHeader->e_lfanew);
		PIMAGE_OPTIONAL_HEADER pOptHeader = (PIMAGE_OPTIONAL_HEADER)&pNtHeaders->OptionalHeader;

		RtlCopyMemory(buffer, pImageBuffer, pNtHeaders->OptionalHeader.SizeOfHeaders);

		PIMAGE_SECTION_HEADER pSectHeader = IMAGE_FIRST_SECTION(pNtHeaders);

		for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
		{
			RtlCopyMemory((PBYTE)buffer + pSectHeader[i].VirtualAddress, (PBYTE)pImageBuffer + pSectHeader[i].PointerToRawData, pSectHeader[i].SizeOfRawData);
		}
	}

	void RelocateImage(PVOID pReloc, PVOID pBase)
	{
		auto RELOC_FLAG64 = [](WORD RelInfo)
		{
			return ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64);
		};

		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;
		PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)pBase + pDosHeader->e_lfanew);
		PIMAGE_OPTIONAL_HEADER pOptHeader = (PIMAGE_OPTIONAL_HEADER)&pNtHeaders->OptionalHeader;

		// Replace Reloc Section
		PBYTE deltaAddr = (PBYTE)pReloc - pOptHeader->ImageBase;

		if (deltaAddr)
		{
			if (!pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
				return;

			auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>((PBYTE)pBase + pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			while (pRelocData->VirtualAddress)
			{
				UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

				for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo)
				{
					if (RELOC_FLAG64(*pRelativeInfo))
					{
						UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>((PBYTE)pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
						*pPatch += reinterpret_cast<UINT_PTR>(deltaAddr);
					}
				}

				pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
			}
		}
	}

	bool FixImageImport(PVOID pBase)
	{
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBase;
		PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)pBase + pDosHeader->e_lfanew);
		PIMAGE_OPTIONAL_HEADER pOptHeader = (PIMAGE_OPTIONAL_HEADER)&pNtHeaders->OptionalHeader;

		if (pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
		{
			PIMAGE_IMPORT_DESCRIPTOR pImportDescr = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)pBase + pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

			while (pImportDescr->Name)
			{
				LPCSTR szMod = (LPCSTR)((PBYTE)pBase + pImportDescr->Name);
				uintptr_t hModule = utils::get_kernel_module(szMod);

				PULONG_PTR pThunkRef = (PULONG_PTR)((PBYTE)pBase + pImportDescr->OriginalFirstThunk);
				PULONG_PTR pFuncRef = (PULONG_PTR)((PBYTE)pBase + pImportDescr->FirstThunk);

				if (!pThunkRef)
					pThunkRef = pFuncRef;

				for (; *pThunkRef; pThunkRef++, pFuncRef++)
				{
					if (*pThunkRef & IMAGE_ORDINAL_FLAG)
					{
						*pFuncRef = kcontrol::kGetProcAddress(hModule, *pThunkRef);
					}
					else
					{
						PIMAGE_IMPORT_BY_NAME pImport = (PIMAGE_IMPORT_BY_NAME)((PBYTE)pBase + *pThunkRef);
						*pFuncRef = kcontrol::kGetProcAddress(hModule, pImport->Name);

						if (!*pFuncRef)
							*pFuncRef = (uintptr_t)kcontrol::kGetSystemRoutineAddress(pImport->Name);
					}

					if (!*pFuncRef)
						return false;
				}

				++pImportDescr;
			}
		}

		return true;
	}
}