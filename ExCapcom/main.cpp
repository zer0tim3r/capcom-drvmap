#include <Windows.h>
#include <winternl.h>
#include <string>
#include "loader.hpp"
#include "kcontrol.hpp"
#include "ntdef.hpp"
#include "MapHelper.hpp"
#include "xorstr.hpp"

#pragma comment(lib, "ntdll")


bool MapDrv(const wchar_t* path, std::string& reason)
{
	reason = "";

	char pathSys32[1024] = { 0, };
	GetSystemDirectoryA(pathSys32, 1024);
	std::string pathcap = std::string(pathSys32) + xorstr("\\drivers\\capcom.sys");

	if (loader::copy_drv_capcom(pathcap))
	{
		if (auto service = loader::create_service(xorstr("drvcap"), xorstr("Capcom Driver"), pathcap))
		{
			if (loader::start_service(service))
			{
				if (kcontrol::Init())
				{
					PBYTE FileBuffer = NULL;
					if (MapHelper::LoadPEFile(path, FileBuffer))
					{
						auto PESize = MapHelper::PEHelper::GetPESize(FileBuffer);

						if (PVOID uMem = VirtualAlloc(NULL, PESize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))
						{
							MapHelper::MapSections(FileBuffer, uMem);

							if (MapHelper::FixImageImport(uMem))
							{
								PVOID kMem = kcontrol::ExAllocatePool(NonPagedPool, PESize);

								MapHelper::RelocateImage(kMem, uMem);

								kcontrol::kCopyMemory(kMem, uMem, PESize);

								PVOID EntryPoint = NULL;

								kcontrol::IoControl([&kMem, &EntryPoint](kcontrol::MmGetSystemRoutineAddress pMmGetSystemRoutineAddress)
									{
										PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)kMem;
										PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)kMem + pDosHeader->e_lfanew);
										PIMAGE_OPTIONAL_HEADER pOptHeader = (PIMAGE_OPTIONAL_HEADER)&pNtHeaders->OptionalHeader;

										if (pOptHeader->AddressOfEntryPoint)
										{
											typedef NTSTATUS(*fnDriverEntry)(PVOID pDriverBase);
											fnDriverEntry pDriverEntry = (fnDriverEntry)((PBYTE)kMem + pOptHeader->AddressOfEntryPoint);
											pDriverEntry(kMem);

											EntryPoint = pDriverEntry;
										}
									});
							}

							VirtualFree(uMem, 0, MEM_RELEASE);
						}

						delete[] FileBuffer;
					}

					kcontrol::Uninit();
				}
				else reason = xorstr("An error occurred during opening kernel device\n");

				SERVICE_STATUS status = { };
				loader::stop_service(service, &status);
			}
			else reason = xorstr("An error occurred during starting service\n");

			loader::delete_service(service);
		}
		else reason = xorstr("An erorr occurred during creating service\n");
	}
	else reason = xorstr("An erorr occurred during copying capcom driver image\n");

	return reason.empty();
}

bool MapDrv(const unsigned char* buffer, std::string& reason)
{
	reason = "";

	char pathSys32[1024] = { 0, };
	GetSystemDirectoryA(pathSys32, 1024);
	std::string pathcap = std::string(pathSys32) + xorstr("\\drivers\\capcom.sys");

	if (loader::copy_drv_capcom(pathcap))
	{
		if (auto service = loader::create_service(xorstr("drvcap"), xorstr("Capcom Driver"), pathcap))
		{
			if (loader::start_service(service))
			{
				if (kcontrol::Init())
				{
					auto PESize = MapHelper::PEHelper::GetPESize((PVOID)buffer);

					if (PVOID uMem = VirtualAlloc(NULL, PESize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))
					{
						MapHelper::MapSections((PVOID)buffer, uMem);

						if (MapHelper::FixImageImport(uMem))
						{
							PVOID kMem = kcontrol::ExAllocatePool(NonPagedPool, PESize);

							MapHelper::RelocateImage(kMem, uMem);

							kcontrol::kCopyMemory(kMem, uMem, PESize);

							PVOID EntryPoint = NULL;

							kcontrol::IoControl([&kMem, &EntryPoint](kcontrol::MmGetSystemRoutineAddress pMmGetSystemRoutineAddress)
								{
									PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)kMem;
									PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)kMem + pDosHeader->e_lfanew);
									PIMAGE_OPTIONAL_HEADER pOptHeader = (PIMAGE_OPTIONAL_HEADER)&pNtHeaders->OptionalHeader;

									if (pOptHeader->AddressOfEntryPoint)
									{
										typedef NTSTATUS(*fnDriverEntry)(PVOID pDriverBase);
										fnDriverEntry pDriverEntry = (fnDriverEntry)((PBYTE)kMem + pOptHeader->AddressOfEntryPoint);
										pDriverEntry(kMem);

										EntryPoint = pDriverEntry;
									}
								});
						}

						VirtualFree(uMem, 0, MEM_RELEASE);
					}

					kcontrol::Uninit();
				}
				else reason = xorstr("An error occurred during opening kernel device\n");

				SERVICE_STATUS status = { };
				loader::stop_service(service, &status);
			}
			else reason = xorstr("An error occurred during starting service\n");

			loader::delete_service(service);
		}
		else reason = xorstr("An erorr occurred during creating service\n");
	}
	else reason = xorstr("An erorr occurred during copying capcom driver image\n");

	DeleteFileA(pathcap.c_str());

	return reason.empty();
}

//int main()
//{
//	char pathSys32[1024] = { 0, };
//	GetSystemDirectoryA(pathSys32, 1024);
//	std::string pathcap = std::string(pathSys32) + "\\drivers\\capcom.sys";
//	
//	if (loader::copy_drv_capcom(pathcap))
//	{
//		if (auto service = loader::create_service("drvcap", "Capcom Driver", pathcap))
//		{
//			if (loader::start_service(service))
//			{
//				if (kcontrol::Init())
//				{
//					PBYTE FileBuffer = NULL;
//					if (MapHelper::LoadPEFile(L"C:\\Users\\WDAGUtilityAccount\\Desktop\\AE.Kernel.sys", FileBuffer))
//					{
//						auto PESize = MapHelper::PEHelper::GetPESize(FileBuffer);
//
//						printf("PESize : %lX\n", PESize);
//
//						if (PVOID uMem = VirtualAlloc(NULL, PESize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))
//						{
//							MapHelper::MapSections(FileBuffer, uMem);
//
//							if (MapHelper::FixImageImport(uMem))
//							{
//								PVOID kMem = kcontrol::ExAllocatePool(NonPagedPool, PESize);
//								printf("kernel space : %p\n", kMem);
//
//								MapHelper::RelocateImage(kMem, uMem);
//
//								kcontrol::kCopyMemory(kMem, uMem, PESize);
//								
//								PVOID EntryPoint = NULL;
//
//								kcontrol::IoControl([&kMem, &EntryPoint](kcontrol::MmGetSystemRoutineAddress pMmGetSystemRoutineAddress)
//									{
//										PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)kMem;
//										PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)kMem + pDosHeader->e_lfanew);
//										PIMAGE_OPTIONAL_HEADER pOptHeader = (PIMAGE_OPTIONAL_HEADER)&pNtHeaders->OptionalHeader;
//
//										if (pOptHeader->AddressOfEntryPoint)
//										{
//											typedef NTSTATUS(*fnDriverEntry)(PVOID pDriverBase);
//											fnDriverEntry pDriverEntry = (fnDriverEntry)((PBYTE)kMem + pOptHeader->AddressOfEntryPoint);
//											pDriverEntry(kMem);
//
//											EntryPoint = pDriverEntry;
//										}
//									});
//
//								printf("EntryPoint : %p\n", EntryPoint);
//							}
//
//							VirtualFree(uMem, 0, MEM_RELEASE);
//						}
//
//						delete[] FileBuffer;
//					}
//
//					kcontrol::Uninit();
//				}
//				else printf("An error occurred during opening kernel device\n");
//
//				SERVICE_STATUS status = { };
//				loader::stop_service(service, &status);
//			}
//			else printf("An error occurred during starting service\n");
//
//			loader::delete_service(service);
//		}
//		else printf("An erorr occurred during creating service\n");
//	}
//	else printf("An erorr occurred during copying capcom driver image\n");
//
//	system("pause > nul");
//
//	return 0;
//}