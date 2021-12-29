#pragma once
#include <Windows.h>
#include <fstream>
#include <string>
#include "drvcap.hpp"


namespace loader
{
    bool copy_drv_capcom(const std::string& path)
    {
        std::ofstream out(path, std::ios::out | std::ios::binary);

        if (out.is_open())
        {
            out.write((const char*)capcom_sys, sizeof(capcom_sys));
            out.close();

            return true;
        }

        return false;
    }

	SC_HANDLE create_service(const std::string& name, const std::string& display_name, const std::string& path)
	{
        if (auto handle_scm = OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE))
        {
            auto hsvc = CreateServiceA(handle_scm,
                name.c_str(),
                display_name.c_str(),
                SERVICE_ALL_ACCESS,
                SERVICE_KERNEL_DRIVER,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL,
                path.c_str(),
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr);

            if (!hsvc && GetLastError() == ERROR_SERVICE_EXISTS)
                hsvc = OpenServiceA(handle_scm, name.c_str(), SERVICE_ALL_ACCESS);

            return hsvc;
        }

        return NULL;
	}

    bool delete_service(const SC_HANDLE& handle_service)
    {
        const auto success = DeleteService(handle_service);

        if (!success && GetLastError() != ERROR_SERVICE_MARKED_FOR_DELETE)
            return false;

        return CloseServiceHandle(handle_service);
    }

    bool start_service(const SC_HANDLE& handle_service)
    {
        const auto success = StartServiceA(handle_service, 0, nullptr);

        return success || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING;
    }

    bool stop_service(const SC_HANDLE& handle_service, const LPSERVICE_STATUS& service_status)
    {
        return ControlService(handle_service, SERVICE_CONTROL_STOP, service_status);
    }
}