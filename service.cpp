#include "service.hpp"

bool service::RegisterAndStart(const std::wstring& driver_path, std::wstring driver_name) {
    SC_HANDLE scm_handle = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm_handle) {
        return false;
    }

    // Create the service
    SC_HANDLE service_handle = CreateServiceW(
        scm_handle,
        driver_name.c_str(),
        driver_name.c_str(),
        SERVICE_START | SERVICE_STOP | DELETE, // Desired access
        SERVICE_KERNEL_DRIVER, // Service type (for drivers)
        SERVICE_DEMAND_START, // Start type (manual start)
        SERVICE_ERROR_NORMAL,
        driver_path.c_str(),
        nullptr, nullptr, nullptr, nullptr, nullptr
    );

    if (!service_handle) {
        if (GetLastError() == ERROR_SERVICE_EXISTS) {
            service_handle = OpenServiceW(scm_handle, driver_name.c_str(), SERVICE_START);
        }
        if (!service_handle) {
            CloseServiceHandle(scm_handle);
            return false;
        }
    }

    // Start the service
    bool result = StartServiceW(service_handle, 0, nullptr);

    // Cleanup
    CloseServiceHandle(service_handle);
    CloseServiceHandle(scm_handle);

    return result;
}

bool service::StopAndRemove(const std::wstring& driver_name) {
    SC_HANDLE scm_handle = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm_handle) {
        return false;
    }

    SC_HANDLE service_handle = OpenServiceW(scm_handle, driver_name.c_str(), SERVICE_STOP | DELETE);
    if (!service_handle) {
        CloseServiceHandle(scm_handle);
        return false;
    }

    SERVICE_STATUS service_status = {};
    if (ControlService(service_handle, SERVICE_CONTROL_STOP, &service_status)) {
        Sleep(1000);
    }

    bool result = DeleteService(service_handle);

    CloseServiceHandle(service_handle);
    CloseServiceHandle(scm_handle);

    return result;
}
