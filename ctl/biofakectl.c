/*++
biofakectl.c

Control tool for the BioFake virtual fingerprint sensor.

Commands (see README):
  keys                       list keys (* = active)
  create <name>              create a key with a random seed
  delete <name>              delete a key
  select <name>              make the key active for auto capture
  present [name]             answer one parked capture (default: active key)
  mode <ready|reject|failure|custom>
  payload <file.bir>         inject a custom BIR payload
  status                     show driver state
  test                       enumerate WinBio units/databases
  console                    interactive mode
  hotkeys                    Ctrl+Alt+1..9 present keys, Ctrl+Alt+0 quit
  install [inf]              install driver package + create device nodes
  uninstall                  remove device nodes

The control channel is the private IOCTL interface exposed by the
SWD\BioFakeCtl software device node (BIOFAKE_CONTROL_INTERFACE_GUID).
--*/

#include <initguid.h>
#include <windows.h>
#include <cfgmgr32.h>
#include <swdevice.h>
#include <winbio.h>
#include <bcrypt.h>
#include <stdio.h>
#include <stdlib.h>

#include "..\shared\biofake_shared.h"

#pragma comment(lib, "cfgmgr32.lib")
#pragma comment(lib, "winbio.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")

//////////////////////////////////////////////////////////////////////////////
// Control device plumbing
//////////////////////////////////////////////////////////////////////////////

static
HANDLE
OpenControlDevice(
    VOID
    )
{
    ULONG size = 0;
    PWSTR list = NULL;
    CONFIGRET cr;
    HANDLE handle;

    cr = CM_Get_Device_Interface_List_SizeW(&size,
                                            (LPGUID)&BIOFAKE_CONTROL_INTERFACE_GUID,
                                            NULL,
                                            CM_GET_DEVICE_INTERFACE_LIST_PRESENT);
    if (cr != CR_SUCCESS || size < 2) {
        return INVALID_HANDLE_VALUE;
    }

    list = (PWSTR)HeapAlloc(GetProcessHeap(), 0, size * sizeof(WCHAR));
    if (list == NULL) {
        return INVALID_HANDLE_VALUE;
    }

    cr = CM_Get_Device_Interface_ListW((LPGUID)&BIOFAKE_CONTROL_INTERFACE_GUID,
                                       NULL,
                                       list,
                                       size,
                                       CM_GET_DEVICE_INTERFACE_LIST_PRESENT);
    if (cr != CR_SUCCESS || list[0] == L'\0') {
        HeapFree(GetProcessHeap(), 0, list);
        return INVALID_HANDLE_VALUE;
    }

    handle = CreateFileW(list,
                         GENERIC_READ | GENERIC_WRITE,
                         0,
                         NULL,
                         OPEN_EXISTING,
                         0,
                         NULL);

    HeapFree(GetProcessHeap(), 0, list);

    return handle;
}

static
BOOL
ControlCall(
    _In_ DWORD IoControlCode,
    _In_opt_ void* InBuffer,
    _In_ DWORD InSize,
    _Out_opt_ void* OutBuffer,
    _In_ DWORD OutSize,
    _Out_opt_ DWORD* Returned
    )
{
    HANDLE device;
    DWORD bytes = 0;
    BOOL ok;

    device = OpenControlDevice();
    if (device == INVALID_HANDLE_VALUE) {
        fwprintf(stderr,
                 L"[!] control device not found.\n"
                 L"    Install first:  biofakectl install\n"
                 L"    Or check Device Manager for 'BioFake Virtual Sensor Control'.\n");
        return FALSE;
    }

    ok = DeviceIoControl(device,
                         IoControlCode,
                         InBuffer,
                         InSize,
                         OutBuffer,
                         OutSize,
                         &bytes,
                         NULL);

    CloseHandle(device);

    if (Returned != NULL) {
        *Returned = bytes;
    }

    if (!ok) {
        fwprintf(stderr, L"[!] DeviceIoControl failed (error %lu)\n", GetLastError());
    }

    return ok;
}

//////////////////////////////////////////////////////////////////////////////
// Commands
//////////////////////////////////////////////////////////////////////////////

static
const wchar_t*
ModeName(
    _In_ ULONG Mode
    )
{
    switch (Mode) {
    case BIOFAKE_MODE_READY:   return L"ready";
    case BIOFAKE_MODE_REJECT:  return L"reject";
    case BIOFAKE_MODE_FAILURE: return L"failure";
    case BIOFAKE_MODE_CUSTOM:  return L"custom";
    default:                   return L"unknown";
    }
}

static
int
CmdKeys(
    VOID
    )
{
    BIOFAKE_KEY_INFO info[BIOFAKE_MAX_KEYS];
    DWORD returned = 0;
    ULONG i;

    if (!ControlCall(IOCTL_BIOFAKE_LIST_KEYS,
                     NULL, 0,
                     info, sizeof(info),
                     &returned)) {
        return 1;
    }

    ULONG count = returned / sizeof(info[0]);
    if (count == 0) {
        wprintf(L"(no keys - use: biofakectl create <name>)\n");
        return 0;
    }

    for (i = 0; i < count; i++) {
        wprintf(L"%ls%ls\n", info[i].Active ? L"* " : L"  ", info[i].Name);
    }

    return 0;
}

static
int
CmdCreate(
    _In_ const wchar_t* Name
    )
{
    BIOFAKE_KEY_ADD_IN in;

    if (Name == NULL || Name[0] == L'\0') {
        fwprintf(stderr, L"usage: biofakectl create <name>\n");
        return 1;
    }

    if (wcslen(Name) >= BIOFAKE_MAX_NAME_CCH) {
        fwprintf(stderr, L"[!] name too long (max %d chars)\n", BIOFAKE_MAX_NAME_CCH - 1);
        return 1;
    }

    RtlZeroMemory(&in, sizeof(in));
    wcsncpy_s(in.Name, BIOFAKE_MAX_NAME_CCH, Name, _TRUNCATE);

    if (BCryptGenRandom(NULL,
                        in.Seed,
                        BIOFAKE_SEED_SIZE,
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) != STATUS_SUCCESS) {
        fwprintf(stderr, L"[!] BCryptGenRandom failed\n");
        return 1;
    }

    if (!ControlCall(IOCTL_BIOFAKE_ADD_KEY, &in, sizeof(in), NULL, 0, NULL)) {
        return 1;
    }

    wprintf(L"[+] key '%ls' created (random seed). Use 'select' to make it active.\n", Name);
    return 0;
}

static
int
CmdDelete(
    _In_ const wchar_t* Name
    )
{
    BIOFAKE_NAME_IN in;

    if (Name == NULL || Name[0] == L'\0') {
        fwprintf(stderr, L"usage: biofakectl delete <name>\n");
        return 1;
    }

    RtlZeroMemory(&in, sizeof(in));
    wcsncpy_s(in.Name, BIOFAKE_MAX_NAME_CCH, Name, _TRUNCATE);

    if (!ControlCall(IOCTL_BIOFAKE_DELETE_KEY, &in, sizeof(in), NULL, 0, NULL)) {
        return 1;
    }

    wprintf(L"[+] key '%ls' deleted\n", Name);
    return 0;
}

static
int
CmdSelect(
    _In_ const wchar_t* Name
    )
{
    BIOFAKE_NAME_IN in;

    if (Name == NULL || Name[0] == L'\0') {
        fwprintf(stderr, L"usage: biofakectl select <name>\n");
        return 1;
    }

    RtlZeroMemory(&in, sizeof(in));
    wcsncpy_s(in.Name, BIOFAKE_MAX_NAME_CCH, Name, _TRUNCATE);

    if (!ControlCall(IOCTL_BIOFAKE_SELECT_KEY, &in, sizeof(in), NULL, 0, NULL)) {
        return 1;
    }

    wprintf(L"[+] key '%ls' is now active (captures return it)\n", Name);
    return 0;
}

static
int
CmdPresent(
    _In_ const wchar_t* Name
    )
{
    BIOFAKE_NAME_IN in;

    RtlZeroMemory(&in, sizeof(in));
    if (Name != NULL && Name[0] != L'\0') {
        wcsncpy_s(in.Name, BIOFAKE_MAX_NAME_CCH, Name, _TRUNCATE);
    }

    if (!ControlCall(IOCTL_BIOFAKE_PRESENT, &in, sizeof(in), NULL, 0, NULL)) {
        return 1;
    }

    if (in.Name[0] != L'\0') {
        wprintf(L"[+] presented '%ls' (parked capture answered with this key)\n", in.Name);
    } else {
        wprintf(L"[+] presented the active key\n");
    }
    return 0;
}

static
int
CmdMode(
    _In_ const wchar_t* Mode
    )
{
    BIOFAKE_MODE_IN in;

    if (Mode == NULL) {
        fwprintf(stderr, L"usage: biofakectl mode <ready|reject|failure|custom>\n");
        return 1;
    }

    if (_wcsicmp(Mode, L"ready") == 0) {
        in.Mode = BIOFAKE_MODE_READY;
    } else if (_wcsicmp(Mode, L"reject") == 0) {
        in.Mode = BIOFAKE_MODE_REJECT;
    } else if (_wcsicmp(Mode, L"failure") == 0) {
        in.Mode = BIOFAKE_MODE_FAILURE;
    } else if (_wcsicmp(Mode, L"custom") == 0) {
        in.Mode = BIOFAKE_MODE_CUSTOM;
    } else {
        fwprintf(stderr, L"[!] unknown mode '%ls'\n", Mode);
        return 1;
    }

    if (!ControlCall(IOCTL_BIOFAKE_SET_MODE, &in, sizeof(in), NULL, 0, NULL)) {
        return 1;
    }

    wprintf(L"[+] mode = %ls\n", Mode);
    return 0;
}

static
int
CmdPayload(
    _In_ const wchar_t* Path
    )
{
    HANDLE file;
    LARGE_INTEGER size;
    DWORD read = 0;
    BYTE* buffer;

    if (Path == NULL || Path[0] == L'\0') {
        fwprintf(stderr, L"usage: biofakectl payload <file.bir>\n");
        return 1;
    }

    file = CreateFileW(Path,
                       GENERIC_READ,
                       FILE_SHARE_READ,
                       NULL,
                       OPEN_EXISTING,
                       0,
                       NULL);
    if (file == INVALID_HANDLE_VALUE) {
        fwprintf(stderr, L"[!] cannot open '%ls' (error %lu)\n", Path, GetLastError());
        return 1;
    }

    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 ||
        size.QuadPart > BIOFAKE_CUSTOM_BIR_MAX) {
        fwprintf(stderr, L"[!] payload must be 1..%d bytes\n", BIOFAKE_CUSTOM_BIR_MAX);
        CloseHandle(file);
        return 1;
    }

    buffer = (BYTE*)HeapAlloc(GetProcessHeap(), 0, (SIZE_T)size.QuadPart);
    if (buffer == NULL) {
        CloseHandle(file);
        return 1;
    }

    if (!ReadFile(file, buffer, (DWORD)size.QuadPart, &read, NULL) ||
        read != (DWORD)size.QuadPart) {
        fwprintf(stderr, L"[!] read failed\n");
        HeapFree(GetProcessHeap(), 0, buffer);
        CloseHandle(file);
        return 1;
    }
    CloseHandle(file);

    if (!ControlCall(IOCTL_BIOFAKE_SET_CUSTOM, buffer, read, NULL, 0, NULL)) {
        HeapFree(GetProcessHeap(), 0, buffer);
        return 1;
    }

    HeapFree(GetProcessHeap(), 0, buffer);

    wprintf(L"[+] custom BIR injected (%lu bytes), mode = custom\n", read);
    return 0;
}

static
VOID
PrintStatus(
    VOID
    )
{
    BIOFAKE_STATUS_OUT st;

    RtlZeroMemory(&st, sizeof(st));

    if (!ControlCall(IOCTL_BIOFAKE_GET_STATUS, NULL, 0, &st, sizeof(st), NULL)) {
        return;
    }

    wprintf(L"mode          : %ls\n", ModeName(st.Mode));
    wprintf(L"active key    : %ls\n", st.ActiveName[0] ? st.ActiveName : L"(none)");
    wprintf(L"keys          : %lu / %d\n", (unsigned long)st.KeyCount, BIOFAKE_MAX_KEYS);
    wprintf(L"captures      : %lu\n", (unsigned long)st.CaptureCount);
    wprintf(L"pending       : %ls\n", st.PendingCapture ? L"yes" : L"no");
    wprintf(L"custom payload: %ls\n", st.HasCustom ? L"yes" : L"no");
}

static
int
CmdStatus(
    VOID
    )
{
    PrintStatus();
    return 0;
}

//////////////////////////////////////////////////////////////////////////////
// WinBio verification (test)
//////////////////////////////////////////////////////////////////////////////

static
void
PrintCapabilities(
    _In_ ULONG Caps
    )
{
    static const struct { ULONG bit; const wchar_t* name; } caps[] = {
        { 0x00000001, L"SENSOR" },
        { 0x00000002, L"MATCHING" },
        { 0x00000004, L"DATABASE" },
        { 0x00000008, L"PROCESSING" },
        { 0x00000010, L"ENCRYPTION" },
        { 0x00000020, L"NAVIGATION" },
        { 0x00000040, L"INDICATOR" },
        { 0x00000080, L"VIRTUAL_SENSOR" },
        { 0x00000100, L"SECURE_SENSOR" },
    };
    ULONG i;

    wprintf(L"    capabilities: 0x%08lx (", Caps);
    for (i = 0; i < ARRAYSIZE(caps); i++) {
        if (Caps & caps[i].bit) {
            wprintf(L"%ls ", caps[i].name);
        }
    }
    wprintf(L")\n");
}

static
int
CmdTest(
    VOID
    )
{
    WINBIO_SESSION_HANDLE session = NULL;
    PWINBIO_UNIT_SCHEMA units = NULL;
    PWINBIO_STORAGE_SCHEMA databases = NULL;
    SIZE_T unitCount = 0;
    SIZE_T dbCount = 0;
    SIZE_T i;
    HRESULT hr;
    int failed = 0;

    wprintf(L"== WinBio service enumeration ==\n");

    hr = WinBioOpenSession(WINBIO_TYPE_FINGERPRINT,
                           WINBIO_POOL_SYSTEM,
                           WINBIO_FLAG_DEFAULT,
                           NULL,
                           0,
                           (PWINBIO_UUID)WINBIO_DB_DEFAULT,
                           &session);
    if (FAILED(hr)) {
        wprintf(L"[!] WinBioOpenSession failed: 0x%08lx\n", (unsigned long)hr);
        failed = 1;
        goto done;
    }

    hr = WinBioEnumBiometricUnits(WINBIO_TYPE_FINGERPRINT, &units, &unitCount);
    if (FAILED(hr)) {
        wprintf(L"[!] WinBioEnumBiometricUnits failed: 0x%08lx\n", (unsigned long)hr);
        failed = 1;
        goto done;
    }

    wprintf(L"[+] biometric units: %llu\n", (unsigned long long)unitCount);
    for (i = 0; i < unitCount; i++) {
        wprintf(L"    unit %lu: %ls\n",
                (unsigned long)units[i].UnitId,
                units[i].DeviceInstanceId);
        wprintf(L"      description: %ls\n", units[i].Description);
        wprintf(L"      manufacturer: %ls  model: %ls\n",
                units[i].Manufacturer,
                units[i].Model);
        PrintCapabilities(units[i].Capabilities);
    }

    hr = WinBioEnumDatabases(WINBIO_TYPE_FINGERPRINT, &databases, &dbCount);
    if (FAILED(hr)) {
        wprintf(L"[!] WinBioEnumDatabases failed: 0x%08lx\n", (unsigned long)hr);
        failed = 1;
        goto done;
    }

    wprintf(L"[+] template databases: %llu\n", (unsigned long long)dbCount);
    for (i = 0; i < dbCount; i++) {
        wprintf(L"    db: %ls\n", databases[i].FilePath);
    }

    if (unitCount > 0) {
        wprintf(L"[+] BioFake unit is registered with the Windows Biometric Service\n");
    } else {
        wprintf(L"[!] no biometric units found - driver may not be installed/started\n");
        failed = 1;
    }

done:
    if (units != NULL) {
        WinBioFree(units);
    }
    if (databases != NULL) {
        WinBioFree(databases);
    }
    if (session != NULL) {
        WinBioCloseSession(session);
    }

    wprintf(L"\n== driver state ==\n");
    PrintStatus();

    return failed;
}

//////////////////////////////////////////////////////////////////////////////
// Console + hotkeys
//////////////////////////////////////////////////////////////////////////////

static
int
Dispatch(
    _In_ const wchar_t* Command,
    _In_ const wchar_t* Arg
    )
{
    if (_wcsicmp(Command, L"keys") == 0)    return CmdKeys();
    if (_wcsicmp(Command, L"create") == 0)  return CmdCreate(Arg);
    if (_wcsicmp(Command, L"delete") == 0)  return CmdDelete(Arg);
    if (_wcsicmp(Command, L"select") == 0)  return CmdSelect(Arg);
    if (_wcsicmp(Command, L"present") == 0) return CmdPresent(Arg);
    if (_wcsicmp(Command, L"mode") == 0)    return CmdMode(Arg);
    if (_wcsicmp(Command, L"payload") == 0) return CmdPayload(Arg);
    if (_wcsicmp(Command, L"status") == 0)  return CmdStatus();
    if (_wcsicmp(Command, L"test") == 0)    return CmdTest();

    fwprintf(stderr, L"[!] unknown command '%ls'\n", Command);
    return 1;
}

static
int
CmdConsole(
    VOID
    )
{
    wchar_t line[512];
    wchar_t cmd[64];
    wchar_t arg[256];

    wprintf(L"BioFake console. Type 'help' for commands, 'quit' to exit.\n");

    for (;;) {
        wprintf(L"biofake> ");
        fflush(stdout);

        if (fgetws(line, (int)(sizeof(line) / sizeof(line[0])), stdin) == NULL) {
            break;
        }

        cmd[0] = L'\0';
        arg[0] = L'\0';
        swscanf_s(line,
                  L"%63ls %255ls",
                  cmd, (unsigned)(sizeof(cmd) / sizeof(cmd[0])),
                  arg, (unsigned)(sizeof(arg) / sizeof(arg[0])));

        if (cmd[0] == L'\0') {
            continue;
        }
        if (_wcsicmp(cmd, L"quit") == 0 || _wcsicmp(cmd, L"exit") == 0) {
            break;
        }
        if (_wcsicmp(cmd, L"help") == 0) {
            wprintf(L"keys | create <n> | delete <n> | select <n> | present [n]\n");
            wprintf(L"mode <ready|reject|failure|custom> | payload <file>\n");
            wprintf(L"status | test | quit\n");
            continue;
        }

        Dispatch(cmd, arg);
    }

    return 0;
}

static
int
CmdHotkeys(
    VOID
    )
{
    MSG msg;
    int id;
    BIOFAKE_KEY_INFO info[BIOFAKE_MAX_KEYS];
    DWORD returned = 0;

    for (id = 1; id <= 9; id++) {
        if (!RegisterHotKey(NULL,
                            id,
                            MOD_CONTROL | MOD_ALT | MOD_NOREPEAT,
                            (UINT)('0' + id))) {
            fwprintf(stderr, L"[!] cannot register hotkey Ctrl+Alt+%d (error %lu)\n",
                     id, GetLastError());
        }
    }
    if (!RegisterHotKey(NULL, 0, MOD_CONTROL | MOD_ALT | MOD_NOREPEAT, '0')) {
        fwprintf(stderr, L"[!] cannot register quit hotkey\n");
    }

    wprintf(L"Hotkeys active:\n");
    wprintf(L"  Ctrl+Alt+1..9 -> present key N (by 'keys' order)\n");
    wprintf(L"  Ctrl+Alt+0    -> quit\n");

    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        if (msg.message != WM_HOTKEY) {
            continue;
        }

        id = (int)msg.wParam;
        if (id == 0) {
            break;
        }

        if (!ControlCall(IOCTL_BIOFAKE_LIST_KEYS,
                         NULL, 0,
                         info, sizeof(info),
                         &returned)) {
            continue;
        }

        ULONG count = returned / sizeof(info[0]);
        if ((ULONG)id <= count) {
            BIOFAKE_NAME_IN in;
            RtlZeroMemory(&in, sizeof(in));
            wcsncpy_s(in.Name, BIOFAKE_MAX_NAME_CCH,
                      info[id - 1].Name, _TRUNCATE);
            if (ControlCall(IOCTL_BIOFAKE_PRESENT, &in, sizeof(in), NULL, 0, NULL)) {
                wprintf(L"[hotkey] presented '%ls'\n", in.Name);
            }
        } else {
            wprintf(L"[hotkey] no key #%d\n", id);
        }
    }

    for (id = 1; id <= 9; id++) {
        UnregisterHotKey(NULL, id);
    }
    UnregisterHotKey(NULL, 0);

    return 0;
}

//////////////////////////////////////////////////////////////////////////////
// install / uninstall
//////////////////////////////////////////////////////////////////////////////

static
BOOL
RunCommand(
    _In_ const wchar_t* CommandLine
    )
{
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    DWORD exitCode = 1;
    wchar_t cmd[1024];

    RtlZeroMemory(&si, sizeof(si));
    RtlZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);

    wcsncpy_s(cmd, (SIZE_T)(sizeof(cmd) / sizeof(cmd[0])), CommandLine, _TRUNCATE);

    if (!CreateProcessW(NULL,
                        cmd,
                        NULL,
                        NULL,
                        FALSE,
                        0,
                        NULL,
                        NULL,
                        &si,
                        &pi)) {
        fwprintf(stderr, L"[!] cannot run: %ls (error %lu)\n", CommandLine, GetLastError());
        return FALSE;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return exitCode == 0;
}

static
VOID
RestartWbioService(
    VOID
    )
{
    SC_HANDLE scm;
    SC_HANDLE service;
    SERVICE_STATUS status;

    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scm == NULL) {
        fwprintf(stderr, L"[!] OpenSCManager failed (error %lu)\n", GetLastError());
        return;
    }

    service = OpenServiceW(scm, L"WbioSrvc", SERVICE_STOP | SERVICE_START);
    if (service == NULL) {
        fwprintf(stderr, L"[!] cannot open WbioSrvc (error %lu)\n", GetLastError());
        CloseServiceHandle(scm);
        return;
    }

    ControlService(service, SERVICE_CONTROL_STOP, &status);
    Sleep(800);

    if (StartServiceW(service, 0, NULL)) {
        wprintf(L"[+] WbioSrvc restarted\n");
    } else {
        fwprintf(stderr, L"[!] StartService(WbioSrvc) failed (error %lu)\n", GetLastError());
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
}

static
VOID
APIENTRY
SwDeviceCallback(
    _In_ HSWDEVICE hSwDevice,
    _In_ HRESULT CreateResult,
    _In_opt_ PVOID pContext,
    _In_opt_ PCWSTR pszDeviceInstanceId
    )
{
    UNREFERENCED_PARAMETER(hSwDevice);
    UNREFERENCED_PARAMETER(pContext);

    if (SUCCEEDED(CreateResult) && pszDeviceInstanceId != NULL) {
        wprintf(L"[+] device node: %ls\n", pszDeviceInstanceId);
    }
}

static
HRESULT
CreateSwDevice(
    _In_ PCWSTR InstanceId,
    _In_ PCWSTR HardwareId,
    _In_ PCWSTR Description
    )
{
    SW_DEVICE_CREATE_INFO info;
    HSWDEVICE handle = NULL;
    HRESULT hr;

    RtlZeroMemory(&info, sizeof(info));
    info.cbSize = sizeof(info);
    info.pszzInstanceId = InstanceId;
    info.pszzHardwareIds = HardwareId;      // multi-sz, single entry
    info.CapabilityFlags = SWDeviceCapabilitiesDriverRequired | SWDeviceCapabilitiesSilentInstall;
    info.pszDeviceDescription = Description;

    hr = SwDeviceCreate(BIOFAKE_ENUMERATOR,
                        L"HTREE\\ROOT\0",
                        &info,
                        0,
                        NULL,
                        SwDeviceCallback,
                        NULL,
                        &handle);
    if (SUCCEEDED(hr) && handle != NULL) {
        //
        // Persist the node across process exit and reboots.
        //
        SwDeviceSetLifetime(handle, SWDeviceLifetimeParentPresent);
        SwDeviceClose(handle);
    }

    return hr;
}

static
VOID
GetExeDir(
    _Out_writes_(cch) wchar_t* dir,
    _In_ DWORD cch
    )
{
    wchar_t path[MAX_PATH];
    wchar_t* slash;
    DWORD n = GetModuleFileNameW(NULL, path, MAX_PATH);

    dir[0] = L'\0';
    if (n == 0 || n >= MAX_PATH) {
        return;
    }

    slash = wcsrchr(path, L'\\');
    if (slash != NULL) {
        *slash = L'\0';
    }
    wcsncpy_s(dir, cch, path, _TRUNCATE);
}

static
int
CmdInstall(
    _In_ const wchar_t* InfArg
    )
{
    wchar_t exeDir[MAX_PATH];
    wchar_t infPath[MAX_PATH];
    wchar_t cerPath[MAX_PATH];
    wchar_t engineSrc[MAX_PATH];
    wchar_t engineDstDir[MAX_PATH];
    wchar_t engineDst[MAX_PATH];
    wchar_t cmd[1200];
    HSWDEVICE handle = NULL;
    HRESULT hr;

    if (!IsUserAnAdmin()) {
        fwprintf(stderr, L"[!] 'install' must run from an elevated (administrator) prompt\n");
        return 1;
    }

    GetExeDir(exeDir, MAX_PATH);

    //
    // 1. INF path (arg or next to the exe)
    //
    if (InfArg != NULL && InfArg[0] != L'\0') {
        wcsncpy_s(infPath, MAX_PATH, InfArg, _TRUNCATE);
    } else {
        _snwprintf_s(infPath, MAX_PATH, _TRUNCATE, L"%ls\%ls", exeDir, BIOFAKE_INF_NAME);
    }
    if (GetFileAttributesW(infPath) == INVALID_FILE_ATTRIBUTES) {
        fwprintf(stderr, L"[!] INF not found: %ls\n", infPath);
        return 1;
    }

    //
    // 2. Import the test certificate (best effort; needed for test signing)
    //
    _snwprintf_s(cerPath, MAX_PATH, _TRUNCATE, L"%ls\%ls", exeDir, BIOFAKE_CERT_NAME);
    if (GetFileAttributesW(cerPath) != INVALID_FILE_ATTRIBUTES) {
        _snwprintf_s(cmd, (SIZE_T)(sizeof(cmd) / sizeof(cmd[0])), _TRUNCATE,
                     L"certutil -addstore -f Root \"%ls\"", cerPath);
        RunCommand(cmd);
        _snwprintf_s(cmd, (SIZE_T)(sizeof(cmd) / sizeof(cmd[0])), _TRUNCATE,
                     L"certutil -addstore -f TrustedPublisher \"%ls\"", cerPath);
        RunCommand(cmd);
        wprintf(L"[+] test certificate imported\n");
    } else {
        wprintf(L"[i] %ls not found next to biofakectl.exe; skip cert import\n", BIOFAKE_CERT_NAME);
    }

    //
    // 3. Stage the driver package into the driver store
    //
    _snwprintf_s(cmd, (SIZE_T)(sizeof(cmd) / sizeof(cmd[0])), _TRUNCATE,
                 L"pnputil.exe /add-driver \"%ls\" /install", infPath);
    if (!RunCommand(cmd)) {
        fwprintf(stderr, L"[!] pnputil /add-driver failed\n");
        return 1;
    }
    wprintf(L"[+] driver package staged\n");

    //
    // 4. Create the two software device nodes
    //
    hr = CreateSwDevice(BIOFAKE_SENSOR_INSTANCE,
                        BIOFAKE_SENSOR_HWID L"\0",
                        L"BioFake Virtual Fingerprint Sensor");
    if (FAILED(hr)) {
        fwprintf(stderr, L"[!] SwDeviceCreate(sensor) failed: 0x%08lx\n", (unsigned long)hr);
        return 1;
    }

    hr = CreateSwDevice(BIOFAKE_CONTROL_INSTANCE,
                        BIOFAKE_CONTROL_HWID L"\0",
                        L"BioFake Virtual Sensor Control");
    if (FAILED(hr)) {
        fwprintf(stderr, L"[!] SwDeviceCreate(ctl) failed: 0x%08lx\n", (unsigned long)hr);
        return 1;
    }

    UNREFERENCED_PARAMETER(handle);

    //
    // 5. Install the engine adapter into WinBioPlugIns
    //
    _snwprintf_s(engineSrc, MAX_PATH, _TRUNCATE, L"%ls\%ls", exeDir, BIOFAKE_ENGINE_DLL);
    _snwprintf_s(engineDstDir, MAX_PATH, _TRUNCATE,
                 L"%ls\System32\WinBio\WinBioPlugIns", L"C:\\Windows");
    _snwprintf_s(engineDst, MAX_PATH, _TRUNCATE, L"%ls\%ls", engineDstDir, BIOFAKE_ENGINE_DLL);

    CreateDirectoryW(engineDstDir, NULL);
    if (CopyFileW(engineSrc, engineDst, FALSE)) {
        wprintf(L"[+] engine adapter installed: %ls\n", engineDst);
    } else {
        wprintf(L"[i] engine adapter not copied (%ls missing?) - WinBio enrollment will not work\n",
                engineSrc);
    }

    //
    // 6. Restart the biometric service so it picks up the new unit
    //
    RestartWbioService();

    wprintf(L"\n[+] install complete. Verify with:\n");
    wprintf(L"      biofakectl test\n");
    wprintf(L"      biofakectl create mykey && biofakectl select mykey\n");

    return 0;
}

static
int
CmdUninstall(
    VOID
    )
{
    wchar_t engineDst[MAX_PATH];
    wchar_t cmd[1024];

    if (!IsUserAnAdmin()) {
        fwprintf(stderr, L"[!] 'uninstall' must run from an elevated (administrator) prompt\n");
        return 1;
    }

    _snwprintf_s(cmd, (SIZE_T)(sizeof(cmd) / sizeof(cmd[0])), _TRUNCATE,
                 L"pnputil.exe /remove-device \"SWD\BioFake\Sensor\"");
    RunCommand(cmd);

    _snwprintf_s(cmd, (SIZE_T)(sizeof(cmd) / sizeof(cmd[0])), _TRUNCATE,
                 L"pnputil.exe /remove-device \"SWD\BioFake\Ctl\"");
    RunCommand(cmd);

    _snwprintf_s(engineDst, MAX_PATH, _TRUNCATE,
                 L"C:\\Windows\System32\WinBio\WinBioPlugIns\%ls", BIOFAKE_ENGINE_DLL);
    DeleteFileW(engineDst);

    RestartWbioService();

    wprintf(L"[+] uninstall complete\n");
    wprintf(L"[i] driver package cleanup: pnputil /enum-drivers, then\n");
    wprintf(L"    pnputil /delete-driver oemXX.inf /uninstall /force\n");

    return 0;
}

//////////////////////////////////////////////////////////////////////////////
// Entry point
//////////////////////////////////////////////////////////////////////////////

static
VOID
Usage(
    VOID
    )
{
    wprintf(L"biofakectl - control the BioFake virtual fingerprint sensor\n\n");
    wprintf(L"  keys                       list keys (* = active)\n");
    wprintf(L"  create <name>              create a key with a random seed\n");
    wprintf(L"  delete <name>              delete a key\n");
    wprintf(L"  select <name>              make the key active\n");
    wprintf(L"  present [name]             answer one parked capture\n");
    wprintf(L"  mode <ready|reject|failure|custom>\n");
    wprintf(L"  payload <file.bir>         inject a custom BIR\n");
    wprintf(L"  status                     show driver state\n");
    wprintf(L"  test                       enumerate WinBio units/databases\n");
    wprintf(L"  console                    interactive mode\n");
    wprintf(L"  hotkeys                    Ctrl+Alt+1..9 present keys\n");
    wprintf(L"  install [inf]              install driver + create device nodes\n");
    wprintf(L"  uninstall                  remove device nodes\n");
}

int
wmain(
    _In_ int argc,
    _In_reads_(argc) wchar_t** argv
    )
{
    const wchar_t* cmd;

    if (argc < 2) {
        Usage();
        return 0;
    }

    cmd = argv[1];

    if (_wcsicmp(cmd, L"keys") == 0)          return CmdKeys();
    if (_wcsicmp(cmd, L"create") == 0)        return CmdCreate(argc >= 3 ? argv[2] : NULL);
    if (_wcsicmp(cmd, L"delete") == 0)        return CmdDelete(argc >= 3 ? argv[2] : NULL);
    if (_wcsicmp(cmd, L"select") == 0)        return CmdSelect(argc >= 3 ? argv[2] : NULL);
    if (_wcsicmp(cmd, L"present") == 0)       return CmdPresent(argc >= 3 ? argv[2] : L"");
    if (_wcsicmp(cmd, L"mode") == 0)          return CmdMode(argc >= 3 ? argv[2] : NULL);
    if (_wcsicmp(cmd, L"payload") == 0)       return CmdPayload(argc >= 3 ? argv[2] : NULL);
    if (_wcsicmp(cmd, L"status") == 0)        return CmdStatus();
    if (_wcsicmp(cmd, L"test") == 0)          return CmdTest();
    if (_wcsicmp(cmd, L"console") == 0)       return CmdConsole();
    if (_wcsicmp(cmd, L"hotkeys") == 0)       return CmdHotkeys();
    if (_wcsicmp(cmd, L"install") == 0)       return CmdInstall(argc >= 3 ? argv[2] : NULL);
    if (_wcsicmp(cmd, L"uninstall") == 0)     return CmdUninstall();

    Usage();
    return (wcscmp(cmd, L"/?") == 0 || wcscmp(cmd, L"help") == 0) ? 0 : 1;
}
