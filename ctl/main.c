/*++

THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
ANY KIND, EITHER EXPRESSED OR IMPLIED.

biofakectl.exe - control tool for the BioFake virtual fingerprint sensor

Commands:
    status                  Show driver info, stats and present devices
    mode <ready|reject|failure|custom>   Switch sensor behavior
    payload <file.bir>      Feed a custom WINBIO_BIR blob to the driver
    install [path\biofake_wudf.inf]      Install the driver (admin)
    uninstall               Remove device + driver package (admin)
    test                    WinBio enumeration + raw capture proof (admin)
    console                 Interactive key control
    hotkeys                 Global hotkey control (Ctrl+Alt+1..4 / 0)

Environment:
    Windows 10/11 user mode. /MT static CRT, no external dependencies.

--*/

#include <initguid.h>
#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include <setupapi.h>
#include <newdev.h>
#include <winbio.h>
#include "biofake_ioctl.h"

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "newdev.lib")
#pragma comment(lib, "winbio.lib")

//
// {53D29EF7-377C-4D14-864B-EB3A85769359} - GUID_DEVCLASS_BIOMETRIC
//
DEFINE_GUID(GUID_DEVCLASS_BIOFAKE_BIOMETRIC_CLASS,
    0x53d29ef7, 0x377c, 0x4d14, 0x86, 0x4b, 0xeb, 0x3a, 0x85, 0x76, 0x93, 0x59);

static const wchar_t* g_DefaultInfName = L"biofake_wudf.inf";
static const wchar_t* g_DefaultPayloadName = L"payload.bir";

static
VOID
PrintUsage(VOID)
{
    printf("biofakectl - control tool for the BioFake virtual fingerprint sensor\n\n");
    printf("usage:\n");
    printf("  biofakectl status\n");
    printf("  biofakectl mode <ready|reject|failure|custom>\n");
    printf("  biofakectl payload <file.bir>\n");
    printf("  biofakectl install [path\\biofake_wudf.inf]\n");
    printf("  biofakectl uninstall\n");
    printf("  biofakectl test\n");
    printf("  biofakectl console\n");
    printf("  biofakectl hotkeys\n\n");
    printf("modes:\n");
    printf("  ready    capture succeeds with a synthetic ANSI-381 fingerprint\n");
    printf("  reject   capture is rejected with WINBIO_FP_POOR_QUALITY\n");
    printf("  failure  sensor reports WINBIO_SENSOR_FAILURE\n");
    printf("  custom   capture returns the payload set via 'payload'\n");
}

static
HANDLE
OpenControlDevice(VOID)
{
    HDEVINFO                        devInfo;
    SP_DEVICE_INTERFACE_DATA        ifaceData;
    PSP_DEVICE_INTERFACE_DETAIL_DATA_W detail;
    DWORD                           index = 0;
    DWORD                           size;
    HANDLE                          handle = INVALID_HANDLE_VALUE;

    devInfo = SetupDiGetClassDevsW(&GUID_BIOFAKE_CONTROL,
                                   NULL,
                                   NULL,
                                   DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (devInfo == INVALID_HANDLE_VALUE) {
        return INVALID_HANDLE_VALUE;
    }

    ifaceData.cbSize = sizeof(ifaceData);

    while (SetupDiEnumDeviceInterfaces(devInfo, NULL, &GUID_BIOFAKE_CONTROL, index, &ifaceData)) {

        size = 0;
        SetupDiGetDeviceInterfaceDetailW(devInfo, &ifaceData, NULL, 0, &size, NULL);
        if (size == 0) {
            index++;
            continue;
        }

        detail = (PSP_DEVICE_INTERFACE_DETAIL_DATA_W)malloc(size);
        if (detail == NULL) {
            break;
        }
        detail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);

        if (SetupDiGetDeviceInterfaceDetailW(devInfo, &ifaceData, detail, size, NULL, NULL)) {
            handle = CreateFileW(detail->DevicePath,
                                 GENERIC_READ | GENERIC_WRITE,
                                 0,
                                 NULL,
                                 OPEN_EXISTING,
                                 0,
                                 NULL);
        }

        free(detail);

        if (handle != INVALID_HANDLE_VALUE) {
            break;
        }

        index++;
    }

    SetupDiDestroyDeviceInfoList(devInfo);

    return handle;
}

static
BOOL
ControlGetInfo(HANDLE handle, PBIOFAKE_INFO info)
{
    DWORD bytes = 0;

    return DeviceIoControl(handle,
                           IOCTL_BIOFAKE_GET_INFO,
                           NULL,
                           0,
                           info,
                           sizeof(BIOFAKE_INFO),
                           &bytes,
                           NULL);
}

static
BOOL
ControlGetStats(HANDLE handle, PBIOFAKE_STATS stats)
{
    DWORD bytes = 0;

    return DeviceIoControl(handle,
                           IOCTL_BIOFAKE_GET_STATS,
                           NULL,
                           0,
                           stats,
                           sizeof(BIOFAKE_STATS),
                           &bytes,
                           NULL);
}

static
BOOL
ControlSetMode(HANDLE handle, DWORD mode)
{
    DWORD bytes = 0;

    return DeviceIoControl(handle,
                           IOCTL_BIOFAKE_SET_MODE,
                           &mode,
                           sizeof(mode),
                           NULL,
                           0,
                           &bytes,
                           NULL);
}

static
BOOL
ControlSetPayloadFile(HANDLE handle, const wchar_t* path)
{
    BYTE*   blob;
    FILE*   fp;
    long    fileSize;
    DWORD   bytes = 0;
    BOOL    ok;

    if (_wfopen_s(&fp, path, L"rb") != 0 || fp == NULL) {
        printf("error: cannot open payload file '%ls'\n", path);
        return FALSE;
    }

    fseek(fp, 0, SEEK_END);
    fileSize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (fileSize < (long)sizeof(WINBIO_BIR) || fileSize > (long)BIOFAKE_MAX_PAYLOAD) {
        printf("error: payload size %ld out of range [%zu..%u]\n",
               fileSize, sizeof(WINBIO_BIR), BIOFAKE_MAX_PAYLOAD);
        fclose(fp);
        return FALSE;
    }

    blob = (BYTE*)malloc(sizeof(DWORD) + (size_t)fileSize);
    if (blob == NULL) {
        fclose(fp);
        return FALSE;
    }

    ((PDWORD)blob)[0] = (DWORD)fileSize;

    if (fread(blob + sizeof(DWORD), 1, (size_t)fileSize, fp) != (size_t)fileSize) {
        printf("error: short read on payload file\n");
        free(blob);
        fclose(fp);
        return FALSE;
    }
    fclose(fp);

    ok = DeviceIoControl(handle,
                         IOCTL_BIOFAKE_SET_PAYLOAD,
                         blob,
                         (DWORD)(sizeof(DWORD) + (size_t)fileSize),
                         NULL,
                         0,
                         &bytes,
                         NULL);

    free(blob);

    if (ok) {
        printf("payload '%ls' loaded (%ld bytes), mode switched to custom\n", path, fileSize);
    }
    else {
        printf("error: IOCTL_BIOFAKE_SET_PAYLOAD failed (gle=%lu)\n", GetLastError());
    }

    return ok;
}

static
void
PrintStatus(VOID)
{
    HANDLE handle;
    BIOFAKE_INFO info;
    BIOFAKE_STATS stats;
    const wchar_t* modeName[] = { L"ready", L"reject", L"failure", L"custom" };

    handle = OpenControlDevice();
    if (handle == INVALID_HANDLE_VALUE) {
        printf("control interface not found - driver not installed or device not started\n");
        return;
    }

    if (!ControlGetInfo(handle, &info)) {
        printf("error: IOCTL_BIOFAKE_GET_INFO failed (gle=%lu)\n", GetLastError());
        CloseHandle(handle);
        return;
    }

    printf("driver version   : %lu\n", info.Version);
    printf("mode             : %ls\n",
           info.Mode <= 3 ? modeName[info.Mode] : L"unknown");
    printf("payload size     : %lu bytes\n", info.PayloadSize);
    printf("max payload size : %lu bytes\n", info.MaxPayloadSize);

    if (ControlGetStats(handle, &stats)) {
        printf("captures requested: %lu  served: %lu  rejected: %lu  failed: %lu\n",
               stats.CapturesRequested,
               stats.CapturesServed,
               stats.CapturesRejected,
               stats.CapturesFailed);
    }

    CloseHandle(handle);
}

static
void
ListBiometricDevices(VOID)
{
    HDEVINFO            devInfo;
    SP_DEVINFO_DATA     devData;
    wchar_t             hwids[512];
    wchar_t             instanceId[512];
    DWORD               type;
    DWORD               size;
    DWORD               index = 0;

    printf("\n-- biometric class devices present --\n");

    devInfo = SetupDiGetClassDevsW(&GUID_DEVCLASS_BIOFAKE_BIOMETRIC_CLASS,
                                   NULL,
                                   NULL,
                                   DIGCF_PRESENT);
    if (devInfo == INVALID_HANDLE_VALUE) {
        printf("(none)\n");
        return;
    }

    devData.cbSize = sizeof(devData);

    while (SetupDiEnumDeviceInfo(devInfo, index, &devData)) {

        size = sizeof(instanceId);
        if (SetupDiGetDeviceInstanceIdW(devInfo, &devData, instanceId, (DWORD)(sizeof(instanceId) / sizeof(wchar_t)), NULL)) {
            wprintf(L"[%lu] %ls\n", index, instanceId);
        }

        size = sizeof(hwids);
        if (SetupDiGetDeviceRegistryPropertyW(devInfo,
                                              &devData,
                                              SPDRP_HARDWAREID,
                                              &type,
                                              (PBYTE)hwids,
                                              sizeof(hwids),
                                              NULL)) {
            if (type == REG_MULTI_SZ && wcsstr(hwids, L"BIOFAKESENSOR") != NULL) {
                printf("     (BioFake virtual sensor)\n");
            }
        }

        index++;
    }

    if (index == 0) {
        printf("(none)\n");
    }

    SetupDiDestroyDeviceInfoList(devInfo);
}

static
int
CmdStatus(VOID)
{
    PrintStatus();
    ListBiometricDevices();
    return 0;
}

static
int
CmdMode(const wchar_t* mode)
{
    HANDLE handle;
    DWORD value;

    if (mode == NULL) {
        printf("error: mode argument missing\n");
        return 1;
    }

    if (_wcsicmp(mode, L"ready") == 0) {
        value = BIOFAKE_MODE_READY;
    }
    else if (_wcsicmp(mode, L"reject") == 0) {
        value = BIOFAKE_MODE_REJECT;
    }
    else if (_wcsicmp(mode, L"failure") == 0) {
        value = BIOFAKE_MODE_FAILURE;
    }
    else if (_wcsicmp(mode, L"custom") == 0) {
        value = BIOFAKE_MODE_CUSTOM;
    }
    else {
        printf("error: unknown mode '%ls'\n", mode);
        return 1;
    }

    handle = OpenControlDevice();
    if (handle == INVALID_HANDLE_VALUE) {
        printf("control interface not found - driver not installed or device not started\n");
        return 1;
    }

    if (ControlSetMode(handle, value)) {
        printf("mode switched to %ls\n", mode);
    }
    else {
        printf("error: IOCTL_BIOFAKE_SET_MODE failed (gle=%lu)\n", GetLastError());
    }

    CloseHandle(handle);
    return 0;
}

static
int
CmdPayload(const wchar_t* path)
{
    HANDLE handle;
    int result;

    if (path == NULL) {
        printf("error: payload file argument missing\n");
        return 1;
    }

    handle = OpenControlDevice();
    if (handle == INVALID_HANDLE_VALUE) {
        printf("control interface not found - driver not installed or device not started\n");
        return 1;
    }

    result = ControlSetPayloadFile(handle, path) ? 0 : 1;

    CloseHandle(handle);
    return result;
}

static
BOOL
IsElevated(VOID)
{
    BOOL elevated = FALSE;
    TOKEN_ELEVATION elevation;
    DWORD size = 0;
    HANDLE token = NULL;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return FALSE;
    }

    if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size)) {
        elevated = elevation.TokenIsElevated != 0;
    }

    CloseHandle(token);

    return elevated;
}

static
int
CmdInstall(const wchar_t* infPath)
{
    GUID classGuid = GUID_DEVCLASS_BIOFAKE_BIOMETRIC_CLASS;
    HDEVINFO devInfo;
    SP_DEVINFO_DATA devData;
    wchar_t hwids[] = L"ROOT\0BIOFAKESENSOR\0";
    wchar_t cmd[1024];
    BOOL rebootRequired = FALSE;
    BOOL ok;

    if (!IsElevated()) {
        printf("error: 'install' requires an elevated (administrator) prompt\n");
        return 1;
    }

    if (infPath == NULL) {
        infPath = g_DefaultInfName;
    }

    //
    // Step 1: stage the driver package (INF + DLLs + CAT must be in the
    // same directory as the INF).
    //
    _snwprintf_s(cmd, _TRUNCATE, _TRUNCATE, L"pnputil.exe /add-driver \"%ls\" /install", infPath);
    _wsystem(cmd);

    //
    // Step 2: create the root-enumerated devnode (devcon-style).
    //
    devInfo = SetupDiCreateDeviceInfoList(&classGuid, NULL);
    if (devInfo == INVALID_HANDLE_VALUE) {
        printf("error: SetupDiCreateDeviceInfoList failed (gle=%lu)\n", GetLastError());
        return 1;
    }

    devData.cbSize = sizeof(devData);

    if (!SetupDiCreateDeviceInfoW(devInfo,
                                  L"BioFakeVirtualSensor",
                                  &classGuid,
                                  L"BioFake Virtual Fingerprint Sensor",
                                  NULL,
                                  DICD_GENERATE_ID,
                                  &devData)) {
        printf("error: SetupDiCreateDeviceInfo failed (gle=%lu)\n", GetLastError());
        SetupDiDestroyDeviceInfoList(devInfo);
        return 1;
    }

    if (!SetupDiSetDeviceRegistryPropertyW(devInfo,
                                           &devData,
                                           SPDRP_HARDWAREID,
                                           (PBYTE)hwids,
                                           (DWORD)sizeof(hwids))) {
        printf("error: SetupDiSetDeviceRegistryProperty(HARDWAREID) failed (gle=%lu)\n", GetLastError());
        SetupDiDestroyDeviceInfoList(devInfo);
        return 1;
    }

    if (!SetupDiCallClassInstaller(DIF_REGISTERDEVICE, devInfo, &devData)) {
        printf("error: DIF_REGISTERDEVICE failed (gle=%lu)\n", GetLastError());
        SetupDiDestroyDeviceInfoList(devInfo);
        return 1;
    }

    //
    // Step 3: bind the staged driver package to the new devnode.
    //
    ok = UpdateDriverForPlugAndPlayDevicesW(NULL,
                                            L"ROOT\\BIOFAKESENSOR",
                                            infPath,
                                            INSTALLFLAG_FORCE,
                                            &rebootRequired);

    SetupDiDestroyDeviceInfoList(devInfo);

    if (ok) {
        printf("driver installed OK%s\n", rebootRequired ? " (reboot recommended)" : "");
        printf("next: run 'biofakectl test' (as administrator) to verify WinBio recognition\n");
        return 0;
    }

    printf("error: UpdateDriverForPlugAndPlayDevices failed (gle=%lu)\n", GetLastError());
    printf("hints: make sure test signing is enabled (bcdedit /set testsigning on + reboot)\n");
    printf("       and that INF, DLLs and biofake.cat are in the same folder\n");
    return 1;
}

static
int
CmdUninstall(VOID)
{
    HDEVINFO        devInfo;
    SP_DEVINFO_DATA devData;
    wchar_t         hwids[512];
    DWORD           type;
    DWORD           size;
    DWORD           index;
    BOOL            removedAny = FALSE;

    if (!IsElevated()) {
        printf("error: 'uninstall' requires an elevated (administrator) prompt\n");
        return 1;
    }

    devInfo = SetupDiGetClassDevsW(&GUID_DEVCLASS_BIOFAKE_BIOMETRIC_CLASS,
                                   NULL,
                                   NULL,
                                   DIGCF_PRESENT);
    if (devInfo != INVALID_HANDLE_VALUE) {

        devData.cbSize = sizeof(devData);

        index = 0;
        while (SetupDiEnumDeviceInfo(devInfo, index, &devData)) {

            index++;

            size = sizeof(hwids);
            if (!SetupDiGetDeviceRegistryPropertyW(devInfo,
                                                   &devData,
                                                   SPDRP_HARDWAREID,
                                                   &type,
                                                   (PBYTE)hwids,
                                                   sizeof(hwids),
                                                   NULL)) {
                continue;
            }

            if (type == REG_MULTI_SZ && wcsstr(hwids, L"BIOFAKESENSOR") != NULL) {
                if (SetupDiCallClassInstaller(DIF_REMOVE, devInfo, &devData)) {
                    removedAny = TRUE;
                    printf("device removed\n");
                }
                else {
                    printf("warning: DIF_REMOVE failed (gle=%lu)\n", GetLastError());
                }
            }
        }

        SetupDiDestroyDeviceInfoList(devInfo);
    }

    //
    // Delete the staged driver package from the driver store.
    //
    if (SetupUninstallOEMInfW(g_DefaultInfName, SUOI_FORCEDELETE, NULL)) {
        printf("driver package '%ls' deleted from driver store\n", g_DefaultInfName);
    }
    else {
        printf("note: driver store package not deleted automatically (gle=%lu)\n", GetLastError());
        printf("      remove it manually with: pnputil /enum-drivers  then  pnputil /delete-driver oemXX.inf /uninstall\n");
    }

    if (!removedAny) {
        printf("no BioFake device was present\n");
    }

    printf("done - restart the Windows Biometric Service or reboot to fully clear state\n");
    return 0;
}

static
void
PrintWinBioUnit(const WINBIO_UNIT_SCHEMA* unit)
{
    wprintf(L"unit %lu: pool=%lu factor=0x%08lx subtype=0x%08lx caps=0x%08lx\n",
            unit->UnitId,
            unit->PoolType,
            unit->BiometricFactor,
            unit->SensorSubType,
            unit->Capabilities);
    wprintf(L"  device : %ls\n", unit->DeviceInstanceId);
    wprintf(L"  desc   : %ls\n", unit->Description);
    wprintf(L"  model  : %ls  mfr: %ls  sn: %ls\n",
            unit->Model, unit->Manufacturer, unit->SerialNumber);
}

static
int
CmdTest(VOID)
{
    WINBIO_UNIT_SCHEMA*     units = NULL;
    WINBIO_STORAGE_SCHEMA*  databases = NULL;
    WINBIO_SESSION_HANDLE   session = NULL;
    SIZE_T                  unitCount = 0;
    SIZE_T                  dbCount = 0;
    SIZE_T                  i;
    HRESULT                 hr;

    ListBiometricDevices();

    printf("\n-- WinBioEnumBiometricUnits --\n");

    hr = WinBioEnumBiometricUnits(WINBIO_TYPE_FINGERPRINT, &units, &unitCount);
    if (FAILED(hr)) {
        printf("WinBioEnumBiometricUnits failed: 0x%08lX\n", (unsigned long)hr);
    }
    else {
        printf("biometric units: %zu\n", unitCount);
        for (i = 0; i < unitCount; i++) {
            PrintWinBioUnit(&units[i]);
        }
        WinBioFree(units);
    }

    printf("\n-- WinBioEnumDatabases --\n");

    hr = WinBioEnumDatabases(WINBIO_TYPE_FINGERPRINT, &databases, &dbCount);
    if (FAILED(hr)) {
        printf("WinBioEnumDatabases failed: 0x%08lX\n", (unsigned long)hr);
    }
    else {
        printf("databases: %zu\n", dbCount);
        WinBioFree(databases);
    }

    if (unitCount == 0) {
        printf("\nno biometric unit - Windows does not see a usable sensor yet\n");
        return 1;
    }

    //
    // Raw capture (the real end-to-end proof that the fake sensor works).
    // Requires an elevated prompt.
    //
    printf("\n-- WinBioCaptureSample (RAW) --\n");

    hr = WinBioOpenSession(WINBIO_TYPE_FINGERPRINT,
                           WINBIO_POOL_SYSTEM,
                           WINBIO_FLAG_RAW,
                           NULL,
                           0,
                           &session);
    if (FAILED(hr)) {
        printf("WinBioOpenSession(RAW) failed: 0x%08lX (are you running as admin?)\n", (unsigned long)hr);
        return 1;
    }

    {
        WINBIO_UNIT_ID         unitId = 0;
        PWINBIO_BIR            sample = NULL;
        SIZE_T                 sampleSize = 0;
        WINBIO_REJECT_DETAIL   rejectDetail = 0;

        hr = WinBioCaptureSample(session,
                                 WINBIO_PURPOSE_AUDIT,
                                 WINBIO_DATA_FLAG_RAW,
                                 &unitId,
                                 &sample,
                                 &sampleSize,
                                 &rejectDetail);
        if (SUCCEEDED(hr) && sample != NULL) {
            printf("capture OK: unit %lu, %zu bytes, reject=0x%08lX\n",
                   unitId, sampleSize, rejectDetail);
            printf("  header block: size=%lu offset=%lu\n",
                   sample->HeaderBlock.Size, sample->HeaderBlock.Offset);
            printf("  standard data: size=%lu offset=%lu\n",
                   sample->StandardDataBlock.Size, sample->StandardDataBlock.Offset);
            WinBioFree(sample);
        }
        else {
            printf("WinBioCaptureSample failed: 0x%08lX reject=0x%08lX\n",
                   (unsigned long)hr, rejectDetail);
        }
    }

    WinBioCloseSession(session);

    printf("\nRESULT: Windows sees the BioFake virtual biometric sensor.\n");
    return 0;
}

static
void
PrintConsoleHelp(VOID)
{
    printf("\nkeys: [1] ready  [2] reject  [3] failure  [4] custom payload.bin  [s] status  [q] quit\n");
}

static
int
CmdConsole(VOID)
{
    HANDLE handle;
    int key;
    int running = 1;

    handle = OpenControlDevice();
    if (handle == INVALID_HANDLE_VALUE) {
        printf("control interface not found - driver not installed or device not started\n");
        return 1;
    }

    printf("BioFake console (control interface connected)\n");
    PrintConsoleHelp();

    while (running) {
        key = _getch();

        switch (key) {
        case '1':
            ControlSetMode(handle, BIOFAKE_MODE_READY);
            printf("> mode: ready\n");
            break;
        case '2':
            ControlSetMode(handle, BIOFAKE_MODE_REJECT);
            printf("> mode: reject\n");
            break;
        case '3':
            ControlSetMode(handle, BIOFAKE_MODE_FAILURE);
            printf("> mode: failure\n");
            break;
        case '4':
            ControlSetPayloadFile(handle, g_DefaultPayloadName);
            break;
        case 's':
        case 'S':
            PrintStatus();
            break;
        case 'q':
        case 'Q':
        case 27:
            running = 0;
            break;
        default:
            PrintConsoleHelp();
            break;
        }
    }

    CloseHandle(handle);
    return 0;
}

static
int
CmdHotkeys(VOID)
{
    HANDLE handle;
    MSG msg;
    int running = 1;

    handle = OpenControlDevice();
    if (handle == INVALID_HANDLE_VALUE) {
        printf("control interface not found - driver not installed or device not started\n");
        return 1;
    }

    RegisterHotKey(NULL, 1, MOD_CONTROL | MOD_ALT, '1');
    RegisterHotKey(NULL, 2, MOD_CONTROL | MOD_ALT, '2');
    RegisterHotKey(NULL, 3, MOD_CONTROL | MOD_ALT, '3');
    RegisterHotKey(NULL, 4, MOD_CONTROL | MOD_ALT, '4');
    RegisterHotKey(NULL, 5, MOD_CONTROL | MOD_ALT, '0');

    printf("BioFake global hotkeys active:\n");
    printf("  Ctrl+Alt+1 : mode ready\n");
    printf("  Ctrl+Alt+2 : mode reject\n");
    printf("  Ctrl+Alt+3 : mode failure\n");
    printf("  Ctrl+Alt+4 : load payload.bir (custom)\n");
    printf("  Ctrl+Alt+0 : quit\n");

    while (running && GetMessageW(&msg, NULL, 0, 0) > 0) {

        if (msg.message != WM_HOTKEY) {
            continue;
        }

        switch ((int)msg.wParam) {
        case 1:
            ControlSetMode(handle, BIOFAKE_MODE_READY);
            printf("[hotkey] mode: ready\n");
            break;
        case 2:
            ControlSetMode(handle, BIOFAKE_MODE_REJECT);
            printf("[hotkey] mode: reject\n");
            break;
        case 3:
            ControlSetMode(handle, BIOFAKE_MODE_FAILURE);
            printf("[hotkey] mode: failure\n");
            break;
        case 4:
            ControlSetPayloadFile(handle, g_DefaultPayloadName);
            break;
        case 5:
            running = 0;
            break;
        }
    }

    UnregisterHotKey(NULL, 1);
    UnregisterHotKey(NULL, 2);
    UnregisterHotKey(NULL, 3);
    UnregisterHotKey(NULL, 4);
    UnregisterHotKey(NULL, 5);
    CloseHandle(handle);

    return 0;
}

int
wmain(
    int argc,
    wchar_t** argv
    )
{
    if (argc < 2) {
        PrintUsage();
        return 0;
    }

    if (_wcsicmp(argv[1], L"status") == 0) {
        return CmdStatus();
    }
    else if (_wcsicmp(argv[1], L"mode") == 0) {
        return CmdMode(argc >= 3 ? argv[2] : NULL);
    }
    else if (_wcsicmp(argv[1], L"payload") == 0) {
        return CmdPayload(argc >= 3 ? argv[2] : NULL);
    }
    else if (_wcsicmp(argv[1], L"install") == 0) {
        return CmdInstall(argc >= 3 ? argv[2] : NULL);
    }
    else if (_wcsicmp(argv[1], L"uninstall") == 0) {
        return CmdUninstall();
    }
    else if (_wcsicmp(argv[1], L"test") == 0) {
        return CmdTest();
    }
    else if (_wcsicmp(argv[1], L"console") == 0) {
        return CmdConsole();
    }
    else if (_wcsicmp(argv[1], L"hotkeys") == 0) {
        return CmdHotkeys();
    }

    PrintUsage();
    return 0;
}
