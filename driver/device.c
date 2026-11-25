/*++
device.c

BioFake virtual fingerprint sensor - device creation and role dispatch.

The driver DLL powers two software device nodes (see shared/biofake_shared.h):
  SWD\BioFake    - WBDI sensor node, opened exclusively by the Windows
                   Biometric Service (via the built-in WinBioSensorAdapter).
  SWD\BioFakeCtl - control node opened by biofakectl.exe (key management).

Both nodes are handled by the same EvtDeviceAdd; the role is decided from the
MatchingDeviceId value in the device hardware key.
--*/

#include "biofake.h"

static
BOOLEAN
BioFakeContainsI(
    _In_ PCWSTR Haystack,
    _In_ PCWSTR Needle
    )
{
    SIZE_T i, j;

    if (Haystack == NULL || Needle == NULL) {
        return FALSE;
    }

    for (i = 0; Haystack[i] != L'\0'; i++) {
        for (j = 0; ; j++) {
            WCHAR h = Haystack[i + j];
            WCHAR n = Needle[j];

            if (h >= L'A' && h <= L'Z') {
                h = (WCHAR)(h - L'A' + L'a');
            }
            if (n >= L'A' && n <= L'Z') {
                n = (WCHAR)(n - L'A' + L'a');
            }

            if (n == L'\0') {
                return TRUE;
            }
            if (h != n || h == L'\0') {
                break;
            }
        }
    }

    return FALSE;
}

static
NTSTATUS
BioFakeReadMatchingDeviceId(
    _In_ WDFDEVICE Device,
    _Out_writes_(Cch) WCHAR* Buffer,
    _In_ ULONG Cch
    )
/*++
Reads MatchingDeviceId from the device hardware key so we can tell the
sensor node from the control node.
--*/
{
    WDFKEY key = NULL;
    WDFSTRING string = NULL;
    UNICODE_STRING valueName;
    UNICODE_STRING str;
    NTSTATUS status;
    ULONG i;

    Buffer[0] = L'\0';

    status = WdfDeviceOpenRegistryKey(Device,
                                      PLUGPLAY_REGKEY_DEVICE,
                                      KEY_READ,
                                      WDF_NO_OBJECT_ATTRIBUTES,
                                      &key);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = WdfStringCreate(NULL, WDF_NO_OBJECT_ATTRIBUTES, &string);
    if (!NT_SUCCESS(status)) {
        WdfRegistryClose(key);
        return status;
    }

    RtlInitUnicodeString(&valueName, L"MatchingDeviceId");

    status = WdfRegistryQueryString(key, &valueName, string);
    if (NT_SUCCESS(status)) {
        WdfStringGetUnicodeString(string, &str);
        for (i = 0; i + 1 < Cch && i < str.Length / sizeof(WCHAR); i++) {
            Buffer[i] = str.Buffer[i];
        }
        Buffer[i] = L'\0';
    }

    WdfObjectDelete(string);
    WdfRegistryClose(key);

    return status;
}

NTSTATUS
BioFakeEvtDeviceAdd(
    _In_ WDFDRIVER Driver,
    _Inout_ PWDFDEVICE_INIT DeviceInit
    )
{
    WDF_OBJECT_ATTRIBUTES deviceAttributes;
    WDF_IO_QUEUE_CONFIG defaultQueueConfig;
    WDF_IO_QUEUE_CONFIG captureQueueConfig;
    WDF_DEVICE_PNP_CAPABILITIES pnpCaps;
    WDFQUEUE queue;
    WDFDEVICE device;
    PDEVICE_CONTEXT devCtx;
    PDRIVER_CONTEXT ctx;
    WCHAR deviceId[256];
    BOOLEAN isControl = FALSE;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Driver);

    WdfDeviceInitSetIoType(DeviceInit, WdfDeviceIoBuffered);

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttributes, DEVICE_CONTEXT);

    status = WdfDeviceCreate(&DeviceInit, &deviceAttributes, &device);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (NT_SUCCESS(BioFakeReadMatchingDeviceId(device, deviceId, 256)) &&
        BioFakeContainsI(deviceId, L"biofakectl")) {
        isControl = TRUE;
    }

    devCtx = BioFakeGetDeviceContext(device);
    devCtx->IsSensor = !isControl;

    ctx = BioFakeGetDriverContext(WdfGetDriver());

    //
    // The device is a pure software node: it can disappear at any time.
    //
    WDF_DEVICE_PNP_CAPABILITIES_INIT(&pnpCaps);
    pnpCaps.SurpriseRemovalOK = WdfTrue;
    WdfDeviceSetPnpCapabilities(device, &pnpCaps);

    //
    // Default parallel queue: receives all device-control requests
    // (WBDI IOCTLs on the sensor node, control IOCTLs on the control node).
    //
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&defaultQueueConfig,
                                           WdfIoQueueDispatchParallel);
    defaultQueueConfig.EvtIoDeviceControl = BioFakeEvtIoDeviceControl;

    status = WdfIoQueueCreate(device,
                              &defaultQueueConfig,
                              WDF_NO_OBJECT_ATTRIBUTES,
                              WDF_NO_HANDLE);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (devCtx->IsSensor) {
        //
        // Manual, non-power-managed queue where capture requests park
        // while no key is available. biofakectl present/select completes
        // them from the control node.
        //
        WDF_IO_QUEUE_CONFIG_INIT(&captureQueueConfig, WdfIoQueueDispatchManual);
        captureQueueConfig.PowerManaged = WdfFalse;

        status = WdfIoQueueCreate(device,
                                  &captureQueueConfig,
                                  WDF_NO_OBJECT_ATTRIBUTES,
                                  &queue);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        WdfWaitLockAcquire(ctx->Lock, NULL);
        ctx->CaptureQueue = queue;
        WdfWaitLockRelease(ctx->Lock);

        status = WdfDeviceCreateDeviceInterface(device,
                                                (LPGUID)&GUID_DEVINTERFACE_BIOMETRIC_READER,
                                                NULL);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = WdfDeviceSetDeviceInterfaceState(device,
                                                  (LPGUID)&GUID_DEVINTERFACE_BIOMETRIC_READER,
                                                  NULL,
                                                  TRUE);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    } else {
        //
        // Control node: publish the private control interface for
        // biofakectl.exe.
        //
        status = WdfDeviceCreateDeviceInterface(device,
                                                (LPGUID)&BIOFAKE_CONTROL_INTERFACE_GUID,
                                                NULL);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = WdfDeviceSetDeviceInterfaceState(device,
                                                  (LPGUID)&BIOFAKE_CONTROL_INTERFACE_GUID,
                                                  NULL,
                                                  TRUE);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    return status;
}

VOID
BioFakeEvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode
    )
{
    WDFDEVICE device = WdfIoQueueGetDevice(Queue);
    PDEVICE_CONTEXT devCtx = BioFakeGetDeviceContext(device);
    PDRIVER_CONTEXT ctx = BioFakeGetDriverContext(WdfGetDriver());

    if (devCtx->IsSensor) {
        BioFakeHandleWbdiRequest(ctx,
                                 Request,
                                 IoControlCode,
                                 OutputBufferLength,
                                 InputBufferLength);
    } else {
        BioFakeHandleControlRequest(ctx,
                                    Request,
                                    IoControlCode,
                                    OutputBufferLength,
                                    InputBufferLength);
    }
}
