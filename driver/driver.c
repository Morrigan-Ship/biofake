/*++
driver.c

BioFake virtual fingerprint sensor - driver entry point.

Environment: user mode (UMDF 2.x), inside WUDFHost.
--*/

#include <initguid.h>
#include "biofake.h"

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
/*++
DriverEntry initializes the driver and creates the framework driver object.
The shared DRIVER_CONTEXT is attached to the driver object so the sensor and
control device nodes (both instances of this driver) share one key store.
--*/
{
    WDF_DRIVER_CONFIG config;
    WDF_OBJECT_ATTRIBUTES driverAttributes;
    WDF_OBJECT_ATTRIBUTES lockAttributes;
    NTSTATUS status;
    DRIVER_CONTEXT* ctx;

    UNREFERENCED_PARAMETER(RegistryPath);

    WDF_DRIVER_CONFIG_INIT(&config, BioFakeEvtDeviceAdd);

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&driverAttributes, DRIVER_CONTEXT);

    status = WdfDriverCreate(DriverObject,
                             RegistryPath,
                             &driverAttributes,
                             &config,
                             WDF_NO_HANDLE);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    ctx = BioFakeGetDriverContext(WdfGetDriver());

    WDF_OBJECT_ATTRIBUTES_INIT(&lockAttributes);
    lockAttributes.ParentObject = WdfGetDriver();

    status = WdfWaitLockCreate(&lockAttributes, &ctx->Lock);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    ctx->KeyCount = 0;
    ctx->ActiveIndex = -1;
    ctx->Mode = BIOFAKE_MODE_READY;
    ctx->HasCustom = FALSE;
    ctx->CustomBirSize = 0;
    ctx->CaptureQueue = NULL;
    ctx->CaptureCount = 0;

    return STATUS_SUCCESS;
}

VOID
BioFakeStringCopy(
    _Out_writes_(cchDst) WCHAR* dst,
    _In_ SIZE_T cchDst,
    _In_opt_ PCWSTR src
    )
{
    SIZE_T i = 0;

    if (cchDst == 0) {
        return;
    }

    if (src != NULL) {
        while (i + 1 < cchDst && src[i] != L'\0') {
            dst[i] = src[i];
            i++;
        }
    }

    dst[i] = L'\0';

    // Zero-fill the remainder so buffers are stable in memory.
    for (i = i + 1; i < cchDst; i++) {
        dst[i] = L'\0';
    }
}
