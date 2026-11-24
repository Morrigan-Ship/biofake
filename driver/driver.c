/*++

THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
ANY KIND, EITHER EXPRESSED OR IMPLIED.

BioFake - Virtual WBDI fingerprint sensor driver (KMDF)

Abstract:
    Implements the Windows Biometric Driver Interface (WBDI) for a purely
    virtual (root-enumerated) fingerprint sensor. The Windows Biometric
    Service discovers the device through GUID_DEVINTERFACE_BIOMETRIC_READER
    and serves synthetic (or user supplied) ANSI-381 fingerprint captures.

    A second vendor device interface (GUID_BIOFAKE_CONTROL) allows the
    biofakectl.exe tool to manage keys, switch modes and inject payloads.

Environment:
    Kernel mode, KMDF 1.15+

--*/

#define INITGUID

#include <ntddk.h>
#include <wdf.h>
#include <ntstrsafe.h>
#include <winbio_ioctl.h>
#include <winbio_err.h>
#include "biofake_ioctl.h"

#define BIOFAKE_POOL_TAG 'kFaB'
#define BIOFAKE_PARAMS_PATH L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\BioFake\\Parameters"

#define BIOFAKE_IMG_WIDTH   128
#define BIOFAKE_IMG_HEIGHT  144
#define BIOFAKE_IMG_SIZE    (BIOFAKE_IMG_WIDTH * BIOFAKE_IMG_HEIGHT)

typedef struct _DEVICE_CONTEXT {
    WDFSPINLOCK Lock;
    BIOFAKE_KEY_ENTRY Keys[BIOFAKE_MAX_KEYS];
    ULONG           Mode;
    ULONG           ActiveKey;          // index or BIOFAKE_NO_KEY
    WDFREQUEST      PendingCapture;     // pending IOCTL_BIOMETRIC_CAPTURE_DATA or NULL
    WDFMEMORY       CustomPayload;      // optional custom BIR blob
    ULONG           CapturesRequested;
    ULONG           CapturesServed;
    ULONG           CapturesRejected;
    ULONG           CapturesFailed;
} DEVICE_CONTEXT, *PDEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DEVICE_CONTEXT, BioFakeGetContext)

EVT_WDF_DRIVER_DEVICE_ADD          BioFakeEvtDeviceAdd;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL BioFakeEvtIoDeviceControl;
EVT_WDF_REQUEST_CANCEL             BioFakeEvtRequestCancel;

static ULONG BioFakeBirSize(VOID)
{
    return (ULONG)(sizeof(WINBIO_BIR) +
                   sizeof(WINBIO_BIR_HEADER) +
                   sizeof(WINBIO_BDB_ANSI_381_HEADER) +
                   sizeof(WINBIO_BDB_ANSI_381_RECORD) +
                   BIOFAKE_IMG_SIZE);
}

//
// Deterministic ANSI-381 BIR builder. The image pattern is fully derived
// from the key secret so the same key always produces identical data
// (required for template hash matching).
//
static VOID BioFakeBuildBir(
    _Out_writes_bytes_(BioFakeBirSize()) PUCHAR Base,
    _In_ UCHAR Purpose,
    _In_ UCHAR Flags,
    _In_reads_(BIOFAKE_SECRET_LEN) PCUCHAR Secret
    )
{
    ULONG imgLen = BIOFAKE_IMG_SIZE;
    PWINBIO_BIR bir = (PWINBIO_BIR)Base;
    PWINBIO_BIR_HEADER header;
    PWINBIO_BDB_ANSI_381_HEADER ah;
    PWINBIO_BDB_ANSI_381_RECORD rec;
    PUCHAR image;
    ULONG x, y, state = 0x9E3779B9;
    ULONG i;

    RtlZeroMemory(Base, BioFakeBirSize());

    for (i = 0; i < BIOFAKE_SECRET_LEN; i++) {
        state = (state ^ Secret[i]) * 16777619u + 1u;
    }

    bir->HeaderBlock.Size = (ULONG)sizeof(WINBIO_BIR_HEADER);
    bir->HeaderBlock.Offset = (ULONG)sizeof(WINBIO_BIR);
    bir->StandardDataBlock.Size = (ULONG)(sizeof(WINBIO_BDB_ANSI_381_HEADER) +
                                          sizeof(WINBIO_BDB_ANSI_381_RECORD) +
                                          imgLen);
    bir->StandardDataBlock.Offset = (ULONG)(sizeof(WINBIO_BIR) + sizeof(WINBIO_BIR_HEADER));

    header = (PWINBIO_BIR_HEADER)(Base + bir->HeaderBlock.Offset);
    header->ValidFields = (USHORT)(WINBIO_BIR_FIELD_CBEFF_HEADER_VERSION |
                                   WINBIO_BIR_FIELD_PATRON_HEADER_VERSION |
                                   WINBIO_BIR_FIELD_BIOMETRIC_TYPE |
                                   WINBIO_BIR_FIELD_BIOMETRIC_SUBTYPE |
                                   WINBIO_BIR_FIELD_BIOMETRIC_PURPOSE |
                                   WINBIO_BIR_FIELD_QUALITY |
                                   WINBIO_BIR_FIELD_CREATION_DATE);
    header->HeaderVersion = WINBIO_CBEFF_HEADER_VERSION;
    header->PatronHeaderVersion = WINBIO_PATRON_HEADER_VERSION;
    header->DataFlags = Flags;
    header->Type = WINBIO_TYPE_FINGERPRINT;
    header->Subtype = WINBIO_ANSI_381_POS_RH_INDEX_FINGER;
    header->Purpose = Purpose;
    header->DataQuality = 90;
    header->CreationDate.QuadPart = 0;              // deterministic on purpose
    header->BiometricDataFormat.Owner = WINBIO_ANSI_381_FORMAT_OWNER;
    header->BiometricDataFormat.Type = WINBIO_ANSI_381_FORMAT_TYPE;

    ah = (PWINBIO_BDB_ANSI_381_HEADER)(Base + bir->StandardDataBlock.Offset);
    ah->RecordLength = (ULONG64)(sizeof(WINBIO_BDB_ANSI_381_HEADER) +
                                 sizeof(WINBIO_BDB_ANSI_381_RECORD) + imgLen);
    ah->FormatIdentifier = 0x46495200;              // 'FIR\0'
    ah->VersionNumber = 0x30313000;                 // '010\0'
    ah->CaptureDeviceId = 1;
    ah->ImageAcquisitionLevel = 20;
    ah->HorizontalScanResolution = 500;
    ah->VerticalScanResolution = 500;
    ah->HorizontalImageResolution = 500;
    ah->VerticalImageResolution = 500;
    ah->ElementCount = 1;
    ah->ScaleUnits = WINBIO_ANSI_381_PIXELS_PER_INCH;
    ah->PixelDepth = 8;
    ah->ImageCompressionAlg = WINBIO_ANSI_381_IMG_UNCOMPRESSED;

    rec = (PWINBIO_BDB_ANSI_381_RECORD)((PUCHAR)ah + sizeof(WINBIO_BDB_ANSI_381_HEADER));
    rec->BlockLength = (ULONG)(sizeof(WINBIO_BDB_ANSI_381_RECORD) + imgLen);
    rec->HorizontalLineLength = BIOFAKE_IMG_WIDTH;
    rec->VerticalLineLength = BIOFAKE_IMG_HEIGHT;
    rec->Position = WINBIO_ANSI_381_POS_RH_INDEX_FINGER;
    rec->CountOfViews = 1;
    rec->ViewNumber = 1;
    rec->ImageQuality = 0xFE;
    rec->ImpressionType = WINBIO_ANSI_381_IMP_TYPE_LIVE_SCAN_PLAIN;

    image = (PUCHAR)rec + sizeof(WINBIO_BDB_ANSI_381_RECORD);

    for (y = 0; y < BIOFAKE_IMG_HEIGHT; y++) {
        for (x = 0; x < BIOFAKE_IMG_WIDTH; x++) {
            LONG dx = (LONG)x - (BIOFAKE_IMG_WIDTH / 2);
            LONG dy = (LONG)((LONG)y - (LONG)(BIOFAKE_IMG_HEIGHT / 2)) * 3 / 2;
            LONG d2 = dx * dx + dy * dy;
            ULONG band = ((d2 / 29) & 1) ? 70 : 190;
            ULONG v;

            state = state * 1664525u + 1013904223u;
            band = (band + ((state >> 24) & 0x1F)) & 0xFF;

            {
                ULONG ex = min(x, BIOFAKE_IMG_WIDTH - 1 - x);
                ULONG ey = min(y, BIOFAKE_IMG_HEIGHT - 1 - y);
                ULONG edge = min(ex, ey);
                ULONG fade = edge < 12 ? edge : 12;   // 0..12
                v = 255 - (((255 - band) * (fade * 21 + 13)) / 265);
            }

            if (d2 > 88 * 60) {
                v = 255;                                // outside the finger area
            }

            image[y * BIOFAKE_IMG_WIDTH + x] = (UCHAR)v;
        }
    }
}

//
// Registry persistence (service Parameters key)
//
static NTSTATUS BioFakeOpenParamsKey(_In_ ACCESS_MASK Access, _Out_ PHANDLE Handle)
{
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING path;

    RtlInitUnicodeString(&path, BIOFAKE_PARAMS_PATH);
    InitializeObjectAttributes(&oa, &path, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    return ZwCreateKey(Handle, Access, &oa, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
}

static VOID BioFakeSaveSettings(_In_ PDEVICE_CONTEXT Ctx)
{
    HANDLE h = NULL;
    WCHAR nameBuf[16];
    UNICODE_STRING valueName;
    ULONG i;

    if (!NT_SUCCESS(BioFakeOpenParamsKey(KEY_WRITE, &h))) {
        return;
    }

    RtlInitUnicodeString(&valueName, L"Mode");
    ZwSetValueKey(h, &valueName, 0, REG_DWORD, &Ctx->Mode, sizeof(ULONG));
    RtlInitUnicodeString(&valueName, L"ActiveKey");
    ZwSetValueKey(h, &valueName, 0, REG_DWORD, &Ctx->ActiveKey, sizeof(ULONG));

    for (i = 0; i < BIOFAKE_MAX_KEYS; i++) {
        RtlUnicodeStringPrintf(&valueName, nameBuf, sizeof(nameBuf), L"Key%lu", i);
        if (Ctx->Keys[i].Slot != 0 || Ctx->Keys[i].Name[0] != 0) {
            ZwSetValueKey(h, &valueName, 0, REG_BINARY, &Ctx->Keys[i], sizeof(BIOFAKE_KEY_ENTRY));
        } else {
            ZwDeleteValueKey(h, &valueName);
        }
    }

    ZwClose(h);
}

static VOID BioFakeLoadSettings(_In_ PDEVICE_CONTEXT Ctx)
{
    HANDLE h = NULL;
    WCHAR nameBuf[16];
    UNICODE_STRING valueName;
    UCHAR info[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(BIOFAKE_KEY_ENTRY) + 8];
    ULONG i, result;

    RtlZeroMemory(Ctx->Keys, sizeof(Ctx->Keys));

    if (!NT_SUCCESS(BioFakeOpenParamsKey(KEY_READ, &h))) {
        return;
    }

    RtlInitUnicodeString(&valueName, L"Mode");
    if (NT_SUCCESS(ZwQueryValueKey(h, &valueName, KeyValuePartialInformation,
                                   info, sizeof(info), &result)) &&
        ((PKEY_VALUE_PARTIAL_INFORMATION)info)->Type == REG_DWORD) {
        Ctx->Mode = *(ULONG UNALIGNED *)((PKEY_VALUE_PARTIAL_INFORMATION)info)->Data;
    }

    RtlInitUnicodeString(&valueName, L"ActiveKey");
    if (NT_SUCCESS(ZwQueryValueKey(h, &valueName, KeyValuePartialInformation,
                                   info, sizeof(info), &result)) &&
        ((PKEY_VALUE_PARTIAL_INFORMATION)info)->Type == REG_DWORD) {
        Ctx->ActiveKey = *(ULONG UNALIGNED *)((PKEY_VALUE_PARTIAL_INFORMATION)info)->Data;
    }

    for (i = 0; i < BIOFAKE_MAX_KEYS; i++) {
        RtlUnicodeStringPrintf(&valueName, nameBuf, sizeof(nameBuf), L"Key%lu", i);
        if (NT_SUCCESS(ZwQueryValueKey(h, &valueName, KeyValuePartialInformation,
                                       info, sizeof(info), &result)) &&
            ((PKEY_VALUE_PARTIAL_INFORMATION)info)->Type == REG_BINARY &&
            ((PKEY_VALUE_PARTIAL_INFORMATION)info)->DataLength >= sizeof(BIOFAKE_KEY_ENTRY)) {
            RtlCopyMemory(&Ctx->Keys[i],
                          ((PKEY_VALUE_PARTIAL_INFORMATION)info)->Data,
                          sizeof(BIOFAKE_KEY_ENTRY));
            Ctx->Keys[i].Slot = i;
        }
    }

    ZwClose(h);
}

static NTSTATUS BioFakeFindKey(_In_ PDEVICE_CONTEXT Ctx, _In_ PCWSTR Name, _Out_ ULONG *Index)
{
    ULONG i;

    for (i = 0; i < BIOFAKE_MAX_KEYS; i++) {
        if (Ctx->Keys[i].Name[0] != 0 && wcscmp(Ctx->Keys[i].Name, Name) == 0) {
            *Index = i;
            return STATUS_SUCCESS;
        }
    }
    return STATUS_NOT_FOUND;
}

//
// Complete the pending WBDI capture request (if any).
// CallerData: NULL = cancel-style completion (Status only).
//
static VOID BioFakeCompletePendingCapture(
    _In_ PDEVICE_CONTEXT Ctx,
    _In_ NTSTATUS Status,
    _In_opt_ PCUCHAR BirData,
    _In_ ULONG BirSize
    )
{
    WDFREQUEST request = NULL;
    NTSTATUS unmark;

    WdfSpinLockAcquire(Ctx->Lock);
    if (Ctx->PendingCapture != NULL) {
        request = Ctx->PendingCapture;
        Ctx->PendingCapture = NULL;
    }
    WdfSpinLockRelease(Ctx->Lock);

    if (request == NULL) {
        return;
    }

    unmark = WdfRequestUnmarkCancelable(request);
    if (unmark == STATUS_CANCELLED) {
        return;
    }

    if (BirData != NULL) {
        PVOID out = NULL;
        SIZE_T outLen = 0;
        ULONG required = (ULONG)(FIELD_OFFSET(WINBIO_CAPTURE_DATA, CaptureData.Data) + BirSize);

        if (NT_SUCCESS(WdfRequestRetrieveOutputBuffer(request, sizeof(DWORD), &out, &outLen))) {
            if (outLen >= required) {
                PWINBIO_CAPTURE_DATA cap = (PWINBIO_CAPTURE_DATA)out;
                RtlZeroMemory(cap, required);
                cap->PayloadSize = required;
                cap->WinBioHresult = S_OK;
                cap->SensorStatus = WINBIO_SENSOR_ACCEPT;
                cap->RejectDetail = 0;
                cap->CaptureData.Size = BirSize;
                RtlCopyMemory(cap->CaptureData.Data, BirData, BirSize);
                WdfRequestCompleteWithInformation(request, STATUS_SUCCESS, required);
                return;
            }
            // buffer too small: report the required size (size-query protocol)
            ((PDWORD)out)[0] = required;
            WdfRequestCompleteWithInformation(request, STATUS_SUCCESS, sizeof(DWORD));
            return;
        }
        WdfRequestComplete(request, STATUS_INVALID_PARAMETER);
        return;
    }

    WdfRequestComplete(request, Status);
}

VOID
BioFakeEvtRequestCancel(
    _In_ WDFREQUEST Request
    )
{
    PDEVICE_CONTEXT ctx = BioFakeGetContext(WdfIoQueueGetDevice(WdfRequestGetIoQueue(Request)));

    WdfSpinLockAcquire(ctx->Lock);
    if (ctx->PendingCapture == Request) {
        ctx->PendingCapture = NULL;
    }
    WdfSpinLockRelease(ctx->Lock);

    WdfRequestComplete(Request, STATUS_CANCELLED);
}

NTSTATUS
BioFakeEvtDeviceAdd(
    _In_ WDFDRIVER Driver,
    _Inout_ PWDFDEVICE_INIT DeviceInit
    )
{
    NTSTATUS status;
    WDF_OBJECT_ATTRIBUTES devAttrs, lockAttrs;
    WDF_IO_QUEUE_CONFIG queueConfig;
    WDFDEVICE device;
    PDEVICE_CONTEXT ctx;

    UNREFERENCED_PARAMETER(Driver);

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&devAttrs, DEVICE_CONTEXT);

    status = WdfDeviceCreate(&DeviceInit, &devAttrs, &device);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    ctx = BioFakeGetContext(device);
    RtlZeroMemory(ctx, sizeof(DEVICE_CONTEXT));
    ctx->Device = device;
    ctx->Mode = BIOFAKE_MODE_READY;
    ctx->ActiveKey = BIOFAKE_NO_KEY;

    WDF_OBJECT_ATTRIBUTES_INIT(&lockAttrs);
    lockAttrs.ParentObject = device;
    status = WdfSpinLockCreate(&lockAttrs, &ctx->Lock);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = WdfDeviceCreateDeviceInterface(device, &GUID_DEVINTERFACE_BIOMETRIC_READER, NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = WdfDeviceCreateDeviceInterface(device, &GUID_BIOFAKE_CONTROL, NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchParallel);
    queueConfig.EvtIoDeviceControl = BioFakeEvtIoDeviceControl;

    status = WdfIoQueueCreate(device, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, WDF_NO_HANDLE);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    BioFakeLoadSettings(ctx);

    return STATUS_SUCCESS;
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    WDF_DRIVER_CONFIG config;

    WDF_DRIVER_CONFIG_INIT(&config, BioFakeEvtDeviceAdd);
    return WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, WDF_NO_HANDLE);
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
    PDEVICE_CONTEXT ctx = BioFakeGetContext(WdfIoQueueGetDevice(Queue));
    NTSTATUS status = STATUS_SUCCESS;
    PVOID outBuf = NULL, inBuf = NULL;
    SIZE_T outLen = 0, inLen = 0;
    ULONG mode, active, customSize = 0, i;
    BOOLEAN pending, hasActive, hasCustom;
    UCHAR secret[BIOFAKE_SECRET_LEN];
    PUCHAR customData = NULL;

    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);

    WdfSpinLockAcquire(ctx->Lock);
    mode = ctx->Mode;
    active = ctx->ActiveKey;
    pending = (ctx->PendingCapture != NULL);
    hasActive = (active < BIOFAKE_MAX_KEYS) && (ctx->Keys[active].Name[0] != 0);
    if (hasActive) {
        RtlCopyMemory(secret, ctx->Keys[active].Secret, BIOFAKE_SECRET_LEN);
    }
    hasCustom = (ctx->CustomPayload != NULL);
    if (hasCustom) {
        WdfMemoryGetBuffer(ctx->CustomPayload, &outLen);
        customSize = (ULONG)outLen;
    }
    ctx->CapturesRequested++;
    WdfSpinLockRelease(ctx->Lock);

    switch (IoControlCode) {

    case IOCTL_BIOMETRIC_GET_ATTRIBUTES:
    {
        WINBIO_SENSOR_ATTRIBUTES attr;
        DWORD payloadSize = (DWORD)sizeof(WINBIO_SENSOR_ATTRIBUTES);

        status = WdfRequestRetrieveOutputBuffer(Request, sizeof(DWORD), &outBuf, &outLen);
        if (!NT_SUCCESS(status)) break;

        if (outLen < payloadSize) {
            ((PDWORD)outBuf)[0] = payloadSize;
            WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(DWORD));
            return;
        }

        RtlZeroMemory(&attr, sizeof(attr));
        attr.PayloadSize = payloadSize;
        attr.WinBioHresult = S_OK;
        attr.WinBioVersion.MajorVersion = WINBIO_WBDI_MAJOR_VERSION;
        attr.WinBioVersion.MinorVersion = WINBIO_WBDI_MINOR_VERSION;
        attr.SensorType = WINBIO_TYPE_FINGERPRINT;
        attr.SensorSubType = WINBIO_FP_SENSOR_SUBTYPE_TOUCH;
        attr.Capabilities = WINBIO_CAPABILITY_SENSOR;
        wcscpy_s(attr.ManufacturerName, WINBIO_MAX_STRING_LEN, L"BioFake Project");
        wcscpy_s(attr.ModelName, WINBIO_MAX_STRING_LEN, L"BioFake Virtual Sensor");
        wcscpy_s(attr.SerialNumber, WINBIO_MAX_STRING_LEN, L"BF-VS-0000001");
        attr.FirmwareVersion.MajorVersion = 1;
        attr.FirmwareVersion.MinorVersion = 0;
        attr.SupportedFormatEntries = 1;
        attr.SupportedFormat[0].Owner = WINBIO_ANSI_381_FORMAT_OWNER;
        attr.SupportedFormat[0].Type = WINBIO_ANSI_381_FORMAT_TYPE;

        RtlCopyMemory(outBuf, &attr, payloadSize);
        WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, payloadSize);
        return;
    }

    case IOCTL_BIOMETRIC_GET_SENSOR_STATUS:
    {
        WINBIO_DIAGNOSTICS diag;
        DWORD payloadSize = (DWORD)FIELD_OFFSET(WINBIO_DIAGNOSTICS, VendorDiagnostics.Data);

        status = WdfRequestRetrieveOutputBuffer(Request, sizeof(DWORD), &outBuf, &outLen);
        if (!NT_SUCCESS(status)) break;

        if (outLen < payloadSize) {
            ((PDWORD)outBuf)[0] = payloadSize;
            WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(DWORD));
            return;
        }

        RtlZeroMemory(&diag, sizeof(diag));
        diag.PayloadSize = payloadSize;
        diag.WinBioHresult = S_OK;
        diag.SensorStatus = (mode == BIOFAKE_MODE_FAILURE) ? WINBIO_SENSOR_FAILURE : WINBIO_SENSOR_READY;
        diag.VendorDiagnostics.Size = 0;
        RtlCopyMemory(outBuf, &diag, payloadSize);
        WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, payloadSize);
        return;
    }

    case IOCTL_BIOMETRIC_CALIBRATE:
    {
        WINBIO_CALIBRATION_INFO cal;
        DWORD payloadSize = (DWORD)FIELD_OFFSET(WINBIO_CALIBRATION_INFO, CalibrationData.Data);

        status = WdfRequestRetrieveOutputBuffer(Request, sizeof(DWORD), &outBuf, &outLen);
        if (!NT_SUCCESS(status)) break;

        if (outLen < payloadSize) {
            ((PDWORD)outBuf)[0] = payloadSize;
            WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(DWORD));
            return;
        }
        RtlZeroMemory(&cal, sizeof(cal));
        cal.PayloadSize = payloadSize;
        cal.WinBioHresult = S_OK;
        cal.CalibrationData.Size = 0;
        RtlCopyMemory(outBuf, &cal, payloadSize);
        WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, payloadSize);
        return;
    }

    case IOCTL_BIOMETRIC_RESET:
    {
        WINBIO_BLANK_PAYLOAD blank;

        BioFakeCompletePendingCapture(ctx, WINBIO_E_CANCELED, NULL, 0);

        status = WdfRequestRetrieveOutputBuffer(Request, sizeof(WINBIO_BLANK_PAYLOAD), &outBuf, &outLen);
        if (!NT_SUCCESS(status)) break;

        blank.PayloadSize = (DWORD)sizeof(WINBIO_BLANK_PAYLOAD);
        blank.WinBioHresult = S_OK;
        RtlCopyMemory(outBuf, &blank, sizeof(blank));
        WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(blank));
        return;
    }

    case IOCTL_BIOMETRIC_SET_INDICATOR:
    {
        WINBIO_GET_INDICATOR ind;

        status = WdfRequestRetrieveInputBuffer(Request, sizeof(WINBIO_SET_INDICATOR), &inBuf, &inLen);
        if (!NT_SUCCESS(status)) break;

        status = WdfRequestRetrieveOutputBuffer(Request, sizeof(WINBIO_GET_INDICATOR), &outBuf, &outLen);
        if (!NT_SUCCESS(status)) break;

        ind.PayloadSize = (DWORD)sizeof(WINBIO_GET_INDICATOR);
        ind.WinBioHresult = S_OK;
        ind.IndicatorStatus = ((PWINBIO_SET_INDICATOR)inBuf)->IndicatorStatus;
        RtlCopyMemory(outBuf, &ind, sizeof(ind));
        WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(ind));
        return;
    }

    case IOCTL_BIOMETRIC_GET_INDICATOR:
    {
        WINBIO_GET_INDICATOR ind;

        status = WdfRequestRetrieveOutputBuffer(Request, sizeof(WINBIO_GET_INDICATOR), &outBuf, &outLen);
        if (!NT_SUCCESS(status)) break;

        ind.PayloadSize = (DWORD)sizeof(WINBIO_GET_INDICATOR);
        ind.WinBioHresult = S_OK;
        ind.IndicatorStatus = WINBIO_INDICATOR_OFF;
        RtlCopyMemory(outBuf, &ind, sizeof(ind));
        WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(ind));
        return;
    }

    case IOCTL_BIOMETRIC_UPDATE_FIRMWARE:
    case IOCTL_BIOMETRIC_GET_SUPPORTED_ALGORITHMS:
        status = STATUS_NOT_SUPPORTED;
        break;

    case IOCTL_BIOMETRIC_CAPTURE_DATA:
    {
        WINBIO_CAPTURE_PARAMETERS params;
        ULONG birSize, required;

        RtlZeroMemory(&params, sizeof(params));
        if (NT_SUCCESS(WdfRequestRetrieveInputBuffer(Request, 0, &inBuf, &inLen)) &&
            inLen >= sizeof(WINBIO_CAPTURE_PARAMETERS)) {
            RtlCopyMemory(&params, inBuf, sizeof(params));
        }

        status = WdfRequestRetrieveOutputBuffer(Request, sizeof(DWORD), &outBuf, &outLen);
        if (!NT_SUCCESS(status)) break;

        if (pending) {
            WdfRequestComplete(Request, (NTSTATUS)WINBIO_E_DATA_COLLECTION_IN_PROGRESS);
            return;
        }

        birSize = (mode == BIOFAKE_MODE_CUSTOM && hasCustom) ? customSize : BioFakeBirSize();
        required = (ULONG)(FIELD_OFFSET(WINBIO_CAPTURE_DATA, CaptureData.Data) + birSize);

        if (outLen < required) {
            ((PDWORD)outBuf)[0] = required;
            WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(DWORD));
            return;
        }

        if (mode == BIOFAKE_MODE_REJECT) {
            PWINBIO_CAPTURE_DATA cap = (PWINBIO_CAPTURE_DATA)outBuf;
            RtlZeroMemory(cap, sizeof(WINBIO_CAPTURE_DATA));
            cap->PayloadSize = (DWORD)FIELD_OFFSET(WINBIO_CAPTURE_DATA, CaptureData.Data);
            cap->WinBioHresult = S_OK;
            cap->SensorStatus = WINBIO_SENSOR_REJECT;
            cap->RejectDetail = WINBIO_FP_POOR_QUALITY;
            cap->CaptureData.Size = 0;
            WdfSpinLockAcquire(ctx->Lock);
            ctx->CapturesRejected++;
            WdfSpinLockRelease(ctx->Lock);
            WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, cap->PayloadSize);
            return;
        }

        if (mode == BIOFAKE_MODE_FAILURE) {
            PWINBIO_CAPTURE_DATA cap = (PWINBIO_CAPTURE_DATA)outBuf;
            RtlZeroMemory(cap, sizeof(WINBIO_CAPTURE_DATA));
            cap->PayloadSize = (DWORD)FIELD_OFFSET(WINBIO_CAPTURE_DATA, CaptureData.Data);
            cap->WinBioHresult = WINBIO_E_DEVICE_FAILURE;
            cap->SensorStatus = WINBIO_SENSOR_FAILURE;
            cap->RejectDetail = 0;
            cap->CaptureData.Size = 0;
            WdfSpinLockAcquire(ctx->Lock);
            ctx->CapturesFailed++;
            WdfSpinLockRelease(ctx->Lock);
            WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, cap->PayloadSize);
            return;
        }

        if ((mode == BIOFAKE_MODE_READY && hasActive) ||
            (mode == BIOFAKE_MODE_CUSTOM && hasCustom)) {
            PWINBIO_CAPTURE_DATA cap = (PWINBIO_CAPTURE_DATA)outBuf;
            PUCHAR bir = (PUCHAR)cap + FIELD_OFFSET(WINBIO_CAPTURE_DATA, CaptureData.Data);
            UCHAR purpose = params.Purpose ? params.Purpose : (UCHAR)WINBIO_PURPOSE_VERIFY;

            if (mode == BIOFAKE_MODE_CUSTOM && hasCustom) {
                PVOID p = WdfMemoryGetBuffer(ctx->CustomPayload, NULL);
                birSize = customSize;
                RtlCopyMemory(bir, p, birSize);
            } else {
                BioFakeBuildBir(bir, purpose,
                                (UCHAR)(WINBIO_DATA_FLAG_RAW | WINBIO_DATA_FLAG_OPTION_MASK_PRESENT),
                                secret);
            }

            cap->PayloadSize = (DWORD)(FIELD_OFFSET(WINBIO_CAPTURE_DATA, CaptureData.Data) + birSize);
            cap->WinBioHresult = S_OK;
            cap->SensorStatus = WINBIO_SENSOR_ACCEPT;
            cap->RejectDetail = 0;
            cap->CaptureData.Size = birSize;

            WdfSpinLockAcquire(ctx->Lock);
            ctx->CapturesServed++;
            WdfSpinLockRelease(ctx->Lock);
            WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, cap->PayloadSize);
            return;
        }

        //
        // Nothing to serve automatically: pend the capture until the
        // control tool presents a key / payload or cancels.
        //
        WdfSpinLockAcquire(ctx->Lock);
        if (ctx->PendingCapture != NULL) {
            WdfSpinLockRelease(ctx->Lock);
            WdfRequestComplete(Request, (NTSTATUS)WINBIO_E_DATA_COLLECTION_IN_PROGRESS);
            return;
        }
        ctx->PendingCapture = Request;
        WdfSpinLockRelease(ctx->Lock);

        status = WdfRequestMarkCancelableEx(Request, BioFakeEvtRequestCancel);
        if (!NT_SUCCESS(status)) {
            WdfSpinLockAcquire(ctx->Lock);
            ctx->PendingCapture = NULL;
            WdfSpinLockRelease(ctx->Lock);
            WdfRequestComplete(Request, status);
        }
        return;
    }

    case IOCTL_BIOFAKE_GET_INFO:
    {
        BIOFAKE_INFO info;

        status = WdfRequestRetrieveOutputBuffer(Request, sizeof(BIOFAKE_INFO), &outBuf, &outLen);
        if (!NT_SUCCESS(status)) break;

        info.Version = 1;
        info.Mode = mode;
        info.ActiveKey = active;
        info.CapturePending = pending ? 1 : 0;
        info.MaxPayloadSize = BIOFAKE_MAX_PAYLOAD;
        info.PayloadSize = (mode == BIOFAKE_MODE_CUSTOM && hasCustom) ? customSize : BioFakeBirSize();

        RtlCopyMemory(outBuf, &info, sizeof(info));
        WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(info));
        return;
    }

    case IOCTL_BIOFAKE_GET_STATS:
    {
        BIOFAKE_STATS stats;

        status = WdfRequestRetrieveOutputBuffer(Request, sizeof(BIOFAKE_STATS), &outBuf, &outLen);
        if (!NT_SUCCESS(status)) break;

        stats.CapturesRequested = ctx->CapturesRequested;
        stats.CapturesServed = ctx->CapturesServed;
        stats.CapturesRejected = ctx->CapturesRejected;
        stats.CapturesFailed = ctx->CapturesFailed;
        RtlCopyMemory(outBuf, &stats, sizeof(stats));
        WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(stats));
        return;
    }

    case IOCTL_BIOFAKE_SET_MODE:
    {
        status = WdfRequestRetrieveInputBuffer(Request, sizeof(DWORD), &inBuf, &inLen);
        if (!NT_SUCCESS(status)) break;

        WdfSpinLockAcquire(ctx->Lock);
        ctx->Mode = *(PULONG)inBuf;
        WdfSpinLockRelease(ctx->Lock);
        BioFakeSaveSettings(ctx);
        WdfRequestComplete(Request, STATUS_SUCCESS);
        return;
    }

    case IOCTL_BIOFAKE_ADD_KEY:
    {
        PBIOFAKE_KEY_ENTRY entry = (PBIOFAKE_KEY_ENTRY)inBuf;
        ULONG slot = BIOFAKE_NO_KEY;

        status = WdfRequestRetrieveInputBuffer(Request, sizeof(BIOFAKE_KEY_ENTRY), &inBuf, &inLen);
        if (!NT_SUCCESS(status)) break;

        entry = (PBIOFAKE_KEY_ENTRY)inBuf;
        entry->Name[BIOFAKE_NAME_CHARS - 1] = 0;

        if (entry->Name[0] == 0) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        WdfSpinLockAcquire(ctx->Lock);
        if (NT_SUCCESS(BioFakeFindKey(ctx, entry->Name, &slot))) {
            WdfSpinLockRelease(ctx->Lock);
            status = STATUS_OBJECT_NAME_COLLISION;
            break;
        }
        for (i = 0; i < BIOFAKE_MAX_KEYS; i++) {
            if (ctx->Keys[i].Name[0] == 0) {
                slot = i;
                break;
            }
        }
        if (slot == BIOFAKE_NO_KEY) {
            WdfSpinLockRelease(ctx->Lock);
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }
        RtlCopyMemory(&ctx->Keys[slot], entry, sizeof(BIOFAKE_KEY_ENTRY));
        ctx->Keys[slot].Slot = slot;
        if (ctx->ActiveKey >= BIOFAKE_MAX_KEYS) {
            ctx->ActiveKey = slot;
        }
        WdfSpinLockRelease(ctx->Lock);

        BioFakeSaveSettings(ctx);
        WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(DWORD));
        return;
    }

    case IOCTL_BIOFAKE_REMOVE_KEY:
    {
        PBIOFAKE_NAME_VALUE nv;
        ULONG slot;

        status = WdfRequestRetrieveInputBuffer(Request, sizeof(BIOFAKE_NAME_VALUE), &inBuf, &inLen);
        if (!NT_SUCCESS(status)) break;

        nv = (PBIOFAKE_NAME_VALUE)inBuf;
        nv->Name[BIOFAKE_NAME_CHARS - 1] = 0;

        WdfSpinLockAcquire(ctx->Lock);
        status = BioFakeFindKey(ctx, nv->Name, &slot);
        if (NT_SUCCESS(status)) {
            RtlZeroMemory(&ctx->Keys[slot], sizeof(BIOFAKE_KEY_ENTRY));
            if (ctx->ActiveKey == slot) {
                ctx->ActiveKey = BIOFAKE_NO_KEY;
            }
        }
        WdfSpinLockRelease(ctx->Lock);

        if (!NT_SUCCESS(status)) break;
        BioFakeSaveSettings(ctx);
        WdfRequestComplete(Request, STATUS_SUCCESS);
        return;
    }

    case IOCTL_BIOFAKE_SELECT_KEY:
    {
        PBIOFAKE_NAME_VALUE nv;
        ULONG slot;

        status = WdfRequestRetrieveInputBuffer(Request, sizeof(BIOFAKE_NAME_VALUE), &inBuf, &inLen);
        if (!NT_SUCCESS(status)) break;

        nv = (PBIOFAKE_NAME_VALUE)inBuf;
        nv->Name[BIOFAKE_NAME_CHARS - 1] = 0;

        WdfSpinLockAcquire(ctx->Lock);
        status = BioFakeFindKey(ctx, nv->Name, &slot);
        if (NT_SUCCESS(status)) {
            ctx->ActiveKey = slot;
        }
        WdfSpinLockRelease(ctx->Lock);

        if (!NT_SUCCESS(status)) break;
        BioFakeSaveSettings(ctx);
        WdfRequestComplete(Request, STATUS_SUCCESS);
        return;
    }

    case IOCTL_BIOFAKE_PRESENT_KEY:
    {
        PBIOFAKE_NAME_VALUE nv;
        ULONG slot;
        UCHAR secretLocal[BIOFAKE_SECRET_LEN];
        BOOLEAN found = FALSE;

        status = WdfRequestRetrieveInputBuffer(Request, sizeof(BIOFAKE_NAME_VALUE), &inBuf, &inLen);
        if (!NT_SUCCESS(status)) break;

        nv = (PBIOFAKE_NAME_VALUE)inBuf;
        nv->Name[BIOFAKE_NAME_CHARS - 1] = 0;

        WdfSpinLockAcquire(ctx->Lock);
        if (NT_SUCCESS(BioFakeFindKey(ctx, nv->Name, &slot))) {
            RtlCopyMemory(secretLocal, ctx->Keys[slot].Secret, BIOFAKE_SECRET_LEN);
            found = TRUE;
        }
        WdfSpinLockRelease(ctx->Lock);

        if (!found) {
            status = STATUS_NOT_FOUND;
            break;
        }

        {
            UCHAR bir[BIOFAKE_PAYLOAD_STACK];
            BioFakeBuildBir(bir, (UCHAR)WINBIO_PURPOSE_VERIFY,
                            (UCHAR)(WINBIO_DATA_FLAG_RAW | WINBIO_DATA_FLAG_OPTION_MASK_PRESENT),
                            secretLocal);
            BioFakeCompletePendingCapture(ctx, STATUS_SUCCESS, bir, BioFakeBirSize());
        }
        WdfRequestComplete(Request, STATUS_SUCCESS);
        return;
    }

    case IOCTL_BIOFAKE_CANCEL:
        BioFakeCompletePendingCapture(ctx, WINBIO_E_CANCELED, NULL, 0);
        WdfRequestComplete(Request, STATUS_SUCCESS);
        return;

    case IOCTL_BIOFAKE_SET_PAYLOAD:
    {
        PDWORD hdr;
        ULONG size;
        WDFMEMORY mem = NULL;

        status = WdfRequestRetrieveInputBuffer(Request, sizeof(DWORD), &inBuf, &inLen);
        if (!NT_SUCCESS(status)) break;

        hdr = (PDWORD)inBuf;
        size = hdr[0];
        if (size == 0 || size > BIOFAKE_MAX_PAYLOAD || (SIZE_T)size + sizeof(DWORD) > inLen) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        WDF_OBJECT_ATTRIBUTES memAttrs;
        WDF_OBJECT_ATTRIBUTES_INIT(&memAttrs);
        memAttrs.ParentObject = WdfIoQueueGetDevice(Queue);

        status = WdfMemoryCreate(&memAttrs, NonPagedPool, BIOFAKE_POOL_TAG, size, &mem, NULL);
        if (!NT_SUCCESS(status)) break;

        RtlCopyMemory(WdfMemoryGetBuffer(mem, NULL), (PUCHAR)inBuf + sizeof(DWORD), size);

        WdfSpinLockAcquire(ctx->Lock);
        {
            WDFMEMORY old = ctx->CustomPayload;
            ctx->CustomPayload = mem;
            ctx->Mode = BIOFAKE_MODE_CUSTOM;
            mem = old;
        }
        WdfSpinLockRelease(ctx->Lock);

        if (mem != NULL) {
            WdfObjectDelete(mem);
        }
        BioFakeSaveSettings(ctx);
        WdfRequestComplete(Request, STATUS_SUCCESS);
        return;
    }

    default:
        status = STATUS_NOT_SUPPORTED;
        break;
    }

    WdfRequestCompleteWithInformation(Request, status, 0);
}
