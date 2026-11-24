/*++

THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
ANY KIND, EITHER EXPRESSED OR IMPLIED.

BioFake - Virtual WBDI fingerprint sensor driver (UMDF 2.x)

Abstract:
    Implements the Windows Biometric Driver Interface (WBDI) for a purely
    virtual (root-enumerated, software) fingerprint sensor. The Windows
    Biometric Service (WbioSrvc) discovers the device through
    GUID_DEVINTERFACE_BIOMETRIC_READER, loads the in-box
    WinBioSensorAdapter.DLL, and this driver serves fully synthetic
    (or user supplied) ANSI-381 fingerprint captures.

    A second, vendor-defined device interface (GUID_BIOFAKE_CONTROL) allows
    the biofakectl.exe tool to switch operating modes and feed custom BIR
    payloads at runtime.

Environment:
    User-mode driver framework (UMDF 2.x)

--*/

#include <initguid.h>
#include <wdf.h>
#include <winioctl.h>
#include <winbio_ioctl.h>
#include <math.h>
#include "biofake_ioctl.h"

//
// {B10FA4CE-8D21-4E9A-B1F3-2A7C6D5E4F03} - fake sensor identity GUID (informational)
//
DEFINE_GUID(GUID_BIOFAKE_SENSOR_ID,
    0xb10fa4ce, 0x8d21, 0x4e9a, 0xb1, 0xf3, 0x2a, 0x7c, 0x6d, 0x5e, 0x4f, 0x03);

//
// Synthetic capture geometry
//
#define BIOFAKE_IMG_WIDTH   128
#define BIOFAKE_IMG_HEIGHT  144

typedef enum _BIOFAKE_MODE {
    BioFakeModeReady    = BIOFAKE_MODE_READY,
    BioFakeModeReject   = BIOFAKE_MODE_REJECT,
    BioFakeModeFailure  = BIOFAKE_MODE_FAILURE,
    BioFakeModeCustom   = BIOFAKE_MODE_CUSTOM
} BIOFAKE_MODE;

//
// Per-device context
//
typedef struct _DEVICE_CONTEXT {
    WDFWAITLOCK     StateLock;
    ULONG           Mode;               // BIOFAKE_MODE_*
    ULONG           IndicatorStatus;    // WINBIO_INDICATOR_*
    WDFMEMORY       CustomPayload;      // holds a complete WINBIO_BIR blob (may be NULL)
    ULONG           CapturesRequested;
    ULONG           CapturesServed;
    ULONG           CapturesRejected;
    ULONG           CapturesFailed;
} DEVICE_CONTEXT, *PDEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DEVICE_CONTEXT, BioFakeGetContext)

EVT_WDF_DRIVER_DEVICE_ADD       BioFakeEvtDeviceAdd;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL BioFakeEvtIoDeviceControl;

//
// Forward declarations of helpers
//
static ULONG BioFakeBirSize(VOID);

static VOID BioFakeBuildBir(
    _Out_writes_bytes_(BioFakeBirSize()) PVOID BirBuffer,
    _In_ UCHAR Purpose,
    _In_ UCHAR DataFlags,
    _In_ UCHAR Subtype
    );

static VOID BioFakeGenerateImage(
    _Out_writes_bytes_(BIOFAKE_IMG_WIDTH * BIOFAKE_IMG_HEIGHT) PBYTE Image
    );

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT     DriverObject,
    _In_ PUNICODE_STRING    RegistryPath
    )
/*++

Routine Description:

    DriverEntry initializes the driver and creates the WDF driver object.

--*/
{
    NTSTATUS            status;
    WDF_DRIVER_CONFIG   config;

    WDF_DRIVER_CONFIG_INIT(&config, BioFakeEvtDeviceAdd);

    status = WdfDriverCreate(
        DriverObject,
        RegistryPath,
        WDF_NO_OBJECT_ATTRIBUTES,
        &config,
        WDF_NO_HANDLE
        );

    return status;
}

NTSTATUS
BioFakeEvtDeviceAdd(
    _In_    WDFDRIVER       Driver,
    _Inout_ PWDFDEVICE_INIT DeviceInit
    )
/*++

Routine Description:

    EvtDeviceAdd: creates the framework device, registers both device
    interfaces (WBDI reader + BioFake control) and a sequential default
    I/O queue that dispatches all IOCTLs.

--*/
{
    NTSTATUS                status;
    WDF_OBJECT_ATTRIBUTES   devAttrs;
    WDF_OBJECT_ATTRIBUTES   lockAttrs;
    WDF_IO_QUEUE_CONFIG     queueConfig;
    WDFDEVICE               device;
    PDEVICE_CONTEXT         devCtx;

    UNREFERENCED_PARAMETER(Driver);

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&devAttrs, DEVICE_CONTEXT);

    status = WdfDeviceCreate(&DeviceInit, &devAttrs, &device);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    devCtx = BioFakeGetContext(device);
    RtlZeroMemory(devCtx, sizeof(DEVICE_CONTEXT));

    devCtx->Mode = BioFakeModeReady;
    devCtx->IndicatorStatus = WINBIO_INDICATOR_OFF;

    WDF_OBJECT_ATTRIBUTES_INIT(&lockAttrs);
    lockAttrs.ParentObject = device;

    status = WdfWaitLockCreate(&lockAttrs, &devCtx->StateLock);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // The WBDI interface is the one Windows Biometric Service enumerates.
    //
    status = WdfDeviceCreateDeviceInterface(device,
                                            &GUID_DEVINTERFACE_BIOMETRIC_READER,
                                            NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Vendor control interface used by biofakectl.exe.
    //
    status = WdfDeviceCreateDeviceInterface(device,
                                            &GUID_BIOFAKE_CONTROL,
                                            NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    //
    // Sequential default queue: WBDI allows a single pending capture at a
    // time and our control state updates are trivial, so serial dispatch
    // is the simplest correct choice.
    //
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchSequential);
    queueConfig.EvtIoDeviceControl = BioFakeEvtIoDeviceControl;

    status = WdfIoQueueCreate(device,
                              &queueConfig,
                              WDF_NO_OBJECT_ATTRIBUTES,
                              WDF_NO_HANDLE);

    return status;
}

VOID
BioFakeEvtIoDeviceControl(
    _In_ WDFQUEUE   Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t     OutputBufferLength,
    _In_ size_t     InputBufferLength,
    _In_ ULONG      IoControlCode
    )
/*++

Routine Description:

    Handles WBDI IOCTLs (GUID_DEVINTERFACE_BIOMETRIC_READER clients, i.e.
    the Windows Biometric Service) and the vendor control IOCTLs
    (GUID_BIOFAKE_CONTROL clients, i.e. biofakectl.exe).

--*/
{
    PDEVICE_CONTEXT devCtx = BioFakeGetContext(WdfIoQueueGetDevice(Queue));
    NTSTATUS        status = STATUS_SUCCESS;
    PVOID           outBuffer = NULL;
    PVOID           inBuffer = NULL;
    size_t          outLength = 0;
    size_t          inLength = 0;

    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);

    switch (IoControlCode) {

    //
    // =============== WBDI: mandatory IOCTLs =================
    //

    case IOCTL_BIOMETRIC_GET_ATTRIBUTES:
    {
        WINBIO_SENSOR_ATTRIBUTES    attr;
        PWINBIO_STRING              src;
        DWORD                       payloadSize = (DWORD)sizeof(WINBIO_SENSOR_ATTRIBUTES);

        status = WdfRequestRetrieveOutputBuffer(Request,
                                                sizeof(DWORD),
                                                &outBuffer,
                                                &outLength);
        if (!NT_SUCCESS(status)) {
            break;
        }

        if (outLength < payloadSize) {
            //
            // Size query: return the required payload size.
            //
            ((PDWORD)outBuffer)[0] = payloadSize;
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

        src = &attr.ManufacturerName;
        wcscpy_s((wchar_t*)src, WINBIO_MAX_STRING_LEN, L"BioFake Project");
        src = &attr.ModelName;
        wcscpy_s((wchar_t*)src, WINBIO_MAX_STRING_LEN, L"BioFake Virtual Sensor");
        src = &attr.SerialNumber;
        wcscpy_s((wchar_t*)src, WINBIO_MAX_STRING_LEN, L"BF-VS-0000001");

        attr.FirmwareVersion.MajorVersion = 1;
        attr.FirmwareVersion.MinorVersion = 0;
        attr.SupportedFormatEntries = 1;
        attr.SupportedFormat[0].Owner = WINBIO_ANSI_381_FORMAT_OWNER;
        attr.SupportedFormat[0].Type = WINBIO_ANSI_381_FORMAT_TYPE;

        RtlCopyMemory(outBuffer, &attr, payloadSize);
        WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, payloadSize);
        return;
    }

    case IOCTL_BIOMETRIC_GET_SENSOR_STATUS:
    {
        WINBIO_DIAGNOSTICS  diag;
        DWORD               payloadSize;

        status = WdfRequestRetrieveOutputBuffer(Request,
                                                sizeof(DWORD),
                                                &outBuffer,
                                                &outLength);
        if (!NT_SUCCESS(status)) {
            break;
        }

        payloadSize = (DWORD)FIELD_OFFSET(WINBIO_DIAGNOSTICS, VendorDiagnostics.Data);

        if (outLength < payloadSize) {
            ((PDWORD)outBuffer)[0] = payloadSize;
            WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(DWORD));
            return;
        }

        RtlZeroMemory(&diag, sizeof(diag));
        diag.PayloadSize = payloadSize;
        diag.WinBioHresult = S_OK;
        diag.SensorStatus = (devCtx->Mode == BioFakeModeFailure) ?
                                WINBIO_SENSOR_FAILURE : WINBIO_SENSOR_READY;
        diag.VendorDiagnostics.Size = 0;

        RtlCopyMemory(outBuffer, &diag, payloadSize);
        WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, payloadSize);
        return;
    }

    case IOCTL_BIOMETRIC_CALIBRATE:
    {
        WINBIO_CALIBRATION_INFO cal;
        DWORD                   payloadSize;

        status = WdfRequestRetrieveOutputBuffer(Request,
                                                sizeof(DWORD),
                                                &outBuffer,
                                                &outLength);
        if (!NT_SUCCESS(status)) {
            break;
        }

        payloadSize = (DWORD)FIELD_OFFSET(WINBIO_CALIBRATION_INFO, CalibrationData.Data);

        if (outLength < payloadSize) {
            ((PDWORD)outBuffer)[0] = payloadSize;
            WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(DWORD));
            return;
        }

        RtlZeroMemory(&cal, sizeof(cal));
        cal.PayloadSize = payloadSize;
        cal.WinBioHresult = S_OK;
        cal.CalibrationData.Size = 0;

        RtlCopyMemory(outBuffer, &cal, payloadSize);
        WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, payloadSize);
        return;
    }

    case IOCTL_BIOMETRIC_RESET:
    {
        WINBIO_BLANK_PAYLOAD blank;

        status = WdfRequestRetrieveOutputBuffer(Request,
                                                sizeof(DWORD),
                                                &outBuffer,
                                                &outLength);
        if (!NT_SUCCESS(status)) {
            break;
        }

        if (outLength < sizeof(WINBIO_BLANK_PAYLOAD)) {
            ((PDWORD)outBuffer)[0] = (DWORD)sizeof(WINBIO_BLANK_PAYLOAD);
            WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(DWORD));
            return;
        }

        //
        // Reset the virtual sensor to a known state and cancel any
        // hypothetical pending data collection (none can be pending here).
        //
        WdfWaitLockAcquire(devCtx->StateLock, NULL);
        devCtx->IndicatorStatus = WINBIO_INDICATOR_OFF;
        WdfWaitLockRelease(devCtx->StateLock);

        RtlZeroMemory(&blank, sizeof(blank));
        blank.PayloadSize = (DWORD)sizeof(WINBIO_BLANK_PAYLOAD);
        blank.WinBioHresult = S_OK;

        RtlCopyMemory(outBuffer, &blank, sizeof(WINBIO_BLANK_PAYLOAD));
        WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(WINBIO_BLANK_PAYLOAD));
        return;
    }

    case IOCTL_BIOMETRIC_CAPTURE_DATA:
    {
        WINBIO_CAPTURE_PARAMETERS   params;
        PWINBIO_CAPTURE_DATA        capture;
        PBYTE                       bir;
        DWORD                       birSize;
        DWORD                       payloadSize;
        ULONG                       currentMode;
        WDFMEMORY                   customPayload = NULL;
        PVOID                       payloadData;
        SIZE_T                      payloadLength = 0;

        status = WdfRequestRetrieveOutputBuffer(Request,
                                                sizeof(DWORD),
                                                &outBuffer,
                                                &outLength);
        if (!NT_SUCCESS(status)) {
            break;
        }

        RtlZeroMemory(&params, sizeof(params));

        status = WdfRequestRetrieveInputBuffer(Request,
                                               0,
                                               &inBuffer,
                                               &inLength);
        if (NT_SUCCESS(status) && inLength >= sizeof(WINBIO_CAPTURE_PARAMETERS)) {
            RtlCopyMemory(&params, inBuffer, sizeof(params));
        }

        WdfWaitLockAcquire(devCtx->StateLock, NULL);

        devCtx->CapturesRequested++;
        currentMode = devCtx->Mode;

        if (currentMode == BioFakeModeCustom && devCtx->CustomPayload != NULL) {
            customPayload = devCtx->CustomPayload;
        }

        WdfWaitLockRelease(devCtx->StateLock);

        birSize = BioFakeBirSize();
        payloadSize = (DWORD)(FIELD_OFFSET(WINBIO_CAPTURE_DATA, CaptureData.Data) + birSize);

        if (outLength < payloadSize) {
            //
            // Size query: report the maximum payload we may produce.
            //
            ((PDWORD)outBuffer)[0] = payloadSize;
            WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(DWORD));
            return;
        }

        capture = (PWINBIO_CAPTURE_DATA)outBuffer;
        RtlZeroMemory(capture, payloadSize);

        if (currentMode == BioFakeModeFailure) {
            capture->PayloadSize = (DWORD)FIELD_OFFSET(WINBIO_CAPTURE_DATA, CaptureData.Data);
            capture->WinBioHresult = E_FAIL;
            capture->SensorStatus = WINBIO_SENSOR_FAILURE;
            capture->RejectDetail = 0;
            capture->CaptureData.Size = 0;

            WdfWaitLockAcquire(devCtx->StateLock, NULL);
            devCtx->CapturesFailed++;
            WdfWaitLockRelease(devCtx->StateLock);

            WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, capture->PayloadSize);
            return;
        }

        if (currentMode == BioFakeModeReject) {
            capture->PayloadSize = (DWORD)FIELD_OFFSET(WINBIO_CAPTURE_DATA, CaptureData.Data);
            capture->WinBioHresult = S_OK;
            capture->SensorStatus = WINBIO_SENSOR_REJECT;
            capture->RejectDetail = WINBIO_FP_POOR_QUALITY;
            capture->CaptureData.Size = 0;

            WdfWaitLockAcquire(devCtx->StateLock, NULL);
            devCtx->CapturesRejected++;
            WdfWaitLockRelease(devCtx->StateLock);

            WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, capture->PayloadSize);
            return;
        }

        //
        // READY (synthetic capture) or CUSTOM (user supplied BIR).
        //
        bir = (PBYTE)capture + FIELD_OFFSET(WINBIO_CAPTURE_DATA, CaptureData.Data);

        if (currentMode == BioFakeModeCustom && customPayload != NULL) {
            payloadData = WdfMemoryGetBuffer(customPayload, &payloadLength);

            birSize = (DWORD)payloadLength;
            payloadSize = (DWORD)(FIELD_OFFSET(WINBIO_CAPTURE_DATA, CaptureData.Data) + birSize);

            if (outLength < payloadSize) {
                //
                // Custom payload larger than the caller's buffer:
                // report the required size and let the caller retry.
                //
                ((PDWORD)outBuffer)[0] = payloadSize;
                WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(DWORD));
                return;
            }

            RtlCopyMemory(bir, payloadData, birSize);
        }
        else {
            UCHAR purpose = params.Purpose ? params.Purpose : WINBIO_PURPOSE_VERIFY;
            UCHAR flags = params.Flags ? params.Flags :
                          (UCHAR)(WINBIO_DATA_FLAG_RAW | WINBIO_DATA_FLAG_OPTION_MASK_PRESENT);
            BioFakeBuildBir(bir, purpose, flags, WINBIO_ANSI_381_POS_RH_INDEX_FINGER);
        }

        capture->PayloadSize = payloadSize;
        capture->WinBioHresult = S_OK;
        capture->SensorStatus = WINBIO_SENSOR_READY;
        capture->RejectDetail = 0;
        capture->CaptureData.Size = birSize;

        WdfWaitLockAcquire(devCtx->StateLock, NULL);
        devCtx->CapturesServed++;
        WdfWaitLockRelease(devCtx->StateLock);

        WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, payloadSize);
        return;
    }

    //
    // =============== WBDI: optional IOCTLs ==================
    //

    case IOCTL_BIOMETRIC_GET_INDICATOR:
    {
        WINBIO_GET_INDICATOR indicator;

        status = WdfRequestRetrieveOutputBuffer(Request,
                                                sizeof(DWORD),
                                                &outBuffer,
                                                &outLength);
        if (!NT_SUCCESS(status)) {
            break;
        }

        if (outLength < sizeof(WINBIO_GET_INDICATOR)) {
            ((PDWORD)outBuffer)[0] = (DWORD)sizeof(WINBIO_GET_INDICATOR);
            WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(DWORD));
            return;
        }

        indicator.PayloadSize = (DWORD)sizeof(WINBIO_GET_INDICATOR);
        indicator.WinBioHresult = S_OK;
        indicator.IndicatorStatus = devCtx->IndicatorStatus;

        RtlCopyMemory(outBuffer, &indicator, sizeof(WINBIO_GET_INDICATOR));
        WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(WINBIO_GET_INDICATOR));
        return;
    }

    case IOCTL_BIOMETRIC_SET_INDICATOR:
    {
        WINBIO_GET_INDICATOR indicator;

        status = WdfRequestRetrieveInputBuffer(Request,
                                               sizeof(WINBIO_SET_INDICATOR),
                                               &inBuffer,
                                               &inLength);
        if (!NT_SUCCESS(status)) {
            break;
        }

        devCtx->IndicatorStatus =
            ((PWINBIO_SET_INDICATOR)inBuffer)->IndicatorStatus == WINBIO_INDICATOR_ON ?
                WINBIO_INDICATOR_ON : WINBIO_INDICATOR_OFF;

        indicator.PayloadSize = (DWORD)sizeof(WINBIO_GET_INDICATOR);
        indicator.WinBioHresult = S_OK;
        indicator.IndicatorStatus = devCtx->IndicatorStatus;

        status = WdfRequestRetrieveOutputBuffer(Request,
                                                sizeof(DWORD),
                                                &outBuffer,
                                                &outLength);
        if (!NT_SUCCESS(status)) {
            break;
        }

        if (outLength < sizeof(WINBIO_GET_INDICATOR)) {
            ((PDWORD)outBuffer)[0] = (DWORD)sizeof(WINBIO_GET_INDICATOR);
            WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(DWORD));
            return;
        }

        RtlCopyMemory(outBuffer, &indicator, sizeof(WINBIO_GET_INDICATOR));
        WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(WINBIO_GET_INDICATOR));
        return;
    }

    //
    // Capabilities we do not advertise are answered with STATUS_NOT_SUPPORTED.
    //
    case IOCTL_BIOMETRIC_UPDATE_FIRMWARE:
    case IOCTL_BIOMETRIC_GET_SUPPORTED_ALGORITHMS:
    case IOCTL_BIOMETRIC_GET_PRIVATE_SENSOR_TYPE:
    case IOCTL_BIOMETRIC_CONNECT_SECURE:
    case IOCTL_BIOMETRIC_CAPTURE_ENCRYPTED_DATA:
    case IOCTL_BIOMETRIC_NOTIFY_WAKE:
        status = STATUS_NOT_SUPPORTED;
        break;

    //
    // =============== BioFake vendor control =================
    //

    case IOCTL_BIOFAKE_GET_INFO:
    {
        BIOFAKE_INFO info;

        status = WdfRequestRetrieveOutputBuffer(Request,
                                                sizeof(BIOFAKE_INFO),
                                                &outBuffer,
                                                &outLength);
        if (!NT_SUCCESS(status)) {
            break;
        }

        info.Version = 1;
        info.Mode = devCtx->Mode;
        info.MaxPayloadSize = BIOFAKE_MAX_PAYLOAD;

        if (devCtx->Mode == BioFakeModeCustom && devCtx->CustomPayload != NULL) {
            SIZE_T payloadLength = 0;
            WdfMemoryGetBuffer(devCtx->CustomPayload, &payloadLength);
            info.PayloadSize = (DWORD)payloadLength;
        }
        else {
            info.PayloadSize = BioFakeBirSize();
        }

        RtlCopyMemory(outBuffer, &info, sizeof(info));
        WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(info));
        return;
    }

    case IOCTL_BIOFAKE_SET_MODE:
    {
        status = WdfRequestRetrieveInputBuffer(Request,
                                               sizeof(DWORD),
                                               &inBuffer,
                                               &inLength);
        if (!NT_SUCCESS(status)) {
            break;
        }

        devCtx->Mode = *(PDWORD)inBuffer;
        WdfRequestComplete(Request, STATUS_SUCCESS);
        return;
    }

    case IOCTL_BIOFAKE_SET_PAYLOAD:
    {
        PDWORD  header;
        DWORD   size;
        WDFMEMORY newMemory = NULL;

        status = WdfRequestRetrieveInputBuffer(Request,
                                               sizeof(DWORD) + sizeof(WINBIO_BIR),
                                               &inBuffer,
                                               &inLength);
        if (!NT_SUCCESS(status)) {
            break;
        }

        header = (PDWORD)inBuffer;
        size = header[0];

        if (size == 0 || size > BIOFAKE_MAX_PAYLOAD ||
            (SIZE_T)size + sizeof(DWORD) > inLength) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        status = WdfMemoryCreate(NULL,
                                 NonPagedPool,
                                 'FoiB',
                                 size,
                                 &newMemory,
                                 NULL);
        if (!NT_SUCCESS(status)) {
            break;
        }

        RtlCopyMemory(WdfMemoryGetBuffer(newMemory, NULL),
                      (PBYTE)inBuffer + sizeof(DWORD),
                      size);

        WdfWaitLockAcquire(devCtx->StateLock, NULL);

        devCtx->Mode = BioFakeModeCustom;

        if (devCtx->CustomPayload != NULL) {
            WDFMEMORY old = devCtx->CustomPayload;
            devCtx->CustomPayload = newMemory;
            WdfObjectDelete(old);
        }
        else {
            devCtx->CustomPayload = newMemory;
        }

        WdfWaitLockRelease(devCtx->StateLock);

        WdfRequestComplete(Request, STATUS_SUCCESS);
        return;
    }

    case IOCTL_BIOFAKE_GET_STATS:
    {
        BIOFAKE_STATS stats;

        status = WdfRequestRetrieveOutputBuffer(Request,
                                                sizeof(BIOFAKE_STATS),
                                                &outBuffer,
                                                &outLength);
        if (!NT_SUCCESS(status)) {
            break;
        }

        stats.CapturesRequested = devCtx->CapturesRequested;
        stats.CapturesServed = devCtx->CapturesServed;
        stats.CapturesRejected = devCtx->CapturesRejected;
        stats.CapturesFailed = devCtx->CapturesFailed;

        RtlCopyMemory(outBuffer, &stats, sizeof(stats));
        WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(stats));
        return;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    WdfRequestCompleteWithInformation(Request, status, 0);
}

static
ULONG
BioFakeBirSize(
    VOID
    )
/*++

Routine Description:

    Size of the synthetic WINBIO_BIR blob produced by BioFakeBuildBir.

--*/
{
    return (ULONG)(sizeof(WINBIO_BIR) +
                   sizeof(WINBIO_BIR_HEADER) +
                   sizeof(WINBIO_BDB_ANSI_381_HEADER) +
                   sizeof(WINBIO_BDB_ANSI_381_RECORD) +
                   (BIOFAKE_IMG_WIDTH * BIOFAKE_IMG_HEIGHT));
}

static
VOID
BioFakeBuildBir(
    _Out_writes_bytes_(BioFakeBirSize()) PVOID BirBuffer,
    _In_ UCHAR Purpose,
    _In_ UCHAR DataFlags,
    _In_ UCHAR Subtype
    )
/*++

Routine Description:

    Builds a complete WINBIO_BIR containing a synthetic ANSI-381
    fingerprint image:

        [WINBIO_BIR]        32 bytes   offset/size table
        [WINBIO_BIR_HEADER] CBEFF patron format A header
        [ANSI-381 header]   standard data block header
        [ANSI-381 record]   one finger view descriptor
        [image]             8-bit grayscale ridge pattern

--*/
{
    PBYTE                       base = (PBYTE)BirBuffer;
    PWINBIO_BIR                 bir = (PWINBIO_BIR)base;
    PWINBIO_BIR_HEADER          header;
    PWINBIO_BDB_ANSI_381_HEADER ansiHeader;
    PWINBIO_BDB_ANSI_381_RECORD record;
    PBYTE                       image;
    ULONGLONG                   now = 0;
    ULONG                       imageLength = BIOFAKE_IMG_WIDTH * BIOFAKE_IMG_HEIGHT;

    RtlZeroMemory(base, BioFakeBirSize());

    GetSystemTimeAsFileTime((PFILETIME)&now);

    bir->HeaderBlock.Size = (ULONG)sizeof(WINBIO_BIR_HEADER);
    bir->HeaderBlock.Offset = (ULONG)sizeof(WINBIO_BIR);

    bir->StandardDataBlock.Size = (ULONG)(sizeof(WINBIO_BDB_ANSI_381_HEADER) +
                                          sizeof(WINBIO_BDB_ANSI_381_RECORD) +
                                          imageLength);
    bir->StandardDataBlock.Offset = (ULONG)(sizeof(WINBIO_BIR) + sizeof(WINBIO_BIR_HEADER));

    bir->VendorDataBlock.Size = 0;
    bir->VendorDataBlock.Offset = 0;
    bir->SignatureBlock.Size = 0;
    bir->SignatureBlock.Offset = 0;

    header = (PWINBIO_BIR_HEADER)(base + bir->HeaderBlock.Offset);
    header->ValidFields = (USHORT)(WINBIO_BIR_FIELD_CBEFF_HEADER_VERSION |
                                   WINBIO_BIR_FIELD_PATRON_HEADER_VERSION |
                                   WINBIO_BIR_FIELD_BIOMETRIC_TYPE |
                                   WINBIO_BIR_FIELD_BIOMETRIC_SUBTYPE |
                                   WINBIO_BIR_FIELD_BIOMETRIC_PURPOSE |
                                   WINBIO_BIR_FIELD_QUALITY |
                                   WINBIO_BIR_FIELD_CREATION_DATE);
    header->HeaderVersion = WINBIO_CBEFF_HEADER_VERSION;
    header->PatronHeaderVersion = WINBIO_PATRON_HEADER_VERSION;
    header->DataFlags = DataFlags;
    header->Type = WINBIO_TYPE_FINGERPRINT;
    header->Subtype = Subtype;
    header->Purpose = Purpose;
    header->DataQuality = 90;   // 0-100 scale, positive = usable quality
    header->CreationDate.QuadPart = (LONGLONG)now;
    header->BiometricDataFormat.Owner = WINBIO_ANSI_381_FORMAT_OWNER;
    header->BiometricDataFormat.Type = WINBIO_ANSI_381_FORMAT_TYPE;
    header->ProductId.Owner = WINBIO_NO_FORMAT_OWNER_AVAILABLE;
    header->ProductId.Type = WINBIO_NO_FORMAT_TYPE_AVAILABLE;

    ansiHeader = (PWINBIO_BDB_ANSI_381_HEADER)(base + bir->StandardDataBlock.Offset);
    ansiHeader->RecordLength = (ULONG64)(sizeof(WINBIO_BDB_ANSI_381_HEADER) +
                                         sizeof(WINBIO_BDB_ANSI_381_RECORD) +
                                         imageLength);
    ansiHeader->FormatIdentifier = 0x46495200;      // 'F' 'I' 'R' 0x00
    ansiHeader->VersionNumber = 0x30313000;         // '0' '1' '0' 0x00
    ansiHeader->ProductId.Owner = WINBIO_NO_FORMAT_OWNER_AVAILABLE;
    ansiHeader->ProductId.Type = WINBIO_NO_FORMAT_TYPE_AVAILABLE;
    ansiHeader->CaptureDeviceId = 1;
    ansiHeader->ImageAcquisitionLevel = WINBIO_ANSI_381_IMG_ACQ_LEVEL_20;
    ansiHeader->HorizontalScanResolution = 500;     // dpi
    ansiHeader->VerticalScanResolution = 500;
    ansiHeader->HorizontalImageResolution = 500;
    ansiHeader->VerticalImageResolution = 500;
    ansiHeader->ElementCount = 1;
    ansiHeader->ScaleUnits = WINBIO_ANSI_381_PIXELS_PER_INCH;
    ansiHeader->PixelDepth = 8;
    ansiHeader->ImageCompressionAlg = WINBIO_ANSI_381_IMG_UNCOMPRESSED;
    ansiHeader->Reserved = 0;

    record = (PWINBIO_BDB_ANSI_381_RECORD)((PBYTE)ansiHeader + sizeof(WINBIO_BDB_ANSI_381_HEADER));
    record->BlockLength = (ULONG)(sizeof(WINBIO_BDB_ANSI_381_RECORD) + imageLength);
    record->HorizontalLineLength = BIOFAKE_IMG_WIDTH;
    record->VerticalLineLength = BIOFAKE_IMG_HEIGHT;
    record->Position = Subtype;
    record->CountOfViews = 1;
    record->ViewNumber = 1;
    record->ImageQuality = 0xFE;
    record->ImpressionType = WINBIO_ANSI_381_IMP_TYPE_LIVE_SCAN_PLAIN;
    record->Reserved = 0;

    image = (PBYTE)record + sizeof(WINBIO_BDB_ANSI_381_RECORD);
    BioFakeGenerateImage(image);
}

static
VOID
BioFakeGenerateImage(
    _Out_writes_bytes_(BIOFAKE_IMG_WIDTH * BIOFAKE_IMG_HEIGHT) PBYTE Image
    )
/*++

Routine Description:

    Deterministically generates a plausible 8-bit grayscale fingerprint
    pattern: elliptical concentric ridges with mild sinusoidal distortion
    and white borders.

--*/
{
    const double cx = BIOFAKE_IMG_WIDTH * 0.5;
    const double cy = BIOFAKE_IMG_HEIGHT * 0.48;
    int x;
    int y;

    for (y = 0; y < BIOFAKE_IMG_HEIGHT; y++) {
        for (x = 0; x < BIOFAKE_IMG_WIDTH; x++) {
            double dx = (double)x - cx;
            double dy = ((double)y - cy) * 1.25;
            double d = sqrt(dx * dx + dy * dy);
            double wobble = 3.0 * sin(y * 0.045 + x * 0.012) + 2.0 * sin(x * 0.03);
            double v = 128.0 + 95.0 * sin(d * 0.55 + wobble);
            double edge = (double)x;
            double fade;
            double e2;

            if (edge > (BIOFAKE_IMG_WIDTH - 1 - x)) {
                edge = (double)(BIOFAKE_IMG_WIDTH - 1 - x);
            }
            e2 = (double)y;
            if (e2 > (BIOFAKE_IMG_HEIGHT - 1 - y)) {
                e2 = (double)(BIOFAKE_IMG_HEIGHT - 1 - y);
            }
            if (e2 < edge) {
                edge = e2;
            }

            fade = edge < 12.0 ? edge / 12.0 : 1.0;
            v = 255.0 - (255.0 - v) * fade;

            if (v < 0.0) {
                v = 0.0;
            }
            else if (v > 255.0) {
                v = 255.0;
            }

            Image[y * BIOFAKE_IMG_WIDTH + x] = (BYTE)v;
        }
    }
}
