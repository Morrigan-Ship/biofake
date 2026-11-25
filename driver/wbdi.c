/*++
wbdi.c

WBDI request handling for the sensor device node (SWD\BioFake).

Implements all mandatory WBDI IOCTLs and answers IOCTL_BIOMETRIC_CAPTURE_DATA
with a deterministic ANSI 381 BIR built from the active key.

Capture model:
  - READY  : every capture is answered immediately with the active key.
  - REJECT : capture completes with WINBIO_SENSOR_REJECT / poor quality.
  - FAILURE: capture completes with WINBIO_SENSOR_FAILURE / device failure.
  - CUSTOM : capture returns the BIR injected via biofakectl payload.
  - no key : the capture request parks in the manual capture queue until
             biofakectl present/select answers it (framework handles cancel).
--*/

#include "biofake.h"
#include <winbio_err.h>

SIZE_T
BioFakeBirSize(
    VOID
    )
{
    return sizeof(WINBIO_BIR)
         + sizeof(WINBIO_BIR_HEADER)
         + sizeof(WINBIO_BDB_ANSI_381_HEADER)
         + sizeof(WINBIO_BDB_ANSI_381_RECORD)
         + BIOFAKE_IMAGE_SIZE;
}

VOID
BioFakeBuildBir(
    _In_ const BIOFAKE_KEY* Key,
    _In_ BYTE Purpose,
    _Out_writes_(Cap) BYTE* Out,
    _In_ SIZE_T Cap,
    _Out_ SIZE_T* BirSize
    )
/*++
Lays out a complete WINBIO_BIR:
  [WINBIO_BIR (32B)][WINBIO_BIR_HEADER][ANSI 381 header][ANSI 381 record][image]
--*/
{
    PWINBIO_BIR bir;
    PWINBIO_BIR_HEADER header;
    PWINBIO_BDB_ANSI_381_HEADER a381;
    PWINBIO_BDB_ANSI_381_RECORD rec;
    BYTE* image;
    SIZE_T birSize = BioFakeBirSize();

    UNREFERENCED_PARAMETER(Cap);

    RtlZeroMemory(Out, birSize);

    bir = (PWINBIO_BIR)Out;
    header = (PWINBIO_BIR_HEADER)(Out + sizeof(WINBIO_BIR));
    a381 = (PWINBIO_BDB_ANSI_381_HEADER)(Out + sizeof(WINBIO_BIR) + sizeof(WINBIO_BIR_HEADER));
    rec = (PWINBIO_BDB_ANSI_381_RECORD)((BYTE*)a381 + sizeof(WINBIO_BDB_ANSI_381_HEADER));
    image = (BYTE*)rec + sizeof(WINBIO_BDB_ANSI_381_RECORD);

    bir->HeaderBlock.Size = (ULONG)sizeof(WINBIO_BIR_HEADER);
    bir->HeaderBlock.Offset = (ULONG)sizeof(WINBIO_BIR);
    bir->StandardDataBlock.Size = (ULONG)(sizeof(WINBIO_BDB_ANSI_381_HEADER)
                                          + sizeof(WINBIO_BDB_ANSI_381_RECORD)
                                          + BIOFAKE_IMAGE_SIZE);
    bir->StandardDataBlock.Offset = (ULONG)(sizeof(WINBIO_BIR) + sizeof(WINBIO_BIR_HEADER));
    bir->VendorDataBlock.Size = 0;
    bir->VendorDataBlock.Offset = 0;
    bir->SignatureBlock.Size = 0;
    bir->SignatureBlock.Offset = 0;

    header->ValidFields = (USHORT)(WINBIO_BIR_FIELD_CBEFF_HEADER_VERSION
                                   | WINBIO_BIR_FIELD_PATRON_HEADER_VERSION
                                   | WINBIO_BIR_FIELD_BIOMETRIC_TYPE
                                   | WINBIO_BIR_FIELD_BIOMETRIC_SUBTYPE
                                   | WINBIO_BIR_FIELD_BIOMETRIC_PURPOSE
                                   | WINBIO_BIR_FIELD_QUALITY);
    header->HeaderVersion = WINBIO_CBEFF_HEADER_VERSION;
    header->PatronHeaderVersion = WINBIO_PATRON_HEADER_VERSION;
    header->DataFlags = (WINBIO_BIR_DATA_FLAGS)(WINBIO_DATA_FLAG_RAW
                                                | WINBIO_DATA_FLAG_OPTION_MASK_PRESENT);
    header->Type = WINBIO_TYPE_FINGERPRINT;
    header->Subtype = Key->SubType;
    header->Purpose = Purpose;
    header->DataQuality = 80;
    header->CreationDate.QuadPart = 0;
    header->ValidityPeriod.BeginDate.QuadPart = 0;
    header->ValidityPeriod.EndDate.QuadPart = 0;
    header->BiometricDataFormat.Owner = WINBIO_ANSI_381_FORMAT_OWNER;
    header->BiometricDataFormat.Type = WINBIO_ANSI_381_FORMAT_TYPE;
    header->ProductId.Owner = WINBIO_ANSI_381_FORMAT_OWNER;
    header->ProductId.Type = WINBIO_ANSI_381_FORMAT_TYPE;

    a381->RecordLength = (ULONG64)(sizeof(WINBIO_BDB_ANSI_381_HEADER)
                                   + sizeof(WINBIO_BDB_ANSI_381_RECORD)
                                   + BIOFAKE_IMAGE_SIZE);
    a381->FormatIdentifier = 0x46495200;    // 'F','I','R',0
    a381->VersionNumber = 0x30313000;       // '0','1','0',0
    a381->ProductId.Owner = WINBIO_ANSI_381_FORMAT_OWNER;
    a381->ProductId.Type = WINBIO_ANSI_381_FORMAT_TYPE;
    a381->CaptureDeviceId = 1;
    a381->ImageAcquisitionLevel = WINBIO_ANSI_381_IMG_ACQ_LEVEL_20;
    a381->HorizontalScanResolution = 500;
    a381->VerticalScanResolution = 500;
    a381->HorizontalImageResolution = 500;
    a381->VerticalImageResolution = 500;
    a381->ElementCount = 1;
    a381->ScaleUnits = WINBIO_ANSI_381_PIXELS_PER_INCH;
    a381->PixelDepth = 8;
    a381->ImageCompressionAlg = WINBIO_ANSI_381_IMG_UNCOMPRESSED;
    a381->Reserved = 0;

    rec->BlockLength = (ULONG)(sizeof(WINBIO_BDB_ANSI_381_RECORD) + BIOFAKE_IMAGE_SIZE);
    rec->HorizontalLineLength = BIOFAKE_IMAGE_W;
    rec->VerticalLineLength = BIOFAKE_IMAGE_H;
    rec->Position = Key->SubType;
    rec->CountOfViews = 1;
    rec->ViewNumber = 1;
    rec->ImageQuality = 0xFE;
    rec->ImpressionType = WINBIO_ANSI_381_IMP_TYPE_LIVE_SCAN_PLAIN;
    rec->Reserved = 0;

    RtlCopyMemory(image, Key->Image, BIOFAKE_IMAGE_SIZE);

    *BirSize = birSize;
}

static
VOID
BioFakeFillCaptureError(
    _Out_ PWINBIO_CAPTURE_DATA CaptureData,
    _In_ HRESULT WinBioHresult,
    _In_ WINBIO_SENSOR_STATUS SensorStatus,
    _In_ WINBIO_REJECT_DETAIL RejectDetail
    )
{
    CaptureData->PayloadSize = (DWORD)sizeof(WINBIO_CAPTURE_DATA);
    CaptureData->WinBioHresult = WinBioHresult;
    CaptureData->SensorStatus = SensorStatus;
    CaptureData->RejectDetail = RejectDetail;
    CaptureData->CaptureData.Size = 0;
}

static
VOID
BioFakeOnGetAttributes(
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength
    )
{
    PWINBIO_SENSOR_ATTRIBUTES attrs = NULL;
    PVOID buffer = NULL;
    size_t size = 0;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(OutputBufferLength);

    status = WdfRequestRetrieveOutputBuffer(Request,
                                            sizeof(DWORD),
                                            &buffer,
                                            &size);
    if (!NT_SUCCESS(status)) {
        WdfRequestComplete(Request, STATUS_INVALID_PARAMETER);
        return;
    }

    if (size < sizeof(WINBIO_SENSOR_ATTRIBUTES)) {
        //
        // Too small: report the required payload size and let the caller
        // retry (same pattern as the WudfBioUsbSample).
        //
        ((PDWORD)buffer)[0] = (DWORD)sizeof(WINBIO_SENSOR_ATTRIBUTES);
        WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(DWORD));
        return;
    }

    attrs = (PWINBIO_SENSOR_ATTRIBUTES)buffer;
    RtlZeroMemory(attrs, size);

    attrs->PayloadSize = (DWORD)sizeof(WINBIO_SENSOR_ATTRIBUTES);
    attrs->WinBioHresult = S_OK;
    attrs->WinBioVersion.MajorVersion = WINBIO_WBDI_MAJOR_VERSION;
    attrs->WinBioVersion.MinorVersion = WINBIO_WBDI_MINOR_VERSION;
    attrs->SensorType = WINBIO_TYPE_FINGERPRINT;
    attrs->SensorSubType = WINBIO_FP_SENSOR_SUBTYPE_TOUCH;
    attrs->Capabilities = WINBIO_CAPABILITY_SENSOR;

    BioFakeStringCopy(attrs->ManufacturerName,
                      WINBIO_MAX_STRING_LEN + 1,
                      L"BioFake Project");
    BioFakeStringCopy(attrs->ModelName,
                      WINBIO_MAX_STRING_LEN + 1,
                      L"BioFake Virtual Fingerprint Sensor");
    BioFakeStringCopy(attrs->SerialNumber,
                      WINBIO_MAX_STRING_LEN + 1,
                      L"BF-0000-0001");

    attrs->FirmwareVersion.MajorVersion = 1;
    attrs->FirmwareVersion.MinorVersion = 0;
    attrs->SupportedFormatEntries = 1;
    attrs->SupportedFormat[0].Owner = WINBIO_ANSI_381_FORMAT_OWNER;
    attrs->SupportedFormat[0].Type = WINBIO_ANSI_381_FORMAT_TYPE;

    WdfRequestCompleteWithInformation(Request,
                                      STATUS_SUCCESS,
                                      attrs->PayloadSize);
}

static
VOID
BioFakeOnReset(
    _In_ WDFREQUEST Request,
    _In_ PDRIVER_CONTEXT Ctx,
    _In_ size_t OutputBufferLength
    )
{
    PWINBIO_BLANK_PAYLOAD payload = NULL;
    PVOID buffer = NULL;
    size_t size = 0;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(OutputBufferLength);

    //
    // Cancel any parked capture request.
    //
    if (Ctx->CaptureQueue != NULL) {
        WdfIoQueuePurgeSynchronously(Ctx->CaptureQueue);
        WdfIoQueueStart(Ctx->CaptureQueue);
    }

    status = WdfRequestRetrieveOutputBuffer(Request,
                                            sizeof(DWORD),
                                            &buffer,
                                            &size);
    if (!NT_SUCCESS(status)) {
        WdfRequestComplete(Request, STATUS_INVALID_PARAMETER);
        return;
    }

    if (size < sizeof(WINBIO_BLANK_PAYLOAD)) {
        ((PDWORD)buffer)[0] = (DWORD)sizeof(WINBIO_BLANK_PAYLOAD);
        WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(DWORD));
        return;
    }

    payload = (PWINBIO_BLANK_PAYLOAD)buffer;
    payload->PayloadSize = (DWORD)sizeof(WINBIO_BLANK_PAYLOAD);
    payload->WinBioHresult = S_OK;

    WdfRequestCompleteWithInformation(Request,
                                      STATUS_SUCCESS,
                                      payload->PayloadSize);
}

static
VOID
BioFakeOnGetSensorStatus(
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength
    )
{
    PWINBIO_DIAGNOSTICS diag = NULL;
    PVOID buffer = NULL;
    size_t size = 0;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(OutputBufferLength);

    status = WdfRequestRetrieveOutputBuffer(Request,
                                            sizeof(DWORD),
                                            &buffer,
                                            &size);
    if (!NT_SUCCESS(status)) {
        WdfRequestComplete(Request, STATUS_INVALID_PARAMETER);
        return;
    }

    if (size < sizeof(WINBIO_DIAGNOSTICS)) {
        ((PDWORD)buffer)[0] = (DWORD)sizeof(WINBIO_DIAGNOSTICS);
        WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(DWORD));
        return;
    }

    diag = (PWINBIO_DIAGNOSTICS)buffer;
    RtlZeroMemory(diag, size);
    diag->PayloadSize = (DWORD)sizeof(WINBIO_DIAGNOSTICS);
    diag->WinBioHresult = S_OK;
    diag->SensorStatus = WINBIO_SENSOR_READY;
    diag->VendorDiagnostics.Size = 0;

    WdfRequestCompleteWithInformation(Request,
                                      STATUS_SUCCESS,
                                      diag->PayloadSize);
}

static
VOID
BioFakeOnCalibrate(
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength
    )
{
    PWINBIO_CALIBRATION_INFO cal = NULL;
    PVOID buffer = NULL;
    size_t size = 0;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(OutputBufferLength);

    status = WdfRequestRetrieveOutputBuffer(Request,
                                            sizeof(DWORD),
                                            &buffer,
                                            &size);
    if (!NT_SUCCESS(status)) {
        WdfRequestComplete(Request, STATUS_INVALID_PARAMETER);
        return;
    }

    if (size < sizeof(WINBIO_CALIBRATION_INFO)) {
        ((PDWORD)buffer)[0] = (DWORD)sizeof(WINBIO_CALIBRATION_INFO);
        WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(DWORD));
        return;
    }

    cal = (PWINBIO_CALIBRATION_INFO)buffer;
    RtlZeroMemory(cal, size);
    cal->PayloadSize = (DWORD)sizeof(WINBIO_CALIBRATION_INFO);
    cal->WinBioHresult = S_OK;
    cal->CalibrationData.Size = 0;

    WdfRequestCompleteWithInformation(Request,
                                      STATUS_SUCCESS,
                                      cal->PayloadSize);
}

static
VOID
BioFakeOnCaptureData(
    _In_ WDFREQUEST Request,
    _In_ PDRIVER_CONTEXT Ctx,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength
    )
{
    PWINBIO_CAPTURE_PARAMETERS params = NULL;
    PWINBIO_CAPTURE_DATA captureData = NULL;
    PVOID inBuffer = NULL;
    PVOID outBuffer = NULL;
    size_t inSize = 0;
    size_t outSize = 0;
    SIZE_T birSize;
    BYTE purpose;
    LONG keyIndex;
    NTSTATUS status;

    status = WdfRequestRetrieveInputBuffer(Request,
                                           sizeof(WINBIO_CAPTURE_PARAMETERS),
                                           &inBuffer,
                                           &inSize);
    if (!NT_SUCCESS(status) || inSize < sizeof(WINBIO_CAPTURE_PARAMETERS)) {
        WdfRequestComplete(Request, STATUS_INVALID_PARAMETER);
        return;
    }

    params = (PWINBIO_CAPTURE_PARAMETERS)inBuffer;

    status = WdfRequestRetrieveOutputBuffer(Request,
                                            sizeof(DWORD),
                                            &outBuffer,
                                            &outSize);
    if (!NT_SUCCESS(status)) {
        WdfRequestComplete(Request, STATUS_INVALID_PARAMETER);
        return;
    }

    if (outSize < sizeof(WINBIO_CAPTURE_DATA)) {
        //
        // Not even room for the fixed header: report the payload size that
        // would be required for a full capture.
        //
        birSize = (Ctx->HasCustom && Ctx->Mode == BIOFAKE_MODE_CUSTOM)
                    ? Ctx->CustomBirSize
                    : BioFakeBirSize();
        ((PDWORD)outBuffer)[0] = (DWORD)(sizeof(WINBIO_CAPTURE_DATA) + birSize);
        WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(DWORD));
        return;
    }

    captureData = (PWINBIO_CAPTURE_DATA)outBuffer;
    purpose = (BYTE)params->Purpose;

    WdfWaitLockAcquire(Ctx->Lock, NULL);

    if (Ctx->Mode == BIOFAKE_MODE_REJECT) {
        BioFakeFillCaptureError(captureData,
                                S_OK,
                                WINBIO_SENSOR_REJECT,
                                WINBIO_FP_POOR_QUALITY);
        WdfWaitLockRelease(Ctx->Lock);
        WdfRequestCompleteWithInformation(Request,
                                          STATUS_SUCCESS,
                                          sizeof(WINBIO_CAPTURE_DATA));
        return;
    }

    if (Ctx->Mode == BIOFAKE_MODE_FAILURE) {
        BioFakeFillCaptureError(captureData,
                                WINBIO_E_DEVICE_FAILURE,
                                WINBIO_SENSOR_FAILURE,
                                0);
        WdfWaitLockRelease(Ctx->Lock);
        WdfRequestCompleteWithInformation(Request,
                                          STATUS_SUCCESS,
                                          sizeof(WINBIO_CAPTURE_DATA));
        return;
    }

    if (Ctx->Mode == BIOFAKE_MODE_CUSTOM && Ctx->HasCustom) {
        SIZE_T blobSize = Ctx->CustomBirSize;
        if (outSize < sizeof(WINBIO_CAPTURE_DATA) + blobSize) {
            WdfWaitLockRelease(Ctx->Lock);
            BioFakeFillCaptureError(captureData,
                                    WINBIO_E_NO_CAPTURE_DATA,
                                    WINBIO_SENSOR_FAILURE,
                                    0);
            WdfRequestCompleteWithInformation(Request,
                                              STATUS_SUCCESS,
                                              sizeof(WINBIO_CAPTURE_DATA));
            return;
        }

        captureData->PayloadSize = (DWORD)(sizeof(WINBIO_CAPTURE_DATA) + blobSize);
        captureData->WinBioHresult = S_OK;
        captureData->SensorStatus = WINBIO_SENSOR_ACCEPT;
        captureData->RejectDetail = 0;
        captureData->CaptureData.Size = (DWORD)blobSize;
        RtlCopyMemory((BYTE*)captureData + sizeof(WINBIO_CAPTURE_DATA),
                      Ctx->CustomBir,
                      blobSize);

        Ctx->CaptureCount++;
        WdfWaitLockRelease(Ctx->Lock);
        WdfRequestCompleteWithInformation(Request,
                                          STATUS_SUCCESS,
                                          sizeof(WINBIO_CAPTURE_DATA) + blobSize);
        return;
    }

    keyIndex = BioFakeFindKey(Ctx, NULL);   // active key
    if (Ctx->Mode == BIOFAKE_MODE_READY && keyIndex >= 0) {
        BioFakeEnsureImage(&Ctx->Keys[keyIndex]);
        birSize = BioFakeBirSize();

        if (outSize < sizeof(WINBIO_CAPTURE_DATA) + birSize ||
            OutputBufferLength < sizeof(WINBIO_CAPTURE_DATA) + birSize) {
            WdfWaitLockRelease(Ctx->Lock);
            BioFakeFillCaptureError(captureData,
                                    WINBIO_E_NO_CAPTURE_DATA,
                                    WINBIO_SENSOR_FAILURE,
                                    0);
            WdfRequestCompleteWithInformation(Request,
                                              STATUS_SUCCESS,
                                              sizeof(WINBIO_CAPTURE_DATA));
            return;
        }

        BioFakeBuildBir(&Ctx->Keys[keyIndex],
                        purpose,
                        (BYTE*)captureData + sizeof(WINBIO_CAPTURE_DATA),
                        birSize,
                        &birSize);

        captureData->PayloadSize = (DWORD)(sizeof(WINBIO_CAPTURE_DATA) + birSize);
        captureData->WinBioHresult = S_OK;
        captureData->SensorStatus = WINBIO_SENSOR_ACCEPT;
        captureData->RejectDetail = 0;
        captureData->CaptureData.Size = (DWORD)birSize;

        Ctx->CaptureCount++;
        WdfWaitLockRelease(Ctx->Lock);
        WdfRequestCompleteWithInformation(Request,
                                          STATUS_SUCCESS,
                                          sizeof(WINBIO_CAPTURE_DATA) + birSize);
        return;
    }

    //
    // No active key (or not in READY mode): park the request in the manual
    // capture queue. It is completed later by biofakectl present/select, or
    // cancelled automatically by the framework.
    //
    WdfRequestForwardToIoQueue(Request, Ctx->CaptureQueue);
    WdfWaitLockRelease(Ctx->Lock);
}

VOID
BioFakeHandleWbdiRequest(
    _In_ PDRIVER_CONTEXT Ctx,
    _In_ WDFREQUEST Request,
    _In_ ULONG IoControlCode,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength
    )
{
    switch (IoControlCode) {
    case IOCTL_BIOMETRIC_GET_ATTRIBUTES:
        BioFakeOnGetAttributes(Request, OutputBufferLength);
        break;

    case IOCTL_BIOMETRIC_RESET:
        BioFakeOnReset(Request, Ctx, OutputBufferLength);
        break;

    case IOCTL_BIOMETRIC_GET_SENSOR_STATUS:
        BioFakeOnGetSensorStatus(Request, OutputBufferLength);
        break;

    case IOCTL_BIOMETRIC_CALIBRATE:
        BioFakeOnCalibrate(Request, OutputBufferLength);
        break;

    case IOCTL_BIOMETRIC_CAPTURE_DATA:
        BioFakeOnCaptureData(Request, Ctx, OutputBufferLength, InputBufferLength);
        break;

    default:
        //
        // Optional IOCTLs (firmware update, algorithms, indicator...) are
        // not advertised in capabilities, so the framework should not send
        // them.
        //
        WdfRequestComplete(Request, STATUS_NOT_IMPLEMENTED);
        break;
    }
}
