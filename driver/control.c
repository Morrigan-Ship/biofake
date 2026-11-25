/*++
control.c

Control node request handling (SWD\BioFakeCtl).

Implements the private IOCTL_BIOFAKE_* channel used by biofakectl.exe:
key add/delete/select, present (manual capture completion), mode switching,
custom BIR injection, status and key listing.

The sensor node is opened exclusively by the Windows Biometric Service, so
this second device node in the same driver/host process is the control path.
--*/

#include "biofake.h"

static
VOID
BioFakeOnAddKey(
    _In_ PDRIVER_CONTEXT Ctx,
    _In_ WDFREQUEST Request
    )
{
    PBIOFAKE_KEY_ADD_IN in;
    PVOID buffer = NULL;
    size_t size = 0;
    PBIOFAKE_KEY key;
    LONG existing;
    NTSTATUS status;

    status = WdfRequestRetrieveInputBuffer(Request,
                                           sizeof(BIOFAKE_KEY_ADD_IN),
                                           &buffer,
                                           &size);
    if (!NT_SUCCESS(status) || size < sizeof(BIOFAKE_KEY_ADD_IN)) {
        WdfRequestComplete(Request, STATUS_INVALID_PARAMETER);
        return;
    }

    in = (PBIOFAKE_KEY_ADD_IN)buffer;
    if (in->Name[0] == L'\0') {
        WdfRequestComplete(Request, STATUS_INVALID_PARAMETER);
        return;
    }

    WdfWaitLockAcquire(Ctx->Lock, NULL);

    existing = BioFakeFindKey(Ctx, in->Name);
    if (existing >= 0) {
        //
        // Re-creating an existing key updates its seed.
        //
        key = &Ctx->Keys[existing];
        RtlCopyMemory(key->Seed, in->Seed, BIOFAKE_SEED_SIZE);
        key->SubType = in->SubType;
        key->ImageBuilt = FALSE;
        WdfWaitLockRelease(Ctx->Lock);
        WdfRequestComplete(Request, STATUS_SUCCESS);
        return;
    }

    if (Ctx->KeyCount >= BIOFAKE_MAX_KEYS) {
        WdfWaitLockRelease(Ctx->Lock);
        WdfRequestComplete(Request, STATUS_INSUFFICIENT_RESOURCES);
        return;
    }

    key = &Ctx->Keys[Ctx->KeyCount];
    RtlZeroMemory(key, sizeof(BIOFAKE_KEY));
    BioFakeStringCopy(key->Name, BIOFAKE_MAX_NAME_CCH, in->Name);
    RtlCopyMemory(key->Seed, in->Seed, BIOFAKE_SEED_SIZE);
    key->SubType = in->SubType;
    key->ImageBuilt = FALSE;
    Ctx->KeyCount++;

    //
    // The first key becomes the active key automatically.
    //
    if (Ctx->ActiveIndex < 0) {
        Ctx->ActiveIndex = (LONG)(Ctx->KeyCount - 1);
    }

    WdfWaitLockRelease(Ctx->Lock);
    WdfRequestComplete(Request, STATUS_SUCCESS);
}

static
VOID
BioFakeOnDeleteKey(
    _In_ PDRIVER_CONTEXT Ctx,
    _In_ WDFREQUEST Request
    )
{
    PBIOFAKE_NAME_IN in;
    PVOID buffer = NULL;
    size_t size = 0;
    ULONG i;
    LONG index;
    NTSTATUS status;

    status = WdfRequestRetrieveInputBuffer(Request,
                                           sizeof(BIOFAKE_NAME_IN),
                                           &buffer,
                                           &size);
    if (!NT_SUCCESS(status) || size < sizeof(BIOFAKE_NAME_IN)) {
        WdfRequestComplete(Request, STATUS_INVALID_PARAMETER);
        return;
    }

    in = (PBIOFAKE_NAME_IN)buffer;

    WdfWaitLockAcquire(Ctx->Lock, NULL);

    index = BioFakeFindKey(Ctx, in->Name);
    if (index < 0) {
        WdfWaitLockRelease(Ctx->Lock);
        WdfRequestComplete(Request, STATUS_NOT_FOUND);
        return;
    }

    for (i = (ULONG)index; i + 1 < Ctx->KeyCount; i++) {
        Ctx->Keys[i] = Ctx->Keys[i + 1];
    }
    Ctx->KeyCount--;

    if ((ULONG)Ctx->ActiveIndex >= Ctx->KeyCount) {
        Ctx->ActiveIndex = (Ctx->KeyCount > 0) ? 0 : -1;
    }

    WdfWaitLockRelease(Ctx->Lock);
    WdfRequestComplete(Request, STATUS_SUCCESS);
}

static
VOID
BioFakeOnSelectKey(
    _In_ PDRIVER_CONTEXT Ctx,
    _In_ WDFREQUEST Request
    )
{
    PBIOFAKE_NAME_IN in;
    PVOID buffer = NULL;
    size_t size = 0;
    LONG index;
    NTSTATUS status;

    status = WdfRequestRetrieveInputBuffer(Request,
                                           sizeof(BIOFAKE_NAME_IN),
                                           &buffer,
                                           &size);
    if (!NT_SUCCESS(status) || size < sizeof(BIOFAKE_NAME_IN)) {
        WdfRequestComplete(Request, STATUS_INVALID_PARAMETER);
        return;
    }

    in = (PBIOFAKE_NAME_IN)buffer;

    WdfWaitLockAcquire(Ctx->Lock, NULL);

    index = BioFakeFindKey(Ctx, in->Name);
    if (index < 0) {
        WdfWaitLockRelease(Ctx->Lock);
        WdfRequestComplete(Request, STATUS_NOT_FOUND);
        return;
    }

    Ctx->ActiveIndex = index;

    //
    // If a capture is already parked (e.g. it arrived while no key was
    // active), answer it right away with the newly selected key.
    //
    BioFakeCompletePendingCapture(Ctx, index);

    WdfWaitLockRelease(Ctx->Lock);
    WdfRequestComplete(Request, STATUS_SUCCESS);
}

static
VOID
BioFakeOnPresentKey(
    _In_ PDRIVER_CONTEXT Ctx,
    _In_ WDFREQUEST Request
    )
{
    PBIOFAKE_NAME_IN in;
    PVOID buffer = NULL;
    size_t size = 0;
    LONG index;
    NTSTATUS status;

    status = WdfRequestRetrieveInputBuffer(Request,
                                           sizeof(BIOFAKE_NAME_IN),
                                           &buffer,
                                           &size);
    if (!NT_SUCCESS(status) || size < sizeof(BIOFAKE_NAME_IN)) {
        WdfRequestComplete(Request, STATUS_INVALID_PARAMETER);
        return;
    }

    in = (PBIOFAKE_NAME_IN)buffer;

    WdfWaitLockAcquire(Ctx->Lock, NULL);

    index = BioFakeFindKey(Ctx, in->Name);  // empty name -> active key
    if (index < 0) {
        WdfWaitLockRelease(Ctx->Lock);
        WdfRequestComplete(Request, STATUS_NOT_FOUND);
        return;
    }

    Ctx->ActiveIndex = index;
    BioFakeCompletePendingCapture(Ctx, index);

    WdfWaitLockRelease(Ctx->Lock);
    WdfRequestComplete(Request, STATUS_SUCCESS);
}

static
VOID
BioFakeOnSetMode(
    _In_ PDRIVER_CONTEXT Ctx,
    _In_ WDFREQUEST Request
    )
{
    PBIOFAKE_MODE_IN in;
    PVOID buffer = NULL;
    size_t size = 0;
    NTSTATUS status;

    status = WdfRequestRetrieveInputBuffer(Request,
                                           sizeof(BIOFAKE_MODE_IN),
                                           &buffer,
                                           &size);
    if (!NT_SUCCESS(status) || size < sizeof(BIOFAKE_MODE_IN)) {
        WdfRequestComplete(Request, STATUS_INVALID_PARAMETER);
        return;
    }

    in = (PBIOFAKE_MODE_IN)buffer;
    if (in->Mode < BIOFAKE_MODE_READY || in->Mode > BIOFAKE_MODE_CUSTOM) {
        WdfRequestComplete(Request, STATUS_INVALID_PARAMETER);
        return;
    }

    WdfWaitLockAcquire(Ctx->Lock, NULL);

    if (in->Mode == BIOFAKE_MODE_CUSTOM && !Ctx->HasCustom) {
        WdfWaitLockRelease(Ctx->Lock);
        WdfRequestComplete(Request, STATUS_INVALID_DEVICE_REQUEST);
        return;
    }

    Ctx->Mode = in->Mode;

    WdfWaitLockRelease(Ctx->Lock);
    WdfRequestComplete(Request, STATUS_SUCCESS);
}

static
VOID
BioFakeOnSetCustom(
    _In_ PDRIVER_CONTEXT Ctx,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength
    )
{
    PVOID buffer = NULL;
    size_t size = 0;
    NTSTATUS status;

    status = WdfRequestRetrieveInputBuffer(Request,
                                           sizeof(WINBIO_BIR),
                                           &buffer,
                                           &size);
    if (!NT_SUCCESS(status) || size < sizeof(WINBIO_BIR)) {
        WdfRequestComplete(Request, STATUS_INVALID_PARAMETER);
        return;
    }

    if (size > BIOFAKE_CUSTOM_BIR_MAX) {
        WdfRequestComplete(Request, STATUS_INVALID_PARAMETER);
        return;
    }

    WdfWaitLockAcquire(Ctx->Lock, NULL);

    RtlCopyMemory(Ctx->CustomBir, buffer, size);
    Ctx->CustomBirSize = size;
    Ctx->HasCustom = TRUE;
    Ctx->Mode = BIOFAKE_MODE_CUSTOM;

    WdfWaitLockRelease(Ctx->Lock);
    WdfRequestComplete(Request, STATUS_SUCCESS);

    UNREFERENCED_PARAMETER(InputBufferLength);
}

static
VOID
BioFakeOnGetStatus(
    _In_ PDRIVER_CONTEXT Ctx,
    _In_ WDFREQUEST Request
    )
{
    PBIOFAKE_STATUS_OUT out;
    PVOID buffer = NULL;
    size_t size = 0;
    NTSTATUS status;

    status = WdfRequestRetrieveOutputBuffer(Request,
                                            sizeof(BIOFAKE_STATUS_OUT),
                                            &buffer,
                                            &size);
    if (!NT_SUCCESS(status) || size < sizeof(BIOFAKE_STATUS_OUT)) {
        WdfRequestComplete(Request, STATUS_INVALID_PARAMETER);
        return;
    }

    out = (PBIOFAKE_STATUS_OUT)buffer;

    WdfWaitLockAcquire(Ctx->Lock, NULL);

    RtlZeroMemory(out, sizeof(BIOFAKE_STATUS_OUT));
    out->Mode = Ctx->Mode;
    out->KeyCount = Ctx->KeyCount;
    out->CaptureCount = Ctx->CaptureCount;
    out->HasCustom = Ctx->HasCustom;

    if (Ctx->ActiveIndex >= 0) {
        BioFakeStringCopy(out->ActiveName,
                          BIOFAKE_MAX_NAME_CCH,
                          Ctx->Keys[Ctx->ActiveIndex].Name);
    }

    WdfWaitLockRelease(Ctx->Lock);

    //
    // Best-effort check whether a capture request is currently parked in
    // the sensor node's manual capture queue. WdfIoQueueGetState reports
    // the queued-request count through its QueueRequests out-parameter.
    //
    out->PendingCapture = FALSE;
    if (Ctx->CaptureQueue != NULL) {
        ULONG queueRequests = 0;

        (VOID)WdfIoQueueGetState(Ctx->CaptureQueue, &queueRequests, NULL);
        out->PendingCapture = (queueRequests > 0) ? TRUE : FALSE;
    }

    WdfRequestCompleteWithInformation(Request,
                                      STATUS_SUCCESS,
                                      sizeof(BIOFAKE_STATUS_OUT));
}

static
VOID
BioFakeOnListKeys(
    _In_ PDRIVER_CONTEXT Ctx,
    _In_ WDFREQUEST Request
    )
{
    PBIOFAKE_KEY_INFO out;
    PVOID buffer = NULL;
    size_t size = 0;
    size_t needed;
    ULONG i;
    NTSTATUS status;

    WdfWaitLockAcquire(Ctx->Lock, NULL);

    needed = (size_t)Ctx->KeyCount * sizeof(BIOFAKE_KEY_INFO);

    status = WdfRequestRetrieveOutputBuffer(Request,
                                            needed,
                                            &buffer,
                                            &size);
    if (!NT_SUCCESS(status) || size < needed) {
        WdfWaitLockRelease(Ctx->Lock);
        WdfRequestComplete(Request, STATUS_INVALID_PARAMETER);
        return;
    }

    out = (PBIOFAKE_KEY_INFO)buffer;
    for (i = 0; i < Ctx->KeyCount; i++) {
        RtlZeroMemory(&out[i], sizeof(BIOFAKE_KEY_INFO));
        BioFakeStringCopy(out[i].Name, BIOFAKE_MAX_NAME_CCH, Ctx->Keys[i].Name);
        out[i].Active = ((LONG)i == Ctx->ActiveIndex) ? TRUE : FALSE;
    }

    WdfWaitLockRelease(Ctx->Lock);

    WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, needed);
}

VOID
BioFakeCompletePendingCapture(
    _In_ PDRIVER_CONTEXT Ctx,
    _In_ LONG KeyIndex
    )
/*++
Completes the oldest parked capture request with the BIR of Keys[KeyIndex].
Caller must hold Ctx->Lock.
--*/
{
    WDFREQUEST request = NULL;
    PWINBIO_CAPTURE_DATA captureData;
    PVOID buffer = NULL;
    size_t size = 0;
    SIZE_T birSize;
    NTSTATUS status;

    if (Ctx->CaptureQueue == NULL || KeyIndex < 0 || KeyIndex >= (LONG)Ctx->KeyCount) {
        return;
    }

    status = WdfIoQueueRetrieveNextRequest(Ctx->CaptureQueue, &request);
    if (!NT_SUCCESS(status)) {
        return;     // nothing parked
    }

    BioFakeEnsureImage(&Ctx->Keys[KeyIndex]);
    birSize = BioFakeBirSize();

    status = WdfRequestRetrieveOutputBuffer(request,
                                            sizeof(WINBIO_CAPTURE_DATA),
                                            &buffer,
                                            &size);
    if (!NT_SUCCESS(status)) {
        WdfRequestComplete(request, STATUS_INVALID_BUFFER_SIZE);
        return;
    }

    if (size < sizeof(WINBIO_CAPTURE_DATA) + birSize) {
        WdfRequestComplete(request, STATUS_INVALID_BUFFER_SIZE);
        return;
    }

    captureData = (PWINBIO_CAPTURE_DATA)buffer;
    captureData->PayloadSize = (DWORD)(sizeof(WINBIO_CAPTURE_DATA) + birSize);
    captureData->WinBioHresult = S_OK;
    captureData->SensorStatus = WINBIO_SENSOR_ACCEPT;
    captureData->RejectDetail = 0;
    captureData->CaptureData.Size = (DWORD)birSize;

    BioFakeBuildBir(&Ctx->Keys[KeyIndex],
                    WINBIO_PURPOSE_VERIFY,
                    (BYTE*)captureData + sizeof(WINBIO_CAPTURE_DATA),
                    birSize,
                    &birSize);

    Ctx->CaptureCount++;
    WdfRequestCompleteWithInformation(request,
                                      STATUS_SUCCESS,
                                      sizeof(WINBIO_CAPTURE_DATA) + birSize);
}

VOID
BioFakeHandleControlRequest(
    _In_ PDRIVER_CONTEXT Ctx,
    _In_ WDFREQUEST Request,
    _In_ ULONG IoControlCode,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength
    )
{
    UNREFERENCED_PARAMETER(OutputBufferLength);

    switch (IoControlCode) {
    case IOCTL_BIOFAKE_ADD_KEY:
        BioFakeOnAddKey(Ctx, Request);
        break;

    case IOCTL_BIOFAKE_DELETE_KEY:
        BioFakeOnDeleteKey(Ctx, Request);
        break;

    case IOCTL_BIOFAKE_SELECT_KEY:
        BioFakeOnSelectKey(Ctx, Request);
        break;

    case IOCTL_BIOFAKE_PRESENT:
        BioFakeOnPresentKey(Ctx, Request);
        break;

    case IOCTL_BIOFAKE_SET_MODE:
        BioFakeOnSetMode(Ctx, Request);
        break;

    case IOCTL_BIOFAKE_SET_CUSTOM:
        BioFakeOnSetCustom(Ctx, Request, InputBufferLength);
        break;

    case IOCTL_BIOFAKE_GET_STATUS:
        BioFakeOnGetStatus(Ctx, Request);
        break;

    case IOCTL_BIOFAKE_LIST_KEYS:
        BioFakeOnListKeys(Ctx, Request);
        break;

    default:
        WdfRequestComplete(Request, STATUS_INVALID_DEVICE_REQUEST);
        break;
    }
}
