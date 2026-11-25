/*++
biofake.h

BioFake WBDI driver - internal header.
--*/

#pragma once

#include <windows.h>
#include <wdf.h>
#include <winbio_types.h>
#include <winbio_ioctl.h>

#include "..\shared\biofake_shared.h"

//////////////////////////////////////////////////////////////////////////////
// Synthetic capture geometry
//////////////////////////////////////////////////////////////////////////////

#define BIOFAKE_IMAGE_W     128
#define BIOFAKE_IMAGE_H     128
#define BIOFAKE_IMAGE_SIZE  (BIOFAKE_IMAGE_W * BIOFAKE_IMAGE_H)     // 8bpp grayscale

//////////////////////////////////////////////////////////////////////////////
// Driver-wide context (shared by the sensor and control device nodes,
// both live in the same WUDFHost process)
//////////////////////////////////////////////////////////////////////////////

typedef struct _BIOFAKE_KEY {
    WCHAR Name[BIOFAKE_MAX_NAME_CCH];
    BYTE  Seed[BIOFAKE_SEED_SIZE];
    BYTE  SubType;
    BOOLEAN ImageBuilt;
    BYTE  Image[BIOFAKE_IMAGE_SIZE];    // lazily generated, deterministic
} BIOFAKE_KEY, *PBIOFAKE_KEY;

typedef struct _DRIVER_CONTEXT {
    WDFWAITLOCK  Lock;
    BIOFAKE_KEY  Keys[BIOFAKE_MAX_KEYS];
    ULONG        KeyCount;
    LONG         ActiveIndex;           // -1 = none
    ULONG        Mode;                  // BIOFAKE_MODE
    BOOLEAN      HasCustom;
    BYTE         CustomBir[BIOFAKE_CUSTOM_BIR_MAX];
    SIZE_T       CustomBirSize;
    WDFQUEUE     CaptureQueue;          // manual queue of the sensor node (NULL until created)
    ULONG        CaptureCount;
} DRIVER_CONTEXT, *PDRIVER_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DRIVER_CONTEXT, BioFakeGetDriverContext)

//////////////////////////////////////////////////////////////////////////////
// Per-device context
//////////////////////////////////////////////////////////////////////////////

typedef struct _DEVICE_CONTEXT {
    BOOLEAN IsSensor;                   // TRUE = WBDI sensor node, FALSE = control node
} DEVICE_CONTEXT, *PDEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DEVICE_CONTEXT, BioFakeGetDeviceContext)

//////////////////////////////////////////////////////////////////////////////
// driver.c
//////////////////////////////////////////////////////////////////////////////

VOID
BioFakeStringCopy(
    _Out_writes_(cchDst) WCHAR* dst,
    _In_ SIZE_T cchDst,
    _In_opt_ PCWSTR src
    );

//////////////////////////////////////////////////////////////////////////////
// device.c
//////////////////////////////////////////////////////////////////////////////

NTSTATUS
BioFakeEvtDeviceAdd(
    _In_ WDFDRIVER Driver,
    _Inout_ PWDFDEVICE_INIT DeviceInit
    );

VOID
BioFakeEvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode
    );

//////////////////////////////////////////////////////////////////////////////
// keys.c
//////////////////////////////////////////////////////////////////////////////

BOOLEAN
BioFakeNameEqualI(
    _In_opt_ PCWSTR a,
    _In_opt_ PCWSTR b
    );

// Returns index into ctx->Keys, or -1. Caller must hold ctx->Lock.
LONG
BioFakeFindKey(
    _In_ DRIVER_CONTEXT* Ctx,
    _In_opt_ PCWSTR Name
    );

// Generates the deterministic fingerprint image for the key on first use.
VOID
BioFakeEnsureImage(
    _Inout_ BIOFAKE_KEY* Key
    );

//////////////////////////////////////////////////////////////////////////////
// wbdi.c
//////////////////////////////////////////////////////////////////////////////

// Builds a WINBIO_BIR (CBEFF header + ANSI 381 raw fingerprint image) for the
// key into Out. *BirSize receives the total size.
VOID
BioFakeBuildBir(
    _In_ const BIOFAKE_KEY* Key,
    _In_ BYTE Purpose,
    _Out_writes_(Cap) BYTE* Out,
    _In_ SIZE_T Cap,
    _Out_ SIZE_T* BirSize
    );

SIZE_T
BioFakeBirSize(
    VOID
    );

// Sensor-side WBDI request handling (dispatched by BioFakeEvtIoDeviceControl).
VOID
BioFakeHandleWbdiRequest(
    _In_ DRIVER_CONTEXT* Ctx,
    _In_ WDFREQUEST Request,
    _In_ ULONG IoControlCode,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength
    );

//////////////////////////////////////////////////////////////////////////////
// control.c
//////////////////////////////////////////////////////////////////////////////

// Control-side private IOCTL handling.
VOID
BioFakeHandleControlRequest(
    _In_ DRIVER_CONTEXT* Ctx,
    _In_ WDFREQUEST Request,
    _In_ ULONG IoControlCode,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength
    );

// If a capture request is parked in the manual capture queue, complete it now
// with the BIR of Keys[KeyIndex]. Caller must hold Ctx->Lock.
VOID
BioFakeCompletePendingCapture(
    _In_ DRIVER_CONTEXT* Ctx,
    _In_ LONG KeyIndex
    );
