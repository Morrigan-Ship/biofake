/*++

THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
ANY KIND, EITHER EXPRESSED OR IMPLIED.

BioFakeEngineAdapter - minimal Windows Biometric Framework engine adapter

Abstract:
    Windows Biometric Service builds a "biometric unit" from a device plus
    three user-mode plug-in adapters (sensor / engine / storage). For WBDI
    drivers the sensor adapter and storage adapter are the in-box DLLs
    (WinBioSensorAdapter.DLL, WinBioStorageAdapter.DLL), but every unit
    still requires an engine adapter.

    This adapter is intentionally a minimal stub:
      - it declares ANSI-381 as the preferred sample format
      - it accepts samples (capture paths work)
      - it does NOT match templates or support enrollment, so Identify /
        Verify always report "no match" and enrollment fails cleanly

    This is exactly what is needed for a *virtual sensor research* device:
    Windows recognizes the hardware, enumerates the biometric unit, and
    raw capture data flows out of the driver.

Environment:
    User mode. Loaded by the Windows Biometric Service (WbioSrvc).

--*/

#ifndef NTDDI_VERSION
#define NTDDI_VERSION NTDDI_WIN10_RS4
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#ifndef WINVER
#define WINVER 0x0A00
#endif

#include <windows.h>
#include <winbio_adapter.h>

//
// {B10FA4CE-8D21-4E9A-B1F3-2A7C6D5E4F03}
//
static const GUID BIOFAKE_ENGINE_ADAPTER_ID = {
    0xb10fa4ce, 0x8d21, 0x4e9a, { 0xb1, 0xf3, 0x2a, 0x7c, 0x6d, 0x5e, 0x4f, 0x03 }
};

typedef struct _ENGINE_CONTEXT {
    ULONGLONG Reserved;
} ENGINE_CONTEXT, *PENGINE_CONTEXT;

static HRESULT
WINAPI
EngineAttach(
    _Inout_ PWINBIO_PIPELINE Pipeline
    )
{
    if (!ARGUMENT_PRESENT(Pipeline)) {
        return E_POINTER;
    }

    Pipeline->EngineContext = (PWINIBIO_ENGINE_CONTEXT)
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(ENGINE_CONTEXT));

    return Pipeline->EngineContext ? S_OK : E_OUTOFMEMORY;
}

static HRESULT
WINAPI
EngineDetach(
    _Inout_ PWINBIO_PIPELINE Pipeline
    )
{
    if (!ARGUMENT_PRESENT(Pipeline)) {
        return E_POINTER;
    }

    if (Pipeline->EngineContext != NULL) {
        HeapFree(GetProcessHeap(), 0, Pipeline->EngineContext);
        Pipeline->EngineContext = NULL;
    }

    return S_OK;
}

static HRESULT
WINAPI
EngineClearContext(
    _Inout_ PWINBIO_PIPELINE Pipeline
    )
{
    return EngineDetach(Pipeline);
}

static HRESULT
WINAPI
EngineQueryPreferredFormat(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _Out_ PWINBIO_REGISTERED_FORMAT StandardFormat,
    _Out_ PWINBIO_UUID VendorFormat
    )
{
    if (!ARGUMENT_PRESENT(Pipeline) ||
        !ARGUMENT_PRESENT(StandardFormat) ||
        !ARGUMENT_PRESENT(VendorFormat)) {
        return E_POINTER;
    }

    //
    // The BioFakeWudf driver produces ANSI-381 fingerprint images.
    //
    StandardFormat->Owner = WINBIO_ANSI_381_FORMAT_OWNER;
    StandardFormat->Type = WINBIO_ANSI_381_FORMAT_TYPE;

    RtlZeroMemory(VendorFormat, sizeof(GUID));

    return S_OK;
}

static HRESULT
WINAPI
EngineQueryIndexVectorSize(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _Out_ PSIZE_T IndexElementCount
    )
{
    if (!ARGUMENT_PRESENT(Pipeline) || !ARGUMENT_PRESENT(IndexElementCount)) {
        return E_POINTER;
    }

    //
    // No template indexing is performed by the stub engine.
    //
    *IndexElementCount = 0;

    return S_OK;
}

static HRESULT
WINAPI
EngineQueryHashAlgorithms(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _Out_ PSIZE_T AlgorithmCount,
    _Out_ PSIZE_T AlgorithmBufferSize,
    _Outptr_result_bytebuffer_all_(*AlgorithmBufferSize) PUCHAR *AlgorithmBuffer
    )
{
    UNREFERENCED_PARAMETER(Pipeline);
    UNREFERENCED_PARAMETER(AlgorithmCount);
    UNREFERENCED_PARAMETER(AlgorithmBufferSize);
    UNREFERENCED_PARAMETER(AlgorithmBuffer);

    //
    // No template hashing -> enrollment is not supported. Returning no
    // algorithms keeps the unit usable for capture-only scenarios.
    //
    return E_NOTIMPL;
}

static HRESULT
WINAPI
EngineSetHashAlgorithm(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _In_ SIZE_T AlgorithmBufferSize,
    _In_reads_z_(AlgorithmBufferSize) PUCHAR AlgorithmBuffer
    )
{
    UNREFERENCED_PARAMETER(Pipeline);
    UNREFERENCED_PARAMETER(AlgorithmBufferSize);
    UNREFERENCED_PARAMETER(AlgorithmBuffer);

    return E_NOTIMPL;
}

static HRESULT
WINAPI
EngineQuerySampleHint(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _Out_ PSIZE_T SampleHint
    )
{
    if (!ARGUMENT_PRESENT(Pipeline) || !ARGUMENT_PRESENT(SampleHint)) {
        return E_POINTER;
    }

    *SampleHint = 1;

    return S_OK;
}

static HRESULT
WINAPI
EngineAcceptSampleData(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _In_reads_bytes_(SampleSize) PWINBIO_BIR SampleBuffer,
    _In_ SIZE_T SampleSize,
    _In_ WINBIO_BIR_PURPOSE Purpose,
    _Out_ PWINBIO_REJECT_DETAIL RejectDetail
    )
{
    UNREFERENCED_PARAMETER(SampleBuffer);
    UNREFERENCED_PARAMETER(SampleSize);
    UNREFERENCED_PARAMETER(Purpose);

    if (!ARGUMENT_PRESENT(Pipeline) || !ARGUMENT_PRESENT(RejectDetail)) {
        return E_POINTER;
    }

    //
    // The stub engine "accepts" every sample (no feature extraction).
    //
    *RejectDetail = 0;

    return S_OK;
}

static HRESULT
WINAPI
EngineExportEngineData(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _In_ WINBIO_BIR_DATA_FLAGS Flags,
    _Outptr_result_bytebuffer_all_(*SampleSize) PWINBIO_BIR *SampleBuffer,
    _Out_ PSIZE_T SampleSize
    )
{
    UNREFERENCED_PARAMETER(Pipeline);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(SampleBuffer);
    UNREFERENCED_PARAMETER(SampleSize);

    return E_NOTIMPL;
}

static HRESULT
WINAPI
EngineVerifyFeatureSet(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _In_ PWINBIO_IDENTITY Identity,
    _In_ WINBIO_BIOMETRIC_SUBTYPE SubFactor,
    _Out_ PBOOLEAN Match,
    _Outptr_result_bytebuffer_all_(*PayloadBlobSize) PUCHAR *PayloadBlob,
    _Out_ PSIZE_T *PayloadBlobSize,
    _Outptr_result_bytebuffer_all_(*HashSize) PUCHAR *HashValue,
    _Out_ PSIZE_T *HashSize,
    _Out_ PWINBIO_REJECT_DETAIL RejectDetail
    )
{
    UNREFERENCED_PARAMETER(Identity);
    UNREFERENCED_PARAMETER(SubFactor);

    if (!ARGUMENT_PRESENT(Pipeline) ||
        !ARGUMENT_PRESENT(Match) ||
        !ARGUMENT_PRESENT(RejectDetail)) {
        return E_POINTER;
    }

    *Match = FALSE;
    *RejectDetail = WINBIO_FP_POOR_QUALITY;

    if (ARGUMENT_PRESENT(PayloadBlob)) {
        *PayloadBlob = NULL;
    }
    if (ARGUMENT_PRESENT(PayloadBlobSize)) {
        *PayloadBlobSize = 0;
    }
    if (ARGUMENT_PRESENT(HashValue)) {
        *HashValue = NULL;
    }
    if (ARGUMENT_PRESENT(HashSize)) {
        *HashSize = 0;
    }

    return WINBIO_E_NO_MATCH;
}

static HRESULT
WINAPI
EngineIdentifyFeatureSet(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _Out_ PWINBIO_IDENTITY Identity,
    _Out_ PWINBIO_BIOMETRIC_SUBTYPE SubFactor,
    _Outptr_result_bytebuffer_all_(*PayloadBlobSize) PUCHAR *PayloadBlob,
    _Out_ PSIZE_T *PayloadBlobSize,
    _Outptr_result_bytebuffer_all_(*HashSize) PUCHAR *HashValue,
    _Out_ PSIZE_T *HashSize,
    _Out_ PWINBIO_REJECT_DETAIL RejectDetail
    )
{
    if (!ARGUMENT_PRESENT(Pipeline) ||
        !ARGUMENT_PRESENT(Identity) ||
        !ARGUMENT_PRESENT(SubFactor) ||
        !ARGUMENT_PRESENT(RejectDetail)) {
        return E_POINTER;
    }

    RtlZeroMemory(Identity, sizeof(WINBIO_IDENTITY));
    Identity->Type = WINBIO_ID_TYPE_NULL;
    *SubFactor = WINBIO_SUBTYPE_NO_INFORMATION;
    *RejectDetail = WINBIO_FP_POOR_QUALITY;

    if (ARGUMENT_PRESENT(PayloadBlob)) {
        *PayloadBlob = NULL;
    }
    if (ARGUMENT_PRESENT(PayloadBlobSize)) {
        *PayloadBlobSize = 0;
    }
    if (ARGUMENT_PRESENT(HashValue)) {
        *HashValue = NULL;
    }
    if (ARGUMENT_PRESENT(HashSize)) {
        *HashSize = 0;
    }

    return WINBIO_E_NO_MATCH;
}

static HRESULT
WINAPI
EngineCreateEnrollment(_Inout_ PWINBIO_PIPELINE Pipeline)
{
    UNREFERENCED_PARAMETER(Pipeline);
    return E_NOTIMPL;
}

static HRESULT
WINAPI
EngineUpdateEnrollment(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _Out_ PWINBIO_REJECT_DETAIL RejectDetail
    )
{
    UNREFERENCED_PARAMETER(Pipeline);

    if (ARGUMENT_PRESENT(RejectDetail)) {
        *RejectDetail = 0;
    }

    return E_NOTIMPL;
}

static HRESULT
WINAPI
EngineGetEnrollmentStatus(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _Out_ PWINBIO_REJECT_DETAIL RejectDetail
    )
{
    UNREFERENCED_PARAMETER(Pipeline);

    if (ARGUMENT_PRESENT(RejectDetail)) {
        *RejectDetail = 0;
    }

    return E_NOTIMPL;
}

static HRESULT
WINAPI
EngineGetEnrollmentHash(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _Outptr_result_bytebuffer_all_(*HashSize) PUCHAR *HashValue,
    _Out_ PSIZE_T *HashSize
    )
{
    UNREFERENCED_PARAMETER(Pipeline);
    UNREFERENCED_PARAMETER(HashValue);
    UNREFERENCED_PARAMETER(HashSize);

    return E_NOTIMPL;
}

static HRESULT
WINAPI
EngineCheckForDuplicate(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _Out_ PWINBIO_IDENTITY Identity,
    _Out_ PWINBIO_BIOMETRIC_SUBTYPE SubFactor,
    _Out_ PBOOLEAN Duplicate
    )
{
    UNREFERENCED_PARAMETER(Pipeline);

    if (ARGUMENT_PRESENT(Identity)) {
        RtlZeroMemory(Identity, sizeof(WINBIO_IDENTITY));
        Identity->Type = WINBIO_ID_TYPE_NULL;
    }
    if (ARGUMENT_PRESENT(SubFactor)) {
        *SubFactor = WINBIO_SUBTYPE_NO_INFORMATION;
    }
    if (ARGUMENT_PRESENT(Duplicate)) {
        *Duplicate = FALSE;
    }

    return E_NOTIMPL;
}

static HRESULT
WINAPI
EngineCommitEnrollment(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _In_ PWINBIO_IDENTITY Identity,
    _In_ WINBIO_BIOMETRIC_SUBTYPE SubFactor,
    _In_reads_bytes_(PayloadBlobSize) PUCHAR PayloadBlob,
    _In_ SIZE_T PayloadBlobSize
    )
{
    UNREFERENCED_PARAMETER(Pipeline);
    UNREFERENCED_PARAMETER(Identity);
    UNREFERENCED_PARAMETER(SubFactor);
    UNREFERENCED_PARAMETER(PayloadBlob);
    UNREFERENCED_PARAMETER(PayloadBlobSize);

    return E_NOTIMPL;
}

static HRESULT
WINAPI
EngineDiscardEnrollment(_Inout_ PWINBIO_PIPELINE Pipeline)
{
    UNREFERENCED_PARAMETER(Pipeline);
    return E_NOTIMPL;
}

static HRESULT
WINAPI
EngineControlUnit(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _In_ ULONG ControlCode,
    _In_reads_bytes_(SendBufferSize) PUCHAR SendBuffer,
    _In_ SIZE_T SendBufferSize,
    _Out_writes_bytes_to_(ReceiveBufferSize, *ReceiveDataSize) PUCHAR ReceiveBuffer,
    _In_ SIZE_T ReceiveBufferSize,
    _Out_ PSIZE_T ReceiveDataSize,
    _Out_ PULONG OperationStatus
    )
{
    UNREFERENCED_PARAMETER(Pipeline);
    UNREFERENCED_PARAMETER(ControlCode);
    UNREFERENCED_PARAMETER(SendBuffer);
    UNREFERENCED_PARAMETER(SendBufferSize);
    UNREFERENCED_PARAMETER(ReceiveBuffer);
    UNREFERENCED_PARAMETER(ReceiveBufferSize);

    if (ARGUMENT_PRESENT(ReceiveDataSize)) {
        *ReceiveDataSize = 0;
    }
    if (ARGUMENT_PRESENT(OperationStatus)) {
        *OperationStatus = (ULONG)E_NOTIMPL;
    }

    return E_NOTIMPL;
}

static HRESULT
WINAPI
EngineControlUnitPrivileged(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _In_ ULONG ControlCode,
    _In_reads_bytes_(SendBufferSize) PUCHAR SendBuffer,
    _In_ SIZE_T SendBufferSize,
    _Out_writes_bytes_to_(ReceiveBufferSize, *ReceiveDataSize) PUCHAR ReceiveBuffer,
    _In_ SIZE_T ReceiveBufferSize,
    _Out_ PSIZE_T ReceiveDataSize,
    _Out_ PULONG OperationStatus
    )
{
    return EngineControlUnit(Pipeline,
                             ControlCode,
                             SendBuffer,
                             SendBufferSize,
                             ReceiveBuffer,
                             ReceiveBufferSize,
                             ReceiveDataSize,
                             OperationStatus);
}

static HRESULT
WINAPI
EngineNotifyPowerChange(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _In_ ULONG PowerEventType
    )
{
    UNREFERENCED_PARAMETER(Pipeline);
    UNREFERENCED_PARAMETER(PowerEventType);

    return S_OK;
}

//
// Interface dispatch table. Interface version 2.0 covers everything a
// capture-only fingerprint engine needs on Windows 7 through Windows 11.
// V3+ members are left NULL; the framework wrappers answer E_NOTIMPL.
//
static WINBIO_ENGINE_INTERFACE g_BioFakeEngineInterface = {
    WINBIO_ENGINE_INTERFACE_VERSION_2,          // Version
    WINBIO_ADAPTER_TYPE_ENGINE,                 // Type
    sizeof(WINBIO_ENGINE_INTERFACE),            // Size
    { 0xb10fa4ce, 0x8d21, 0x4e9a,               // AdapterId
      { 0xb1, 0xf3, 0x2a, 0x7c, 0x6d, 0x5e, 0x4f, 0x03 } },

    EngineAttach,                               // Attach
    EngineDetach,                               // Detach
    EngineClearContext,                         // ClearContext
    EngineQueryPreferredFormat,                 // QueryPreferredFormat
    EngineQueryIndexVectorSize,                 // QueryIndexVectorSize
    EngineQueryHashAlgorithms,                  // QueryHashAlgorithms
    EngineSetHashAlgorithm,                     // SetHashAlgorithm
    EngineQuerySampleHint,                      // QuerySampleHint
    EngineAcceptSampleData,                     // AcceptSampleData
    EngineExportEngineData,                     // ExportEngineData
    EngineVerifyFeatureSet,                     // VerifyFeatureSet
    EngineIdentifyFeatureSet,                   // IdentifyFeatureSet
    EngineCreateEnrollment,                     // CreateEnrollment
    EngineUpdateEnrollment,                     // UpdateEnrollment
    EngineGetEnrollmentStatus,                  // GetEnrollmentStatus
    EngineGetEnrollmentHash,                    // GetEnrollmentHash
    EngineCheckForDuplicate,                    // CheckForDuplicate
    EngineCommitEnrollment,                     // CommitEnrollment
    EngineDiscardEnrollment,                    // DiscardEnrollment
    EngineControlUnit,                          // ControlUnit
    EngineControlUnitPrivileged,                // ControlUnitPrivileged

    //
    // V2.0 methods
    //
    EngineNotifyPowerChange,                    // NotifyPowerChange
    NULL,                                       // Reserved_1

    //
    // V3.0 methods
    //
    NULL,                                       // PipelineInit
    NULL,                                       // PipelineCleanup
    NULL,                                       // Activate
    NULL,                                       // Deactivate
    NULL,                                       // QueryExtendedInfo
    NULL,                                       // IdentifyAll
    NULL,                                       // SetEnrollmentSelector
    NULL,                                       // SetEnrollmentParameters
    NULL,                                       // QueryExtendedEnrollmentStatus
    NULL,                                       // RefreshCache
    NULL,                                       // SelectCalibrationFormat
    NULL,                                       // QueryCalibrationData
    NULL,                                       // SetAccountPolicy

    //
    // V4.0 methods
    //
    NULL,                                       // CreateKey
    NULL,                                       // IdentifyFeatureSetSecure

    //
    // V5.0 methods
    //
    NULL,                                       // AcceptPrivateSensorTypeInfo

    //
    // V6.0 methods
    //
    NULL,                                       // CreateEnrollmentAuthenticated
    NULL                                        // IdentifyFeatureSetAuthenticated
};

HRESULT
WINAPI
WbioQueryEngineInterface(
    _Out_ PWINBIO_ENGINE_INTERFACE *EngineInterface
    )
{
    if (!ARGUMENT_PRESENT(EngineInterface)) {
        return E_POINTER;
    }

    *EngineInterface = &g_BioFakeEngineInterface;

    return S_OK;
}
