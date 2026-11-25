/*++
engine.c

BioFake WinBio Engine Adapter.

Loaded by the Windows Biometric Service (WbioSrvc) as the engine plug-in of
the BioFake biometric unit. The INF wires it in via:

  HKR,WinBio\Configurations\0,EngineAdapterBinary,,"BioFakeEngineAdapter.dll"

Matching model
--------------
Captured samples are raw ANSI 381 fingerprint images produced by the BioFake
virtual sensor. Every capture for the same key is byte-identical, so the
"feature set" of a sample is simply the SHA-256 of its Standard Data Block
(the image bytes). A template is a vendor-format BIR carrying the enrolled
hash; verify/identify compare hashes against the template database maintained
by the built-in storage adapter.

Template blob layout (inside the BIR Vendor Data Block):

  ULONG Magic;    // 0x454B4642 ('BFKE')
  ULONG Version;  // 1
  BYTE  Hash[32]; // SHA-256 of the enrolled sample's standard data block
--*/

#include <initguid.h>
#include <windows.h>

// winbio_adapter.h uses the DDK-style ARGUMENT_PRESENT macro inside its
// inline WbioSensor*/WbioStorage* helper functions. That macro comes from
// ntdef.h in kernel-mode builds; user-mode headers never define it, so the
// compiler reports C4013 and treats it as an implicit int function. Define
// it here, before the adapter header, unless it is already available.
#ifndef ARGUMENT_PRESENT
#define ARGUMENT_PRESENT(arg) ((arg) != NULL)
#endif

#include <winbio_adapter.h>
#include <bcrypt.h>

#include "..\shared\biofake_shared.h"

#define BIOFAKE_TEMPLATE_MAGIC      0x454B4642UL    // 'BFKE'
#define BIOFAKE_TEMPLATE_VERSION    1
#define BIOFAKE_HASH_SIZE           32

#define BIOFAKE_SHA256_OID          "2.16.840.1.101.3.4.2.1"

typedef struct _BIOFAKE_TEMPLATE_BLOB {
    ULONG Magic;
    ULONG Version;
    BYTE  Hash[BIOFAKE_HASH_SIZE];
} BIOFAKE_TEMPLATE_BLOB, *PBIOFAKE_TEMPLATE_BLOB;

typedef struct _BIOFAKE_ENGINE_CONTEXT {
    BOOLEAN HasCurrentSample;
    BYTE    CurrentHash[BIOFAKE_HASH_SIZE];     // hash of the latest accepted sample

    BOOLEAN Enrolling;
    BYTE    EnrollHash[BIOFAKE_HASH_SIZE];      // merged enrollment hash
    ULONG   SampleCount;

    BOOLEAN HasTemplate;                        // PROCESSED template available
    BYTE    TemplateHash[BIOFAKE_HASH_SIZE];
} BIOFAKE_ENGINE_CONTEXT, *PBIOFAKE_ENGINE_CONTEXT;

//////////////////////////////////////////////////////////////////////////////
// Helpers
//////////////////////////////////////////////////////////////////////////////

static
PVOID
BioFakeEngineAlloc(
    _In_ PWINBIO_PIPELINE Pipeline,
    _In_ SIZE_T Size
    )
/*++
Buffers returned to the framework must be allocated with the framework's
AllocateMemory callback (RS2+) so the service can free them with FreeMemory.
Falls back to HeapAlloc (the framework's own allocator is the process heap).
--*/
{
    PVOID p = NULL;

    if (Pipeline != NULL &&
        Pipeline->FrameworkInterface != NULL &&
        Pipeline->FrameworkInterface->AllocateMemory != NULL) {
        if (SUCCEEDED(Pipeline->FrameworkInterface->AllocateMemory(Pipeline, Size, &p))) {
            return p;
        }
        return NULL;
    }

    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Size);
}

static
VOID
BioFakeEngineFree(
    _In_ PWINBIO_PIPELINE Pipeline,
    _In_opt_ PVOID p
    )
{
    if (p == NULL) {
        return;
    }

    if (Pipeline != NULL &&
        Pipeline->FrameworkInterface != NULL &&
        Pipeline->FrameworkInterface->FreeMemory != NULL) {
        Pipeline->FrameworkInterface->FreeMemory(Pipeline, p);
        return;
    }

    HeapFree(GetProcessHeap(), 0, p);
}

static
HRESULT
BioFakeSha256(
    _In_reads_bytes_(Size) const BYTE* Data,
    _In_ SIZE_T Size,
    _Out_ BYTE Hash[BIOFAKE_HASH_SIZE]
    )
{
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    NTSTATUS st;

    st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(st)) {
        return E_FAIL;
    }

    st = BCryptCreateHash(alg, &hash, NULL, 0, NULL, 0, 0);
    if (!BCRYPT_SUCCESS(st)) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return E_FAIL;
    }

    st = BCryptHashData(hash, (PUCHAR)Data, (ULONG)Size, 0);
    if (!BCRYPT_SUCCESS(st)) {
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(alg, 0);
        return E_FAIL;
    }

    st = BCryptFinishHash(hash, Hash, BIOFAKE_HASH_SIZE, 0);

    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);

    return BCRYPT_SUCCESS(st) ? S_OK : E_FAIL;
}

static
BOOLEAN
BioFakeParseTemplateBlob(
    _In_reads_bytes_(BlobSize) const BYTE* Blob,
    _In_ SIZE_T BlobSize,
    _Out_ BYTE Hash[BIOFAKE_HASH_SIZE]
    )
/*++
Extracts the enrolled hash from a template BIR produced by
EngineAdapterExportEngineData(PROCESSED).
--*/
{
    PWINBIO_BIR bir;
    PBIOFAKE_TEMPLATE_BLOB blob;

    if (Blob == NULL || BlobSize < sizeof(WINBIO_BIR) + sizeof(BIOFAKE_TEMPLATE_BLOB)) {
        return FALSE;
    }

    bir = (PWINBIO_BIR)Blob;

    if (bir->VendorDataBlock.Size != sizeof(BIOFAKE_TEMPLATE_BLOB) ||
        bir->VendorDataBlock.Offset == 0 ||
        (SIZE_T)bir->VendorDataBlock.Offset + bir->VendorDataBlock.Size > BlobSize) {
        return FALSE;
    }

    blob = (PBIOFAKE_TEMPLATE_BLOB)(Blob + bir->VendorDataBlock.Offset);

    if (blob->Magic != BIOFAKE_TEMPLATE_MAGIC || blob->Version != BIOFAKE_TEMPLATE_VERSION) {
        return FALSE;
    }

    RtlCopyMemory(Hash, blob->Hash, BIOFAKE_HASH_SIZE);
    return TRUE;
}

static
VOID
BioFakeBuildExportBir(
    _In_ WINBIO_BIR_DATA_FLAGS Flags,
    _In_reads_bytes_(BIOFAKE_HASH_SIZE) const BYTE* Hash,
    _Out_ PVOID Buffer
    )
/*++
Lays out a BIR: [WINBIO_BIR][WINBIO_BIR_HEADER][BIOFAKE_TEMPLATE_BLOB]
--*/
{
    PWINBIO_BIR bir = (PWINBIO_BIR)Buffer;
    PWINBIO_BIR_HEADER header;
    PBIOFAKE_TEMPLATE_BLOB blob;

    RtlZeroMemory(Buffer,
                  sizeof(WINBIO_BIR) + sizeof(WINBIO_BIR_HEADER) + sizeof(BIOFAKE_TEMPLATE_BLOB));

    bir->HeaderBlock.Size = (ULONG)sizeof(WINBIO_BIR_HEADER);
    bir->HeaderBlock.Offset = (ULONG)sizeof(WINBIO_BIR);
    bir->StandardDataBlock.Size = 0;
    bir->StandardDataBlock.Offset = 0;
    bir->VendorDataBlock.Size = (ULONG)sizeof(BIOFAKE_TEMPLATE_BLOB);
    bir->VendorDataBlock.Offset = (ULONG)(sizeof(WINBIO_BIR) + sizeof(WINBIO_BIR_HEADER));
    bir->SignatureBlock.Size = 0;
    bir->SignatureBlock.Offset = 0;

    header = (PWINBIO_BIR_HEADER)((BYTE*)Buffer + sizeof(WINBIO_BIR));
    header->ValidFields = (USHORT)(WINBIO_BIR_FIELD_CBEFF_HEADER_VERSION
                                   | WINBIO_BIR_FIELD_PATRON_HEADER_VERSION
                                   | WINBIO_BIR_FIELD_BIOMETRIC_TYPE
                                   | WINBIO_BIR_FIELD_BIOMETRIC_SUBTYPE
                                   | WINBIO_BIR_FIELD_BIOMETRIC_PURPOSE
                                   | WINBIO_BIR_FIELD_QUALITY);
    header->HeaderVersion = WINBIO_CBEFF_HEADER_VERSION;
    header->PatronHeaderVersion = WINBIO_PATRON_HEADER_VERSION;
    header->DataFlags = (WINBIO_BIR_DATA_FLAGS)(Flags | WINBIO_DATA_FLAG_OPTION_MASK_PRESENT);
    header->Type = WINBIO_TYPE_FINGERPRINT;
    header->Subtype = WINBIO_SUBTYPE_NO_INFORMATION;
    header->Purpose = (WINBIO_BIR_PURPOSE)(WINBIO_PURPOSE_ENROLL
                                           | WINBIO_PURPOSE_VERIFY
                                           | WINBIO_PURPOSE_IDENTIFY);
    header->DataQuality = 90;
    header->CreationDate.QuadPart = 0;
    header->ValidityPeriod.BeginDate.QuadPart = 0;
    header->ValidityPeriod.EndDate.QuadPart = 0;
    header->BiometricDataFormat.Owner = 0;
    header->BiometricDataFormat.Type = 0;
    header->ProductId.Owner = 0;
    header->ProductId.Type = 0;

    blob = (PBIOFAKE_TEMPLATE_BLOB)((BYTE*)Buffer + bir->VendorDataBlock.Offset);
    blob->Magic = BIOFAKE_TEMPLATE_MAGIC;
    blob->Version = BIOFAKE_TEMPLATE_VERSION;
    RtlCopyMemory(blob->Hash, Hash, BIOFAKE_HASH_SIZE);
}

//////////////////////////////////////////////////////////////////////////////
// V1.0 engine adapter callbacks
//////////////////////////////////////////////////////////////////////////////

static
HRESULT
WINAPI
EngineAdapterAttach(
    _Inout_ PWINBIO_PIPELINE Pipeline
    )
{
    PBIOFAKE_ENGINE_CONTEXT ctx;

    if (!ARGUMENT_PRESENT(Pipeline)) {
        return E_POINTER;
    }

    ctx = (PBIOFAKE_ENGINE_CONTEXT)HeapAlloc(GetProcessHeap(),
                                             HEAP_ZERO_MEMORY,
                                             sizeof(BIOFAKE_ENGINE_CONTEXT));
    if (ctx == NULL) {
        return E_OUTOFMEMORY;
    }

    // Pipeline->EngineContext is PWINIBIO_ENGINE_CONTEXT, an opaque pointer
    // type declared by winbio_adapter.h. Route through PVOID so the private
    // context can be stored without an incompatible-pointer warning.
    Pipeline->EngineContext = (PVOID)ctx;
    return S_OK;
}

static
HRESULT
WINAPI
EngineAdapterDetach(
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

static
HRESULT
WINAPI
EngineAdapterClearContext(
    _Inout_ PWINBIO_PIPELINE Pipeline
    )
{
    PBIOFAKE_ENGINE_CONTEXT ctx;

    if (!ARGUMENT_PRESENT(Pipeline)) {
        return E_POINTER;
    }

    ctx = (PBIOFAKE_ENGINE_CONTEXT)Pipeline->EngineContext;
    if (ctx != NULL) {
        RtlZeroMemory(ctx, sizeof(BIOFAKE_ENGINE_CONTEXT));
    }

    return S_OK;
}

static
HRESULT
WINAPI
EngineAdapterQueryPreferredFormat(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _Out_ PWINBIO_REGISTERED_FORMAT StandardFormat,
    _Out_ PWINBIO_UUID VendorFormat
    )
{
    UNREFERENCED_PARAMETER(Pipeline);

    if (!ARGUMENT_PRESENT(StandardFormat) || !ARGUMENT_PRESENT(VendorFormat)) {
        return E_POINTER;
    }

    // Raw ANSI 381 fingerprint images.
    StandardFormat->Owner = WINBIO_ANSI_381_FORMAT_OWNER;
    StandardFormat->Type = WINBIO_ANSI_381_FORMAT_TYPE;

    RtlZeroMemory(VendorFormat, sizeof(WINBIO_UUID));

    return S_OK;
}

static
HRESULT
WINAPI
EngineAdapterQueryIndexVectorSize(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _Out_ PSIZE_T IndexElementCount
    )
{
    UNREFERENCED_PARAMETER(Pipeline);

    if (!ARGUMENT_PRESENT(IndexElementCount)) {
        return E_POINTER;
    }

    *IndexElementCount = 4;
    return S_OK;
}

static
HRESULT
WINAPI
EngineAdapterQueryHashAlgorithms(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _Out_ PSIZE_T AlgorithmCount,
    _Out_ PSIZE_T AlgorithmBufferSize,
    _Outptr_result_bytebuffer_all_(*AlgorithmBufferSize) PUCHAR *AlgorithmBuffer
    )
{
    static const CHAR sha256Oid[] = BIOFAKE_SHA256_OID; // includes terminator
    SIZE_T oidSize = sizeof(sha256Oid);
    PUCHAR buffer;

    UNREFERENCED_PARAMETER(Pipeline);

    if (!ARGUMENT_PRESENT(AlgorithmCount) ||
        !ARGUMENT_PRESENT(AlgorithmBufferSize) ||
        !ARGUMENT_PRESENT(AlgorithmBuffer)) {
        return E_POINTER;
    }

    buffer = (PUCHAR)BioFakeEngineAlloc(Pipeline, oidSize);
    if (buffer == NULL) {
        return E_OUTOFMEMORY;
    }

    RtlCopyMemory(buffer, sha256Oid, oidSize);

    *AlgorithmCount = 1;
    *AlgorithmBufferSize = oidSize;
    *AlgorithmBuffer = buffer;

    return S_OK;
}

static
HRESULT
WINAPI
EngineAdapterSetHashAlgorithm(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _In_ SIZE_T AlgorithmBufferSize,
    _In_reads_z_(AlgorithmBufferSize) PUCHAR AlgorithmBuffer
    )
{
    static const CHAR sha256Oid[] = BIOFAKE_SHA256_OID;

    UNREFERENCED_PARAMETER(Pipeline);

    if (!ARGUMENT_PRESENT(AlgorithmBuffer) && AlgorithmBufferSize != 0) {
        return E_POINTER;
    }

    if (AlgorithmBufferSize >= sizeof(sha256Oid) &&
        RtlEqualMemory(AlgorithmBuffer, sha256Oid, sizeof(sha256Oid))) {
        return S_OK;
    }

    return E_INVALIDARG;
}

static
HRESULT
WINAPI
EngineAdapterQuerySampleHint(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _Out_ PSIZE_T SampleHint
    )
{
    UNREFERENCED_PARAMETER(Pipeline);

    if (!ARGUMENT_PRESENT(SampleHint)) {
        return E_POINTER;
    }

    // One capture is enough to complete an enrollment: captures for the
    // same key are byte-identical.
    *SampleHint = 1;
    return S_OK;
}

static
HRESULT
WINAPI
EngineAdapterAcceptSampleData(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _In_reads_bytes_(SampleSize) PWINBIO_BIR SampleBuffer,
    _In_ SIZE_T SampleSize,
    _In_ WINBIO_BIR_PURPOSE Purpose,
    _Out_ PWINBIO_REJECT_DETAIL RejectDetail
    )
{
    PBIOFAKE_ENGINE_CONTEXT ctx;
    const BYTE* data;
    SIZE_T size;
    HRESULT hr;

    UNREFERENCED_PARAMETER(Purpose);

    if (!ARGUMENT_PRESENT(Pipeline) ||
        !ARGUMENT_PRESENT(SampleBuffer) ||
        !ARGUMENT_PRESENT(RejectDetail)) {
        return E_POINTER;
    }

    *RejectDetail = 0;

    ctx = (PBIOFAKE_ENGINE_CONTEXT)Pipeline->EngineContext;
    if (ctx == NULL) {
        return WINBIO_E_INVALID_DEVICE_STATE;
    }

    if (SampleSize < sizeof(WINBIO_BIR) ||
        SampleBuffer->StandardDataBlock.Size == 0 ||
        SampleBuffer->StandardDataBlock.Offset == 0 ||
        (SIZE_T)SampleBuffer->StandardDataBlock.Offset + SampleBuffer->StandardDataBlock.Size > SampleSize) {
        *RejectDetail = WINBIO_FP_POOR_QUALITY;
        return WINBIO_E_BAD_CAPTURE;
    }

    data = (const BYTE*)SampleBuffer + SampleBuffer->StandardDataBlock.Offset;
    size = SampleBuffer->StandardDataBlock.Size;

    hr = BioFakeSha256(data, size, ctx->CurrentHash);
    if (FAILED(hr)) {
        *RejectDetail = WINBIO_FP_MERGE_FAILURE;
        return E_FAIL;
    }

    ctx->HasCurrentSample = TRUE;

    return S_OK;
}

static
HRESULT
WINAPI
EngineAdapterExportEngineData(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _In_ WINBIO_BIR_DATA_FLAGS Flags,
    _Outptr_result_bytebuffer_all_(*SampleSize) PWINBIO_BIR *SampleBuffer,
    _Out_ PSIZE_T SampleSize
    )
{
    PBIOFAKE_ENGINE_CONTEXT ctx;
    PVOID buffer;
    const BYTE* hash;

    if (!ARGUMENT_PRESENT(Pipeline) ||
        !ARGUMENT_PRESENT(SampleBuffer) ||
        !ARGUMENT_PRESENT(SampleSize)) {
        return E_POINTER;
    }

    ctx = (PBIOFAKE_ENGINE_CONTEXT)Pipeline->EngineContext;
    if (ctx == NULL) {
        return WINBIO_E_INVALID_DEVICE_STATE;
    }

    if (Flags & WINBIO_DATA_FLAG_PROCESSED) {
        if (!ctx->HasTemplate) {
            return WINBIO_E_INVALID_DEVICE_STATE;
        }
        hash = ctx->TemplateHash;
    } else {
        if (!ctx->HasCurrentSample) {
            return WINBIO_E_NO_CAPTURE_DATA;
        }
        hash = ctx->CurrentHash;
    }

    buffer = BioFakeEngineAlloc(Pipeline,
                                sizeof(WINBIO_BIR) +
                                sizeof(WINBIO_BIR_HEADER) +
                                sizeof(BIOFAKE_TEMPLATE_BLOB));
    if (buffer == NULL) {
        return E_OUTOFMEMORY;
    }

    BioFakeBuildExportBir(Flags, hash, buffer);

    *SampleBuffer = (PWINBIO_BIR)buffer;
    *SampleSize = sizeof(WINBIO_BIR) + sizeof(WINBIO_BIR_HEADER) + sizeof(BIOFAKE_TEMPLATE_BLOB);

    return S_OK;
}

static
HRESULT
WINAPI
EngineAdapterVerifyFeatureSet(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _In_ PWINBIO_IDENTITY Identity,
    _In_ WINBIO_BIOMETRIC_SUBTYPE SubFactor,
    _Out_ PBOOLEAN Match,
    _Outptr_result_bytebuffer_all_(*PayloadBlobSize) PUCHAR *PayloadBlob,
    _Out_ PSIZE_T PayloadBlobSize,
    _Outptr_result_bytebuffer_all_(*HashSize) PUCHAR *HashValue,
    _Out_ PSIZE_T HashSize,
    _Out_ PWINBIO_REJECT_DETAIL RejectDetail
    )
{
    PBIOFAKE_ENGINE_CONTEXT ctx;
    WINBIO_STORAGE_RECORD record;
    BYTE storedHash[BIOFAKE_HASH_SIZE];
    PUCHAR hashCopy;
    BOOLEAN matched = FALSE;
    HRESULT hr;

    if (!ARGUMENT_PRESENT(Pipeline) ||
        !ARGUMENT_PRESENT(Identity) ||
        !ARGUMENT_PRESENT(Match) ||
        !ARGUMENT_PRESENT(PayloadBlob) ||
        !ARGUMENT_PRESENT(PayloadBlobSize) ||
        !ARGUMENT_PRESENT(HashValue) ||
        !ARGUMENT_PRESENT(HashSize) ||
        !ARGUMENT_PRESENT(RejectDetail)) {
        return E_POINTER;
    }

    *Match = FALSE;
    *PayloadBlob = NULL;
    *PayloadBlobSize = 0;
    *HashValue = NULL;
    *HashSize = 0;
    *RejectDetail = 0;

    ctx = (PBIOFAKE_ENGINE_CONTEXT)Pipeline->EngineContext;
    if (ctx == NULL) {
        return WINBIO_E_INVALID_DEVICE_STATE;
    }

    if (!ctx->HasCurrentSample) {
        return WINBIO_E_NO_CAPTURE_DATA;
    }

    hr = WbioStorageQueryBySubject(Pipeline, Identity, SubFactor);
    if (FAILED(hr)) {
        if (hr == WINBIO_E_DATABASE_NO_RESULTS) {
            return S_OK;    // no record for this subject: not a match
        }
        return hr;
    }

    hr = WbioStorageFirstRecord(Pipeline);
    while (SUCCEEDED(hr)) {
        hr = WbioStorageGetCurrentRecord(Pipeline, &record);
        if (FAILED(hr)) {
            return hr;
        }

        if (BioFakeParseTemplateBlob(record.TemplateBlob,
                                     record.TemplateBlobSize,
                                     storedHash) &&
            RtlEqualMemory(storedHash, ctx->CurrentHash, BIOFAKE_HASH_SIZE)) {
            matched = TRUE;
            break;
        }

        hr = WbioStorageNextRecord(Pipeline);
        if (hr == WINBIO_E_DATABASE_NO_MORE_RECORDS) {
            hr = S_OK;
            break;
        }
    }

    if (matched) {
        hashCopy = (PUCHAR)BioFakeEngineAlloc(Pipeline, BIOFAKE_HASH_SIZE);
        if (hashCopy == NULL) {
            return E_OUTOFMEMORY;
        }
        RtlCopyMemory(hashCopy, ctx->CurrentHash, BIOFAKE_HASH_SIZE);
        *HashValue = hashCopy;
        *HashSize = BIOFAKE_HASH_SIZE;
    }

    *Match = matched ? TRUE : FALSE;
    return S_OK;
}

static
HRESULT
WINAPI
EngineAdapterIdentifyFeatureSet(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _Out_ PWINBIO_IDENTITY Identity,
    _Out_ PWINBIO_BIOMETRIC_SUBTYPE SubFactor,
    _Outptr_result_bytebuffer_all_(*PayloadBlobSize) PUCHAR *PayloadBlob,
    _Out_ PSIZE_T PayloadBlobSize,
    _Outptr_result_bytebuffer_all_(*HashSize) PUCHAR *HashValue,
    _Out_ PSIZE_T HashSize,
    _Out_ PWINBIO_REJECT_DETAIL RejectDetail
    )
{
    PBIOFAKE_ENGINE_CONTEXT ctx;
    WINBIO_IDENTITY wildcard;
    WINBIO_STORAGE_RECORD record;
    BYTE storedHash[BIOFAKE_HASH_SIZE];
    PUCHAR hashCopy;
    BOOLEAN matched = FALSE;
    HRESULT hr;

    if (!ARGUMENT_PRESENT(Pipeline) ||
        !ARGUMENT_PRESENT(Identity) ||
        !ARGUMENT_PRESENT(SubFactor) ||
        !ARGUMENT_PRESENT(PayloadBlob) ||
        !ARGUMENT_PRESENT(PayloadBlobSize) ||
        !ARGUMENT_PRESENT(HashValue) ||
        !ARGUMENT_PRESENT(HashSize) ||
        !ARGUMENT_PRESENT(RejectDetail)) {
        return E_POINTER;
    }

    RtlZeroMemory(Identity, sizeof(WINBIO_IDENTITY));
    *SubFactor = WINBIO_SUBTYPE_NO_INFORMATION;
    *PayloadBlob = NULL;
    *PayloadBlobSize = 0;
    *HashValue = NULL;
    *HashSize = 0;
    *RejectDetail = 0;

    ctx = (PBIOFAKE_ENGINE_CONTEXT)Pipeline->EngineContext;
    if (ctx == NULL) {
        return WINBIO_E_INVALID_DEVICE_STATE;
    }

    if (!ctx->HasCurrentSample) {
        return WINBIO_E_NO_CAPTURE_DATA;
    }

    RtlZeroMemory(&wildcard, sizeof(wildcard));
    wildcard.Type = WINBIO_ID_TYPE_WILDCARD;
    wildcard.Value.Wildcard = WINBIO_IDENTITY_WILDCARD;

    hr = WbioStorageQueryBySubject(Pipeline, &wildcard, WINBIO_SUBTYPE_ANY);
    if (FAILED(hr)) {
        if (hr == WINBIO_E_DATABASE_NO_RESULTS) {
            return WINBIO_E_NO_MATCH;
        }
        return hr;
    }

    hr = WbioStorageFirstRecord(Pipeline);
    while (SUCCEEDED(hr)) {
        hr = WbioStorageGetCurrentRecord(Pipeline, &record);
        if (FAILED(hr)) {
            return hr;
        }

        if (BioFakeParseTemplateBlob(record.TemplateBlob,
                                     record.TemplateBlobSize,
                                     storedHash) &&
            RtlEqualMemory(storedHash, ctx->CurrentHash, BIOFAKE_HASH_SIZE)) {
            matched = TRUE;
            *Identity = *record.Identity;
            *SubFactor = record.SubFactor;
            break;
        }

        hr = WbioStorageNextRecord(Pipeline);
        if (hr == WINBIO_E_DATABASE_NO_MORE_RECORDS) {
            break;
        }
    }

    if (!matched) {
        return WINBIO_E_NO_MATCH;
    }

    hashCopy = (PUCHAR)BioFakeEngineAlloc(Pipeline, BIOFAKE_HASH_SIZE);
    if (hashCopy == NULL) {
        return E_OUTOFMEMORY;
    }
    RtlCopyMemory(hashCopy, ctx->CurrentHash, BIOFAKE_HASH_SIZE);
    *HashValue = hashCopy;
    *HashSize = BIOFAKE_HASH_SIZE;

    return S_OK;
}

static
HRESULT
WINAPI
EngineAdapterCreateEnrollment(
    _Inout_ PWINBIO_PIPELINE Pipeline
    )
{
    PBIOFAKE_ENGINE_CONTEXT ctx;

    if (!ARGUMENT_PRESENT(Pipeline)) {
        return E_POINTER;
    }

    ctx = (PBIOFAKE_ENGINE_CONTEXT)Pipeline->EngineContext;
    if (ctx == NULL) {
        return WINBIO_E_INVALID_DEVICE_STATE;
    }

    ctx->Enrolling = TRUE;
    ctx->SampleCount = 0;
    RtlZeroMemory(ctx->EnrollHash, BIOFAKE_HASH_SIZE);

    return S_OK;
}

static
HRESULT
WINAPI
EngineAdapterUpdateEnrollment(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _Out_ PWINBIO_REJECT_DETAIL RejectDetail
    )
{
    PBIOFAKE_ENGINE_CONTEXT ctx;

    if (!ARGUMENT_PRESENT(Pipeline) || !ARGUMENT_PRESENT(RejectDetail)) {
        return E_POINTER;
    }

    *RejectDetail = 0;

    ctx = (PBIOFAKE_ENGINE_CONTEXT)Pipeline->EngineContext;
    if (ctx == NULL) {
        return WINBIO_E_INVALID_DEVICE_STATE;
    }

    if (!ctx->HasCurrentSample) {
        return WINBIO_E_NO_CAPTURE_DATA;
    }

    // Identical samples merge trivially: the enrollment hash equals the
    // sample hash after the first (and only) capture.
    RtlCopyMemory(ctx->EnrollHash, ctx->CurrentHash, BIOFAKE_HASH_SIZE);
    ctx->SampleCount++;

    return S_OK;
}

static
HRESULT
WINAPI
EngineAdapterGetEnrollmentStatus(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _Out_ PWINBIO_REJECT_DETAIL RejectDetail
    )
{
    PBIOFAKE_ENGINE_CONTEXT ctx;

    if (!ARGUMENT_PRESENT(Pipeline) || !ARGUMENT_PRESENT(RejectDetail)) {
        return E_POINTER;
    }

    *RejectDetail = 0;

    ctx = (PBIOFAKE_ENGINE_CONTEXT)Pipeline->EngineContext;
    if (ctx == NULL) {
        return WINBIO_E_INVALID_DEVICE_STATE;
    }

    if (ctx->SampleCount >= 1) {
        return S_OK;    // ready to commit
    }

    return WINBIO_I_MORE_DATA;
}

static
HRESULT
WINAPI
EngineAdapterGetEnrollmentHash(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _Outptr_result_bytebuffer_all_(*HashSize) PUCHAR *HashValue,
    _Out_ PSIZE_T HashSize
    )
{
    PBIOFAKE_ENGINE_CONTEXT ctx;
    PUCHAR copy;

    if (!ARGUMENT_PRESENT(Pipeline) ||
        !ARGUMENT_PRESENT(HashValue) ||
        !ARGUMENT_PRESENT(HashSize)) {
        return E_POINTER;
    }

    *HashValue = NULL;
    *HashSize = 0;

    ctx = (PBIOFAKE_ENGINE_CONTEXT)Pipeline->EngineContext;
    if (ctx == NULL || !ctx->Enrolling || ctx->SampleCount == 0) {
        return WINBIO_E_INVALID_DEVICE_STATE;
    }

    copy = (PUCHAR)BioFakeEngineAlloc(Pipeline, BIOFAKE_HASH_SIZE);
    if (copy == NULL) {
        return E_OUTOFMEMORY;
    }

    RtlCopyMemory(copy, ctx->EnrollHash, BIOFAKE_HASH_SIZE);
    *HashValue = copy;
    *HashSize = BIOFAKE_HASH_SIZE;

    return S_OK;
}

static
HRESULT
WINAPI
EngineAdapterCheckForDuplicate(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _Out_ PWINBIO_IDENTITY Identity,
    _Out_ PWINBIO_BIOMETRIC_SUBTYPE SubFactor,
    _Out_ PBOOLEAN Duplicate
    )
{
    PBIOFAKE_ENGINE_CONTEXT ctx;
    WINBIO_IDENTITY wildcard;
    WINBIO_STORAGE_RECORD record;
    BYTE storedHash[BIOFAKE_HASH_SIZE];
    BOOLEAN found = FALSE;
    HRESULT hr;

    if (!ARGUMENT_PRESENT(Pipeline) ||
        !ARGUMENT_PRESENT(Identity) ||
        !ARGUMENT_PRESENT(SubFactor) ||
        !ARGUMENT_PRESENT(Duplicate)) {
        return E_POINTER;
    }

    RtlZeroMemory(Identity, sizeof(WINBIO_IDENTITY));
    *SubFactor = WINBIO_SUBTYPE_NO_INFORMATION;
    *Duplicate = FALSE;

    ctx = (PBIOFAKE_ENGINE_CONTEXT)Pipeline->EngineContext;
    if (ctx == NULL || !ctx->Enrolling || ctx->SampleCount == 0) {
        return S_OK;
    }

    RtlZeroMemory(&wildcard, sizeof(wildcard));
    wildcard.Type = WINBIO_ID_TYPE_WILDCARD;
    wildcard.Value.Wildcard = WINBIO_IDENTITY_WILDCARD;

    hr = WbioStorageQueryBySubject(Pipeline, &wildcard, WINBIO_SUBTYPE_ANY);
    if (FAILED(hr)) {
        return S_OK;    // empty database: no duplicates
    }

    hr = WbioStorageFirstRecord(Pipeline);
    while (SUCCEEDED(hr)) {
        hr = WbioStorageGetCurrentRecord(Pipeline, &record);
        if (FAILED(hr)) {
            return hr;
        }

        if (BioFakeParseTemplateBlob(record.TemplateBlob,
                                     record.TemplateBlobSize,
                                     storedHash) &&
            RtlEqualMemory(storedHash, ctx->EnrollHash, BIOFAKE_HASH_SIZE)) {
            found = TRUE;
            *Identity = *record.Identity;
            *SubFactor = record.SubFactor;
            break;
        }

        hr = WbioStorageNextRecord(Pipeline);
        if (hr == WINBIO_E_DATABASE_NO_MORE_RECORDS) {
            break;
        }
    }

    *Duplicate = found ? TRUE : FALSE;
    return S_OK;
}

static
HRESULT
WINAPI
EngineAdapterCommitEnrollment(
    _Inout_ PWINBIO_PIPELINE Pipeline,
    _In_ PWINBIO_IDENTITY Identity,
    _In_ WINBIO_BIOMETRIC_SUBTYPE SubFactor,
    _In_reads_bytes_(PayloadBlobSize) PUCHAR PayloadBlob,
    _In_ SIZE_T PayloadBlobSize
    )
{
    PBIOFAKE_ENGINE_CONTEXT ctx;
    BYTE birBuffer[sizeof(WINBIO_BIR) +
                   sizeof(WINBIO_BIR_HEADER) +
                   sizeof(BIOFAKE_TEMPLATE_BLOB)];
    ULONG indexVector[4];
    WINBIO_STORAGE_RECORD record;
    HRESULT hr;

    if (!ARGUMENT_PRESENT(Pipeline) || !ARGUMENT_PRESENT(Identity)) {
        return E_POINTER;
    }

    ctx = (PBIOFAKE_ENGINE_CONTEXT)Pipeline->EngineContext;
    if (ctx == NULL || !ctx->Enrolling || ctx->SampleCount == 0) {
        return WINBIO_E_INVALID_DEVICE_STATE;
    }

    BioFakeBuildExportBir(WINBIO_DATA_FLAG_PROCESSED, ctx->EnrollHash, birBuffer);

    RtlCopyMemory(indexVector, ctx->EnrollHash, sizeof(indexVector));

    RtlZeroMemory(&record, sizeof(record));
    record.Identity = Identity;
    record.SubFactor = SubFactor;
    record.IndexVector = indexVector;
    record.IndexElementCount = 4;
    record.TemplateBlob = (PUCHAR)birBuffer;
    record.TemplateBlobSize = sizeof(birBuffer);
    record.PayloadBlob = PayloadBlob;
    record.PayloadBlobSize = PayloadBlobSize;

    hr = WbioStorageAddRecord(Pipeline, &record);
    if (FAILED(hr)) {
        return hr;
    }

    RtlCopyMemory(ctx->TemplateHash, ctx->EnrollHash, BIOFAKE_HASH_SIZE);
    ctx->HasTemplate = TRUE;
    ctx->Enrolling = FALSE;

    return S_OK;
}

static
HRESULT
WINAPI
EngineAdapterDiscardEnrollment(
    _Inout_ PWINBIO_PIPELINE Pipeline
    )
{
    PBIOFAKE_ENGINE_CONTEXT ctx;

    if (!ARGUMENT_PRESENT(Pipeline)) {
        return E_POINTER;
    }

    ctx = (PBIOFAKE_ENGINE_CONTEXT)Pipeline->EngineContext;
    if (ctx != NULL) {
        ctx->Enrolling = FALSE;
        ctx->SampleCount = 0;
        RtlZeroMemory(ctx->EnrollHash, BIOFAKE_HASH_SIZE);
    }

    return S_OK;
}

static
HRESULT
WINAPI
EngineAdapterControlUnit(
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

    if (!ARGUMENT_PRESENT(ReceiveDataSize) || !ARGUMENT_PRESENT(OperationStatus)) {
        return E_POINTER;
    }

    *ReceiveDataSize = 0;
    *OperationStatus = ERROR_NOT_SUPPORTED;

    return WINBIO_E_INVALID_CONTROL_CODE;
}

static
HRESULT
WINAPI
EngineAdapterControlUnitPrivileged(
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
    return EngineAdapterControlUnit(Pipeline,
                                    ControlCode,
                                    SendBuffer,
                                    SendBufferSize,
                                    ReceiveBuffer,
                                    ReceiveBufferSize,
                                    ReceiveDataSize,
                                    OperationStatus);
}

//////////////////////////////////////////////////////////////////////////////
// Interface table (V1.0; V2+ entries are left NULL)
//////////////////////////////////////////////////////////////////////////////

static WINBIO_ENGINE_INTERFACE g_EngineInterface;

// The Windows Biometric Service resolves this entry point by name after
// loading the adapter DLL, so it must be exported from the DLL.
__declspec(dllexport)
HRESULT
WINAPI
WbioQueryEngineInterface(
    _Out_ PWINBIO_ENGINE_INTERFACE *EngineInterface
    )
{
    if (!ARGUMENT_PRESENT(EngineInterface)) {
        return E_POINTER;
    }

    *EngineInterface = &g_EngineInterface;
    return S_OK;
}

BOOL
WINAPI
DllMain(
    HINSTANCE hinstDLL,
    DWORD fdwReason,
    LPVOID lpReserved
    )
{
    UNREFERENCED_PARAMETER(lpReserved);

    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hinstDLL);

        RtlZeroMemory(&g_EngineInterface, sizeof(g_EngineInterface));
        // WINBIO_MAKE_INTERFACE_VERSION expands to a braced initializer, which
        // cannot be used in an assignment; set the fields directly instead.
        g_EngineInterface.Version.MajorVersion = 1;
        g_EngineInterface.Version.MinorVersion = 0;
        g_EngineInterface.Type = WINBIO_ADAPTER_TYPE_ENGINE;
        g_EngineInterface.Size = sizeof(WINBIO_ENGINE_INTERFACE);
        g_EngineInterface.AdapterId = BIOFAKE_VENDOR_FORMAT_GUID;

        g_EngineInterface.Attach = EngineAdapterAttach;
        g_EngineInterface.Detach = EngineAdapterDetach;
        g_EngineInterface.ClearContext = EngineAdapterClearContext;
        g_EngineInterface.QueryPreferredFormat = EngineAdapterQueryPreferredFormat;
        g_EngineInterface.QueryIndexVectorSize = EngineAdapterQueryIndexVectorSize;
        g_EngineInterface.QueryHashAlgorithms = EngineAdapterQueryHashAlgorithms;
        g_EngineInterface.SetHashAlgorithm = EngineAdapterSetHashAlgorithm;
        g_EngineInterface.QuerySampleHint = EngineAdapterQuerySampleHint;
        g_EngineInterface.AcceptSampleData = EngineAdapterAcceptSampleData;
        g_EngineInterface.ExportEngineData = EngineAdapterExportEngineData;
        g_EngineInterface.VerifyFeatureSet = EngineAdapterVerifyFeatureSet;
        g_EngineInterface.IdentifyFeatureSet = EngineAdapterIdentifyFeatureSet;
        g_EngineInterface.CreateEnrollment = EngineAdapterCreateEnrollment;
        g_EngineInterface.UpdateEnrollment = EngineAdapterUpdateEnrollment;
        g_EngineInterface.GetEnrollmentStatus = EngineAdapterGetEnrollmentStatus;
        g_EngineInterface.GetEnrollmentHash = EngineAdapterGetEnrollmentHash;
        g_EngineInterface.CheckForDuplicate = EngineAdapterCheckForDuplicate;
        g_EngineInterface.CommitEnrollment = EngineAdapterCommitEnrollment;
        g_EngineInterface.DiscardEnrollment = EngineAdapterDiscardEnrollment;
        g_EngineInterface.ControlUnit = EngineAdapterControlUnit;
        g_EngineInterface.ControlUnitPrivileged = EngineAdapterControlUnitPrivileged;
        break;

    case DLL_PROCESS_DETACH:
        break;
    }

    return TRUE;
}
