/*++

BioFake - Virtual biometric sensor for Windows
Shared definitions between the BioFakeWudf UMDF driver and the biofakectl.exe
control tool.

Include <windows.h> (or <wdf.h>) and <initguid.h> before this header in the
ONE translation unit that should instantiate the GUIDs.

--*/

#ifndef _BIOFAKE_IOCTL_H_
#define _BIOFAKE_IOCTL_H_

//
// Control device interface GUID: {B10FA4CE-8D21-4E9A-B1F3-2A7C6D5E4F02}
//
DEFINE_GUID(GUID_BIOFAKE_CONTROL,
    0xb10fa4ce, 0x8d21, 0x4e9a, 0xb1, 0xf3, 0x2a, 0x7c, 0x6d, 0x5e, 0x4f, 0x02);

//
// Hardware IDs matched by biofake_wudf.inf
//
#define BIOFAKE_HWID_ROOT   L"ROOT\\BIOFAKESENSOR"
#define BIOFAKE_HWID_SW     L"BIOFAKE\\VBIOSENSOR"

//
// Sensor operating modes (set via IOCTL_BIOFAKE_SET_MODE)
//
#define BIOFAKE_MODE_READY      0   // capture succeeds with the synthetic fingerprint
#define BIOFAKE_MODE_REJECT     1   // capture is rejected (WINBIO_FP_POOR_QUALITY)
#define BIOFAKE_MODE_FAILURE    2   // sensor reports a device failure
#define BIOFAKE_MODE_CUSTOM     3   // capture returns the payload set via IOCTL_BIOFAKE_SET_PAYLOAD

//
// Custom control IOCTLs (METHOD_BUFFERED)
//
#define BIOFAKE_IOCTL_TYPE      FILE_DEVICE_UNKNOWN

#define IOCTL_BIOFAKE_GET_INFO    CTL_CODE(BIOFAKE_IOCTL_TYPE, 0x0801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BIOFAKE_SET_MODE    CTL_CODE(BIOFAKE_IOCTL_TYPE, 0x0802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BIOFAKE_SET_PAYLOAD CTL_CODE(BIOFAKE_IOCTL_TYPE, 0x0803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BIOFAKE_GET_STATS   CTL_CODE(BIOFAKE_IOCTL_TYPE, 0x0804, METHOD_BUFFERED, FILE_ANY_ACCESS)

//
// Payloads
//
typedef struct _BIOFAKE_INFO {
    DWORD Version;          // driver control interface version
    DWORD Mode;             // current BIOFAKE_MODE_*
    DWORD PayloadSize;      // size (bytes) of the BIR currently served by capture
    DWORD MaxPayloadSize;   // maximum accepted IOCTL_BIOFAKE_SET_PAYLOAD size
} BIOFAKE_INFO, *PBIOFAKE_INFO;

typedef struct _BIOFAKE_STATS {
    DWORD CapturesRequested;
    DWORD CapturesServed;
    DWORD CapturesRejected;
    DWORD CapturesFailed;
} BIOFAKE_STATS, *PBIOFAKE_STATS;

// Input for IOCTL_BIOFAKE_SET_PAYLOAD: DWORD Size followed by a complete WINBIO_BIR blob
#define BIOFAKE_MAX_PAYLOAD 0x400000

#endif // _BIOFAKE_IOCTL_H_
