/*++

BioFake - Virtual biometric sensor for Windows
Shared definitions between the BioFakeWudf KMDF driver and the biofakectl.exe
control tool.

Include <windows.h> (or <wdf.h> + <ntddk.h>) and define INITGUID before this
header in the ONE translation unit that should instantiate the GUIDs.

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

//
// Key slot layout (shared by driver + ctl)
//
#define BIOFAKE_MAX_KEYS    8
#define BIOFAKE_NAME_CHARS  32
#define BIOFAKE_SECRET_LEN  32

//
// Sensor operating modes (set via IOCTL_BIOFAKE_SET_MODE)
//
#define BIOFAKE_MODE_READY      0   // capture succeeds with the active key fingerprint
#define BIOFAKE_MODE_REJECT     1   // capture is rejected (WINBIO_FP_POOR_QUALITY)
#define BIOFAKE_MODE_FAILURE    2   // sensor reports WINBIO_SENSOR_FAILURE
#define BIOFAKE_MODE_CUSTOM     3   // capture returns the payload set via IOCTL_BIOFAKE_SET_PAYLOAD

//
// Custom control IOCTLs (METHOD_BUFFERED)
//
#define BIOFAKE_IOCTL_TYPE      FILE_DEVICE_UNKNOWN

#define IOCTL_BIOFAKE_GET_INFO    CTL_CODE(BIOFAKE_IOCTL_TYPE, 0x0801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BIOFAKE_SET_MODE    CTL_CODE(BIOFAKE_IOCTL_TYPE, 0x0802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BIOFAKE_ADD_KEY     CTL_CODE(BIOFAKE_IOCTL_TYPE, 0x0803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BIOFAKE_REMOVE_KEY  CTL_CODE(BIOFAKE_IOCTL_TYPE, 0x0804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BIOFAKE_SELECT_KEY  CTL_CODE(BIOFAKE_IOCTL_TYPE, 0x0805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BIOFAKE_PRESENT_KEY CTL_CODE(BIOFAKE_IOCTL_TYPE, 0x0806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BIOFAKE_CANCEL      CTL_CODE(BIOFAKE_IOCTL_TYPE, 0x0807, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BIOFAKE_SET_PAYLOAD CTL_CODE(BIOFAKE_IOCTL_TYPE, 0x0808, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_BIOFAKE_GET_STATS   CTL_CODE(BIOFAKE_IOCTL_TYPE, 0x0809, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma pack(push, 4)

//
// In/out payloads for the control interface.
// NOTE: the ctl tool defines the same structures independently so that it can
// be built without kernel headers; sizes must stay in sync.
//
typedef struct _BIOFAKE_INFO {
    DWORD Version;                              // driver control interface version
    DWORD Mode;                                 // current BIOFAKE_MODE_*
    DWORD ActiveKey;                            // index or BIOFAKE_NO_KEY
    DWORD CapturePending;                       // TRUE if a WBDI capture is pending
    DWORD PayloadSize;                          // size (bytes) of data served by capture
    DWORD MaxPayloadSize;                       // maximum accepted SET_PAYLOAD size
} BIOFAKE_INFO, *PBIOFAKE_INFO;

typedef struct _BIOFAKE_KEY_ENTRY {
    DWORD Slot;                                 // filled by driver on ADD_KEY
    WCHAR Name[BIOFAKE_NAME_CHARS];             // NUL-terminated key name
    UCHAR Secret[BIOFAKE_SECRET_LEN];           // fingerprint seed
} BIOFAKE_KEY_ENTRY, *PBIOFAKE_KEY_ENTRY;

typedef struct _BIOFAKE_NAME_VALUE {
    WCHAR Name[BIOFAKE_NAME_CHARS];
} BIOFAKE_NAME_VALUE, *PBIOFAKE_NAME_VALUE;

typedef struct _BIOFAKE_STATS {
    DWORD CapturesRequested;
    DWORD CapturesServed;
    DWORD CapturesRejected;
    DWORD CapturesFailed;
} BIOFAKE_STATS, *PBIOFAKE_STATS;

#pragma pack(pop)

#define BIOFAKE_NO_KEY  0xFFFFFFFF
#define BIOFAKE_MAX_PAYLOAD 0x400000

#endif // _BIOFAKE_IOCTL_H_
