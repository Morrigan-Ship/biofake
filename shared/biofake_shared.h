/*++
biofake_shared.h

Shared contract between the BioFake UMDF driver (control device node) and the
biofakectl.exe user-mode tool.

The driver registers two software device nodes that both use this driver DLL:

  SWD\BioFake    - WBDI fingerprint sensor. Exposes
                   GUID_DEVINTERFACE_BIOMETRIC_READER, is opened exclusively by
                   the Windows Biometric Service (via the built-in generic
                   sensor adapter).
  SWD\BioFakeCtl - control node. Exposes BIOFAKE_CONTROL_INTERFACE_GUID and is
                   opened by biofakectl.exe to manage keys and trigger captures.

Because the biometric node is opened with exclusive access (INF Exclusive=1),
a second device node is the cleanest way for user mode to talk to the driver.

Both nodes run inside the same WUDFHost process, so the driver shares one
DRIVER_CONTEXT between them.
--*/

#pragma once

#include <windows.h>

// The following two GUIDs are *defined* here via DEFINE_GUID. Any translation
// unit that needs the definitions must include <initguid.h> BEFORE this file;
// other translation units just get extern declarations.
//
// Control device interface (biofakectl.exe opens devices by this GUID).
DEFINE_GUID(BIOFAKE_CONTROL_INTERFACE_GUID,
            0x8f2a4c6e, 0x1d3b, 0x4a9c, 0x9e, 0x5f, 0xb1, 0x0f, 0xa4, 0xce, 0x00, 0x01);

// Vendor format GUID used by the engine adapter for processed templates.
DEFINE_GUID(BIOFAKE_VENDOR_FORMAT_GUID,
            0x6f1d2a10, 0x3c4e, 0x4e8b, 0x9a, 0x21, 0xb1, 0x0f, 0xa4, 0xce, 0x00, 0x02);

// Hardware IDs of the two software device nodes (created by biofakectl install
// via SwDeviceCreate). The driver decides its role per device node by reading
// MatchingDeviceId from the device hardware key.
#define BIOFAKE_SENSOR_HWID   L"SWD\\BioFake"
#define BIOFAKE_CONTROL_HWID  L"SWD\\BioFakeCtl"

#define BIOFAKE_ENUMERATOR    L"BioFake"
#define BIOFAKE_SENSOR_INSTANCE  L"Sensor"
#define BIOFAKE_CONTROL_INSTANCE L"Ctl"

// Engine adapter DLL name that must live in %WINDIR%\System32\WinBioPlugIns.
#define BIOFAKE_ENGINE_DLL    L"BioFakeEngineAdapter.dll"
#define BIOFAKE_INF_NAME      L"biofake_wudf.inf"
#define BIOFAKE_CERT_NAME     L"biofake-test.cer"

//////////////////////////////////////////////////////////////////////////////
// Control channel: private IOCTLs on the control device node
//////////////////////////////////////////////////////////////////////////////

// Vendor device type (range 0x8000+ is reserved for vendors).
#define FILE_DEVICE_BIOFAKE   0x8000

// CTL_CODE expands to signed int arithmetic; cast to DWORD so the private
// IOCTL constants are unsigned. They are passed to DWORD parameters and
// compared against ULONG control codes, which otherwise triggers C4245 at
// every call site.
#define BIOFAKE_CTL_CODE(code) \
    ((DWORD)CTL_CODE(FILE_DEVICE_BIOFAKE, (code), METHOD_BUFFERED, FILE_ANY_ACCESS))

#define IOCTL_BIOFAKE_ADD_KEY     BIOFAKE_CTL_CODE(0x001) // in: BIOFAKE_KEY_ADD_IN
#define IOCTL_BIOFAKE_DELETE_KEY  BIOFAKE_CTL_CODE(0x002) // in: BIOFAKE_NAME_IN
#define IOCTL_BIOFAKE_SELECT_KEY  BIOFAKE_CTL_CODE(0x003) // in: BIOFAKE_NAME_IN
#define IOCTL_BIOFAKE_PRESENT     BIOFAKE_CTL_CODE(0x004) // in: BIOFAKE_NAME_IN (may be all-zero => active key)
#define IOCTL_BIOFAKE_SET_MODE    BIOFAKE_CTL_CODE(0x005) // in: BIOFAKE_MODE_IN
#define IOCTL_BIOFAKE_SET_CUSTOM  BIOFAKE_CTL_CODE(0x006) // in: raw BIR bytes
#define IOCTL_BIOFAKE_GET_STATUS  BIOFAKE_CTL_CODE(0x007) // out: BIOFAKE_STATUS_OUT
#define IOCTL_BIOFAKE_LIST_KEYS   BIOFAKE_CTL_CODE(0x008) // out: BIOFAKE_KEY_INFO[count]

//////////////////////////////////////////////////////////////////////////////
// Structures
//////////////////////////////////////////////////////////////////////////////

#define BIOFAKE_MAX_KEYS        16
#define BIOFAKE_MAX_NAME_CCH    64
#define BIOFAKE_SEED_SIZE       32
#define BIOFAKE_CUSTOM_BIR_MAX  (512 * 1024)

// Sensor behavior mode.
typedef enum _BIOFAKE_MODE {
    BIOFAKE_MODE_READY   = 1, // every capture is answered immediately with the active key
    BIOFAKE_MODE_REJECT  = 2, // capture completes with WINBIO_SENSOR_REJECT / poor quality
    BIOFAKE_MODE_FAILURE = 3, // capture completes with WINBIO_SENSOR_FAILURE / E_FAIL
    BIOFAKE_MODE_CUSTOM  = 4  // capture returns the injected custom BIR (pending if none)
} BIOFAKE_MODE;

typedef struct _BIOFAKE_KEY_ADD_IN {
    WCHAR Name[BIOFAKE_MAX_NAME_CCH];   // key name, zero-terminated
    BYTE  Seed[BIOFAKE_SEED_SIZE];      // deterministic image seed
    BYTE  SubType;                      // WINBIO_ANSI_381_POS_xxx (0 = unknown)
} BIOFAKE_KEY_ADD_IN, *PBIOFAKE_KEY_ADD_IN;

typedef struct _BIOFAKE_NAME_IN {
    WCHAR Name[BIOFAKE_MAX_NAME_CCH];   // empty string = active key
} BIOFAKE_NAME_IN, *PBIOFAKE_NAME_IN;

typedef struct _BIOFAKE_MODE_IN {
    ULONG Mode;                         // BIOFAKE_MODE
} BIOFAKE_MODE_IN, *PBIOFAKE_MODE_IN;

typedef struct _BIOFAKE_KEY_INFO {
    WCHAR   Name[BIOFAKE_MAX_NAME_CCH];
    BOOLEAN Active;
} BIOFAKE_KEY_INFO, *PBIOFAKE_KEY_INFO;

typedef struct _BIOFAKE_STATUS_OUT {
    ULONG   Mode;                       // BIOFAKE_MODE
    ULONG   KeyCount;
    ULONG   CaptureCount;               // captures served since driver start
    BOOLEAN PendingCapture;             // a capture IOCTL is parked waiting
    BOOLEAN HasCustom;
    WCHAR   ActiveName[BIOFAKE_MAX_NAME_CCH];
} BIOFAKE_STATUS_OUT, *PBIOFAKE_STATUS_OUT;
