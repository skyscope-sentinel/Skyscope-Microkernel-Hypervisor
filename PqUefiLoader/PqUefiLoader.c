#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/PrintLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h> // For gBS
#include <Protocol/SimpleFileSystem.h>
#include <Guid/FileInfo.h> // For EFI_FILE_INFO

#include <oqs/oqs.h>
#include <oqs/sig_ml_dsa.h> // For OQS_SIG_ML_DSA_65_LENGTH_PUBLIC_KEY

// --- Multiboot2 Tag Definitions ---
#define MULTIBOOT_TAG_ALIGN         8
#define MULTIBOOT_TAG_TYPE_END      0
#define MULTIBOOT_TAG_TYPE_MODULE   3
#define MULTIBOOT_TAG_TYPE_MMAP     6 // Memory Map tag type

// Multiboot2 Memory Types
#define MULTIBOOT_MEMORY_AVAILABLE        1
#define MULTIBOOT_MEMORY_RESERVED         2
#define MULTIBOOT_MEMORY_ACPI_RECLAIMABLE 3
#define MULTIBOOT_MEMORY_NVS              4
#define MULTIBOOT_MEMORY_BADRAM           5

#pragma pack(push, 1) // Ensure packed structures

typedef struct {
  UINT32 Type;
  UINT32 Size;
} multiboot_tag_t;

typedef struct {
  UINT32 Type;
  UINT32 Size;
  UINT32 ModStart;
  UINT32 ModEnd; // In Multiboot2 spec, this is a physical address.
                 // We'll use buffer address + size for now.
  CHAR8  Name[0]; // Variable size for module name (null-terminated string)
                 // For simplicity, we'll allocate fixed size structs or manage names carefully.
} multiboot_tag_module_t;

// A more complete module tag if we want to copy names:
typedef struct {
  UINT32 Type;
  UINT32 Size;
  UINT32 ModStart;
  UINT32 ModEnd;
  CHAR8  CmdLine[256]; // Example fixed size for name/cmdline
} multiboot_tag_module_with_name_t;


typedef struct {
  UINT32 Type;
  UINT32 Size;
  CHAR8  String[0]; // Variable size for string data
} multiboot_tag_string_t;

typedef struct {
  UINT64 Addr;
  UINT64 Len;
  UINT32 Type;
  UINT32 Reserved;
} multiboot_mmap_entry_t;

typedef struct {
  UINT32 Type;
  UINT32 Size;
  UINT32 EntrySize;
  UINT32 EntryVersion;
  multiboot_mmap_entry_t Entries[0]; // Variable number of entries
} multiboot_tag_mmap_t;

#pragma pack(pop)

// --- ACPI Definitions ---
#define EFI_ACPI_20_TABLE_GUID \
  { 0x8868e871, 0xe4f1, 0x11d3, {0xbc, 0x22, 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81 } }
#define EFI_ACPI_TABLE_GUID \
  { 0xeb9d2d30, 0x2d88, 0x11d3, {0x9a, 0x16, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d } }

#define RSDP_SIGNATURE "RSD PTR " // Note the space at the end
#define MCFG_SIGNATURE "MCFG"

#pragma pack(push, 1)
typedef struct {
  CHAR8  Signature[8];
  UINT8  Checksum;
  CHAR8  OemId[6];
  UINT8  Revision;
  UINT32 RsdtAddress;
  // ACPI 2.0+ fields
  UINT32 Length;
  UINT64 XsdtAddress;
  UINT8  ExtendedChecksum;
  UINT8  Reserved[3];
} RSDP_DESCRIPTOR;

typedef struct {
  CHAR8  Signature[4];
  UINT32 Length;
  UINT8  Revision;
  UINT8  Checksum;
  CHAR8  OemId[6];
  CHAR8  OemTableId[8];
  UINT32 OemRevision;
  UINT32 CreatorId;
  UINT32 CreatorRevision;
} ACPI_SDT_HEADER;

typedef struct {
  ACPI_SDT_HEADER Header;
  UINT64          Entry[]; // Array of physical addresses to other ACPI tables
} XSDT_TABLE; // Also used for RSDT by only considering Header.Length for iteration

typedef struct {
  UINT64 BaseAddress;
  UINT16 PciSegmentGroupNumber;
  UINT8  StartBusNumber;
  UINT8  EndBusNumber;
  UINT32 Reserved;
} MCFG_ALLOCATION_STRUCTURE; // Renamed to avoid conflict if MCFG_ALLOCATION is a common macro

typedef struct {
  ACPI_SDT_HEADER Header;
  UINT64          Reserved;
  MCFG_ALLOCATION_STRUCTURE Allocation[];
} MCFG_TABLE;

#pragma pack(pop)

// --- PCI Definitions ---
#define PCI_CONFIG_ADDRESS(Bus, Device, Function, Register) \
  ((UINT64)(Bus) << 20 | (UINT32)(Device) << 15 | (UINT32)(Function) << 12 | (UINT32)(Register))

#define PCI_VENDOR_ID_OFFSET         0x00
#define PCI_DEVICE_ID_OFFSET         0x02
#define PCI_CLASS_CODE_OFFSET        0x09 // SubClass, ProgIF, BaseClass (BBSSPP)
#define PCI_HEADER_TYPE_OFFSET       0x0E

typedef struct {
  UINT16 VendorId;
  UINT16 DeviceId;
  UINT8  Bus;
  UINT8  Device;
  UINT8  Function;
  UINT32 ClassCode; // Combined: BaseClass (byte), SubClass (byte), ProgIF (byte)
} PciDeviceInfo;

// Max PCI devices to store (example)
#define MAX_PCI_DEVICES_TO_SCAN 32 // Renamed for clarity

// --- Custom Multiboot2 Hardware Info Tag ---
#define MULTIBOOT_TAG_TYPE_HW_INFO 0xABCDEF01 // Example custom type for our hardware info

#pragma pack(push, 1)
// Base structure for the HW info tag
typedef struct {
  UINT32 Type;
  UINT32 Size;
  UINT32 NumPciDevs;
  // PciDeviceInfo PciDevs[]; // Data follows here
} MultibootTagHwInfoBase;

// A structure that includes a fixed-size array for PciDevs for easier allocation
// and use within PqUefiLoader. The actual tag written to MB2 info will have
// its size field set to reflect only the actual number of devices.
typedef struct {
  MultibootTagHwInfoBase Base;
  PciDeviceInfo          PciDevs[MAX_PCI_DEVICES_TO_SCAN];
} MultibootTagHwInfoWithPci;
#pragma pack(pop)

// --- Helper function to validate ACPI SDT table checksum ---
STATIC
BOOLEAN
IsAcpiSdtChecksumValid (
  IN ACPI_SDT_HEADER *Table
  )
{
  UINT8 Sum = 0;
  if (Table == NULL) {
    return FALSE;
  }
  for (UINT32 i = 0; i < Table->Length; i++) {
    Sum += ((UINT8 *)Table)[i];
  }
  return Sum == 0;
}

// --- Helper function to find ACPI tables (RSDP, XSDT/RSDT, and specific table like MCFG) ---
STATIC
EFI_STATUS
FindAcpiSystemTables (
  OUT RSDP_DESCRIPTOR **RsdpPtr,
  OUT ACPI_SDT_HEADER **RootSdtPtr, // Can be RSDT or XSDT
  OUT VOID            **McfgTablePtr // Generic pointer for MCFG or other tables
  )
{
  EFI_STATUS      Status;
  EFI_GUID        Acpi20TableGuid = EFI_ACPI_20_TABLE_GUID;
  EFI_GUID        AcpiTableGuid = EFI_ACPI_TABLE_GUID; // For ACPI 1.0
  RSDP_DESCRIPTOR *LocalRsdp = NULL;
  ACPI_SDT_HEADER *LocalRootSdt = NULL; // Points to XSDT or RSDT
  VOID            *SpecificTable = NULL;
  UINTN           i;

  if (RsdpPtr == NULL || RootSdtPtr == NULL || McfgTablePtr == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  // Initialize output parameters
  *RsdpPtr = NULL;
  *RootSdtPtr = NULL;
  *McfgTablePtr = NULL;

  // Step 1: Find RSDP
  // Try ACPI 2.0+ GUID first
  Status = LibGetSystemConfigurationTable(&Acpi20TableGuid, (VOID**)&LocalRsdp);
  if (EFI_ERROR(Status) || LocalRsdp == NULL) {
    // Try ACPI 1.0 GUID if 2.0+ fails
    Status = LibGetSystemConfigurationTable(&AcpiTableGuid, (VOID**)&LocalRsdp);
    if (EFI_ERROR(Status) || LocalRsdp == NULL) {
      Print(L"Failed to find any ACPI RSDP: %r\n", Status);
      return Status;
    }
  }

  // Validate RSDP Signature
  if (AsciiStrnCmp(LocalRsdp->Signature, RSDP_SIGNATURE, 8) != 0) {
    Print(L"RSDP signature invalid.\n");
    return EFI_CRC_ERROR;
  }

  // Validate RSDP Checksum (for ACPI 1.0 part)
  UINT8 Checksum = 0;
  for (i = 0; i < OFFSET_OF(RSDP_DESCRIPTOR, Length); i++) { // Length field is start of ACPI 2.0 part
    Checksum += ((UINT8 *)LocalRsdp)[i];
  }
  if (Checksum != 0) {
    Print(L"RSDP (ACPI 1.0 part) checksum invalid.\n");
    // return EFI_CRC_ERROR; // Be lenient for now, some firmware might have issues
  }

  // If ACPI 2.0+, validate Extended Checksum
  if (LocalRsdp->Revision >= 2) {
    Checksum = 0; // Reset for full length
    for (i = 0; i < LocalRsdp->Length; i++) {
      Checksum += ((UINT8 *)LocalRsdp)[i];
    }
    if (Checksum != 0) {
      Print(L"RSDP Extended (ACPI 2.0+ part) checksum invalid.\n");
      // return EFI_CRC_ERROR; // Be lenient
    }
  }
  Print(L"RSDP found at 0x%p (Revision: %d)\n", LocalRsdp, LocalRsdp->Revision);
  *RsdpPtr = LocalRsdp;

  // Step 2: Get Root SDT (XSDT for ACPI 2.0+, RSDT for ACPI 1.0)
  if (LocalRsdp->Revision >= 2 && LocalRsdp->XsdtAddress != 0) {
    LocalRootSdt = (ACPI_SDT_HEADER *)(UINTN)LocalRsdp->XsdtAddress;
    Print(L"Using XSDT at 0x%lX\n", LocalRsdp->XsdtAddress);
  } else if (LocalRsdp->RsdtAddress != 0) {
    LocalRootSdt = (ACPI_SDT_HEADER *)(UINTN)LocalRsdp->RsdtAddress;
    Print(L"Using RSDT at 0x%X\n", LocalRsdp->RsdtAddress);
  } else {
    Print(L"No XSDT or RSDT address found in RSDP.\n");
    return EFI_NOT_FOUND;
  }
  *RootSdtPtr = LocalRootSdt;

  // Validate Root SDT Header and Checksum
  if (!IsAcpiSdtChecksumValid(LocalRootSdt)) {
    Print(L"Warning: Root SDT (%.4a) checksum invalid, but proceeding.\n", LocalRootSdt->Signature);
    // Proceeding anyway as some firmware might have incorrect checksums.
  }
   Print(L"Root SDT (%.4a) found with Length: %d\n", LocalRootSdt->Signature, LocalRootSdt->Length);


  // Step 3: Iterate Root SDT to find the MCFG table
  UINTN NumEntries;
  BOOLEAN IsXsdt = (AsciiStrnCmp(LocalRootSdt->Signature, "XSDT", 4) == 0);

  if (IsXsdt) {
    NumEntries = (LocalRootSdt->Length - sizeof(ACPI_SDT_HEADER)) / sizeof(UINT64);
  } else { // RSDT
    NumEntries = (LocalRootSdt->Length - sizeof(ACPI_SDT_HEADER)) / sizeof(UINT32);
  }
  Print(L"Root SDT (%.4a) has %d entries.\n", LocalRootSdt->Signature, NumEntries);

  for (i = 0; i < NumEntries; i++) {
    ACPI_SDT_HEADER *CurrentTableHdr;
    UINT64          TableAddress = 0;

    if (IsXsdt) {
      TableAddress = ((XSDT_TABLE *)LocalRootSdt)->Entry[i];
    } else { // RSDT
      TableAddress = (UINT64)((UINT32 *)((XSDT_TABLE *)LocalRootSdt)->Entry)[i];
    }

    CurrentTableHdr = (ACPI_SDT_HEADER *)(UINTN)TableAddress;

    if (CurrentTableHdr == NULL || CurrentTableHdr < (ACPI_SDT_HEADER*)0x1000 || TableAddress == 0) {
      // Print(L"Skipping potentially invalid table address (0x%lX) at index %d.\n", TableAddress, i);
      continue;
    }

    // Check if the mapped address is valid and readable up to header size at least
    // This is a basic check; proper memory map checking would be more robust.
    if (TableAddress > 0xFFFFFFFF && sizeof(UINTN) == 4) { // Avoid dereferencing high addresses on 32-bit builds if that's an issue
        // Print(L"Skipping high address table 0x%lX on 32-bit system model (index %d)\n", TableAddress, i);
        continue;
    }
    // A more robust check involves querying memory map for readability. For now, direct dereference.

    // Print(L"  Table %d at 0x%lX Signature: %.4a\n", i, TableAddress, CurrentTableHdr->Signature);

    if (AsciiStrnCmp(CurrentTableHdr->Signature, MCFG_SIGNATURE, 4) == 0) {
      if (IsAcpiSdtChecksumValid(CurrentTableHdr)) {
        SpecificTable = (VOID *)CurrentTableHdr;
        Print(L"MCFG table found at 0x%lX and checksum valid.\n", TableAddress);
        break;
      } else {
        Print(L"MCFG table found at 0x%lX, but checksum invalid. Trying to use anyway.\n", TableAddress);
        SpecificTable = (VOID *)CurrentTableHdr; // Use even if checksum is bad
        break;
      }
    }
  }

  if (SpecificTable != NULL) {
    *McfgTablePtr = SpecificTable;
  } else {
    Print(L"MCFG table not found in Root SDT (%.4a).\n", LocalRootSdt->Signature);
    // This is not an error for FindAcpiSystemTables itself, caller checks McfgTablePtr
  }

  return EFI_SUCCESS;
}

// --- Helper function to scan PCI devices using MCFG ---
STATIC
UINT32
ScanPciDevices (
  IN  MCFG_TABLE    *Mcfg,
  OUT PciDeviceInfo *PciDevicesList, // Renamed for clarity
  IN  UINT32        MaxDevicesToScan // Renamed for clarity
  )
{
  UINT32 DeviceCount = 0;
  UINTN  NumAllocations;

  if (Mcfg == NULL || PciDevicesList == NULL || MaxDevicesToScan == 0) {
    return 0;
  }

  // Calculate the number of MCFG allocation structures.
  // Header.Length includes the full size of the table.
  // Subtract size of header and the UINT64 Reserved field before Allocation array.
  if (Mcfg->Header.Length < (sizeof(ACPI_SDT_HEADER) + sizeof(UINT64))) {
      Print(L"MCFG table length too small to contain allocations.\n");
      return 0;
  }
  NumAllocations = (Mcfg->Header.Length - (sizeof(ACPI_SDT_HEADER) + sizeof(UINT64))) / sizeof(MCFG_ALLOCATION_STRUCTURE);
  Print(L"MCFG Table (Length: %d) has %d allocation structure(s).\n", Mcfg->Header.Length, NumAllocations);

  for (UINTN i = 0; i < NumAllocations; i++) {
    MCFG_ALLOCATION_STRUCTURE *Alloc = &Mcfg->Allocation[i];
    Print(L"  MCFG Allocation %d: BaseAddr=0x%lX, SegGrp=%d, BusStart=%d, BusEnd=%d\n",
          i, Alloc->BaseAddress, Alloc->PciSegmentGroupNumber, Alloc->StartBusNumber, Alloc->EndBusNumber);

    // Iterate through buses for this allocation structure
    // For simplicity, we'll limit the bus scan range here, e.g., scan only a few buses
    // A full scan would be: For (UINT16 Bus = Alloc->StartBusNumber; Bus <= Alloc->EndBusNumber; Bus++)
    UINT8 BusScanEnd = Alloc->StartBusNumber + 2; // Scan only first 2 buses in range, or fewer if range is smaller
    if (BusScanEnd > (Alloc->EndBusNumber + 1)) {
        BusScanEnd = Alloc->EndBusNumber + 1;
    }
    if (BusScanEnd <= Alloc->StartBusNumber && Alloc->EndBusNumber >= Alloc->StartBusNumber) { // Ensure at least one bus if range is valid
        BusScanEnd = Alloc->StartBusNumber + 1;
    }


    for (UINT16 Bus = Alloc->StartBusNumber; Bus < BusScanEnd; Bus++) {
      for (UINT8 Device = 0; Device < 32; Device++) {
        for (UINT8 Function = 0; Function < 8; Function++) {
          if (DeviceCount >= MaxDevicesToScan) {
            return DeviceCount;
          }

          UINT64 ConfigSpacePciExBase = Alloc->BaseAddress;
          // UEFI identity-maps physical memory, so we can cast physical PCI-E config space address to a pointer.
          UINTN PciDeviceConfigBaseAddress = (UINTN)ConfigSpacePciExBase +
                                             PCI_CONFIG_ADDRESS((UINT8)Bus, Device, Function, 0);

          volatile UINT16 *VendorIdPtr = (volatile UINT16 *)(PciDeviceConfigBaseAddress + PCI_VENDOR_ID_OFFSET);

          // Check if Vendor ID is valid (not 0xFFFF)
          if (*VendorIdPtr == 0xFFFF) {
            if (Function == 0) { // If Func 0 doesn't exist, no other funcs for this device exist
                break;
            }
            continue; // Skip this function
          }

          PciDevicesList[DeviceCount].VendorId = *VendorIdPtr;
          PciDevicesList[DeviceCount].DeviceId = *(volatile UINT16 *)(PciDeviceConfigBaseAddress + PCI_DEVICE_ID_OFFSET);

          // Read Class Code (3 bytes: BaseClass, SubClass, ProgIF)
          // BaseClass is at offset 0x0B, SubClass at 0x0A, ProgIF at 0x09
          // We read them in that order to form BBSSPP
          UINT8 BaseClass = *(volatile UINT8 *)(PciDeviceConfigBaseAddress + PCI_CLASS_CODE_OFFSET + 2); // Offset 0x0B
          UINT8 SubClass  = *(volatile UINT8 *)(PciDeviceConfigBaseAddress + PCI_CLASS_CODE_OFFSET + 1); // Offset 0x0A
          UINT8 ProgIF    = *(volatile UINT8 *)(PciDeviceConfigBaseAddress + PCI_CLASS_CODE_OFFSET + 0); // Offset 0x09
          PciDevicesList[DeviceCount].ClassCode = ((UINT32)BaseClass << 16) | ((UINT32)SubClass << 8) | ProgIF;

          PciDevicesList[DeviceCount].Bus = (UINT8)Bus;
          PciDevicesList[DeviceCount].Device = Device;
          PciDevicesList[DeviceCount].Function = Function;

          Print(L"PCI: %02X:%02X.%X VID:%04X DID:%04X Class:%06X\n",
                Bus, Device, Function,
                PciDevicesList[DeviceCount].VendorId,
                PciDevicesList[DeviceCount].DeviceId,
                PciDevicesList[DeviceCount].ClassCode);

          DeviceCount++;

          // If this is function 0, check if it's a multi-function device.
          // If not, no need to check other functions for this device.
          if (Function == 0) {
            UINT8 HeaderType = *(volatile UINT8 *)(PciDeviceConfigBaseAddress + PCI_HEADER_TYPE_OFFSET);
            if (!(HeaderType & 0x80)) { // Bit 7 indicates multi-function
              break; // Not a multi-function device, move to next device
            }
          }
        }
      }
    }
  }
  return DeviceCount;
}


// --- ELF64 Definitions (subset) ---
#define EI_NIDENT 16
#define ELFMAG0   0x7f
#define ELFMAG1   'E'
#define ELFMAG2   'L'
#define ELFMAG3   'F'

#define ET_EXEC   2     // Executable file
#define EM_X86_64 62    // AMD x86-64 architecture

#pragma pack(push, 1)
typedef struct {
  UINT8                 e_ident[EI_NIDENT]; // ELF Magic number and other info
  UINT16                e_type;             // Object file type
  UINT16                e_machine;          // Architecture
  UINT32                e_version;          // Object file version
  UINT64                e_entry;            // Entry point virtual address
  UINT64                e_phoff;            // Program header table file offset
  UINT64                e_shoff;            // Section header table file offset
  UINT32                e_flags;            // Processor-specific flags
  UINT16                e_ehsize;           // ELF header size in bytes
  UINT16                e_phentsize;        // Program header table entry size
  UINT16                e_phnum;            // Program header table entry count
  UINT16                e_shentsize;        // Section header table entry size
  UINT16                e_shnum;            // Section header table entry count
  UINT16                e_shstrndx;         // Section header string table index
} Elf64_Ehdr;
#pragma pack(pop)

// --- Helper function to translate EFI memory type to Multiboot2 memory type ---
UINT32
TranslateEfiToMb2MemoryType(
  IN EFI_MEMORY_TYPE EfiType
)
{
  switch (EfiType) {
    case EfiLoaderCode:
    case EfiLoaderData:
    case EfiBootServicesCode:
    case EfiBootServicesData:
    case EfiConventionalMemory:
      return MULTIBOOT_MEMORY_AVAILABLE;

    case EfiACPIReclaimMemory:
      return MULTIBOOT_MEMORY_ACPI_RECLAIMABLE;

    case EfiACPIMemoryNVS:
      return MULTIBOOT_MEMORY_NVS;

    // EfiReservedMemoryType, EfiRuntimeServicesCode, EfiRuntimeServicesData,
    // EfiUnusableMemory, EfiMemoryMappedIO, EfiMemoryMappedIOPortSpace,
    // EfiPalCode, EfiPersistentMemory, EfiMaxMemoryType
    default:
      return MULTIBOOT_MEMORY_RESERVED;
  }
}

// --- Function to get memory map and prepare MB2 mmap tag ---
EFI_STATUS
GetMemoryMapAndPrepareMb2MmapTag(
  IN OUT VOID**   Mb2InfoBufferHostPtr,    // Pointer to the host of the main MB2 info buffer pointer
  IN OUT UINTN*   Mb2InfoBufferSize,     // Pointer to the size of the main MB2 info buffer
  IN OUT UINT8**  CurrentMb2TagWritePtr, // Pointer to where the next tag should be written
  OUT    UINTN*   OutMapKey              // Output for the memory map key
)
{
  EFI_STATUS            Status;
  EFI_MEMORY_DESCRIPTOR *EfiMemoryMap = NULL;
  UINTN                 EfiMemoryMapSize = 0;
  UINTN                 EfiDescriptorSize = 0;
  UINT32                EfiDescriptorVersion = 0;
  UINTN                 LocalMapKey = 0;
  UINTN                 Index;
  multiboot_tag_mmap_t* Mb2MmapTag;
  multiboot_mmap_entry_t* Mb2MmapEntryPtr; // Changed name to avoid conflict
  UINTN                 NumEfiDescriptors;
  UINTN                 ActualNumMb2EntriesWritten = 0;
  UINTN                 RequiredMb2MmapTagHeaderSize = sizeof(multiboot_tag_mmap_t);
  UINTN                 CurrentMb2MmapTagTotalSize;


  if (Mb2InfoBufferHostPtr == NULL || *Mb2InfoBufferHostPtr == NULL || Mb2InfoBufferSize == NULL ||
      CurrentMb2TagWritePtr == NULL || *CurrentMb2TagWritePtr == NULL || OutMapKey == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  // Step 1: Get the size of the memory map.
  Status = gBS->GetMemoryMap(&EfiMemoryMapSize, EfiMemoryMap, &LocalMapKey, &EfiDescriptorSize, &EfiDescriptorVersion);
  if (Status != EFI_BUFFER_TOO_SMALL) {
    Print(L"Unexpected status from initial GetMemoryMap: %r\n", Status);
    return (Status == EFI_SUCCESS) ? EFI_LOAD_ERROR : Status;
  }

  // Step 2: Allocate a buffer for the memory map. Add padding.
  EfiMemoryMapSize += EfiDescriptorSize * 5;
  EfiMemoryMap = AllocatePool(EfiMemoryMapSize);
  if (EfiMemoryMap == NULL) {
    Print(L"Failed to allocate buffer for EFI Memory Map (Size: %d bytes)\n", EfiMemoryMapSize);
    return EFI_OUT_OF_RESOURCES;
  }

  // Step 3: Get the actual memory map.
  Status = gBS->GetMemoryMap(&EfiMemoryMapSize, EfiMemoryMap, &LocalMapKey, &EfiDescriptorSize, &EfiDescriptorVersion);
  if (EFI_ERROR(Status)) {
    Print(L"Failed to get EFI Memory Map: %r\n", Status);
    FreePool(EfiMemoryMap);
    return Status;
  }

  *OutMapKey = LocalMapKey;

  NumEfiDescriptors = EfiMemoryMapSize / EfiDescriptorSize;
  Print(L"UEFI Memory Map: %d entries, Descriptor size: %d, Total map size: %d\n",
        NumEfiDescriptors, EfiDescriptorSize, EfiMemoryMapSize);

  // Check if there's enough space for at least the mmap tag header
  if (((UINTN)(*CurrentMb2TagWritePtr) + RequiredMb2MmapTagHeaderSize) > ((UINTN)(*Mb2InfoBufferHostPtr) + *Mb2InfoBufferSize)) {
    Print(L"ERROR: Not enough space in MB2 buffer for MMAP tag header.\n");
    FreePool(EfiMemoryMap);
    return EFI_BUFFER_TOO_SMALL;
  }

  Mb2MmapTag = (multiboot_tag_mmap_t*)*CurrentMb2TagWritePtr;
  Mb2MmapTag->Type = MULTIBOOT_TAG_TYPE_MMAP;
  Mb2MmapTag->EntrySize = sizeof(multiboot_mmap_entry_t);
  Mb2MmapTag->EntryVersion = 0;

  Mb2MmapEntryPtr = Mb2MmapTag->Entries;

  for (Index = 0; Index < NumEfiDescriptors; Index++) {
    EFI_MEMORY_DESCRIPTOR *EfiDesc = (EFI_MEMORY_DESCRIPTOR*)((UINT8*)EfiMemoryMap + (Index * EfiDescriptorSize));

    if (EfiDesc->NumberOfPages == 0) {
        continue; // Skip zero-length entries
    }

    // Check if there's space for ONE more mmap entry
    CurrentMb2MmapTagTotalSize = RequiredMb2MmapTagHeaderSize + ((ActualNumMb2EntriesWritten + 1) * sizeof(multiboot_mmap_entry_t));
    if (((UINTN)(*CurrentMb2TagWritePtr) + CurrentMb2MmapTagTotalSize) > ((UINTN)(*Mb2InfoBufferHostPtr) + *Mb2InfoBufferSize)) {
        Print(L"WARNING: Not enough space in MB2 buffer for all MMAP entries. Wrote %d entries.\n", ActualNumMb2EntriesWritten);
        break; // Stop adding entries if not enough space
    }

    Mb2MmapEntryPtr->Addr = EfiDesc->PhysicalStart;
    Mb2MmapEntryPtr->Len = EfiDesc->NumberOfPages * EFI_PAGE_SIZE;
    Mb2MmapEntryPtr->Type = TranslateEfiToMb2MemoryType(EfiDesc->Type);
    Mb2MmapEntryPtr->Reserved = 0;

    Mb2MmapEntryPtr = (multiboot_mmap_entry_t*)((UINT8*)Mb2MmapEntryPtr + sizeof(multiboot_mmap_entry_t));
    ActualNumMb2EntriesWritten++;
  }

  UINT32 FinalTagDataSize = sizeof(multiboot_tag_mmap_t) + (ActualNumMb2EntriesWritten * sizeof(multiboot_mmap_entry_t));
  Mb2MmapTag->Size = (FinalTagDataSize + MULTIBOOT_TAG_ALIGN - 1) & ~(MULTIBOOT_TAG_ALIGN - 1);

  Print(L"MB2 MMAP Tag: %d entries written. Calculated Size: %d bytes.\n", ActualNumMb2EntriesWritten, Mb2MmapTag->Size);

  *CurrentMb2TagWritePtr += Mb2MmapTag->Size;

  FreePool(EfiMemoryMap);
  return EFI_SUCCESS;
}


// --- File Definitions ---
#define KERNEL_FILENAME  L"kernel.elf"
#define PAYLOAD_FILENAME L"payload.elf"
#define KERNEL_SIG_FILENAME L"kernel.elf.sig"
#define PAYLOAD_SIG_FILENAME L"payload.elf.sig"

// --- Placeholder Public Key for ML-DSA-65 ---
// Actual ML-DSA-65 public key is OQS_SIG_ML_DSA_65_LENGTH_PUBLIC_KEY (2592) bytes.
// Initialized with a deterministic, non-zero pattern: publicKey[i] = (i % 251) + 1.
// This key is still a placeholder for demonstration.
static const UINT8 mlDsa65PublicKey[OQS_SIG_ML_DSA_65_LENGTH_PUBLIC_KEY] = {
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
  0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
  0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
  0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40,
  0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50,
  0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60,
  0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70,
  0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80,
  0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90,
  0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0,
  0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0,
  0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0,
  0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0,
  0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0,
  0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF, 0xF0,
  0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0x01, 0x02, 0x03, 0x04, 0x05,
  0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
  0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
  0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
  0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45,
  0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55,
  0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65,
  0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75,
  0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85,
  0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95,
  0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,
  0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5,
  0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5,
  0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5,
  0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5,
  0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF, 0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5,
  0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
  0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A,
  0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A,
  0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A,
  0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A,
  0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A,
  0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A,
  0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A,
  0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A,
  0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A,
  0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA,
  0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA,
  0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA,
  0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA,
  0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA,
  0xEB, 0xEC, 0xED, 0xEE, 0xEF, 0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA,
  0xFB, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
  0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
  0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
  0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
  0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F,
  0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
  0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
  0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
  0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
  0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
  0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF,
  0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
  0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,
  0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF,
  0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0x01, 0x02, 0x03, 0x04,
  0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
  0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24,
  0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34,
  0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44,
  0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54,
  0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64,
  0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74,
  0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80, 0x81, 0x82, 0x83, 0x84,
  0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90, 0x91, 0x92, 0x93, 0x94,
  0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4,
  0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4,
  0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4,
  0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4,
  0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0, 0xE1, 0xE2, 0xE3, 0xE4,
  0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF, 0xF0, 0xF1, 0xF2, 0xF3, 0xF4,
  0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
  0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
  0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
  0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
  0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
  0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59,
  0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69,
  0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79,
  0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
  0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99,
  0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9,
  0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9,
  0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9,
  0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9,
  0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9,
  0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF, 0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9,
  0xFA, 0xFB, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C
};

/**
  Helper function to read a file from the EFI System Partition (ESP).

  @param[in]  FileName     The name of the file to read.
  @param[out] FileBuffer   A pointer to receive the allocated buffer containing the file data.
  @param[out] FileSize     A pointer to receive the size of the file.

  @retval EFI_SUCCESS      The file was read successfully.
  @retval other            An error occurred.
**/
EFI_STATUS
ReadFileFromEspToBuffer ( // Renamed to clarify its role
  IN  CHAR16* FileName,
  OUT VOID**  FileBuffer,
  OUT UINTN*  FileSize
  )
{
  EFI_STATUS                       Status;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL  *SimpleFileSystem;
  EFI_FILE_PROTOCOL                *FsRoot;
  EFI_FILE_PROTOCOL                *FileHandle;
  EFI_FILE_INFO                    *FileInfo;
  UINTN                            FileInfoSize;
  UINTN                            ReadSize;

  if (FileBuffer == NULL || FileSize == NULL || FileName == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  *FileBuffer = NULL;
  *FileSize = 0;
  // This function will now allocate a temporary buffer.
  // The caller is responsible for freeing it if needed,
  // or it will be freed by LoadFileIntoLoaderPages.

  Status = gBS->LocateProtocol (&gEfiSimpleFileSystemProtocolGuid, NULL, (VOID**)&SimpleFileSystem);
  if (EFI_ERROR (Status)) {
    Print(L"Failed to locate SimpleFileSystem protocol for %s: %r\n", FileName, Status);
    return Status;
  }

  Status = SimpleFileSystem->OpenVolume (SimpleFileSystem, &FsRoot);
  if (EFI_ERROR (Status)) {
    Print(L"Failed to open ESP volume: %r\n", Status);
    return Status;
  }

  Status = FsRoot->Open (FsRoot, &FileHandle, FileName, EFI_FILE_MODE_READ, 0);
  if (EFI_ERROR (Status)) {
    Print(L"Failed to open file %s: %r\n", FileName, Status);
    FsRoot->Close(FsRoot);
    return Status;
  }

  // Get file size
  FileInfoSize = 0;
  Status = FileHandle->GetInfo(FileHandle, &gEfiFileInfoGuid, &FileInfoSize, NULL);
  if (Status != EFI_BUFFER_TOO_SMALL) {
     Print(L"Failed to get FileInfo size for %s: %r (size %d bytes)\n", FileName, Status, FileInfoSize);
     FileHandle->Close(FileHandle);
     FsRoot->Close(FsRoot);
     return (Status == EFI_SUCCESS) ? EFI_DEVICE_ERROR : Status; // if success, it means FileInfoSize was 0
  }

  FileInfo = AllocatePool(FileInfoSize);
  if (FileInfo == NULL) {
    Print(L"Failed to allocate memory for FileInfo of %s\n", FileName);
    FileHandle->Close(FileHandle);
    FsRoot->Close(FsRoot);
    return EFI_OUT_OF_RESOURCES;
  }

  Status = FileHandle->GetInfo(FileHandle, &gEfiFileInfoGuid, &FileInfoSize, FileInfo);
  if (EFI_ERROR (Status)) {
    Print(L"Failed to get FileInfo for %s: %r\n", FileName, Status);
    FreePool(FileInfo);
    FileHandle->Close(FileHandle);
    FsRoot->Close(FsRoot);
    return Status;
  }

  *FileSize = FileInfo->FileSize;
  FreePool(FileInfo); // FileInfo is no longer needed

  if (*FileSize == 0) {
    Print(L"File %s is empty.\n", FileName);
    *FileBuffer = NULL; // Ensure buffer is NULL for 0-size file
    FileHandle->Close(FileHandle);
    FsRoot->Close(FsRoot);
    return EFI_SUCCESS; // Reading an empty file is not an error in itself
  }

  *FileBuffer = AllocatePool(*FileSize);
  if (*FileBuffer == NULL) {
    Print(L"Failed to allocate buffer for %s (Size: %d bytes)\n", FileName, *FileSize);
    FileHandle->Close(FileHandle);
    FsRoot->Close(FsRoot);
    return EFI_OUT_OF_RESOURCES;
  }

  ReadSize = *FileSize;
  Status = FileHandle->Read(FileHandle, &ReadSize, *FileBuffer);
  if (EFI_ERROR (Status) || ReadSize != *FileSize) {
    Print(L"Failed to read file %s (Read: %d, Expected: %d): %r\n", FileName, ReadSize, *FileSize, Status);
    FreePool(*FileBuffer);
    *FileBuffer = NULL;
    *FileSize = 0;
    FileHandle->Close(FileHandle);
    FsRoot->Close(FsRoot);
    return EFI_DEVICE_ERROR;
  }

  FileHandle->Close(FileHandle);
  FsRoot->Close(FsRoot);

  return EFI_SUCCESS;
}


/**
  The user Entry Point for Application. The user code starts with this function
  as the real entry point for the application.

  @param[in] ImageHandle    The firmware allocated handle for the EFI image.
  @param[in] SystemTable    A pointer to the EFI System Table.

  @retval EFI_SUCCESS       The entry point is executed successfully.
  @retval other             Some error occurs when executing this entry point.

**/
EFI_STATUS
EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
/**
  Loads a file from ESP into EfiLoaderData memory.

  @param[in]  FileName             Name of the file to load.
  @param[out] PhysicalAddress      Pointer to store the physical address of the loaded file.
  @param[out] FileSize             Pointer to store the size of the loaded file.

  @retval EFI_SUCCESS              File loaded successfully.
  @retval Other                    Error codes from ReadFileFromEspToBuffer or AllocatePages.
**/
EFI_STATUS
LoadFileIntoLoaderPages (
  IN  CHAR16*               FileName,
  OUT EFI_PHYSICAL_ADDRESS* PhysicalAddress,
  OUT UINTN*                FileSize
  )
{
  EFI_STATUS Status;
  VOID*      TempBuffer = NULL;
  UINTN      TempFileSize = 0;
  UINTN      NumPages;

  if (PhysicalAddress == NULL || FileSize == NULL || FileName == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  *PhysicalAddress = 0;
  *FileSize = 0;

  // 1. Read file into a temporary buffer (EfiBootServicesData or similar)
  Status = ReadFileFromEspToBuffer(FileName, &TempBuffer, &TempFileSize);
  if (EFI_ERROR(Status)) {
    Print(L"Failed to read %s into temporary buffer: %r\n", FileName, Status);
    return Status;
  }
  if (TempFileSize == 0) {
    Print(L"File %s is empty, not loading into EfiLoaderData.\n", FileName);
    // TempBuffer might be NULL or allocated (if ReadFileFromEspToBuffer changes for 0-byte files)
    if (TempBuffer != NULL) FreePool(TempBuffer);
    return EFI_SUCCESS; // Or EFI_NOT_FOUND / EFI_LOAD_ERROR if empty file is an error
  }

  // 2. Calculate number of pages needed
  NumPages = EFI_SIZE_TO_PAGES(TempFileSize);

  // 3. Allocate EfiLoaderData pages
  //    Using AllocateAnyPages allows the firmware to place it optimally.
  //    The OS is expected to handle this physical address.
  Status = gBS->AllocatePages(AllocateAnyPages, EfiLoaderData, NumPages, PhysicalAddress);
  if (EFI_ERROR(Status)) {
    Print(L"Failed to allocate %d EfiLoaderData pages for %s: %r\n", NumPages, FileName, Status);
    FreePool(TempBuffer); // Free the temporary buffer
    return Status;
  }

  // 4. Copy content from temporary buffer to EfiLoaderData region
  gBS->CopyMem((VOID*)(UINTN)(*PhysicalAddress), TempBuffer, TempFileSize);
  *FileSize = TempFileSize;

  Print(L"File %s loaded into EfiLoaderData at 0x%016lx (Size: %d bytes, %d pages)\n",
        FileName, *PhysicalAddress, *FileSize, NumPages);

  // 5. Free the temporary buffer
  FreePool(TempBuffer);

  return EFI_SUCCESS;
}


  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS Status = EFI_SUCCESS;
  OQS_SIG *sig = NULL;

  // Buffers for signature files (remain in EfiBootServicesData as they are temporary)
  VOID* kernelSigFileBuffer = NULL;
  UINTN kernelSigFileSize = 0;
  VOID* payloadSigFileBuffer = NULL;
  UINTN payloadSigFileSize = 0;

  // Physical addresses and sizes for kernel & payload in EfiLoaderData
  EFI_PHYSICAL_ADDRESS kernelPhysicalAddress = 0;
  UINTN kernelFileSize = 0;
  EFI_PHYSICAL_ADDRESS payloadPhysicalAddress = 0;
  UINTN payloadFileSize = 0;
  UINT64 kernelEntryPoint = 0;
  UINTN MapKey = 0; // Will hold the key from GetMemoryMap


  VOID* mb2InfoBuffer = NULL;
  // Allocate a larger buffer for MB2 info, as memory map + PCI info can be significant.
  // Increased to 4 pages (16KB) as a safer starting point.
  UINTN mb2InfoSize = EFI_PAGE_SIZE * 4;
  UINT8* currentMb2TagPtr = NULL;
  // UINTN i; // Loop counter for key initialization - NO LONGER NEEDED

  // ACPI/PCI related variables
  RSDP_DESCRIPTOR *Rsdp = NULL;
  ACPI_SDT_HEADER *RootSdt = NULL;
  VOID            *McfgTableVoid = NULL; // Use VOID* for McfgTablePtr from FindAcpiSystemTables
  MCFG_TABLE      *Mcfg = NULL;
  PciDeviceInfo   PciDevicesFound[MAX_PCI_DEVICES_TO_SCAN];
  UINT32          NumPciDevicesFound = 0;

  // mlDsa65PublicKey is now a static const global array, no runtime initialization needed.

  Print(L"PqUefiLoader starting...\n");

  // --- Load Kernel and Payload into EfiLoaderData ---
  Status = LoadFileIntoLoaderPages(KERNEL_FILENAME, &kernelPhysicalAddress, &kernelFileSize);
  Print(L"Loading %s into EfiLoaderData: %r\n", KERNEL_FILENAME, Status);
  if (EFI_ERROR(Status) || kernelPhysicalAddress == 0) {
    Status = EFI_ERROR(Status) ? Status : EFI_LOAD_ERROR; // Ensure error status
    goto CleanupAndExit;
  }

  Status = LoadFileIntoLoaderPages(PAYLOAD_FILENAME, &payloadPhysicalAddress, &payloadFileSize);
  Print(L"Loading %s into EfiLoaderData: %r\n", PAYLOAD_FILENAME, Status);
  if (EFI_ERROR(Status) || payloadPhysicalAddress == 0) {
    Status = EFI_ERROR(Status) ? Status : EFI_LOAD_ERROR;
    goto CleanupAndExit;
  }

  // --- Load Signature Files (into temporary buffers) ---
  Status = ReadFileFromEspToBuffer(KERNEL_SIG_FILENAME, &kernelSigFileBuffer, &kernelSigFileSize);
  Print(L"Loading %s into temporary buffer: %r (Size: %d bytes)\n", KERNEL_SIG_FILENAME, Status, kernelSigFileSize);
  if (EFI_ERROR(Status)) {
    goto CleanupAndExit;
  }

  Status = ReadFileFromEspToBuffer(PAYLOAD_SIG_FILENAME, &payloadSigFileBuffer, &payloadSigFileSize);
  Print(L"Loading %s into temporary buffer: %r (Size: %d bytes)\n", PAYLOAD_SIG_FILENAME, Status, payloadSigFileSize);
  if (EFI_ERROR(Status)) {
    goto CleanupAndExit;
  }

  Print(L"Kernel at 0x%016lx, Payload at 0x%016lx. Proceeding with verification...\n", kernelPhysicalAddress, payloadPhysicalAddress);

  sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
  if (sig == NULL) {
    Print(L"Failed to create OQS_SIG object for %a.\n", OQS_SIG_alg_ml_dsa_65);
    Status = EFI_ABORTED;
    goto CleanupAndExit;
  }
  Print(L"OQS_SIG object for %a created.\n", OQS_SIG_alg_ml_dsa_65);

  // Validate public key length consistency
  if (sig->length_public_key != OQS_SIG_ML_DSA_65_LENGTH_PUBLIC_KEY) {
    Print(L"ERROR: Mismatch in public key size for %a!\n", OQS_SIG_alg_ml_dsa_65);
    Print(L"  liboqs expects: %d bytes\n", sig->length_public_key);
    Print(L"  Embedded key macro OQS_SIG_ML_DSA_65_LENGTH_PUBLIC_KEY is: %d bytes\n", OQS_SIG_ML_DSA_65_LENGTH_PUBLIC_KEY);
    Print(L"  sizeof(mlDsa65PublicKey) is: %d bytes\n", sizeof(mlDsa65PublicKey));
    Status = EFI_INVALID_PARAMETER;
    // OQS_SIG_free(sig) will be called in CleanupAndExit
    goto CleanupAndExit;
  }
  // Also check against the actual size of our embedded key array for sanity
  if (sig->length_public_key != sizeof(mlDsa65PublicKey)) {
     Print(L"ERROR: Mismatch between liboqs expected PK size and sizeof(mlDsa65PublicKey)!\n");
     Print(L"  liboqs expects: %d bytes\n", sig->length_public_key);
     Print(L"  sizeof(mlDsa65PublicKey) is: %d bytes\n", sizeof(mlDsa65PublicKey));
     Status = EFI_INVALID_PARAMETER;
     goto CleanupAndExit;
  }


  // Verify Kernel (passing physical address directly)
  // Note: OQS_SIG_verify returns OQS_SUCCESS (0) on success.
  Status = OQS_SIG_verify(sig, (UINT8*)(UINTN)kernelPhysicalAddress, kernelFileSize,
                          (UINT8*)kernelSigFileBuffer, kernelSigFileSize,
                          mlDsa65PublicKey, sizeof(mlDsa65PublicKey));
  if (Status == OQS_SUCCESS) {
    Print(L"Kernel signature verification SUCCESS (using dummy key).\n");
    Status = EFI_SUCCESS; // Convert OQS_SUCCESS to EFI_SUCCESS for internal logic
  } else {
    Print(L"Kernel signature verification FAILED (using dummy key). OQS_STATUS: %d\n", Status);
    Status = EFI_SECURITY_VIOLATION;
    goto CleanupAndExit;
  }

  // Verify Payload (passing physical address directly)
  Status = OQS_SIG_verify(sig, (UINT8*)(UINTN)payloadPhysicalAddress, payloadFileSize,
                          (UINT8*)payloadSigFileBuffer, payloadSigFileSize,
                          mlDsa65PublicKey, sizeof(mlDsa65PublicKey));
  if (Status == OQS_SUCCESS) {
    Print(L"Payload signature verification SUCCESS (using dummy key).\n");
    Status = EFI_SUCCESS; // Convert OQS_SUCCESS to EFI_SUCCESS
  } else {
    Print(L"Payload signature verification FAILED (using dummy key). OQS_STATUS: %d\n", Status);
    Status = EFI_SECURITY_VIOLATION;
    goto CleanupAndExit;
  }

  Print(L"All signature verifications passed (using dummy key).\n");

  // --- Parse Kernel ELF Header for Entry Point ---
  if (kernelPhysicalAddress == 0 || kernelFileSize < sizeof(Elf64_Ehdr)) {
    Print(L"ERROR: Kernel not loaded or too small to be an ELF file.\n");
    Status = EFI_LOAD_ERROR;
    goto CleanupAndExit;
  }
  Elf64_Ehdr* kernelHeader = (Elf64_Ehdr*)(UINTN)kernelPhysicalAddress;

  // Validate ELF Magic
  if (!(kernelHeader->e_ident[0] == ELFMAG0 &&
        kernelHeader->e_ident[1] == ELFMAG1 &&
        kernelHeader->e_ident[2] == ELFMAG2 &&
        kernelHeader->e_ident[3] == ELFMAG3)) {
    Print(L"ERROR: Kernel ELF magic number is incorrect!\n");
    Status = EFI_LOAD_ERROR;
    goto CleanupAndExit;
  }
   Print(L"Kernel ELF Magic: OK\n");
   Print(L"Kernel Type: 0x%x, Machine: 0x%x, Version: 0x%x\n", kernelHeader->e_type, kernelHeader->e_machine, kernelHeader->e_version);

  // For a bootloader, the kernel is typically an executable.
  // e_entry is the physical address if linked to be loaded at a specific address or is PIC.
  kernelEntryPoint = kernelHeader->e_entry;
  Print(L"Kernel ELF Entry Point: 0x%016lx\n", kernelEntryPoint);
  if (kernelEntryPoint == 0) {
      Print(L"WARNING: Kernel entry point is 0. This might be an issue.\n");
  }

  // --- ACPI and PCI Scan ---
  Print(L"PqUefiLoader: Starting ACPI table discovery...\n");
  Status = FindAcpiSystemTables(&Rsdp, &RootSdt, &McfgTableVoid);
  if (EFI_ERROR(Status)) {
      Print(L"ACPI system table discovery failed: %r\n", Status);
      // Not fatal, Mcfg will remain NULL.
  } else {
      Print(L"RSDP found at 0x%p, Root SDT (%.4a) at 0x%p\n", Rsdp, RootSdt->Signature, RootSdt);
      if (McfgTableVoid != NULL) {
          Mcfg = (MCFG_TABLE *)McfgTableVoid; // Cast to specific type
          Print(L"MCFG table found at 0x%p. Starting PCI scan...\n", Mcfg);
          NumPciDevicesFound = ScanPciDevices(Mcfg, PciDevicesFound, MAX_PCI_DEVICES_TO_SCAN);
          Print(L"PCI Scan complete. Found %d devices.\n", NumPciDevicesFound);
      } else {
          Print(L"MCFG table NOT found.\n");
      }
  }
  // --- End ACPI and PCI Scan ---

  // --- Prepare Multiboot2 Information ---
  Print(L"Preparing Multiboot2 information (using physical addresses)...\n");
  mb2InfoBuffer = AllocatePool(mb2InfoSize);
  if (mb2InfoBuffer == NULL) {
    Print(L"Failed to allocate buffer for Multiboot2 info (Size: %d bytes).\n", mb2InfoSize);
    Status = EFI_OUT_OF_RESOURCES;
    goto CleanupAndExit;
  }
  gBS->SetMem(mb2InfoBuffer, mb2InfoSize, 0); // Zero out the buffer
  currentMb2TagPtr = (UINT8*)mb2InfoBuffer;

  // --- Get Memory Map and Prepare MB2 Mmap Tag ---
  // This needs to be done *before* other tags and before ExitBootServices.
  // The MapKey obtained here is crucial for ExitBootServices.
  Status = GetMemoryMapAndPrepareMb2MmapTag(&mb2InfoBuffer, &mb2InfoSize, &currentMb2TagPtr, &MapKey);
  if (EFI_ERROR(Status)) {
    Print(L"Failed to get memory map and prepare MB2 mmap tag: %r\n", Status);
    goto CleanupAndExit;
  }
  Print(L"UEFI Memory Map Key for ExitBootServices: 0x%X\n", MapKey);
  Print(L"Multiboot2 mmap tag prepared. Current MB2 buffer pointer: 0x%p\n", currentMb2TagPtr);


  // --- Module Tags ---
  // Ensure currentMb2TagPtr is correctly advanced and there's space.

  // --- Custom Hardware Info Tag (with PCI devices) ---
  // This tag should be added *before* the End Tag and after other essential tags like Mmap and Modules.
  if (NumPciDevicesFound > 0) {
    UINTN actualPciDataPayloadSize = NumPciDevicesFound * sizeof(PciDeviceInfo);
    UINTN hwInfoTagRequiredDataPortionSize = sizeof(MultibootTagHwInfoBase) + actualPciDataPayloadSize;
    // Align the total size of the tag up to MULTIBOOT_TAG_ALIGN
    UINT32 hwInfoTagTotalAlignedSize = (UINT32)((hwInfoTagRequiredDataPortionSize + MULTIBOOT_TAG_ALIGN - 1) & ~(MULTIBOOT_TAG_ALIGN - 1));

    Print(L"Preparing Custom HW Info Tag: PCI Devs=%d, DataPayloadSize=%d, TotalAlignedTagSize=%d\n",
        NumPciDevicesFound, actualPciDataPayloadSize, hwInfoTagTotalAlignedSize);

    if (((UINTN)currentMb2TagPtr + hwInfoTagTotalAlignedSize) > ((UINTN)mb2InfoBuffer + mb2InfoSize)) {
        Print(L"ERROR: Not enough space in MB2 buffer for Custom HW Info tag (Need %d, Have %d remaining approx).\n",
              hwInfoTagTotalAlignedSize, (UINTN)mb2InfoBuffer + mb2InfoSize - (UINTN)currentMb2TagPtr);
        // Not treating as fatal for now, just skipping the tag.
    } else {
        MultibootTagHwInfoBase *hwInfoTag = (MultibootTagHwInfoBase*)currentMb2TagPtr;
        hwInfoTag->Type = MULTIBOOT_TAG_TYPE_HW_INFO;
        hwInfoTag->Size = hwInfoTagTotalAlignedSize;
        hwInfoTag->NumPciDevs = NumPciDevicesFound;

        // Copy PciDevicesFound data immediately after the MultibootTagHwInfoBase part of the tag
        UINT8* pciDataDestinationInTag = (UINT8*)currentMb2TagPtr + sizeof(MultibootTagHwInfoBase);
        gBS->CopyMem(pciDataDestinationInTag, PciDevicesFound, actualPciDataPayloadSize);

        Print(L"  Custom HW Info Tag added: Type=0x%X, Size=%d, PCI Devs=%d\n",
               hwInfoTag->Type, hwInfoTag->Size, hwInfoTag->NumPciDevs);
        currentMb2TagPtr += hwInfoTag->Size; // Advance by the aligned size
    }
  }

  CHAR8 kernelModuleName[] = "kernel";
  CHAR8 payloadModuleName[] = "vmm_payload";
  UINTN kernelModuleNameLen = sizeof(kernelModuleName); // includes null terminator
  UINTN payloadModuleNameLen = sizeof(payloadModuleName); // includes null terminator

  // 1. Kernel Module Tag
  UINTN requiredSpaceForKernelTag = (sizeof(multiboot_tag_module_t) + kernelModuleNameLen + MULTIBOOT_TAG_ALIGN -1) & ~(MULTIBOOT_TAG_ALIGN -1);
  if (((UINTN)currentMb2TagPtr + requiredSpaceForKernelTag) > ((UINTN)mb2InfoBuffer + mb2InfoSize)) {
      Print(L"ERROR: Not enough space in MB2 buffer for kernel module tag.\n");
      Status = EFI_BUFFER_TOO_SMALL;
      goto CleanupAndExit;
  }
  multiboot_tag_module_t *kernelModuleTag = (multiboot_tag_module_t*)currentMb2TagPtr;
  kernelModuleTag->Type = MULTIBOOT_TAG_TYPE_MODULE;
  UINT32 kernelTagActualSize = sizeof(multiboot_tag_module_t) + kernelModuleNameLen;
  kernelModuleTag->Size = (kernelTagActualSize + MULTIBOOT_TAG_ALIGN - 1) & ~(MULTIBOOT_TAG_ALIGN - 1);
  kernelModuleTag->ModStart = (UINT32)kernelPhysicalAddress;
  kernelModuleTag->ModEnd = (UINT32)(kernelPhysicalAddress + kernelFileSize);
  gBS->CopyMem(kernelModuleTag->Name, kernelModuleName, kernelModuleNameLen);
  Print(L"  Kernel Module (Phys): Start=0x%08x, End=0x%08x, Size=0x%08x, Name=%a\n",
        kernelModuleTag->ModStart, kernelModuleTag->ModEnd, kernelModuleTag->Size, kernelModuleTag->Name);
  currentMb2TagPtr += kernelModuleTag->Size;


  // 2. Payload (VMM) Module Tag
  UINTN requiredSpaceForPayloadTag = (sizeof(multiboot_tag_module_t) + payloadModuleNameLen + MULTIBOOT_TAG_ALIGN -1) & ~(MULTIBOOT_TAG_ALIGN -1);
  if (((UINTN)currentMb2TagPtr + requiredSpaceForPayloadTag) > ((UINTN)mb2InfoBuffer + mb2InfoSize)) {
      Print(L"ERROR: Not enough space in MB2 buffer for payload module tag.\n");
      Status = EFI_BUFFER_TOO_SMALL;
      goto CleanupAndExit;
  }
  multiboot_tag_module_t *payloadModuleTag = (multiboot_tag_module_t*)currentMb2TagPtr;
  payloadModuleTag->Type = MULTIBOOT_TAG_TYPE_MODULE;
  UINT32 payloadTagActualSize = sizeof(multiboot_tag_module_t) + payloadModuleNameLen;
  payloadModuleTag->Size = (payloadTagActualSize + MULTIBOOT_TAG_ALIGN - 1) & ~(MULTIBOOT_TAG_ALIGN - 1);
  payloadModuleTag->ModStart = (UINT32)payloadPhysicalAddress;
  payloadModuleTag->ModEnd = (UINT32)(payloadPhysicalAddress + payloadFileSize);
  gBS->CopyMem(payloadModuleTag->Name, payloadModuleName, payloadModuleNameLen);
   Print(L"  Payload Module (Phys): Start=0x%08x, End=0x%08x, Size=0x%08x, Name=%a\n",
        payloadModuleTag->ModStart, payloadModuleTag->ModEnd, payloadModuleTag->Size, payloadModuleTag->Name);
  currentMb2TagPtr += payloadModuleTag->Size;


  // 3. End Tag
  UINTN requiredSpaceForEndTag = sizeof(multiboot_tag_t);
   if (((UINTN)currentMb2TagPtr + requiredSpaceForEndTag) > ((UINTN)mb2InfoBuffer + mb2InfoSize)) {
      Print(L"ERROR: Not enough space in MB2 buffer for end tag.\n");
      Status = EFI_BUFFER_TOO_SMALL;
      goto CleanupAndExit;
  }
  multiboot_tag_t *endTag = (multiboot_tag_t*)currentMb2TagPtr;
  endTag->Type = MULTIBOOT_TAG_TYPE_END;
  endTag->Size = sizeof(multiboot_tag_t);
  Print(L"  End Tag: Type=%d, Size=%d\n", endTag->Type, endTag->Size);
  currentMb2TagPtr += endTag->Size;

  Print(L"Multiboot2 info prepared at address: 0x%p (Total size used: %d bytes of %d available)\n",
        mb2InfoBuffer, (UINTN)(currentMb2TagPtr - (UINT8*)mb2InfoBuffer), mb2InfoSize);

  // --- Exit Boot Services and Jump to Kernel ---
  Print(L"Attempting to ExitBootServices with MapKey: 0x%X...\n", MapKey);
  Status = gBS->ExitBootServices(ImageHandle, MapKey);

  if (EFI_ERROR(Status)) {
    // This Print might not work if console services are already partially torn down.
    Print(L"ERROR: ExitBootServices failed: %r. System halted.\n", Status);
    // Attempt to restore console if possible for a moment (highly unlikely to work reliably)
    // gBS->ConnectController(SystemTable->ConsoleOutHandle, NULL, NULL, TRUE);
    // Print(L"ExitBootServices failed: %r\n", Status);
    while (1) {
      CpuDeadLoop(); // Halt execution
    }
  }

  // At this point, Boot Services are GONE. No more gBS calls, no more Print().
  // We can only use Runtime Services if specifically set up, or just jump to the kernel.

  UINT64 mb2PhysicalAddr = (UINT64)(UINTN)mb2InfoBuffer; // mb2InfoBuffer is from AllocatePool, which gives
                                                       // a physical address in EfiBootServicesData/EfiLoaderData
                                                       // that is identity mapped at this stage.
  UINT64 kernelEntry = kernelEntryPoint;

  Print(L"Jumping to kernel at 0x%lX with MB2 info at 0x%lX (RDI)...\n", kernelEntry, mb2PhysicalAddr);
  // The above Print won't actually execute as Print relies on Boot Services.

  __asm__ __volatile__ (
    "movq %0, %%rdi\n\t"  // Load MB2 info address into RDI
    "jmp *%1"             // Jump to kernel entry point
    :                     // No output operands
    : "r" (mb2PhysicalAddr), "r" (kernelEntry) // Input operands
    : "rdi", "memory"     // Clobbered registers (RDI by mov, memory by jmp)
  );

  // This part should be unreachable.
  Status = EFI_SUCCESS;

CleanupAndExit:
  // If ExitBootServices failed, we might fall through here if the halt loop is removed.
  // However, most resources (like mb2InfoBuffer) are EfiBootServicesData and are effectively
  // lost or owned by the (non-booted) OS after a failed ExitBootServices.
  // Freeing them here is problematic.
  Print(L"Cleaning up resources (should only occur on pre-ExitBootServices errors)...\n");
  if (mb2InfoBuffer != NULL) {
    FreePool(mb2InfoBuffer);
    Print(L"Multiboot2 info buffer freed.\n");
  }
  if (sig != NULL) {
    OQS_SIG_free(sig);
    Print(L"OQS_SIG object freed.\n");
  }
  // Kernel and Payload buffers are now EfiLoaderData, not freed by us.
  // kernelFileBuffer and payloadFileBuffer are replaced by kernelPhysicalAddress and payloadPhysicalAddress.
  if (kernelSigFileBuffer != NULL) {
    FreePool(kernelSigFileBuffer);
    Print(L"Kernel signature file buffer freed.\n");
  }
  if (payloadSigFileBuffer != NULL) {
    FreePool(payloadSigFileBuffer);
    Print(L"Payload signature file buffer freed.\n");
  }
  // mb2InfoBuffer is still freed as it's EfiBootServicesData or similar.

  if (EFI_ERROR(Status)) {
     Print(L"PqUefiLoader finished with error: %r\n", Status);
  } else {
     Print(L"PqUefiLoader finished successfully.\n");
  }
  return Status;
}
