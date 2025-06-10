/*
 * LinuxVMM.c
 * CAmkES component C implementation for a Linux Virtual Machine Monitor
 */

#include <stdio.h>
#include <string.h>
#include <errno.h> // For error codes

#include <camkes.h>

// seL4 specific includes
#include <sel4/sel4.h>
#include <simple/simple.h>
#include <vka/object.h>
#include <vka/vka.h>
#include <vka/capops.h>
#include <allocman/allocman.h>
#include <sel4utils/vspace.h>
#include <sel4utils/sel4_zf_logif.h> // For ZF_LOGE etc. if used

// libsel4vm includes
#include <sel4vm/guest_vm.h>
#include <sel4vm/guest_ram.h>
#include <sel4vm/guest_vcpu.h>
#include <sel4vm/boot.h> // For vm_guest_cpu_create, vcpu_set_rip etc.
#include <sel4vm/arch/x86/boot.h> // For setup_linux_boot_params (conceptual or actual)
#include <sel4vm/guest_x86_platform.h> // For vm_install_legacy_serial_device etc.

// libsel4vmmplatsupport includes
#include <sel4vmmplatsupport/drivers/pci_helper.h> // Example, may not be directly needed yet
#include <sel4vmmplatsupport/arch/x86/devices/devices.h> // For device definitions like LINUX_SERIAL_PORT
#include <sel4vmmplatsupport/arch/x86/devices/virtio_con.h> // For VirtIO Console
#include <sel4vmmplatsupport/guest_image.h> // For load_linux_guest_image
#include <sel4vmmplatsupport/platform/sel4_serial.h> // For sel4platsupport_serial_ops_t if needed

// Includes for PCI passthrough (conceptual)
#include <sel4vm/guest_pci.h>
#include <sel4vm/arch/x86/guest_pci_legacy.h> // For guest_pci_get_bdf or similar helper
#include <sel4vmmplatsupport/arch/x86/devices/pci_passthrough.h>

// Includes for VirtIO Block (conceptual)
#include <sel4vmmplatsupport/arch/x86/devices/virtio_blk.h> // Assumed to define virtio_req_id_t, virtio_block_request_complete, etc.

// VirtIO Status Codes (subset)
#define VIRTIO_BLK_S_OK     0
#define VIRTIO_BLK_S_IOERR  1
// #define VIRTIO_BLK_S_UNSUPP 2 // Not used in this example

// Conceptual structure for a segment of a guest buffer in a VirtIO request
typedef struct {
    uintptr_t paddr;             // Guest physical address of the segment
    size_t    len;               // Length of this segment
    BOOL      is_device_writable;// True if the device (VMM) is expected to write to this segment
} virtio_guest_buffer_segment_t;

// Conceptual function to get segments of a guest buffer associated with a request
// Returns SUCCESS (0) if segment_info is populated, or an error code.
// segment_index should be incremented by the caller to get subsequent segments.
// Returns an error (e.g., -1 or specific code) when no more segments.
// This is a placeholder for what a VirtIO backend library would provide.
static inline int virtio_get_guest_buffer_segment(virtio_req_id_t req_id, int segment_index, virtio_guest_buffer_segment_t *segment_info) {
    // TODO: This needs to be implemented based on actual libsel4vm VirtIO queue processing.
    // It would look into the vring descriptors associated with req_id.
    // For now, this function will not work and is a placeholder.
    // A real implementation would not take guest_paddr_list[] and len_list[] in the callbacks,
    // but would use req_id to find that info.
    if (segment_info && req_id){
        // This is a HACK to make it compile and simulate one segment.
        // The callbacks will need to be rewritten based on how libsel4vm actually provides segment data.
        static uintptr_t* _guest_paddr_list = NULL;
        static size_t* _len_list = NULL;
        static unsigned int* _num_segments = NULL;
        static BOOL* _is_write_list = NULL; // For read callbacks, guest buffers are writable by device. For write, readable by device.

        if (segment_index == 0) { // First call for a new req_id, store the lists
            _guest_paddr_list = (uintptr_t*)((void**)req_id)[0];
            _len_list = (size_t*)((void**)req_id)[1];
            _num_segments = (unsigned int*)((void**)req_id)[2];
            _is_write_list = (BOOL*)((void**)req_id)[3]; // True if device writes to guest (read_cb), false if device reads from guest (write_cb)
        }

        if (_num_segments && segment_index < *_num_segments) {
            segment_info->paddr = _guest_paddr_list[segment_index];
            segment_info->len = _len_list[segment_index];
            segment_info->is_device_writable = _is_write_list[segment_index];
            return 0; // SUCCESS
        }
    }
    return -1; // No more segments or error
}


#define MIN(a, b) (((a) < (b)) ? (a) : (b))

// Default serial port for Linux guest
#define LINUX_SERIAL_PORT VMM_SERIAL_PORT // VMM_SERIAL_PORT is usually 0x3F8, defined in devices.h
#define PIT_IRQ 0 // Standard IRQ line for PIT on the primary PIC
#define VIRTIO_CONSOLE_INPUT_QUEUE_IDX 0  // Standard queue index for guest receive (VMM transmit)
#define VIRTIO_CONSOLE_OUTPUT_QUEUE_IDX 1 // Standard queue index for guest transmit (VMM receive)

// Max PCI devices the VMM will store from the bootloader tag
// This should ideally match or be less than PqUefiLoader's MAX_PCI_DEVICES_TO_SCAN
#define MAX_PCI_DEVICES_FROM_LOADER 32

// --- PCI Device Info Structure (mirroring PqUefiLoader's definition) ---
typedef struct {
  UINT16 VendorId;
  UINT16 DeviceId;
  UINT8  Bus;
  UINT8  Device;
  UINT8  Function;
  UINT32 ClassCode; // Combined: BaseClass (byte), SubClass (byte), ProgIF (byte)
} PciDeviceInfo_t; // Added _t to avoid potential type conflict if PciDeviceInfo is defined elsewhere

// --- Custom Multiboot2 Hardware Info Tag (mirroring PqUefiLoader's definition) ---
#define MULTIBOOT_TAG_TYPE_HW_INFO 0xABCDEF01 // Must match PqUefiLoader

#pragma pack(push, 1)
typedef struct {
  UINT32 Type;
  UINT32 Size;
  UINT32 NumPciDevs;
  // PciDeviceInfo_t PciDevs[]; // Data follows here in the actual tag
} MultibootTagHwInfoBase_t; // Added _t
#pragma pack(pop)

// Basic Multiboot2 tag structure (generic)
#pragma pack(push, 1)
typedef struct {
    UINT32 Type;
    UINT32 Size;
} multiboot_generic_tag_t;
#pragma pack(pop)


// Global VM object for this VMM instance
vm_t vm;

// Global storage for PCI device information received from PqUefiLoader
static PciDeviceInfo_t g_vmm_pci_devices[MAX_PCI_DEVICES_FROM_LOADER];
static UINT32 g_vmm_num_pci_devices = 0;
static size_t g_windows_disk_image_size = 0; // To store the actual dataport size

// Helper functions for serial device (using CAmkES interface `serial_port`)
static int vmm_serial_putchar(int c, void *cookie) {
    if (serial_port_putchar_bool(c)) {
        return c;
    }
    return -1;
}

static int vmm_serial_getchar(void *cookie) {
    return -1;
}

// --- CAmkES Component Entry Point ---
int run(void) {
    printf("LinuxVMM CAmkES component starting...\n");
    int err;

    // --- Retrieve Configuration Attributes ---
    unsigned long long p_guest_ram_size_bytes = strtoull(guest_ram_size, NULL, 16);
    unsigned long long p_guest_ram_paddr_base = strtoull(guest_ram_paddr_base, NULL, 16);
    if ((p_guest_ram_size_bytes == 0 && errno == EINVAL) || (p_guest_ram_paddr_base == 0 && errno == EINVAL && strcmp(guest_ram_paddr_base,"0x0") !=0 && strcmp(guest_ram_paddr_base,"0") !=0 )) {
        printf("LinuxVMM ERROR: Invalid guest RAM configuration strings.\n"); return -1;
    }

    int vcpu_id_attr = linux_guest_vcpu_id;
    int num_vcpus_attr = linux_guest_num_vcpus;

    unsigned long long p_virtio_con_mmio_paddr = strtoull(virtio_con_mmio_paddr, NULL, 16);
    unsigned long long p_virtio_con_mmio_size = strtoull(virtio_con_mmio_size, NULL, 16);
    int p_virtio_con_irq = strtol(virtio_con_irq, NULL, 10);

    unsigned long p_pt_nic_vid = strtoul(passthrough_nic_vid, NULL, 16);
    unsigned long p_pt_nic_did = strtoul(passthrough_nic_did, NULL, 16);
    unsigned long long p_pt_nic_bar0_size_config = strtoull(passthrough_nic_bar0_size_config, NULL, 16);
    int p_pt_nic_assigned_irq = strtol(passthrough_nic_assigned_irq, NULL, 10);

    unsigned long p_pt_gpu_vid = strtoul(passthrough_gpu_vid, NULL, 16);
    unsigned long p_pt_gpu_did = strtoul(passthrough_gpu_did, NULL, 16);
    unsigned long long p_pt_gpu_bar0_size_config = strtoull(passthrough_gpu_bar0_size_config, NULL, 16);
    unsigned long long p_pt_gpu_bar1_size_config = strtoull(passthrough_gpu_bar1_size_config, NULL, 16);
    unsigned long long p_pt_gpu_bar3_size_config = strtoull(passthrough_gpu_bar3_size_config, NULL, 16);
    int p_pt_gpu_assigned_irq = strtol(passthrough_gpu_assigned_irq, NULL, 10);

    unsigned long long p_virtio_blk_mmio_paddr = strtoull(virtio_blk_mmio_paddr, NULL, 16);
    unsigned long long p_virtio_blk_mmio_size = strtoull(virtio_blk_mmio_size, NULL, 16);
    int p_virtio_blk_irq = strtol(virtio_blk_irq, NULL, 10);
    unsigned long long p_windows_disk_image_size_config = strtoull(windows_disk_image_size_config, NULL, 16);

    BOOL is_windows_guest_val = (strcmp(is_windows_guest, "true") == 0 || strcmp(is_windows_guest, "1") == 0);

    g_windows_disk_image_size = (size_t)windows_disk_image_dataport_size();
    if (g_windows_disk_image_size == 0 && p_windows_disk_image_size_config > 0) {
        printf("LinuxVMM WARNING: Disk image dataport size is 0, but config expects > 0.\n");
    }

    printf("LinuxVMM Config: RAM Size=0x%llx (%.2fMB), PBase=0x%llx\n", p_guest_ram_size_bytes, (double)p_guest_ram_size_bytes / (1024*1024), p_guest_ram_paddr_base);
    // ... (other printf statements for config) ...
    printf("LinuxVMM Config: Is Windows Guest = %s\n", is_windows_guest_val ? "TRUE" : "FALSE");


    if (num_vcpus_attr <= 0 || num_vcpus_attr > MAX_VCPU_PER_VM) {
        printf("LinuxVMM ERROR: Invalid num_vcpus_attr: %d\n", num_vcpus_attr); return -1;
    }

    printf("LinuxVMM: Initializing seL4 utilities...\n");
    simple_t simple_data; vka_t vka_data; vspace_t vspace_data;
    simple_default_init_bootinfo(&simple_data, seL4_GetBootInfo());
    if (simple_data.info == NULL) { printf("LinuxVMM ERROR: Failed to get BootInfo\n"); return -1; }
    printf("  simple_default_init_bootinfo: OK\n");
    err = vka_allocator_init(&vka_data, &simple_data);
    if (err) { printf("LinuxVMM ERROR: Failed to init vka allocator: %d\n", err); return -1; }
    printf("  vka_allocator_init: OK\n");
    err = sel4utils_bootstrap_vspace_with_bootinfo_leaky(&vspace_data, &vka_data, simple_data.info);
    if (err) { printf("LinuxVMM ERROR: Failed to bootstrap vspace: %d\n", err); return -1; }
    printf("  sel4utils_bootstrap_vspace_with_bootinfo_leaky: OK\n");

    seL4_BootInfo* bi = seL4_GetBootInfo();
    if (bi != NULL && bi->mbcp_physical_addr != 0) {
        printf("LinuxVMM: MB2 info at paddr: 0x%lx\n", (unsigned long)bi->mbcp_physical_addr);
        UINTN mb2_info_vaddr = (UINTN)bi->mbcp_physical_addr; // UNSAFE - needs mapping
        if (mb2_info_vaddr != 0) ParsePciHardwareInfoTag(mb2_info_vaddr);
        else printf("LinuxVMM WARNING: MB2 info could not be mapped (TODO).\n");
    } else printf("LinuxVMM WARNING: No MB2 info found.\n");

    printf("LinuxVMM: Creating VM object...\n");
    err = vm_create("LinuxVM", vcpu_id_attr, num_vcpus_attr, &vka_data, &vspace_data, &simple_data, &vm);
    if (err) { printf("LinuxVMM ERROR: vm_create failed: %d\n", err); return -1; }
    printf("  vm_create: OK (VM: %s)\n", vm.name);

    printf("LinuxVMM: Mapping guest RAM...\n");
    err = vm_ram_map_guest_memory(&vm, (uintptr_t)p_guest_ram_paddr_base, (size_t)p_guest_ram_size_bytes, NULL);
    if (err) { printf("LinuxVMM ERROR: vm_ram_map_guest_memory failed: %d\n", err); return -1; }
    printf("  vm_ram_map_guest_memory: OK\n");

    printf("LinuxVMM: Installing legacy devices...\n");
    vmm_serial_ops_t serial_ops = { .putc = vmm_serial_putchar, .getc = vmm_serial_getchar, .priv = NULL };
    err = vm_install_legacy_serial_device(&vm, LINUX_SERIAL_PORT, &serial_ops);
    if (err) { printf("LinuxVMM ERROR: vm_install_legacy_serial_device failed: %d\n", err); return -1; }
    printf("  vm_install_legacy_serial_device: OK\n");
    err = vm_install_pic_device(&vm);
    if (err) { printf("LinuxVMM ERROR: vm_install_pic_device failed: %d\n", err); return -1; }
    printf("  vm_install_pic_device: OK\n");
    err = vm_install_pit_device(&vm);
    if (err) { printf("LinuxVMM ERROR: vm_install_pit_device failed: %d\n", err); return -1; }
    printf("  vm_install_pit_device: OK\n");

    printf("LinuxVMM: Installing VirtIO Console device...\n");
    err = vm_install_virtio_con_device(&vm, (uintptr_t)p_virtio_con_mmio_paddr, (size_t)p_virtio_con_mmio_size, (unsigned int)p_virtio_con_irq, virtio_console_notify_cb, NULL, NULL);
    if (err) { printf("LinuxVMM ERROR: vm_install_virtio_con_device failed: %d\n", err); return -1; }
    printf("  vm_install_virtio_con_device: OK\n");

    printf("LinuxVMM: Installing VirtIO Block device...\n");
    if (g_windows_disk_image_size != p_windows_disk_image_size_config && p_windows_disk_image_size_config != 0) {
        printf("LinuxVMM WARNING: windows_disk_image_dataport size (0x%zx) != configured size (0x%llx). Using dataport's actual size (0x%zx).\n",
               g_windows_disk_image_size, p_windows_disk_image_size_config, g_windows_disk_image_size);
    }
    err = vm_install_virtio_blk_device(&vm, (uintptr_t)p_virtio_blk_mmio_paddr, (size_t)p_virtio_blk_mmio_size, (unsigned int)p_virtio_blk_irq,
                                       virtio_block_read_cb, virtio_block_write_cb, NULL, NULL,
                                       (void*)windows_disk_image_dataport, g_windows_disk_image_size);
    if (err) { printf("LinuxVMM ERROR: vm_install_virtio_blk_device failed: %d\n", err); return -1; }
    printf("  vm_install_virtio_blk_device: OK, Disk Img: %s, Size: 0x%zx\n", windows_disk_image_name, g_windows_disk_image_size);

    // --- ACPI Configuration for Windows (Placeholder) ---
    if (is_windows_guest_val) {
        printf("LinuxVMM INFO: Applying Windows-specific ACPI configurations (TODO)...\n");
        printf("  TODO: Ensure FADT flags, DSDT/SSDTs are suitable for a Windows guest.\n");
    }

    printf("LinuxVMM: Attempting PCI passthrough device setup...\n");
    BOOL pt_device_found_and_configured = FALSE;
    if (p_pt_nic_vid != 0 || p_pt_nic_did != 0) {
        if (g_vmm_num_pci_devices > 0) {
            for (UINT32 i = 0; i < g_vmm_num_pci_devices; i++) {
                if (g_vmm_pci_devices[i].VendorId == p_pt_nic_vid && g_vmm_pci_devices[i].DeviceId == p_pt_nic_did) {
                    // ... (NIC passthrough setup as before)
                    pci_passthrough_device_config_t pt_dev_cfg; memset(&pt_dev_cfg, 0, sizeof(pci_passthrough_device_config_t));
                    pt_dev_cfg.guest_bdf = guest_pci_get_bdf(0,3,0); pt_dev_cfg.phys_bdf = guest_pci_get_bdf(g_vmm_pci_devices[i].Bus, g_vmm_pci_devices[i].Device, g_vmm_pci_devices[i].Function);
                    pt_dev_cfg.vid = g_vmm_pci_devices[i].VendorId; pt_dev_cfg.did = g_vmm_pci_devices[i].DeviceId; pt_dev_cfg.class_code = g_vmm_pci_devices[i].ClassCode;
                    pt_dev_cfg.num_bars = 1; pt_dev_cfg.bar_configs[0].is_memory = TRUE; pt_dev_cfg.bar_configs[0].size = p_pt_nic_bar0_size_config;
                    pt_dev_cfg.bar_configs[0].vmm_vaddr_for_mapping = (uintptr_t)passthrough_nic_bar0_mem;
                    pt_dev_cfg.phys_irq_num = p_pt_nic_assigned_irq; pt_dev_cfg.guest_irq_num = p_pt_nic_assigned_irq;
                    err = vm_pci_add_passthrough_device(&vm, &pt_dev_cfg);
                    if(err){ printf("  ERROR: vm_pci_add_passthrough_device for NIC failed: %d\n", err); }
                    else { printf("  Successfully configured PCI passthrough for NIC.\n"); pt_device_found_and_configured = TRUE;
                        printf("  TODO: Update guest ACPI tables (DSDT/SSDT) to describe this passthrough PCI device.\n");
                        if (is_windows_guest_val) {
                            printf("    ACPI TODO (Windows): Ensure NIC's _DSM methods, IRQ routing, etc., are Windows-compatible in ACPI.\n");
                        }
                    }
                    break;
                }
            }
            if (!pt_device_found_and_configured && (p_pt_nic_vid != 0 || p_pt_nic_did != 0)) {
                printf("  WARNING: Configured passthrough NIC (VID:0x%lx DID:0x%lx) not found.\n", p_pt_nic_vid, p_pt_nic_did);
            }
        } else if (p_pt_nic_vid != 0 || p_pt_nic_did != 0) {
             printf("  INFO: No PCI devices scanned, cannot setup passthrough NIC.\n");
        }
    } else {
        printf("  INFO: No passthrough NIC VID/DID configured. Skipping.\n");
    }

    printf("LinuxVMM: Attempting PCI passthrough GPU setup...\n");
    BOOL pt_gpu_found_and_configured = FALSE;
    if (p_pt_gpu_vid != 0 || p_pt_gpu_did != 0) {
        if (g_vmm_num_pci_devices > 0) {
            for (UINT32 i = 0; i < g_vmm_num_pci_devices; i++) {
                if (g_vmm_pci_devices[i].VendorId == p_pt_gpu_vid && g_vmm_pci_devices[i].DeviceId == p_pt_gpu_did) {
                    // ... (GPU passthrough setup as before) ...
                    pci_passthrough_device_config_t gpu_pt_dev_cfg; memset(&gpu_pt_dev_cfg, 0, sizeof(pci_passthrough_device_config_t));
                    gpu_pt_dev_cfg.guest_bdf = guest_pci_get_bdf(0,4,0); gpu_pt_dev_cfg.phys_bdf = guest_pci_get_bdf(g_vmm_pci_devices[i].Bus, g_vmm_pci_devices[i].Device, g_vmm_pci_devices[i].Function);
                    gpu_pt_dev_cfg.vid = g_vmm_pci_devices[i].VendorId; gpu_pt_dev_cfg.did = g_vmm_pci_devices[i].DeviceId; gpu_pt_dev_cfg.class_code = g_vmm_pci_devices[i].ClassCode;
                    gpu_pt_dev_cfg.num_bars = 0;
                    if(p_pt_gpu_bar0_size_config > 0){ int idx = gpu_pt_dev_cfg.num_bars++; gpu_pt_dev_cfg.bar_configs[idx].is_memory=TRUE; gpu_pt_dev_cfg.bar_configs[idx].size=p_pt_gpu_bar0_size_config; gpu_pt_dev_cfg.bar_configs[idx].vmm_vaddr_for_mapping=(uintptr_t)passthrough_gpu_bar0_mem;}
                    if(p_pt_gpu_bar1_size_config > 0){ int idx = gpu_pt_dev_cfg.num_bars++; gpu_pt_dev_cfg.bar_configs[idx].is_memory=TRUE; gpu_pt_dev_cfg.bar_configs[idx].size=p_pt_gpu_bar1_size_config; gpu_pt_dev_cfg.bar_configs[idx].vmm_vaddr_for_mapping=(uintptr_t)passthrough_gpu_bar1_mem;}
                    if(p_pt_gpu_bar3_size_config > 0){ int idx = gpu_pt_dev_cfg.num_bars++; gpu_pt_dev_cfg.bar_configs[idx].is_memory=TRUE; gpu_pt_dev_cfg.bar_configs[idx].size=p_pt_gpu_bar3_size_config; gpu_pt_dev_cfg.bar_configs[idx].vmm_vaddr_for_mapping=(uintptr_t)passthrough_gpu_bar3_mem;}
                    gpu_pt_dev_cfg.phys_irq_num = p_pt_gpu_assigned_irq; gpu_pt_dev_cfg.guest_irq_num = p_pt_gpu_assigned_irq;
                    printf("  VBIOS for GPU: %s (Size: %zu bytes). TODO: Map to guest.\n", gpu_vbios_image_name, (size_t)gpu_vbios_image_dataport_size());
                    err = vm_pci_add_passthrough_device(&vm, &gpu_pt_dev_cfg);
                    if(err){ printf("  ERROR: vm_pci_add_passthrough_device for GPU failed: %d\n", err); }
                    else { printf("  Successfully configured PCI passthrough for GPU.\n"); pt_gpu_found_and_configured = TRUE;
                        printf("  TODO: Update guest ACPI tables (DSDT/SSDT) to describe passthrough GPU.\n");
                        if (is_windows_guest_val) {
                            printf("    ACPI TODO (Windows): Ensure GPU's _DSM methods, VBIOS shadow, etc., are Windows-compatible.\n");
                        }
                    }
                    break;
                }
            }
            if (!pt_gpu_found_and_configured && (p_pt_gpu_vid != 0 || p_pt_gpu_did != 0)) {
                 printf("  WARNING: Configured passthrough GPU (VID:0x%lx DID:0x%lx) not found.\n", p_pt_gpu_vid, p_pt_gpu_did);
            }
        } else if (p_pt_gpu_vid != 0 || p_pt_gpu_did != 0) {
            printf("  INFO: No PCI devices scanned, cannot setup passthrough GPU.\n");
        }
    } else {
        printf("  INFO: No passthrough GPU VID/DID configured. Skipping.\n");
    }

    uintptr_t linux_entry_point = 0; // Initialize
    if (!is_windows_guest_val) {
        printf("LinuxVMM: Loading Linux image...\n");
        err = load_linux_guest_image(&vm, kernel_image_name, (void*)linux_kernel_image, linux_kernel_image_size(),
                                     initrd_image_name, (void*)linux_initrd_image, linux_initrd_image_size(),
                                     &linux_entry_point);
        if (err) { printf("LinuxVMM ERROR: load_linux_guest_image failed: %d\n", err); return -1; }
        printf("  load_linux_guest_image: OK (Entry Point: 0x%lx)\n", linux_entry_point);
    } else {
        printf("LinuxVMM INFO: Windows guest. Boot from VirtIO block. RIP not set by VMM directly.\n");
    }

    printf("LinuxVMM: Creating VCPU %d...\n", vcpu_id_attr);
    err = vm_guest_cpu_create(vcpu_id_attr, &vm, &vm.vcpus[vcpu_id_attr]);
    if (err) { printf("LinuxVMM ERROR: vm_guest_cpu_create for VCPU %d failed: %d\n", vcpu_id_attr, err); return -1; }
    printf("  vm_guest_cpu_create for VCPU %d: OK\n", vcpu_id_attr);

    if (!is_windows_guest_val) {
        printf("LinuxVMM: Setting initial VCPU registers for VCPU %d for Linux...\n", vcpu_id_attr);
        err = vcpu_set_rip(vm.vcpus[vcpu_id_attr], linux_entry_point);
        if (err) { printf("LinuxVMM ERROR: vcpu_set_rip for VCPU %d failed: %d\n", vcpu_id_attr, err); return -1; }
        printf("  VCPU %d RIP set to 0x%lx\n", vcpu_id_attr, linux_entry_point);
    } else {
         printf("LinuxVMM INFO: Windows guest. VCPU %d initial registers to be set by guest BIOS/UEFI.\n", vcpu_id_attr);
    }

    printf("LinuxVMM: VM Initialized and VCPU %d configured. Entering VCPU run loop...\n", vcpu_id_attr);

    vm_vcpu_t *vcpu = vm.vcpus[vcpu_id_attr];
    seL4_CPtr vcpu_cap = vcpu->vcpu_cap;
    int host_char_input;
    while (1) {
        seL4_VCPU_Run_t vm_exit;
        vm_exit = seL4_VCPU_Run(vcpu_cap, NULL);
        switch (vm_exit.reason) {
            // ... (VM exit handling as before) ...
            case SEL4_VMEXIT_REASON_TIMEOUT:
                printf("VMM: VCPU %d exit due to Timeout. Injecting PIT_IRQ.\n", vcpu_id_attr);
                err = vm_inject_irq(vm.vcpus[vcpu_id_attr], PIT_IRQ);
                if (err) { printf("VMM ERROR: Failed to inject PIT_IRQ on Timeout for VCPU %d: %d\n", vcpu_id_attr, err); }
                break;
            case SEL4_VMEXIT_REASON_UNKNOWN_SYSCALL:
                printf("VMM: VCPU %d halted on Unknown Syscall.\n", vcpu_id_attr);
                printf("  RIP: 0x%lx, RAX: 0x%lx, RBX: 0x%lx, RCX: 0x%lx, RDX: 0x%lx\n",
                       vm_exit.data.unknown_syscall.rip, vm_exit.data.unknown_syscall.rax,
                       vm_exit.data.unknown_syscall.rbx, vm_exit.data.unknown_syscall.rcx,
                       vm_exit.data.unknown_syscall.rdx);
                goto VmErrorHalt;
            case SEL4_VMEXIT_REASON_VCPU_FAULT:
                printf("VMM: VCPU %d halted on VCPU Fault.\n", vcpu_id_attr);
                goto VmErrorHalt;
            case SEL4_VMEXIT_REASON_EXCEPTION:
                printf("VMM: VCPU %d halted on Guest Exception.\n", vcpu_id_attr);
                printf("  Exception Number: %d (0x%x), Error Code: 0x%x\n",
                       vm_exit.data.exception.number, vm_exit.data.exception.number,
                       vm_exit.data.exception.error_code);
                printf("  Fault IP: 0x%lx, Fault Addr (if page fault): 0x%lx\n",
                       vm_exit.data.exception.instruction_fault ? vm_exit.data.exception.fault_ip : 0,
                       (vm_exit.data.exception.number == 14) ? vm_exit.data.exception.fault_addr : 0);
                goto VmErrorHalt;
            case SEL4_VMEXIT_REASON_CPUID:
                printf("VMM: VCPU %d exit for CPUID instruction.\n", vcpu_id_attr);
                handle_cpuid_exit_for_guest(vcpu);
                break;
            default:
                printf("VMM: VCPU %d halted on unhandled VM exit reason: %lu\n", vcpu_id_attr, (unsigned long)vm_exit.reason);
                if (vm_exit.reason < SEL4_VMEXIT_LAST_REASON) {
                    printf("  VMFault IP: 0x%lx, Addr: 0x%lx, InstrLen: %u\n",
                           (unsigned long)vm_exit.data.vm_fault.ip,
                           (unsigned long)vm_exit.data.vm_fault.addr,
                           (unsigned int)vm_exit.data.vm_fault.instruction_len);
                }
                goto VmErrorHalt;
        }

        host_char_input = vmm_serial_getchar(NULL);
        if (host_char_input != -1 && host_char_input != EOF) {
            virtio_device_t *vdev_con_in = vm_get_virtio_device_by_id(&vm, VIRTIO_CONSOLE_DEVICE_ID, 0);
            if (vdev_con_in) {
                virtio_queue_t *vq_guest_input = virtio_get_queue(vdev_con_in, VIRTIO_CONSOLE_INPUT_QUEUE_IDX);
                if (vq_guest_input && virtio_host_can_dequeue_buffer(vq_guest_input)) {
                    virtio_buffer_descriptor_t desc_guest_in;
                    err = virtio_host_dequeue_buffer(vq_guest_input, &desc_guest_in);
                    if (err == 0) {
                        if (desc_guest_in.num_segments > 0 && desc_guest_in.segments[0].len > 0) {
                            char *guest_buf_vaddr = (char*)vm_guest_paddr_to_vaddr(&vm, desc_guest_in.segments[0].paddr, desc_guest_in.segments[0].len);
                            if (guest_buf_vaddr) {
                                guest_buf_vaddr[0] = (char)host_char_input;
                                desc_guest_in.total_len_processed_by_device = 1;
                                err = virtio_host_enqueue_buffer(vq_guest_input, desc_guest_in);
                                if (err == 0) {
                                    err = virtio_host_notify_guest_queue(vq_guest_input);
                                    if (err) printf("LinuxVMM WARNING: virtio_host_notify_guest_queue for console input failed: %d\n", err);
                                } else printf("LinuxVMM ERROR: virtio_host_enqueue_buffer for console input failed: %d\n", err);
                            } else {
                                printf("LinuxVMM WARNING: Failed to translate guest paddr for VirtIO console input. Dropping char.\n");
                                desc_guest_in.total_len_processed_by_device = 0;
                                virtio_host_enqueue_buffer(vq_guest_input, desc_guest_in);
                            }
                        } else {
                             printf("LinuxVMM WARNING: Dequeued VirtIO console input buffer invalid. Dropping char.\n");
                             desc_guest_in.total_len_processed_by_device = 0;
                             virtio_host_enqueue_buffer(vq_guest_input, desc_guest_in);
                        }
                    }
                }
            }
        }
    }

VmErrorHalt:
    printf("LinuxVMM: VM run loop for VCPU %d terminated.\n", vcpu_id_attr);
    return -1;
}

// ... (rest of the file: IRQ handlers, callback functions, etc.) ...
// --- IRQ Handler(s) ---
// ...
// --- Function to Parse Custom PCI Hardware Info from Multiboot2 Tags ---
// ...
// --- PCI Passthrough NIC IRQ Event Handler ---
// ...
// --- PCI Passthrough GPU IRQ Event Handler ---
// ...
// --- CPUID Spoofing Handler ---
// ...
// --- VirtIO Block Callbacks (Conceptual) ---
// ...
// --- VirtIO Console Notification Callback ---
// ...
