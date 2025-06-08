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
// This would be defined in one of the sel4vm headers, e.g. <sel4vm/guest_vm.h>
// For now, we assume it's available. If not, a placeholder struct might be needed.
vm_t vm; // This assumes vm_t is a known type from included headers.

// Global storage for PCI device information received from PqUefiLoader
static PciDeviceInfo_t g_vmm_pci_devices[MAX_PCI_DEVICES_FROM_LOADER];
static UINT32 g_vmm_num_pci_devices = 0;

// Helper functions for serial device (using CAmkES interface `serial_port`)
static int vmm_serial_putchar(int c, void *cookie) {
    // Use the CAmkES serial_port interface's putchar method
    // This assumes 'serial_port_putchar' is the actual function name provided by the seL4Serial connector
    if (serial_port_putchar_bool(c)) { // Assuming it returns bool for success
        return c;
    }
    return -1;
}

static int vmm_serial_getchar(void *cookie) {
    // This is more complex as CAmkES serial might be non-blocking or require polling.
    // For a simple setup, we might not have a getchar from the VMM side for Linux.
    // If the CAmkES interface `serial_port` provides a `getchar` or `read` method:
    // return serial_port_getchar(); // This is hypothetical
    // For now, return -1 (no character)
    return -1;
}

// --- CAmkES Component Entry Point ---
int run(void) {
    printf("LinuxVMM CAmkES component starting...\n");
    int err;

    // --- Retrieve Configuration Attributes ---
    unsigned long long p_guest_ram_size_bytes = 0;
    unsigned long long p_guest_ram_paddr_base = 0;

    p_guest_ram_size_bytes = strtoull(guest_ram_size, NULL, 16);
    if (p_guest_ram_size_bytes == 0 && errno == EINVAL) { // Check for conversion error
        printf("LinuxVMM ERROR: Invalid guest_ram_size: %s\n", guest_ram_size);
        return -1;
    }
    p_guest_ram_paddr_base = strtoull(guest_ram_paddr_base, NULL, 16);
     if (p_guest_ram_paddr_base == 0 && errno == EINVAL && strcmp(guest_ram_paddr_base,"0x0") !=0 && strcmp(guest_ram_paddr_base,"0") !=0 ) {
        printf("LinuxVMM ERROR: Invalid guest_ram_paddr_base: %s\n", guest_ram_paddr_base);
        return -1;
    }

    int vcpu_id_attr = linux_guest_vcpu_id;
    int num_vcpus_attr = linux_guest_num_vcpus;

    // VirtIO Console Config
    unsigned long long p_virtio_con_mmio_paddr = strtoull(virtio_con_mmio_paddr, NULL, 16);
    unsigned long long p_virtio_con_mmio_size = strtoull(virtio_con_mmio_size, NULL, 16);
    int p_virtio_con_irq = strtol(virtio_con_irq, NULL, 10);

    // PCI Passthrough NIC Config
    unsigned long p_pt_nic_vid = strtoul(passthrough_nic_vid, NULL, 16);
    unsigned long p_pt_nic_did = strtoul(passthrough_nic_did, NULL, 16);
    // The CAmkES attribute `passthrough_nic_bar0_paddr_expected` is for VMM logic, not directly used for mapping here.
    // We will primarily use the passthrough_nic_bar0_size_config for BAR configuration.
    unsigned long long p_pt_nic_bar0_size_config = strtoull(passthrough_nic_bar0_size_config, NULL, 16);
    int p_pt_nic_assigned_irq = strtol(passthrough_nic_assigned_irq, NULL, 10);

    printf("LinuxVMM Config: RAM Size=0x%llx bytes (%.2f MB), RAM PBase=0x%llx\n",
           p_guest_ram_size_bytes, (double)p_guest_ram_size_bytes / (1024 * 1024), p_guest_ram_paddr_base);
    printf("LinuxVMM Config: Kernel Image='%s', Initrd Image='%s'\n",
           kernel_image_name, initrd_image_name);
    printf("LinuxVMM Config: VCPU ID Base=%d, Num VCPUs=%d\n", vcpu_id_attr, num_vcpus_attr);
    printf("LinuxVMM Config: VirtIO Console MMIO PBase=0x%llx, Size=0x%llx, IRQ=%d\n",
           p_virtio_con_mmio_paddr, p_virtio_con_mmio_size, p_virtio_con_irq);
    printf("LinuxVMM Config: Passthrough NIC VID=0x%lx, DID=0x%lx, BAR0 Size Config=0x%llx, Assigned IRQ=%d\n",
           p_pt_nic_vid, p_pt_nic_did, p_pt_nic_bar0_size_config, p_pt_nic_assigned_irq);

    if (num_vcpus_attr <= 0 || num_vcpus_attr > MAX_VCPU_PER_VM) { // MAX_VCPU_PER_VM should be defined in sel4vm
        printf("LinuxVMM ERROR: Invalid num_vcpus_attr: %d\n", num_vcpus_attr);
        return -1;
    }

    // --- Initialize seL4 Utilities ---
    printf("LinuxVMM: Initializing seL4 utilities...\n");
    simple_t simple_data;
    vka_t vka_data;
    vspace_t vspace_data;

    simple_default_init_bootinfo(&simple_data, seL4_GetBootInfo());
    if (simple_data.info == NULL) {
        printf("LinuxVMM ERROR: Failed to get BootInfo\n");
        return -1;
    }
    printf("  simple_default_init_bootinfo: OK\n");

    err = vka_allocator_init(&vka_data, &simple_data);
    if (err) {
        printf("LinuxVMM ERROR: Failed to init vka allocator: %d\n", err);
        return -1;
    }
    printf("  vka_allocator_init: OK\n");

    err = sel4utils_bootstrap_vspace_with_bootinfo_leaky(&vspace_data, &vka_data, simple_data.info);
    if (err) {
        printf("LinuxVMM ERROR: Failed to bootstrap vspace: %d\n", err);
        // Note: simple_tear_down(&simple_data) might be needed if vka_allocator_init succeeded
        return -1;
    }
    printf("  sel4utils_bootstrap_vspace_with_bootinfo_leaky: OK\n");

    // --- Parse Multiboot2 PCI Hardware Info Tag ---
    // seL4_GetBootInfo() provides access to the BootInfo structure.
    // The Multiboot2 info structure address is in seL4_GetBootInfo()->mbcp_physical_addr
    // This physical address needs to be mapped into the VMM's VSpace to be accessed.
    // For now, we'll assume it's identity mapped or accessible directly if it's within
    // the VMM's initial memory grant. A proper mapping might be needed in a full system.
    seL4_BootInfo* bi = seL4_GetBootInfo();
    if (bi != NULL && bi->mbcp_physical_addr != 0) {
        printf("LinuxVMM: Multiboot2 info structure found at physical address: 0x%lx\n", (unsigned long)bi->mbcp_physical_addr);
        // TODO: Map bi->mbcp_physical_addr to a virtual address if not already accessible.
        // For this example, we cast it directly, assuming it's mapped.
        // This is UNSAFE without ensuring the mapping exists and is correct.
        // A robust solution would use sel4utils_map_frame_iospace or similar if it's device memory,
        // or ensure the region is covered by initial VMM memory mappings.
        // Let's assume for now it's part of BootInfo that's already mapped by CAmkES rootserver.
        UINTN mb2_info_vaddr = (UINTN)bi->mbcp_physical_addr; // Placeholder - direct cast
        // In a real CAmkES app, this might be:
        // mb2_info_vaddr = (UINTN)camkes_bootinfo_get_info_frame_map_address(bi);
        // Or if CapDL loaded it to a specific location known to the VMM:
        // mb2_info_vaddr = (UINTN)mb2_information_dataport_ptr; (if passed via dataport)

        // Check for a reasonable address (e.g. not NULL if cast from a potentially unmapped phys addr)
        if (mb2_info_vaddr != 0) {
             ParsePciHardwareInfoTag(mb2_info_vaddr);
        } else {
            printf("LinuxVMM WARNING: Multiboot2 info address is NULL or could not be mapped (TODO).\n");
        }
    } else {
        printf("LinuxVMM WARNING: No Multiboot2 info structure address found in BootInfo.\n");
    }


    // --- Create VM Object ---
    printf("LinuxVMM: Creating VM object...\n");
    // Note: vm_create might expect vcpu_id_base as an int, not the attribute directly.
    err = vm_create("LinuxVM", vcpu_id_attr, num_vcpus_attr, &vka_data, &vspace_data, &simple_data, &vm);
    if (err) {
        printf("LinuxVMM ERROR: vm_create failed: %d\n", err);
        // sel4utils_tear_down_vspace(&vspace_data) might be needed
        // vka_allocator_destroy(&vka_data)
        return -1;
    }
    printf("  vm_create: OK (VM: %s)\n", vm.name);

    // --- Map Guest RAM ---
    printf("LinuxVMM: Mapping guest RAM...\n");
    // Ensure types match for vm_ram_map_guest_memory if it expects uintptr_t / size_t
    err = vm_ram_map_guest_memory(&vm, (uintptr_t)p_guest_ram_paddr_base, (size_t)p_guest_ram_size_bytes, NULL);
    if (err) {
        printf("LinuxVMM ERROR: vm_ram_map_guest_memory failed: %d\n", err);
        // vm_destroy(&vm) and other cleanups
        return -1;
    }
    printf("  vm_ram_map_guest_memory: OK (Base: 0x%llx, Size: 0x%llx)\n", p_guest_ram_paddr_base, p_guest_ram_size_bytes);

    // --- Install Legacy Devices ---
    printf("LinuxVMM: Installing legacy devices...\n");
    vmm_serial_ops_t serial_ops = {
        .putc = vmm_serial_putchar,
        .getc = vmm_serial_getchar,
        .priv = NULL // No cookie needed for these simple ops
    };
    err = vm_install_legacy_serial_device(&vm, LINUX_SERIAL_PORT, &serial_ops);
    if (err) {
        printf("LinuxVMM ERROR: vm_install_legacy_serial_device failed: %d\n", err);
        return -1;
    }
    printf("  vm_install_legacy_serial_device: OK (Port: 0x%x)\n", LINUX_SERIAL_PORT);

    err = vm_install_pic_device(&vm);
    if (err) {
        printf("LinuxVMM ERROR: vm_install_pic_device failed: %d\n", err);
        return -1;
    }
    printf("  vm_install_pic_device: OK\n");

    err = vm_install_pit_device(&vm);
    if (err) {
        printf("LinuxVMM ERROR: vm_install_pit_device failed: %d\n", err);
        return -1;
    }
    printf("  vm_install_pit_device: OK\n");

    // --- Install VirtIO Console Device ---
    printf("LinuxVMM: Installing VirtIO Console device...\n");
    // The virtio_console_notify_cb function needs to be defined.
    // The exact signature for vm_install_virtio_con_device might vary.
    // Assuming it takes paddr, size, irq, notify_cb, ack_cb (NULL here), cookie (NULL here).
    err = vm_install_virtio_con_device(&vm,
                                       (uintptr_t)p_virtio_con_mmio_paddr,
                                       (size_t)p_virtio_con_mmio_size,
                                       (unsigned int)p_virtio_con_irq,
                                       virtio_console_notify_cb, // Callback for guest->host data
                                       NULL,  // No specific ack callback needed for simple output
                                       NULL); // No private cookie data for the callback for now
    if (err) {
        printf("LinuxVMM ERROR: vm_install_virtio_con_device failed: %d\n", err);
        return -1;
    }
    printf("  vm_install_virtio_con_device: OK (MMIO PBase: 0x%llx, IRQ: %d)\n",
           p_virtio_con_mmio_paddr, p_virtio_con_irq);

    // --- PCI Passthrough Device Setup ---
    printf("LinuxVMM: Attempting PCI passthrough device setup...\n");
    BOOL pt_device_found_and_configured = FALSE;
    // Only attempt if a passthrough device VID/DID is configured (non-zero)
    if (p_pt_nic_vid != 0 || p_pt_nic_did != 0) {
        if (g_vmm_num_pci_devices > 0) {
            for (UINT32 i = 0; i < g_vmm_num_pci_devices; i++) {
                if (g_vmm_pci_devices[i].VendorId == p_pt_nic_vid && g_vmm_pci_devices[i].DeviceId == p_pt_nic_did) {
                    printf("  Found target passthrough NIC: %02X:%02X.%X VID:%04X DID:%04X Class: %06X\n",
                           g_vmm_pci_devices[i].Bus, g_vmm_pci_devices[i].Device, g_vmm_pci_devices[i].Function,
                           g_vmm_pci_devices[i].VendorId, g_vmm_pci_devices[i].DeviceId, g_vmm_pci_devices[i].ClassCode);

                    // This structure and its fields are based on typical needs for PCI passthrough.
                    // Actual libsel4vm might have a different structure or helper functions.
                    pci_passthrough_device_config_t pt_dev_cfg;
                    memset(&pt_dev_cfg, 0, sizeof(pci_passthrough_device_config_t));

                    // Assign a guest B/D/F. For simplicity, use a fixed one.
                    // This needs careful management if multiple devices are passed through.
                    // guest_pci_get_bdf is a conceptual helper from sel4vm/arch/x86/guest_pci_legacy.h or similar
                    pt_dev_cfg.guest_bdf = guest_pci_get_bdf(0, 3, 0); // Example: Guest Bus 0, Device 3, Function 0

                    pt_dev_cfg.phys_bdf = guest_pci_get_bdf(g_vmm_pci_devices[i].Bus,
                                                            g_vmm_pci_devices[i].Device,
                                                            g_vmm_pci_devices[i].Function);
                    pt_dev_cfg.vid = g_vmm_pci_devices[i].VendorId;
                    pt_dev_cfg.did = g_vmm_pci_devices[i].DeviceId;
                    pt_dev_cfg.class_code = g_vmm_pci_devices[i].ClassCode;

                    // Configure BAR0. A real VMM would scan all BARs from the physical device's PCI config space.
                    // This example assumes BAR0 is memory and uses the CAmkES dataport and configured size.
                    pt_dev_cfg.num_bars = 1;
                    pt_dev_cfg.bar_configs[0].is_memory = TRUE;
                    pt_dev_cfg.bar_configs[0].size = p_pt_nic_bar0_size_config;
                    // The CAmkES dataport `passthrough_nic_bar0_mem` provides the VMM's virtual address
                    // to the physical BAR0 memory, mapped by CAmkES build system / root CNode.
                    pt_dev_cfg.bar_configs[0].vmm_vaddr_for_mapping = (uintptr_t)passthrough_nic_bar0_mem;

                    pt_dev_cfg.phys_irq_num = p_pt_nic_assigned_irq;
                    // The guest_irq_num might be the same or translated by an IOMMU/vPIC.
                    // For simple legacy IRQ passthrough, it's often the same.
                    pt_dev_cfg.guest_irq_num = p_pt_nic_assigned_irq;

                    // The CAmkES IRQ event handler 'passthrough_nic_irq_event_handle' will be triggered.
                    // vm_pci_add_passthrough_device needs the CAmkES IRQ cap or a way to register our handler.
                    // This part is highly dependent on libsel4vm API.
                    // For now, we assume libsel4vm's passthrough setup for x86 might involve
                    // directly providing the GSI (Global System Interrupt) number, and the VMM
                    // will need to have a CAmkES 'consumes IRQ' for that GSI.
                    // pt_dev_cfg.irq_cap_or_notification_details = ... ; // This would be platform/lib specific

                    err = vm_pci_add_passthrough_device(&vm, &pt_dev_cfg);
                    if (err) {
                        printf("  ERROR: vm_pci_add_passthrough_device failed: %d\n", err);
                    } else {
                        printf("  Successfully configured PCI passthrough for phys %02X:%02X.%X to guest BDF %02X:%02X.%X\n",
                               GUEST_PCI_BUS(pt_dev_cfg.phys_bdf), GUEST_PCI_DEVICE(pt_dev_cfg.phys_bdf), GUEST_PCI_FUNCTION(pt_dev_cfg.phys_bdf),
                               GUEST_PCI_BUS(pt_dev_cfg.guest_bdf), GUEST_PCI_DEVICE(pt_dev_cfg.guest_bdf), GUEST_PCI_FUNCTION(pt_dev_cfg.guest_bdf));
                        pt_device_found_and_configured = TRUE;
                        printf("  TODO: Update guest ACPI tables (DSDT/SSDT) to describe this passthrough PCI device.\n");
                    }
                    break; // Found and processed the first matching device
                }
            }
            if (!pt_device_found_and_configured) {
                printf("  WARNING: Configured passthrough NIC (VID:0x%lx DID:0x%lx) not found among scanned PCI devices.\n",
                       p_pt_nic_vid, p_pt_nic_did);
            }
        } else if (g_vmm_num_pci_devices == 0) {
             printf("  INFO: No PCI devices were previously scanned/found by PqUefiLoader, cannot setup passthrough NIC.\n");
        }
    } else {
        printf("  INFO: No passthrough NIC VID/DID configured. Skipping PCI passthrough setup.\n");
    }


    // --- Load Linux Image ---
    printf("LinuxVMM: Loading Linux image...\n");
    // Ensure kernel_image_name and initrd_image_name (attributes) are suitable C strings.
    // CAmkES string attributes are already char*.
    uintptr_t linux_entry_point;
    err = load_linux_guest_image(&vm, kernel_image_name, (void*)linux_kernel_image, linux_kernel_image_size(),
                                 initrd_image_name, (void*)linux_initrd_image, linux_initrd_image_size(),
                                 &linux_entry_point);
    if (err) {
        printf("LinuxVMM ERROR: load_linux_guest_image failed: %d\n", err);
        return -1;
    }
    printf("  load_linux_guest_image: OK (Entry Point: 0x%lx)\n", linux_entry_point);

    // --- Create VCPU(s) ---
    // Assuming single VCPU for now as per task, num_vcpus_attr should be 1.
    if (num_vcpus_attr != 1) {
        printf("LinuxVMM WARNING: This skeleton only explicitly creates 1 VCPU, but %d were configured.\n", num_vcpus_attr);
        // A loop would be needed here for multiple VCPUs.
    }
    printf("LinuxVMM: Creating VCPU %d...\n", vcpu_id_attr);
    // vm.vcpus[0] implies vm_t has an array or similar for VCPUs. This needs to align with vm_t definition.
    // Let's assume vm_guest_cpu_create handles indexing or vm.vcpus is correctly sized by vm_create.
    err = vm_guest_cpu_create(vcpu_id_attr, &vm, &vm.vcpus[vcpu_id_attr]); // Use vcpu_id_attr as index if it's 0-based
    if (err) {
        printf("LinuxVMM ERROR: vm_guest_cpu_create for VCPU %d failed: %d\n", vcpu_id_attr, err);
        return -1;
    }
    printf("  vm_guest_cpu_create for VCPU %d: OK\n", vcpu_id_attr);

    // --- Set Initial VCPU Registers ---
    // This is highly dependent on what load_linux_guest_image already did.
    // If load_linux_guest_image sets up the Linux zero page and boot parameters,
    // it might also return the correct register values or set them.
    // For a minimal setup, setting RIP is essential. Other registers (like RSI for device tree
    // or boot params) depend on the kernel's expectations.
    printf("LinuxVMM: Setting initial VCPU registers for VCPU %d...\n", vcpu_id_attr);
    err = vcpu_set_rip(vm.vcpus[vcpu_id_attr], linux_entry_point);
    if (err) {
        printf("LinuxVMM ERROR: vcpu_set_rip for VCPU %d failed: %d\n", vcpu_id_attr, err);
        return -1;
    }
    printf("  VCPU %d RIP set to 0x%lx\n", vcpu_id_attr, linux_entry_point);

    // Conceptual call to setup other Linux boot parameters (EAX, EBX, ESI for zero page, etc.)
    // This is often architecture and kernel specific.
    // For x86, typically EAX has a magic number, EBX has the address of the boot params (zero page).
    // Many details are handled by a comprehensive load_linux_guest_image function.
    // For now, we assume load_linux_guest_image has prepared necessary params in guest RAM
    // and RIP is the primary register we must set.
    // uintptr_t ram_base = vm_get_guest_ram_base(&vm); // Assuming this function exists
    // size_t ram_size = vm_get_guest_ram_size(&vm);   // Assuming this function exists
    // uintptr_t initrd_addr = get_initrd_load_addr(&vm, initrd_image_name); // Conceptual
    // size_t initrd_size = get_initrd_size(&vm, initrd_image_name);       // Conceptual
    // setup_linux_boot_params_standard(vm.vcpus[vcpu_id_attr], linux_entry_point, ram_base, ram_size, initrd_addr, initrd_size, kernel_cmd_line_string);
    // printf("  Conceptual: Linux boot params set for VCPU %d.\n", vcpu_id_attr);

    printf("LinuxVMM: VM Initialized and VCPU %d configured. Entering VCPU run loop...\n", vcpu_id_attr);

    // --- VCPU Run Loop ---
    // This assumes vm.vcpus[vcpu_id_attr]->vcpu.cap is the VCPU capability.
    // The exact structure might vary (e.g., vm.vcpus[vcpu_id_attr]->vcpu_cap).
    // Check sel4vm/guest_vcpu.h or sel4vm/boot.h for the actual VCPU capability field.
    // For this example, we assume vm.vcpus[vcpu_id_attr] is of type guest_vcpu_t*
    // and guest_vcpu_t has a field 'vcpu_cap' or 'vcpu.cap' or similar.
    // Based on common examples, `vm.vcpus[X]->vcpu.cptr` or `vm.vcpus[X]->vcpu_cap` are possibilities.
    // Let's assume vm.vcpus[vcpu_id_attr]->vcpu_obj.cptr based on some sel4vm patterns.
    // If vm_guest_cpu_create stores the created VCPU cap directly in guest_vcpu_t->vcpu_cap:
    seL4_CPtr vcpu_cap = vm.vcpus[vcpu_id_attr]->vcpu_cap; // Adjust if field name is different
    int host_char_input; // For polling serial input for guest
        // This might involve checking a flag set by the CAmkES timer handler
        // or directly calling an IRQ processing function if events are queued.
        // For now, we assume timer IRQ injection happens in system_timer_handle().

        seL4_VCPU_Run_t vm_exit;
        // The second argument to seL4_VCPU_Run is for sending data with the run command,
        // typically NULL unless responding to a specific type of VM exit.
        vm_exit = seL4_VCPU_Run(vcpu_cap, NULL);

        // Handle VM exit reasons
        switch (vm_exit.reason) {
            case SEL4_VMEXIT_REASON_TIMEOUT:
                // This reason is only generated if seL4_VCPU_SetTimeout was called for this VCPU.
                // If we are relying on an external CAmkES timer to inject IRQs,
                // this specific exit might not be the primary way we handle timer events.
                // However, if it does occur, we could inject a timer IRQ here.
                printf("VMM: VCPU %d exit due to Timeout. Injecting PIT_IRQ.\n", vcpu_id_attr);
                err = vm_inject_irq(vm.vcpus[vcpu_id_attr], PIT_IRQ);
                if (err) {
                    printf("VMM ERROR: Failed to inject PIT_IRQ on Timeout for VCPU %d: %d\n", vcpu_id_attr, err);
                    // Consider how to handle this - break, continue, or attempt recovery.
                }
                break;

            case SEL4_VMEXIT_REASON_UNKNOWN_SYSCALL:
                printf("VMM: VCPU %d halted on Unknown Syscall.\n", vcpu_id_attr);
                // Print detailed information if available from vm_exit payload
                // E.g., vm_exit.data.unknown_syscall.rax, .rbx, .rcx, .rdx, .rsi, .rdi, .rbp, .rip, .rsp, .rflags
                printf("  RIP: 0x%lx, RAX: 0x%lx, RBX: 0x%lx, RCX: 0x%lx, RDX: 0x%lx\n",
                       vm_exit.data.unknown_syscall.rip, vm_exit.data.unknown_syscall.rax,
                       vm_exit.data.unknown_syscall.rbx, vm_exit.data.unknown_syscall.rcx,
                       vm_exit.data.unknown_syscall.rdx);
                goto VmErrorHalt; // Halt VM on unhandled syscall

            case SEL4_VMEXIT_REASON_VCPU_FAULT:
                printf("VMM: VCPU %d halted on VCPU Fault.\n", vcpu_id_attr);
                // This is typically an unrecoverable fault within the VCPU itself.
                // Print details if possible, e.g., from vm_exit.data.vcpu_fault.rip etc.
                // seL4_UserContext regs;
                // seL4_VCPU_ReadRegs(vcpu_cap, SEL4_VCPU_ALL_REGS_MASK, &regs); (Conceptual)
                // printf("  VCPU Fault RIP: 0x%lx\n", regs.rip);
                goto VmErrorHalt;

            case SEL4_VMEXIT_REASON_EXCEPTION:
                printf("VMM: VCPU %d halted on Guest Exception.\n", vcpu_id_attr);
                // Details in vm_exit.data.exception: .number, .error_code, .instruction_fault, etc.
                printf("  Exception Number: %d (0x%x), Error Code: 0x%x\n",
                       vm_exit.data.exception.number, vm_exit.data.exception.number,
                       vm_exit.data.exception.error_code);
                printf("  Fault IP: 0x%lx, Fault Addr (if page fault): 0x%lx\n",
                       vm_exit.data.exception.instruction_fault ? vm_exit.data.exception.fault_ip : 0, // Check instruction_fault
                       (vm_exit.data.exception.number == 14) ? vm_exit.data.exception.fault_addr : 0); // Page fault exception number is 14
                goto VmErrorHalt;

            // Add more cases here for other VM exits like IO_FAULT, HLT, DEBUG_EXCEPTION etc.
            // case SEL4_VMEXIT_REASON_IO_FAULT:
            //    handle_io_fault(&vm, vm.vcpus[vcpu_id_attr], &vm_exit.data.io_fault);
            //    break;

            default:
                printf("VMM: VCPU %d halted on unhandled VM exit reason: %d\n", vcpu_id_attr, vm_exit.reason);
                goto VmErrorHalt;
        }

        // --- Poll for Host Serial Input and forward to Guest VirtIO Console Input Queue ---
        host_char_input = vmm_serial_getchar(NULL);
        if (host_char_input != -1 && host_char_input != EOF) {
            // printf("VMM: Host serial input '%c'\n", (char)host_char_input);
            virtio_device_t *vdev_con_in = vm_get_virtio_device_by_id(&vm, VIRTIO_CONSOLE_DEVICE_ID, 0);
            if (vdev_con_in) {
                virtio_queue_t *vq_guest_input = virtio_get_queue(vdev_con_in, VIRTIO_CONSOLE_INPUT_QUEUE_IDX);
                if (vq_guest_input && virtio_host_can_dequeue_buffer(vq_guest_input)) {
                    virtio_buffer_descriptor_t desc_guest_in;
                    err = virtio_host_dequeue_buffer(vq_guest_input, &desc_guest_in);
                    if (err == 0) {
                        if (desc_guest_in.num_segments > 0 && desc_guest_in.segments[0].len > 0) {
                            // Assuming single segment for simplicity for input character.
                            // Guest provides a buffer, VMM writes the char into it.
                            char *guest_buf_vaddr = (char*)vm_guest_paddr_to_vaddr(&vm, desc_guest_in.segments[0].paddr, desc_guest_in.segments[0].len);
                            if (guest_buf_vaddr) {
                                guest_buf_vaddr[0] = (char)host_char_input;
                                desc_guest_in.total_len_processed_by_device = 1; // VMM "wrote" 1 byte to guest buffer

                                err = virtio_host_enqueue_buffer(vq_guest_input, desc_guest_in);
                                if (err) {
                                    printf("LinuxVMM ERROR: virtio_host_enqueue_buffer for console input failed: %d\n", err);
                                } else {
                                    err = virtio_host_notify_guest_queue(vq_guest_input);
                                    if (err) {
                                        printf("LinuxVMM WARNING: virtio_host_notify_guest_queue for console input failed: %d\n", err);
                                    }
                                }
                            } else {
                                printf("LinuxVMM WARNING: Failed to translate guest paddr for VirtIO console input buffer. Dropping char.\n");
                                desc_guest_in.total_len_processed_by_device = 0; // Nothing written
                                virtio_host_enqueue_buffer(vq_guest_input, desc_guest_in); // Return buffer to guest
                            }
                        } else {
                             printf("LinuxVMM WARNING: Dequeued VirtIO console input buffer has no valid/sufficient segments. Dropping char.\n");
                             desc_guest_in.total_len_processed_by_device = 0;
                             virtio_host_enqueue_buffer(vq_guest_input, desc_guest_in); // Return buffer
                        }
                    } else {
                        // If dequeue fails, guest might not have provided buffers yet.
                        // printf("LinuxVMM WARNING: virtio_host_dequeue_buffer for console input failed: %d. Char dropped.\n", err);
                    }
                } else {
                    // Guest has no available input buffers. Character is dropped.
                    // printf("LinuxVMM: Host char '%c' received, but guest VirtIO console has no available input buffers. Char dropped.\n", (char)host_char_input);
                }
            }
            // else { printf("LinuxVMM: Host char '%c' received, but no VirtIO console device found. Char dropped.\n", (char)host_char_input); }
        }
    }

VmErrorHalt:
    printf("LinuxVMM: VM run loop for VCPU %d terminated due to unhandled exit or error.\n", vcpu_id_attr);
    // Clean up or indicate failure
    return -1;
}


// --- IRQ Handler(s) ---
// This function is assumed to be called by the CAmkES timer component
// when the timer fires. The `system_timer` interface in LinuxVMM.camkes
// should be connected to a timer component that provides this callback.
void system_timer_handle(void) {
    int err;
    // This handler is for the VMM's system timer, used to inject timer IRQs into the guest.
    // printf("LinuxVMM: system_timer_handle() (timer event for VMM) called.\n");

    if (vm.initialised && vm.vcpus[linux_guest_vcpu_id] != NULL) {
        // Check if VM and VCPU are ready, and if the VCPU pointer itself is valid.
        // vm.vcpus is an array, so ensure linux_guest_vcpu_id is a valid index.
        if (linux_guest_vcpu_id < vm.num_vcpus && vm.vcpus[linux_guest_vcpu_id]) {
            // Inject PIT IRQ (IRQ 0 on primary PIC) into the guest VCPU
            err = vm_inject_irq(vm.vcpus[linux_guest_vcpu_id], PIT_IRQ);
            if (err) {
                printf("LinuxVMM ERROR: Failed to inject PIT_IRQ into VCPU %d: %d\n", linux_guest_vcpu_id, err);
            } else {
                // printf("LinuxVMM: Injected PIT_IRQ into VCPU %d.\n", linux_guest_vcpu_id);
            }
        } else {
            printf("LinuxVMM WARNING: system_timer_handle: VCPU %d not valid or ready.\n", linux_guest_vcpu_id);
        }
    } else {
        // printf("LinuxVMM WARNING: system_timer_handle called but VM not initialised or VCPU array not ready.\n");
    }

    // Re-arm the CAmkES timer for the next period.
    // This assumes 'system_timer' is a one-shot timer used periodically.
    // The exact parameters (e.g., timer ID, duration) depend on the Timer interface.
    // Example: Re-arm for another 10ms (10,000,000 ns)
    // This assumes the timer interface is `system_timer_oneshot_relative(uint64_t id, uint64_t ns)`
    // and we are using timer ID 0 for this periodic tick.
    // The component `Timer` that `LinuxVMM.system_timer` connects to must provide this.
    // If `system_timer_wait()` is used, this re-arming would happen after `wait()` returns.
    // If it's an event connection, the timer component itself might re-arm.
    // For now, let's assume we need to call a re-arm function.
    // This is highly dependent on the CAmkES Timer component used.
    // e.g. if `system_timer_periodic(0, 10 * 1000 * 1000)` was called once in `run()`,
    // then no re-arming is needed here.
    // If `system_timer_wait()` is the model for the timer event:
    //   (this function `system_timer_handle` would be called after `system_timer_wait()` returns)
    //   then `system_timer_wait()` would be called again at the end of this handler, or in the main loop.

    // Let's assume the CAmkES timer component is configured to call this handler periodically,
    // or if it's a `consumes event`, that event source (the timer component) re-arms itself.
    // If we used `system_timer->wait()` in a loop in a separate thread, that thread would do:
    // while(1) { system_timer_wait(); system_timer_handle_internal_logic(); }
    // For simplicity, if this `system_timer_handle` is directly called upon timer expiry by CAmkES runtime
    // from a `consumes <TimerInstanceName>_event;` type setup, then the timer component
    // connected to this event is responsible for re-arming if it's meant to be periodic.
    // If we are using a simple one-shot timer that we must re-arm manually:
    if (system_timer_oneshot_relative(0, 10 * 1000 * 1000) != 0) { // 10ms, timer_id 0
         printf("LinuxVMM WARNING: Failed to re-arm one-shot system timer.\n");
    }
}

// Remove the old system_timer_event_irq_handle as it's less clear
// than system_timer_handle for a CAmkES timer event.


// --- Function to Parse Custom PCI Hardware Info from Multiboot2 Tags ---
static void ParsePciHardwareInfoTag(UINTN mb2_info_addr) {
    if (mb2_info_addr == 0) {
        printf("ParsePciHardwareInfoTag: Invalid Multiboot2 info address (NULL).\n");
        return;
    }

    // The first 8 bytes of MB2 info are total_size and reserved. Tags start after that.
    multiboot_generic_tag_t *tag = (multiboot_generic_tag_t *)(mb2_info_addr + 8);
    UINT32 total_mb2_size = *(UINT32*)mb2_info_addr;

    printf("ParsePciHardwareInfoTag: Iterating MB2 tags starting at vaddr 0x%lx (Total MB2 size: %u bytes)\n",
           (unsigned long)tag, total_mb2_size);

    // Iterate while current tag pointer is within the bounds of the MB2 info structure
    // and we haven't hit the END tag type.
    g_vmm_num_pci_devices = 0; // Reset before parsing

    while ((UINTN)tag < (mb2_info_addr + total_mb2_size) && tag->Type != 0 /* MULTIBOOT_TAG_TYPE_END */) {
        // Printf for debugging each tag found
        // printf("  Found MB2 Tag - Type: %u (0x%x), Size: %u\n", tag->Type, tag->Type, tag->Size);

        if (tag->Type == MULTIBOOT_TAG_TYPE_HW_INFO) {
            MultibootTagHwInfoBase_t *hw_info_tag = (MultibootTagHwInfoBase_t *)tag;
            printf("LinuxVMM: Found PCI Hardware Info Tag (Type 0x%X, Size %u) with %u PCI devices reported in tag.\n",
                   hw_info_tag->Type, hw_info_tag->Size, hw_info_tag->NumPciDevs);

            // Pointer to the start of the PciDeviceInfo array within the tag
            PciDeviceInfo_t *pci_devs_from_tag = (PciDeviceInfo_t *)((UINT8 *)hw_info_tag + sizeof(MultibootTagHwInfoBase_t));

            // Calculate how many devices can actually be read based on tag size vs reported NumPciDevs
            UINTN actual_data_in_tag = hw_info_tag->Size - sizeof(MultibootTagHwInfoBase_t);
            UINTN num_devs_by_tag_size = actual_data_in_tag / sizeof(PciDeviceInfo_t);

            UINTN num_devs_to_process = hw_info_tag->NumPciDevs;
            if (num_devs_to_process > num_devs_by_tag_size) {
                 printf("  WARNING: NumPciDevs in tag (%u) is greater than what tag size allows (%u). Clamping to %u.\n",
                        hw_info_tag->NumPciDevs, (unsigned int)num_devs_by_tag_size, (unsigned int)num_devs_by_tag_size);
                 num_devs_to_process = num_devs_by_tag_size;
            }

            for (UINT32 i = 0; i < num_devs_to_process; i++) {
                if (g_vmm_num_pci_devices >= MAX_PCI_DEVICES_FROM_LOADER) {
                    printf("  WARNING: Reached VMM storage limit (%u) for PCI devices. Some devices from tag not stored.\n",
                           MAX_PCI_DEVICES_FROM_LOADER);
                    break;
                }

                PciDeviceInfo_t *src_dev = &pci_devs_from_tag[i];
                // Copy to global storage
                g_vmm_pci_devices[g_vmm_num_pci_devices].VendorId = src_dev->VendorId;
                g_vmm_pci_devices[g_vmm_num_pci_devices].DeviceId = src_dev->DeviceId;
                g_vmm_pci_devices[g_vmm_num_pci_devices].Bus = src_dev->Bus;
                g_vmm_pci_devices[g_vmm_num_pci_devices].Device = src_dev->Device;
                g_vmm_pci_devices[g_vmm_num_pci_devices].Function = src_dev->Function;
                g_vmm_pci_devices[g_vmm_num_pci_devices].ClassCode = src_dev->ClassCode;

                printf("  Stored PCI Device %u: %02X:%02X.%X VID:%04X DID:%04X Class:%06X\n",
                       g_vmm_num_pci_devices,
                       g_vmm_pci_devices[g_vmm_num_pci_devices].Bus,
                       g_vmm_pci_devices[g_vmm_num_pci_devices].Device,
                       g_vmm_pci_devices[g_vmm_num_pci_devices].Function,
                       g_vmm_pci_devices[g_vmm_num_pci_devices].VendorId,
                       g_vmm_pci_devices[g_vmm_num_pci_devices].DeviceId,
                       g_vmm_pci_devices[g_vmm_num_pci_devices].ClassCode);

                g_vmm_num_pci_devices++;
            }
            // No need to search further if we found our specific tag.
            // If multiple such tags could exist, remove the break.
            break;
        }

        // Advance to the next tag: current tag address + tag size, then align up to 8 bytes.
        if (tag->Size == 0) { // Should not happen with valid MB2 structure
            printf("  ERROR: MB2 tag with size 0 found. Aborting parse.\n");
            break;
        }
        tag = (multiboot_generic_tag_t *)(((UINTN)tag + tag->Size + 7) & ~7);
    }
    // printf("ParsePciHardwareInfoTag: Finished iterating MB2 tags.\n");
}


// --- PCI Passthrough NIC IRQ Event Handler ---
// This function will be called when an IRQ event is received on the
// 'passthrough_nic_irq_event' CAmkES interface.
// The CAmkES runtime generates this function name based on the interface instance name.
void passthrough_nic_irq_event_handle(void) {
    // This handler is for the physical interrupt from the passthrough NIC.
    // It needs to acknowledge the interrupt at the physical device level (if necessary)
    // and then inject a virtual IRQ into the guest.

    // printf("LinuxVMM: Passthrough NIC IRQ event received.\n");

    if (!vm.initialised || vm.vcpus[linux_guest_vcpu_id] == NULL) {
        printf("LinuxVMM WARNING: Passthrough NIC IRQ event received, but VM or VCPU not ready.\n");
        // Acknowledge the CAmkES-level event if the connector requires it.
        // This depends on the IRQ connector type (e.g., seL4HardwareInterrupt).
        if (passthrough_nic_irq_event_acknowledge() != 0) { // This is a CAmkES generated function if using seL4HardwareInterrupt
             printf("LinuxVMM WARNING: Failed to acknowledge passthrough NIC IRQ event at CAmkES level.\n");
        }
        return;
    }

    // Conceptual: Acknowledge the physical interrupt at the device.
    // This is highly device-specific. For many NICs, reading a specific register
    // (like Interrupt Cause Read register) or writing to an Interrupt Acknowledge register
    // in its BAR space might be needed. This might involve using the `passthrough_nic_bar0_mem` dataport.
    // For MSI/MSI-X, acknowledgment is often simpler or automatic at the hardware level.
    printf("  TODO: Implement device-specific IRQ acknowledgment for passthrough NIC via BAR access if needed.\n");
    // Example: MmioRead32((uintptr_t)passthrough_nic_bar0_mem + NIC_INTERRUPT_STATUS_REGISTER);


    // Inject the corresponding virtual IRQ into the guest.
    // The guest IRQ number for this device was configured in pt_dev_cfg.guest_irq_num
    // or is the same as the physical IRQ from CAmkES config.
    int guest_irq_for_nic = strtol(passthrough_nic_assigned_irq, NULL, 10);
    int err = vm_inject_irq(vm.vcpus[linux_guest_vcpu_id], guest_irq_for_nic);
    if (err) {
        printf("LinuxVMM ERROR: Failed to inject IRQ %d for passthrough NIC into VCPU %d: %d\n",
               guest_irq_for_nic, linux_guest_vcpu_id, err);
    }
    // else {
    //    printf("LinuxVMM: Injected IRQ %d for passthrough NIC into VCPU %d.\n",
    //           guest_irq_for_nic, linux_guest_vcpu_id);
    // }

    // Acknowledge the CAmkES-level event. This is usually required for level-triggered
    // interrupts or if the seL4HardwareInterrupt connector is used.
    if (passthrough_nic_irq_event_acknowledge() != 0) { // This is a CAmkES generated function
        printf("LinuxVMM WARNING: Failed to acknowledge CAmkES passthrough NIC IRQ event.\n");
    }
}


// --- VirtIO Console Notification Callback ---
// This function is called by the VirtIO console device model (e.g., from MMIO fault handler)
// when the guest notifies the VMM about new data in the output virtqueue (guest -> host).
static void virtio_console_notify_cb(vm_t *notifying_vm, void *cookie) {
    int err;
    int buffers_processed = 0;

    // Ensure it's our VM, though with a single VM it's less critical.
    if (notifying_vm != &vm) {
        printf("LinuxVMM ERROR: virtio_console_notify_cb called with unexpected VM context.\n");
        return;
    }

    // Conceptual: Get the VirtIO console device.
    // This assumes vm_get_virtio_device_by_id can find the device and its type is known or checked.
    // VIRTIO_CONSOLE_DEVICE_ID would be a #define, e.g., 3 for console in VirtIO spec.
    // The '0' is an instance ID if multiple consoles were supported.
    virtio_device_t *vdev = vm_get_virtio_device_by_id(&vm, VIRTIO_CONSOLE_DEVICE_ID, 0);
    if (!vdev) {
        printf("LinuxVMM ERROR: virtio_console_notify_cb: Failed to get VirtIO console device.\n");
        return;
    }

    // Port 1 (VIRTIO_CONSOLE_OUTPUT_PORT_ID or similar define) is typically for guest output (guest TX, VMM RX).
    // Port 0 is for guest input (guest RX, VMM TX).
    // The actual queue index might be different based on feature negotiation (e.g., if multiport is enabled).
    // For a simple single-port console, queue 1 (for output from guest) is common.
    virtio_queue_t *vq_out = virtio_get_queue(vdev, VIRTIO_CONSOLE_OUTPUT_QUEUE_IDX); // VIRTIO_CONSOLE_OUTPUT_QUEUE_IDX usually 1
    if (!vq_out) {
        printf("LinuxVMM ERROR: virtio_console_notify_cb: Failed to get output virtqueue.\n");
        return;
    }

    // printf("LinuxVMM: virtio_console_notify_cb: Handling guest output.\n");

    // Process available buffers from the guest's output queue
    while (virtio_host_can_dequeue_buffer(vq_out)) {
        virtio_buffer_descriptor_t desc; // Assumed structure by placeholder functions
        unsigned int total_bytes_processed_for_desc = 0;

        // Dequeue a buffer (which might be a chain of descriptors)
        err = virtio_host_dequeue_buffer(vq_out, &desc);
        if (err) {
            printf("LinuxVMM ERROR: virtio_host_dequeue_buffer failed: %d\n", err);
            break; // Stop processing this queue on error
        }

        // Iterate through each segment of the scatter-gather list
        for (int i = 0; i < desc.num_segments; i++) {
            // Translate guest physical address to VMM virtual address
            // The segment paddr is from the guest's perspective.
            void *guest_vaddr = vm_guest_paddr_to_vaddr(&vm, desc.segments[i].paddr, desc.segments[i].len);
            if (!guest_vaddr) {
                printf("LinuxVMM ERROR: Failed to translate guest paddr 0x%lx for VirtIO console buffer segment.\n", (unsigned long)desc.segments[i].paddr);
                // Cannot process this segment. Depending on VirtIO spec/implementation,
                // might need to mark buffer as error or skip. For simplicity, we skip.
                continue;
            }

            // Print the content of this segment
            char *char_buf = (char*)guest_vaddr;
            for (int j = 0; j < desc.segments[i].len; j++) {
                vmm_serial_putchar(char_buf[j], NULL); // Using our existing serial putchar
            }
            total_bytes_processed_for_desc += desc.segments[i].len;
        }

        // Enqueue the buffer back to the guest's used ring.
        // The 'len' here is how many bytes the VMM "wrote" into the guest's buffer,
        // but for an output queue (guest TX), it's how many bytes the VMM *read* from the guest.
        // So, we report back the total length of the buffer segments we processed.
        desc.total_len_processed_by_device = total_bytes_processed_for_desc;
        err = virtio_host_enqueue_buffer(vq_out, desc);
        if (err) {
            printf("LinuxVMM ERROR: virtio_host_enqueue_buffer failed: %d\n", err);
            // This is problematic as the guest won't get its buffer back.
            // May need more robust error handling or VM shutdown.
            break;
        }
        buffers_processed++;
    }

    // If we processed any buffers, notify the guest.
    // This might trigger an interrupt in the guest if it enabled notifications.
    if (buffers_processed > 0) {
        err = virtio_host_notify_guest_queue(vq_out);
        if (err) {
            printf("LinuxVMM WARNING: virtio_host_notify_guest_queue for console output failed: %d\n", err);
        }
    }
}
