/*
 * GuestVmm.c
 * CAmkES component C implementation for a generic Guest Virtual Machine Monitor
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h> // For strtoull, atoi, strtol

#include <camkes.h>

// seL4 specific includes
#include <sel4/sel4.h>
#include <simple/simple.h>
#include <vka/object.h>
#include <vka/vka.h>
#include <vka/capops.h>
#include <allocman/allocman.h>
#include <sel4utils/vspace.h>
#include <sel4utils/sel4_zf_logif.h>

// libsel4vm includes
#include <sel4vm/guest_vm.h>
#include <sel4vm/guest_ram.h>
#include <sel4vm/guest_vcpu.h>
#include <sel4vm/boot.h>
#include <sel4vm/arch/x86/boot.h>
#include <sel4vm/guest_x86_platform.h>
#include <sel4vm/guest_pci.h>
#include <sel4vm/arch/x86/guest_pci_legacy.h>
#include <sel4vm/arch/x86/smc.h>
#include <sel4vm/arch/x86/nvram.h>
#include <sel4vm/arch/x86/ide.h>
#include <sel4vm/arch/x86/vga.h>  // Conceptual
#include <sel4vm/arch/x86/usb.h>  // Conceptual
#include <sel4vm/arch/x86/smbios.h> // Conceptual for vm_set_smbios_type2
#include <sel4vm/arch/x86/guest_vcpu_features.h> // Conceptual for vcpu_set_cpuid_profile
#include <sel4vmmplatsupport/arch/x86/devices/virtio_net.h> // Conceptual for vm_install_virtio_net_device

// libsel4vmmplatsupport includes
#include <sel4vmmplatsupport/drivers/pci_helper.h>
#include <sel4vmmplatsupport/arch/x86/devices/devices.h>
#include <sel4vmmplatsupport/arch/x86/devices/virtio_con.h>
#include <sel4vmmplatsupport/arch/x86/devices/pci_passthrough.h>
#include <sel4vmmplatsupport/arch/x86/devices/virtio_blk.h>
#include <sel4vmmplatsupport/guest_image.h>
#include <sel4vmmplatsupport/platform/sel4_serial.h>

// Guest Internal State
typedef enum { GUEST_STATE_STOPPED, GUEST_STATE_CONFIGURING, GUEST_STATE_CONFIGURED, GUEST_STATE_STARTING, GUEST_STATE_RUNNING, GUEST_STATE_STOPPING, GUEST_STATE_ERROR } GuestInternalState;
#define VIRTIO_BLK_S_OK  0
#define VIRTIO_BLK_S_IOERR 1

// --- Conceptual device installation function placeholders ---
#ifndef VM_INSTALL_APPLE_SMC_DEVICE_DECLARED
#define VM_INSTALL_APPLE_SMC_DEVICE_DECLARED
static inline int vm_install_applesmc_device(vm_t *vm, const char *osk_key) { printf("GuestVmm: Conceptual vm_install_applesmc_device (OSK len %zu).\n", osk_key ? strlen(osk_key) : 0); if (!vm || !osk_key || strlen(osk_key) != 64) { return -1; } return 0; }
#endif
#ifndef VM_INSTALL_NVRAM_DEVICE_DECLARED
#define VM_INSTALL_NVRAM_DEVICE_DECLARED
static inline int vm_install_nvram_device(vm_t *vm, void *nvram_storage_ptr, size_t nvram_storage_size) { printf("GuestVmm: Conceptual vm_install_nvram_device (ptr %p, size 0x%zx).\n", nvram_storage_ptr, nvram_storage_size); if (!vm || !nvram_storage_ptr || nvram_storage_size == 0) { return -1; } return 0; }
#endif
#ifndef VM_INSTALL_IDE_CONTROLLER_DECLARED
#define VM_INSTALL_IDE_CONTROLLER_DECLARED
static inline int vm_install_ide_controller(vm_t *vm, int controller_id) { printf("GuestVmm: Conceptual vm_install_ide_controller (id %d).\n", controller_id); if (!vm || controller_id < 0 || controller_id > 1) { return -1; } return 0; }
#endif
#ifndef VM_INSTALL_IDE_DISK_DEVICE_DECLARED
#define VM_INSTALL_IDE_DISK_DEVICE_DECLARED
static inline int vm_install_ide_disk_device(vm_t *vm, int c, int ch, bool m, const char* n, void* dp, size_t ds, bool cd) { printf("GuestVmm: Conceptual vm_install_ide_disk_device: %s (size:0x%zx, cd:%d)\n",n, ds, cd); if (!vm || !dp || ds == 0 || !n) { return -1; } return 0; }
#endif
#ifndef VCPU_SET_CPUID_PROFILE_DECLARED
#define VCPU_SET_CPUID_PROFILE_DECLARED
static inline int vcpu_set_cpuid_profile(vm_vcpu_t* vcpu, const char* model, const char* product) { printf("GuestVmm: Conceptual vcpu_set_cpuid_profile (model:'%s', product:'%s').\n", model, product); if(!vcpu || !model || !product) return -1; return 0;}
#endif
#ifndef VM_SET_SMBIOS_TYPE2_DECLARED
#define VM_SET_SMBIOS_TYPE2_DECLARED
static inline int vm_set_smbios_type2(vm_t* vm, const char* man, const char* prod) { printf("GuestVmm: Conceptual vm_set_smbios_type2 (Man:'%s', Prod:'%s').\n", man, prod); if(!vm || !man || !prod) return -1; return 0;}
#endif
#ifndef VM_INSTALL_VGA_DEVICE_DECLARED
#define VM_INSTALL_VGA_DEVICE_DECLARED
static inline int vm_install_vga_device(vm_t* vm, const char* type) { printf("GuestVmm: Conceptual vm_install_vga_device (type:'%s').\n", type); if(!vm || !type) return -1; return 0;}
#endif
#ifndef VM_INSTALL_USB_CONTROLLER_DEVICE_DECLARED
#define VM_INSTALL_USB_CONTROLLER_DEVICE_DECLARED
static inline int vm_install_usb_controller_device(vm_t* vm, const char* type) { printf("GuestVmm: Conceptual vm_install_usb_controller_device (type:'%s').\n", type); if(!vm || !type) return -1; return 0;}
#endif
#ifndef VM_INSTALL_USB_INPUT_DEVICE_DECLARED
#define VM_INSTALL_USB_INPUT_DEVICE_DECLARED
static inline int vm_install_usb_input_device(vm_t* vm, const char* type) { printf("GuestVmm: Conceptual vm_install_usb_input_device (type:'%s').\n", type); if(!vm || !type) return -1; return 0;}
#endif
// Dummy callbacks for VirtIO Net
static void virtio_net_notify_cb_dummy(vm_t* vm, void* cookie) {}
static int virtio_net_rx_cb_dummy(vm_t *vm, void *cookie, void **buf, unsigned int *len, unsigned int *buf_len) { return 0; }
static int virtio_net_tx_cb_dummy(vm_t *vm, void *cookie, void *buf, unsigned int len) { return len; }
#ifndef VM_INSTALL_VIRTIO_NET_DEVICE_DECLARED
#define VM_INSTALL_VIRTIO_NET_DEVICE_DECLARED
static inline int vm_install_virtio_net_device(vm_t* vm, uintptr_t mmio_addr, size_t mmio_size, int irq,
                                              void* n_cb, void* r_cb, void* w_cb, void* cookie) {
    printf("GuestVmm: Conceptual vm_install_virtio_net_device (addr:0x%lx, size:0x%zx, irq:%d).\n", mmio_addr,mmio_size,irq);
    if(!vm || !mmio_addr || !mmio_size || irq < 0) return -1; return 0;
}
#endif

typedef struct { /* ... */ } virtio_guest_buffer_segment_t;
static inline int virtio_get_guest_buffer_segment(virtio_req_id_t r, int i, virtio_guest_buffer_segment_t *s) { /* ... */ return -1; }
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define LINUX_SERIAL_PORT VMM_SERIAL_PORT
#define PIT_IRQ 0
#define VIRTIO_CONSOLE_INPUT_QUEUE_IDX 0
#define VIRTIO_CONSOLE_OUTPUT_QUEUE_IDX 1
#define MAX_PCI_DEVICES_FROM_LOADER 32
typedef struct { /* ... */ } PciDeviceInfo_t;
#define MULTIBOOT_TAG_TYPE_HW_INFO 0xABCDEF01
#pragma pack(push, 1)
typedef struct { /* ... */ } MultibootTagHwInfoBase_t;
#pragma pack(pop)
#pragma pack(push, 1)
typedef struct { /* ... */ } multiboot_generic_tag_t;
#pragma pack(pop)

vm_t vm;
static PciDeviceInfo_t g_vmm_pci_devices[MAX_PCI_DEVICES_FROM_LOADER];
static UINT32 g_vmm_num_pci_devices = 0;
static size_t g_virtio_blk_disk_size_val = 0;
static GuestInternalState g_guest_state = GUEST_STATE_STOPPED;
static vm_vcpu_t* primary_vcpu = NULL;
// Globals to hold macOS CPUID/SMBIOS info for later VCPU setup
static char g_macos_cpu_model_for_vcpu_setup[64] = "";
static char g_macos_smbios_product_for_vcpu_setup[64] = "";


static int vmm_serial_putchar(int c, void *cookie) { /* ... */ return -1; }
static int vmm_serial_getchar(void *cookie) { /* ... */ return -1; }
static void ParsePciHardwareInfoTag(UINTN mb2_info_addr) { /* ... */ }
static void virtio_block_read_cb(vm_t *vm_ptr, void *cookie, virtio_req_id_t req_id, uint64_t offset, uint32_t total_len_to_rw) { /* ... */ }
static void virtio_block_write_cb(vm_t *vm_ptr, void *cookie, virtio_req_id_t req_id, uint64_t offset, uint32_t total_len_to_rw) { /* ... */ }
static void virtio_console_notify_cb(vm_t *notifying_vm, void *cookie) { /* ... */ }
void passthrough_nic_irq_event_handle(void) { /* ... */ }
void passthrough_gpu_irq_event_handle(void) { /* ... */ }
static void handle_cpuid_exit_for_guest(vm_vcpu_t *vcpu) { /* ... */ }
void system_timer_handle(void) { /* ... */ }
static void guest_vcpu_run_loop_thread_entry(void* arg_not_used) { /* ... */ }


int guest_control_iface_configure_and_init_impl(const char *profile_name, const char *config_data) {
    g_guest_state = GUEST_STATE_CONFIGURING;
    printf("GuestVmm [%s]: configure_and_init_impl. Profile: %s\n", get_instance_name(), profile_name ? profile_name : "N/A");
    int err;

    // --- Default values from CAmkES attributes ---
    errno = 0;
    unsigned long long p_guest_ram_size_bytes_val = strtoull(guest_ram_size, NULL, 16);
    unsigned long long p_guest_ram_paddr_base_val = strtoull(guest_ram_paddr_base, NULL, 16);
    int vcpu_id_val = linux_guest_vcpu_id;
    int num_vcpus_val = linux_guest_num_vcpus;

    char local_kernel_image_name_val[64]; strncpy(local_kernel_image_name_val, kernel_image_name, sizeof(local_kernel_image_name_val)-1); local_kernel_image_name_val[sizeof(local_kernel_image_name_val)-1] = '\0';
    char local_initrd_image_name_val[64]; strncpy(local_initrd_image_name_val, initrd_image_name, sizeof(local_initrd_image_name_val)-1); local_initrd_image_name_val[sizeof(local_initrd_image_name_val)-1] = '\0';
    char local_disk_image_name_val[64]; strncpy(local_disk_image_name_val, windows_disk_image_name, sizeof(local_disk_image_name_val)-1); local_disk_image_name_val[sizeof(local_disk_image_name_val)-1] = '\0';

    char local_opencore_iso_sym_val[64] = "";
    char local_recovery_iso_sym_val[64] = "";
    char local_efi_disk_sym_val[64] = "";
    char local_macos_cpu_val[64] = ""; // Will be copied to g_macos_cpu_model_for_vcpu_setup
    char local_macos_osk_val[128] = "";
    char local_macos_vga_val[64] = "vmware"; // Default VGA for macOS
    char local_macos_usb_val[64] = "qemu-xhci"; // Default USB controller for macOS
    char local_macos_net_val[64] = "virtio-net"; // Default Net for macOS
    char local_macos_smbios_manufacturer_val[64] = "Apple Inc."; // Default
    char local_macos_smbios_product_val[64] = "MacBookPro11,1";   // Default, will be copied to g_macos_smbios_product_for_vcpu_setup

    unsigned long long p_virtio_con_mmio_paddr_val = strtoull(virtio_con_mmio_paddr, NULL, 16);
    unsigned long long p_virtio_con_mmio_size_val = strtoull(virtio_con_mmio_size, NULL, 16);
    int p_virtio_con_irq_val = strtol(virtio_con_irq, NULL, 10);
    unsigned long long p_virtio_blk_mmio_paddr_val = strtoull(virtio_blk_mmio_paddr, NULL, 16);
    unsigned long long p_virtio_blk_mmio_size_val = strtoull(virtio_blk_mmio_size, NULL, 16);
    int p_virtio_blk_irq_val = strtol(virtio_blk_irq, NULL, 10);

    // macOS specific VirtIO Net params (default to 0, expect override from config_data)
    unsigned long long p_virtio_net_macos_mmio_paddr_val = 0;
    unsigned long long p_virtio_net_macos_mmio_size_val = 0x1000; // Default size if not specified
    int p_virtio_net_macos_irq_val = 0;

    BOOL is_windows_guest_val_final = (strcmp(is_windows_guest, "true") == 0 || strcmp(is_windows_guest, "1") == 0);
    char parsed_os_type_str[32] = "";
    // ... (passthrough attribute parsing) ...
    g_virtio_blk_disk_size_val = strtoull(windows_disk_image_size_config, NULL, 16);
    if (g_virtio_blk_disk_size_val == 0) g_virtio_blk_disk_size_val = (size_t)windows_disk_image_dataport_size();

    // --- Parse config_data string to override defaults ---
    if (config_data && strlen(config_data) > 0) {
        char local_config_data_buf[1024]; strncpy(local_config_data_buf, config_data, sizeof(local_config_data_buf) - 1); local_config_data_buf[sizeof(local_config_data_buf) - 1] = '\0';
        char *saveptr_pair, *saveptr_kv; char *pair_token = strtok_r(local_config_data_buf, ";", &saveptr_pair);
        while (pair_token != NULL) {
            char *key = strtok_r(pair_token, "=", &saveptr_kv); char *value = strtok_r(NULL, "=", &saveptr_kv);
            if (key && value) {
                if (strcmp(key, "os_type") == 0) { strncpy(parsed_os_type_str, value, sizeof(parsed_os_type_str) - 1); parsed_os_type_str[sizeof(parsed_os_type_str) - 1] = '\0'; }
                else if (strcmp(key, "ram_mb_hex_bytes") == 0) { errno = 0; unsigned long long prs = strtoull(value, NULL, 16); if (errno==0 && prs>0) p_guest_ram_size_bytes_val = prs; }
                else if (strcmp(key, "num_vcpus") == 0) {  errno = 0; int pv = atoi(value); if (errno==0 && pv > 0 && pv <= MAX_VCPU_PER_VM) num_vcpus_val = pv; }
                else if (strcmp(key, "kernel_img_sym") == 0) { strncpy(local_kernel_image_name_val, value, sizeof(local_kernel_image_name_val)-1); }
                else if (strcmp(key, "initrd_img_sym") == 0) { strncpy(local_initrd_image_name_val, value, sizeof(local_initrd_image_name_val)-1); }
                else if (strcmp(key, "disk_img_sym") == 0) { strncpy(local_disk_image_name_val, value, sizeof(local_disk_image_name_val)-1); }
                else if (strcmp(key, "opencore_iso_sym") == 0) { strncpy(local_opencore_iso_sym_val, value, sizeof(local_opencore_iso_sym_val)-1); }
                else if (strcmp(key, "recovery_iso_sym") == 0) { strncpy(local_recovery_iso_sym_val, value, sizeof(local_recovery_iso_sym_val)-1); }
                else if (strcmp(key, "efi_disk_sym") == 0) { strncpy(local_efi_disk_sym_val, value, sizeof(local_efi_disk_sym_val)-1); }
                else if (strcmp(key, "vblk_disk_size_bytes_hex") == 0) { errno = 0; unsigned long long psz = strtoull(value,NULL,16); if(errno==0 && psz>0) g_virtio_blk_disk_size_val=psz; }
                else if (strcmp(key, "is_windows_guest") == 0) { is_windows_guest_val_final = (strcmp(value, "true") == 0); }
                else if (strcmp(key, "macos_cpu") == 0) { strncpy(local_macos_cpu_val, value, sizeof(local_macos_cpu_val)-1); }
                else if (strcmp(key, "macos_osk") == 0) { strncpy(local_macos_osk_val, value, sizeof(local_macos_osk_val)-1); }
                else if (strcmp(key, "macos_vga") == 0) { strncpy(local_macos_vga_val, value, sizeof(local_macos_vga_val)-1); }
                else if (strcmp(key, "macos_usb") == 0) { strncpy(local_macos_usb_val, value, sizeof(local_macos_usb_val)-1); }
                else if (strcmp(key, "macos_net") == 0) { strncpy(local_macos_net_val, value, sizeof(local_macos_net_val)-1); }
                else if (strcmp(key, "macos_smbios_manufacturer") == 0) { strncpy(local_macos_smbios_manufacturer_val, value, sizeof(local_macos_smbios_manufacturer_val)-1); }
                else if (strcmp(key, "macos_smbios_product") == 0) { strncpy(local_macos_smbios_product_val, value, sizeof(local_macos_smbios_product_val)-1); }
                else if (strcmp(key, "macos_virtio_net_addr") == 0) { errno=0; p_virtio_net_macos_mmio_paddr_val = strtoull(value,NULL,16); if(errno) p_virtio_net_macos_mmio_paddr_val=0;}
                else if (strcmp(key, "macos_virtio_net_size") == 0) { errno=0; p_virtio_net_macos_mmio_size_val = strtoull(value,NULL,16); if(errno) p_virtio_net_macos_mmio_size_val=0x1000;}
                else if (strcmp(key, "macos_virtio_net_irq") == 0) { errno=0; p_virtio_net_macos_irq_val = strtol(value,NULL,10); if(errno) p_virtio_net_macos_irq_val=0;}
            }
            pair_token = strtok_r(NULL, ";", &saveptr_pair);
        }
    }
    if (strlen(parsed_os_type_str) > 0) { /* ... set is_windows_guest_val_final ... */ }
    if (g_virtio_blk_disk_size_val == 0 && strlen(local_disk_image_name_val) > 0) { g_virtio_blk_disk_size_val = (size_t)windows_disk_image_dataport_size(); }

    // --- VM Initialization ---
    simple_t simple_data; vka_t vka_data; vspace_t vspace_data;
    simple_default_init_bootinfo(&simple_data, seL4_GetBootInfo());
    vka_allocator_init(&vka_data, &simple_data);
    sel4utils_bootstrap_vspace_with_bootinfo_leaky(&vspace_data, &vka_data, simple_data.info);
    err = vm_create("GuestVM", vcpu_id_val, num_vcpus_val, &vka_data, &vspace_data, &simple_data, &vm);
    err = vm_ram_map_guest_memory(&vm, (uintptr_t)p_guest_ram_paddr_base_val, (size_t)p_guest_ram_size_bytes_val, NULL);

    vmm_serial_ops_t serial_ops = { .putc = vmm_serial_putchar, .getc = vmm_serial_getchar, .priv = NULL };
    vm_install_legacy_serial_device(&vm, LINUX_SERIAL_PORT, &serial_ops);
    vm_install_pic_device(&vm); vm_install_pit_device(&vm);
    vm_install_virtio_con_device(&vm, (uintptr_t)p_virtio_con_mmio_paddr_val, (size_t)p_virtio_con_mmio_size_val, (unsigned int)p_virtio_con_irq_val, virtio_console_notify_cb, NULL, NULL);

    // OS Specific Device Setup
    if (is_windows_guest_val_final) {
        // ... (Windows VirtIO block setup) ...
    } else if (strcmp(parsed_os_type_str, "macos") == 0) {
        printf("GuestVmm INFO: Applying macOS-specific device configurations...\n");
        strncpy(g_macos_cpu_model_for_vcpu_setup, local_macos_cpu_val, sizeof(g_macos_cpu_model_for_vcpu_setup)-1);
        strncpy(g_macos_smbios_product_for_vcpu_setup, local_macos_smbios_product_val, sizeof(g_macos_smbios_product_for_vcpu_setup)-1);

        err = vm_set_smbios_type2(&vm, local_macos_smbios_manufacturer_val, local_macos_smbios_product_val);
        if(err) printf("GuestVmm ERROR: Failed to set SMBIOS Type 2: %d\n", err); else printf("GuestVmm: SMBIOS Type 2 set.\n");

        if (strlen(local_macos_osk_val) == 64) { /* ... AppleSMC setup ... */ } else { /* error */ return -1; }
        if (strlen(local_efi_disk_sym_val) > 0) { /* ... NVRAM setup ... */ } else { /* info skip */ }
        err = vm_install_ide_controller(&vm, 0);
        if (err) { /* ... */ } else {
            if (strlen(local_opencore_iso_sym_val) > 0) { /* ... OpenCore ISO ... */ }
            if (strlen(local_recovery_iso_sym_val) > 0) { /* ... Recovery ISO ... */ }
        }
        if (strlen(local_disk_image_name_val) > 0) { /* ... Main macOS VirtIO Block ... */ }

        err = vm_install_vga_device(&vm, local_macos_vga_val);
        if(err) printf("GuestVmm ERROR: Failed to install VGA device ('%s'): %d\n", local_macos_vga_val, err); else printf("GuestVmm: VGA device ('%s') installed.\n", local_macos_vga_val);

        err = vm_install_usb_controller_device(&vm, local_macos_usb_val);
        if(err) printf("GuestVmm ERROR: Failed to install USB controller ('%s'): %d\n", local_macos_usb_val, err);
        else {
            printf("GuestVmm: USB Controller ('%s') installed.\n", local_macos_usb_val);
            vm_install_usb_input_device(&vm, "keyboard"); // Best effort
            vm_install_usb_input_device(&vm, "tablet");   // Best effort
        }

        if(p_virtio_net_macos_mmio_paddr_val != 0 && p_virtio_net_macos_irq_val !=0) {
            err = vm_install_virtio_net_device(&vm, p_virtio_net_macos_mmio_paddr_val, p_virtio_net_macos_mmio_size_val,
                                               p_virtio_net_macos_irq_val, virtio_net_notify_cb_dummy,
                                               virtio_net_rx_cb_dummy, virtio_net_tx_cb_dummy, NULL);
            if(err) printf("GuestVmm ERROR: Failed to install macOS VirtIO Net: %d\n", err);
            else printf("GuestVmm: macOS VirtIO Net installed.\n");
        } else {
            printf("GuestVmm INFO: macOS VirtIO Net parameters not fully specified (addr:0x%llx, irq:%d). Skipping.\n",
                   p_virtio_net_macos_mmio_paddr_val, p_virtio_net_macos_irq_val);
        }

    } else { /* ... Linux/Generic VirtIO Block setup ... */ }

    // ... (Passthrough device setup) ...

    // Create VCPU(s)
    err = vm_guest_cpu_create(vcpu_id_val, &vm, &primary_vcpu);
    if(err || !primary_vcpu) { printf("GuestVmm ERROR: vm_guest_cpu_create failed: %d\n", err); return -1;}

    // macOS VCPU specific setup (CPUID profile)
    if (strcmp(parsed_os_type_str, "macos") == 0 && primary_vcpu) {
        if(strlen(g_macos_cpu_model_for_vcpu_setup) > 0 && strlen(g_macos_smbios_product_for_vcpu_setup) > 0) {
            err = vcpu_set_cpuid_profile(primary_vcpu, g_macos_cpu_model_for_vcpu_setup, g_macos_smbios_product_for_vcpu_setup);
            if(err) printf("GuestVmm ERROR: Failed to set macOS CPUID profile: %d\n", err);
            else printf("GuestVmm: macOS CPUID profile set for VCPU.\n");
        } else {
            printf("GuestVmm WARNING: macOS CPU model or SMBIOS product not specified, skipping CPUID profile.\n");
        }
    }

    // Boot logic (RIP setting)
    uintptr_t guest_entry_point = 0;
    if (!is_windows_guest_val_final && strcmp(parsed_os_type_str, "macos") != 0) { /* ... Linux RIP ... */ }
    else { /* ... Windows/macOS RIP by firmware ... */ }

    g_guest_state = GUEST_STATE_CONFIGURED;
    printf("GuestVmm [%s]: Configuration and initialization complete.\n", get_instance_name());
    return 0;
}

// ... (rest of the file: start_guest, stop_guest, force_stop_guest, run) ...
int guest_control_iface_start_guest_impl(void) { return 0;}
int guest_control_iface_stop_guest_impl(void) { return 0;}
int guest_control_iface_force_stop_guest_impl(void) { return 0;}
int run(void) { return 0;}

[end of LinuxVMM/GuestVmm.c]
