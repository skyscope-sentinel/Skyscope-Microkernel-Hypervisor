/*
 * VmManager.c
 * CAmkES component for managing Virtual Machines.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h> // For atoi
#include <camkes.h>


// Define MAX_VM_SLOTS if not already defined (e.g. in a header)
#ifndef MAX_VM_SLOTS
#define MAX_VM_SLOTS 2 // Consistent with multi_vm_app.camkes
#endif

// --- VM Slot State Definitions ---
typedef enum {
    VM_SLOT_STATE_EMPTY,
    VM_SLOT_STATE_CONFIGURED,
    VM_SLOT_STATE_RUNNING,
    VM_SLOT_STATE_ERROR
} VmSlotState;

typedef struct {
    VmSlotState state;
    char profile_name[64];
    char instance_name[128];
} VmSlotStatus;

static VmSlotStatus vm_slots[MAX_VM_SLOTS];


// --- VM Profile Definitions ---
typedef struct {
    char name[64];
    char os_type[16]; // "linux", "windows"
    UINT64 ram_mb;
    UINT32 num_vcpus;

    char kernel_image_symbol[128];
    char initrd_image_symbol[128];
    char primary_disk_image_symbol[128];

    char virtio_console_mmio_paddr_str[16];
    char virtio_console_irq_str[8];
    char virtio_console_mmio_size_str[16];

    char virtio_block_mmio_paddr_str[16];
    char virtio_block_irq_str[8];
    char virtio_block_mmio_size_str[16];
    char virtio_block_disk_image_size_str[20];

} VmProfile;

static VmProfile predefined_vm_profiles[] = {
    {
        .name = "LinuxDefault", .os_type = "linux", .ram_mb = 512, .num_vcpus = 1,
        .kernel_image_symbol = "linux_kernel_for_guest0", .initrd_image_symbol = "initrd_for_guest0", .primary_disk_image_symbol = "",
        .virtio_console_mmio_paddr_str = "0xDF000000", .virtio_console_irq_str = "33", .virtio_console_mmio_size_str = "0x1000",
        .virtio_block_mmio_paddr_str = "0xDF001000", .virtio_block_irq_str = "34", .virtio_block_mmio_size_str = "0x1000",
        .virtio_block_disk_image_size_str = "0x10000000"
    },
    {
        .name = "WindowsDefault", .os_type = "windows", .ram_mb = 1024, .num_vcpus = 2,
        .kernel_image_symbol = "", .initrd_image_symbol = "", .primary_disk_image_symbol = "windows_disk_for_guest1",
        .virtio_console_mmio_paddr_str = "0xDF002000", .virtio_console_irq_str = "35", .virtio_console_mmio_size_str = "0x1000",
        .virtio_block_mmio_paddr_str = "0xDF003000", .virtio_block_irq_str = "36", .virtio_block_mmio_size_str = "0x1000",
        .virtio_block_disk_image_size_str = "0x800000000"
    }
};
static const int num_predefined_vm_profiles = sizeof(predefined_vm_profiles) / sizeof(VmProfile);

// --- Helper for reading user input ---
// This is a simplified version. A robust implementation would handle backspace, arrow keys etc.
// and require a proper serial driver setup for getchar() to be blocking and work as expected.
// Assumes getchar() is available and connected to VmManager's input stream.
static char* VmManager_gets(char *buf, int len) {
    if (buf == NULL || len <= 0) return NULL;

    int c;
    int i = 0;
    // This assumes serial_getchar() or similar is available via CAmkES configuration
    // For now, using standard getchar() as a placeholder.
    // This will likely require `vm_mgr.serial_getchar_int()` if a `Serial` interface is `use`d.
    // If no serial input is configured for VmManager, this will not work.
    printf("VmManager_gets: Waiting for input (up to %d chars, newline to end):\n", len -1);

    while (i < len - 1) {
        c = getchar(); // Placeholder for actual serial input function from CAmkES interface
        if (c == EOF || c == '\n' || c == '\r') {
            break;
        }
        if (c == 0x7f || c == 0x08) { // Handle backspace (DEL or BS)
            if (i > 0) {
                i--;
                printf("\b \b"); // Erase character on console
            }
        } else if (c >= 0x20 && c <= 0x7E) { // Printable ASCII
            buf[i++] = (char)c;
            putchar(c); // Echo character
        }
    }
    buf[i] = '\0';
    putchar('\n'); // Echo newline
    printf("VmManager_gets: Read: \"%s\"\n", buf);
    return buf;
}


// --- VmManagement Interface Implementation ---

int vm_management_iface_create_vm_in_slot_from_profile_impl(int slot, const char *profile_name, const char *instance_name) {
    printf("VmManager: create_vm_in_slot_from_profile_impl. Slot: %d, Profile: %s, InstanceName: %s\n",
           slot, profile_name, instance_name ? instance_name : "DefaultVM");

    if (slot < 0 || slot >= MAX_VM_SLOTS) {
        printf("VmManager ERROR: Invalid slot number: %d\n", slot);
        return -1;
    }
    if (vm_slots[slot].state != VM_SLOT_STATE_EMPTY) {
        printf("VmManager ERROR: Slot %d is not empty (state: %d, profile: %s).\n", slot, vm_slots[slot].state, vm_slots[slot].profile_name);
        return -4; // Slot not empty
    }

    VmProfile *selected_profile = NULL;
    for (int i = 0; i < num_predefined_vm_profiles; i++) {
        if (strcmp(predefined_vm_profiles[i].name, profile_name) == 0) {
            selected_profile = &predefined_vm_profiles[i];
            break;
        }
    }

    if (selected_profile == NULL) {
        printf("VmManager ERROR: Profile '%s' not found.\n", profile_name);
        vm_slots[slot].state = VM_SLOT_STATE_ERROR; // Mark slot as error
        return -2;
    }
    printf("VmManager: Found profile '%s'. OS: %s, RAM: %lluMB, VCPUs: %u\n",
           selected_profile->name, selected_profile->os_type, selected_profile->ram_mb, selected_profile->num_vcpus);

    char config_data_str[1024];
    snprintf(config_data_str, sizeof(config_data_str),
             "os_type=%s;ram_mb_hex_bytes=0x%llx;num_vcpus=%u;kernel_img_sym=%s;initrd_img_sym=%s;disk_img_sym=%s;"
             "vcon_addr_str=%s;vcon_size_str=%s;vcon_irq_str=%s;"
             "vblk_addr_str=%s;vblk_size_str=%s;vblk_irq_str=%s;"
             "is_windows_guest=%s;",
             selected_profile->os_type, selected_profile->ram_mb * 1024 * 1024, selected_profile->num_vcpus,
             selected_profile->kernel_image_symbol, selected_profile->initrd_image_symbol, selected_profile->primary_disk_image_symbol,
             selected_profile->virtio_console_mmio_paddr_str, selected_profile->virtio_console_mmio_size_str, selected_profile->virtio_console_irq_str,
             selected_profile->virtio_block_mmio_paddr_str, selected_profile->virtio_block_mmio_size_str, selected_profile->virtio_block_irq_str,
             (strcmp(selected_profile->os_type, "windows") == 0 ? "true" : "false")
             );
    config_data_str[sizeof(config_data_str)-1] = '\0';

    printf("VmManager: Config data for GuestVmm (slot %d): %s\n", slot, config_data_str);
    int result = -1;

    if (slot == 0) result = control_slot0_configure_and_init(profile_name, config_data_str);
    else if (slot == 1) result = control_slot1_configure_and_init(profile_name, config_data_str);
    else { printf("VmManager ERROR: Slot %d not dispatchable.\n", slot); return -3; }

    if (result == 0) {
        printf("VmManager: GuestVmm in slot %d configured successfully.\n", slot);
        vm_slots[slot].state = VM_SLOT_STATE_CONFIGURED;
        strncpy(vm_slots[slot].profile_name, profile_name, sizeof(vm_slots[slot].profile_name)-1);
        vm_slots[slot].profile_name[sizeof(vm_slots[slot].profile_name)-1] = '\0';
        if(instance_name) strncpy(vm_slots[slot].instance_name, instance_name, sizeof(vm_slots[slot].instance_name)-1);
        else snprintf(vm_slots[slot].instance_name, sizeof(vm_slots[slot].instance_name), "VM_Slot%d", slot);
        vm_slots[slot].instance_name[sizeof(vm_slots[slot].instance_name)-1] = '\0';
    } else {
        printf("VmManager ERROR: GuestVmm slot %d config failed (result: %d).\n", slot, result);
        vm_slots[slot].state = VM_SLOT_STATE_ERROR;
    }
    return result;
}

int vm_management_iface_start_vm_in_slot_impl(int slot) {
    printf("VmManager: start_vm_in_slot_impl for Slot: %d\n", slot);
    if (slot < 0 || slot >= MAX_VM_SLOTS) return -1;
    if (vm_slots[slot].state != VM_SLOT_STATE_CONFIGURED) {
        printf("VmManager ERROR: Slot %d not configured or already running/error.\n", slot);
        return -5; // Not configured or wrong state
    }
    int result = -1;
    if (slot == 0) result = control_slot0_start_guest();
    else if (slot == 1) result = control_slot1_start_guest();
    else { printf("VmManager ERROR: Slot %d not dispatchable.\n", slot); return -3; }

    if (result == 0) vm_slots[slot].state = VM_SLOT_STATE_RUNNING;
    else vm_slots[slot].state = VM_SLOT_STATE_ERROR;
    return result;
}

int vm_management_iface_stop_vm_in_slot_impl(int slot) {
    printf("VmManager: stop_vm_in_slot_impl for Slot: %d\n", slot);
    if (slot < 0 || slot >= MAX_VM_SLOTS) return -1;
    if (vm_slots[slot].state != VM_SLOT_STATE_RUNNING && vm_slots[slot].state != VM_SLOT_STATE_CONFIGURED) {
         printf("VmManager WARNING: Slot %d not running or configured. State: %d\n", slot, vm_slots[slot].state);
    }
    int result = -1;
    if (slot == 0) result = control_slot0_stop_guest();
    else if (slot == 1) result = control_slot1_stop_guest();
    else { printf("VmManager ERROR: Slot %d not dispatchable.\n", slot); return -3; }

    // Even if stop fails, we mark as configured. GuestVmm might be stuck.
    // Force stop might be needed.
    if (vm_slots[slot].state != VM_SLOT_STATE_ERROR) { // Don't overwrite ERROR state
       vm_slots[slot].state = VM_SLOT_STATE_CONFIGURED;
    }
    return result;
}

int vm_management_iface_force_stop_vm_in_slot_impl(int slot) {
    printf("VmManager: force_stop_vm_in_slot_impl for Slot: %d\n", slot);
    if (slot < 0 || slot >= MAX_VM_SLOTS) return -1;
    int result = -1;
    if (slot == 0) result = control_slot0_force_stop_guest();
    else if (slot == 1) result = control_slot1_force_stop_guest();
    else { printf("VmManager ERROR: Slot %d not dispatchable.\n", slot); return -3; }

    if (vm_slots[slot].state != VM_SLOT_STATE_ERROR) {
       vm_slots[slot].state = VM_SLOT_STATE_CONFIGURED;
    }
    return result;
}

int vm_management_iface_delete_vm_from_slot_impl(int slot) {
    printf("VmManager: delete_vm_from_slot_impl for Slot: %d\n", slot);
    if (slot < 0 || slot >= MAX_VM_SLOTS) {
        printf("VmManager ERROR: Invalid slot %d for delete_vm.\n", slot);
        return -1;
    }
    if (vm_slots[slot].state == VM_SLOT_STATE_RUNNING) {
        printf("VmManager ERROR: VM in slot %d is still running. Stop it first.\n", slot);
        return -6; // Still running
    }
    // Conceptually, this would tell GuestVmm to release resources if it held any
    // beyond the RPC call scope. For now, VmManager just resets its state.
    vm_slots[slot].state = VM_SLOT_STATE_EMPTY;
    vm_slots[slot].profile_name[0] = '\0';
    vm_slots[slot].instance_name[0] = '\0';
    printf("VmManager: Slot %d has been marked as EMPTY.\n", slot);
    return 0;
}

int vm_management_iface_list_vms_impl(String *status_str_out) {
    if (status_str_out == NULL) return -1;

    char temp_buf[1024]; // Max size for the status string
    temp_buf[0] = '\0';
    int offset = 0;

    offset += snprintf(temp_buf + offset, sizeof(temp_buf) - offset, "VM Slots Status:\n");
    for (int i = 0; i < MAX_VM_SLOTS; i++) {
        const char* state_str = "UNKNOWN";
        switch(vm_slots[i].state) {
            case VM_SLOT_STATE_EMPTY: state_str = "EMPTY"; break;
            case VM_SLOT_STATE_CONFIGURED: state_str = "CONFIGURED"; break;
            case VM_SLOT_STATE_RUNNING: state_str = "RUNNING"; break;
            case VM_SLOT_STATE_ERROR: state_str = "ERROR"; break;
        }
        offset += snprintf(temp_buf + offset, sizeof(temp_buf) - offset,
                           "  Slot %d: %s (Profile: %s, Instance: %s)\n",
                           i, state_str,
                           vm_slots[i].profile_name[0] ? vm_slots[i].profile_name : "N/A",
                           vm_slots[i].instance_name[0] ? vm_slots[i].instance_name : "N/A");
        if (offset >= sizeof(temp_buf) - 200) { // Check if nearing buffer limit
             snprintf(temp_buf + offset, sizeof(temp_buf) - offset, "...\n(output truncated)\n");
             break;
        }
    }

    // CAmkES String type is typically char*. We need to allocate memory for it.
    // The caller of this IDL method is responsible for freeing it.
    // For simplicity in CAmkES, often fixed-size buffers are used or specific allocators.
    // Here, we'll assume the IDL layer handles copying from a provided buffer or this needs
    // a specific CAmkES string allocation mechanism.
    // A common pattern is for the IDL to expect `status_str_out` to be a sufficiently sized buffer.
    // Let's assume `String` is `char*` and the interface declares it as `out String`.
    // The CAmkES marshalling might involve allocating. If it's a fixed buffer:
    // strncpy(*status_str_out, temp_buf, MAX_STRING_LEN-1); (*status_str_out)[MAX_STRING_LEN-1] = '\0';
    // For now, let's print it and if `status_str_out` is `char**`, allocate.
    // Assuming `String` is `char *` and it's an out parameter that CAmkES expects us to fill.
    // A simple approach for non-allocating `String`: if it's `char status_str_out[MAX_LEN]`.
    // If `String *status_str_out` means `char ** status_str_out_ptr`, then:
    // *status_str_out = strdup(temp_buf); // Requires free by caller

    printf("%s", temp_buf); // Print to VmManager's console as well

    // This is a placeholder if String is char status_str_out[SOME_SIZE] in IDL.
    // If String is char **, then allocation (e.g. strdup) is needed.
    // For now, assuming the first argument is a buffer of sufficient size.
    if (strlen(temp_buf) + 1 > sizeof(String)) { // String is likely typedef char String[]
         strncpy((char*)status_str_out, temp_buf, sizeof(String) -1);
         ((char*)status_str_out)[sizeof(String)-1] = '\0';
         printf("VmManager WARNING: list_vms output truncated for IDL return.\n");
    } else {
         strcpy((char*)status_str_out, temp_buf);
    }
    return 0;
}


// --- CAmkES Component Entry Point ---
int run(void) {
    printf("VmManager CAmkES component starting. Initializing interactive menu...\n");

    // Initialize VM slots state
    for (int i = 0; i < MAX_VM_SLOTS; i++) {
        vm_slots[i].state = VM_SLOT_STATE_EMPTY;
        vm_slots[i].profile_name[0] = '\0';
        vm_slots[i].instance_name[0] = '\0';
    }

    // If VmManager uses a serial port for getchar, it needs to be configured.
    // E.g., in VmManager.camkes: `uses Serial serial_getchar_intf;`
    // And then `serial_getchar_intf_getchar()` would be called in VmManager_gets.
    // For now, `getchar()` is a placeholder.

    char choice_buf[128];
    int choice_num;

    while (1) {
        printf("\n--- VmManager Menu ---\n");
        printf("Profiles:\n");
        for (int i = 0; i < num_predefined_vm_profiles; i++) {
            printf("  %d. Launch Profile: %s (%s, %lluMB RAM, %u VCPU(s))\n",
                   i + 1, predefined_vm_profiles[i].name, predefined_vm_profiles[i].os_type,
                   predefined_vm_profiles[i].ram_mb, predefined_vm_profiles[i].num_vcpus);
        }
        printf("\nActions:\n");
        printf("  L. List VMs and Slots\n");
        printf("  S. Stop a VM (by Slot ID)\n");
        printf("  F. Force Stop a VM (by Slot ID)\n");
        printf("  D. Delete/Free VM Slot (by Slot ID)\n");
        printf("Enter your choice: ");

        if (VmManager_gets(choice_buf, sizeof(choice_buf)) == NULL) {
            printf("VmManager ERROR: Failed to read input. Exiting menu loop (this shouldn't happen).\n");
            break;
        }

        if (strlen(choice_buf) == 0) continue; // Empty input

        choice_num = atoi(choice_buf);

        if (choice_num > 0 && choice_num <= num_predefined_vm_profiles) {
            // Launch profile
            int profile_idx = choice_num - 1;
            int available_slot = -1;
            for (int i = 0; i < MAX_VM_SLOTS; i++) {
                if (vm_slots[i].state == VM_SLOT_STATE_EMPTY) {
                    available_slot = i;
                    break;
                }
            }
            if (available_slot != -1) {
                char instance_name_buf[64];
                snprintf(instance_name_buf, sizeof(instance_name_buf), "%s_Slot%d", predefined_vm_profiles[profile_idx].name, available_slot);
                printf("VmManager: Attempting to launch profile '%s' in slot %d as '%s'...\n",
                       predefined_vm_profiles[profile_idx].name, available_slot, instance_name_buf);
                int create_res = vm_management_iface_create_vm_in_slot_from_profile_impl(available_slot, predefined_vm_profiles[profile_idx].name, instance_name_buf);
                if (create_res == 0) {
                    int start_res = vm_management_iface_start_vm_in_slot_impl(available_slot);
                    if (start_res == 0) printf("VmManager: VM in slot %d started successfully.\n", available_slot);
                    else printf("VmManager ERROR: Failed to start VM in slot %d (result: %d).\n", available_slot, start_res);
                } else {
                     printf("VmManager ERROR: Failed to create/configure VM in slot %d (result: %d).\n", available_slot, create_res);
                }
            } else {
                printf("VmManager INFO: No empty slots available to launch profile '%s'.\n", predefined_vm_profiles[profile_idx].name);
            }
        } else if (choice_buf[0] == 'L' || choice_buf[0] == 'l') {
            // Assuming String is `char result_str_buf[1024];` or similar fixed buffer on stack for IDL out param.
            // This needs to align with the IDL definition of `String`.
            char list_status_buffer[1024] = {0}; // Buffer for the out String
            String list_status_idl_arg = (String)list_status_buffer; // Cast to IDL String type
            vm_management_iface_list_vms_impl(&list_status_idl_arg);
            // The list_vms_impl already prints, but if it solely returned string:
            // printf("%s\n", list_status_buffer);
        } else if (choice_buf[0] == 'S' || choice_buf[0] == 's' ||
                   choice_buf[0] == 'F' || choice_buf[0] == 'f' ||
                   choice_buf[0] == 'D' || choice_buf[0] == 'd') {
            printf("Enter Slot ID (0 to %d): ", MAX_VM_SLOTS - 1);
            if (VmManager_gets(choice_buf, sizeof(choice_buf)) != NULL && strlen(choice_buf) > 0) {
                int slot_id_action = atoi(choice_buf);
                if (slot_id_action >= 0 && slot_id_action < MAX_VM_SLOTS) {
                    if (choice_buf[0] == 'S' || choice_buf[0] == 's') vm_management_iface_stop_vm_in_slot_impl(slot_id_action);
                    else if (choice_buf[0] == 'F' || choice_buf[0] == 'f') vm_management_iface_force_stop_vm_in_slot_impl(slot_id_action);
                    else if (choice_buf[0] == 'D' || choice_buf[0] == 'd') vm_management_iface_delete_vm_from_slot_impl(slot_id_action);
                } else {
                    printf("VmManager ERROR: Invalid Slot ID entered: %s\n", choice_buf);
                }
            } else {
                 printf("VmManager ERROR: Failed to read Slot ID.\n");
            }
        } else {
            printf("VmManager ERROR: Invalid choice '%s'.\n", choice_buf);
        }
        printf("Press ENTER to continue...");
        VmManager_gets(choice_buf, sizeof(choice_buf)); // Simple pause
    }
    return 0;
}
