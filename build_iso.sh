#!/usr/bin/env bash
set -e

# Configuration
PROJECT_ROOT="." # Assuming script is run from project root
PQ_UEFI_LOADER_SRC_DIR="${PROJECT_ROOT}/PqUefiLoader" # Source for UEFI app
SEL4_CAMKES_APP_SRC_DIR="${PROJECT_ROOT}/Sel4CamkesApp" # Source for seL4/CAmkES app

# Output directories for simulated builds
PQ_UEFI_LOADER_BUILD_DIR="${PROJECT_ROOT}/PqUefiLoader_output"
SEL4_CAMKES_APP_BUILD_DIR="${PROJECT_ROOT}/Sel4Camkes_output"

ISO_STAGING_DIR="${PROJECT_ROOT}/iso_staging"
FINAL_ISO_NAME="PqBootable.iso"
FINAL_ISO_PATH="${PROJECT_ROOT}/${FINAL_ISO_NAME}"
ISO_VOLID="PQBOOT_CD"

# Simulated UEFI Loader output file (relative to its build dir)
UEFI_LOADER_EFI_NAME="PqUefiLoader.efi"

# Simulated seL4/CAmkES app output files (relative to its build dir)
KERNEL_BIN_NAME="PqKernelLoader.bin"
PAYLOAD_BIN_NAME="PqPayload.bin"
KERNEL_SIG_NAME="${KERNEL_BIN_NAME}.sig"
PAYLOAD_SIG_NAME="${PAYLOAD_BIN_NAME}.sig"


# --- Simulated Build Functions ---

build_pq_uefi_loader() {
    echo ">>> Simulating: Building PqUefiLoader UEFI Application..."
    echo "    Source directory: ${PQ_UEFI_LOADER_SRC_DIR}"
    echo "    Output directory: ${PQ_UEFI_LOADER_BUILD_DIR}"
    mkdir -p "${PQ_UEFI_LOADER_BUILD_DIR}"
    touch "${PQ_UEFI_LOADER_BUILD_DIR}/${UEFI_LOADER_EFI_NAME}"
    echo "--- PqUefiLoader build complete (simulated)."
}

build_sel4_camkes_app() {
    echo ">>> Simulating: Building seL4/CAmkES Application (Kernel & Payload)..."
    echo "    Source directory: ${SEL4_CAMKES_APP_SRC_DIR}"
    echo "    Output directory: ${SEL4_CAMKES_APP_BUILD_DIR}"
    mkdir -p "${SEL4_CAMKES_APP_BUILD_DIR}"
    touch "${SEL4_CAMKES_APP_BUILD_DIR}/${KERNEL_BIN_NAME}"
    touch "${SEL4_CAMKES_APP_BUILD_DIR}/${PAYLOAD_BIN_NAME}"
    echo "--- seL4/CAmkES application build complete (simulated)."
    # Note: In a real scenario, CAmkES build system would also embed guest OS images (Linux kernel, initrd, Windows/macOS disk images)
    # into the VMM component (e.g., GuestVmm) as ELF segments. These are not directly copied to the ISO staging by this script,
    # but are part of the 'PqPayload.bin' or loaded via other mechanisms by PqKernelLoader.
}

sign_sel4_artifacts() {
    echo ">>> Simulating: Signing seL4/CAmkES artifacts..."
    echo "    Input files: ${SEL4_CAMKES_APP_BUILD_DIR}/${KERNEL_BIN_NAME}, ${SEL4_CAMKES_APP_BUILD_DIR}/${PAYLOAD_BIN_NAME}"
    echo "    Output signature files (simulated)"
    touch "${SEL4_CAMKES_APP_BUILD_DIR}/${KERNEL_SIG_NAME}"
    touch "${SEL4_CAMKES_APP_BUILD_DIR}/${PAYLOAD_SIG_NAME}"
    echo "--- Artifact signing complete (simulated)."
}

# --- ISO Preparation Functions ---

prepare_iso_staging() {
    echo ">>> Preparing ISO staging directory: ${ISO_STAGING_DIR}"
    rm -rf "${ISO_STAGING_DIR}"
    mkdir -p "${ISO_STAGING_DIR}/EFI/BOOT"
    mkdir -p "${ISO_STAGING_DIR}/boot" # For kernel, payload, and signatures

    echo "    Copying UEFI loader to EFI/BOOT/BOOTX64.EFI..."
    cp "${PQ_UEFI_LOADER_BUILD_DIR}/${UEFI_LOADER_EFI_NAME}" "${ISO_STAGING_DIR}/EFI/BOOT/BOOTX64.EFI"

    echo "    Copying Kernel, Payload, and Signatures to /boot/ ..."
    cp "${SEL4_CAMKES_APP_BUILD_DIR}/${KERNEL_BIN_NAME}" "${ISO_STAGING_DIR}/boot/"
    cp "${SEL4_CAMKES_APP_BUILD_DIR}/${PAYLOAD_BIN_NAME}" "${ISO_STAGING_DIR}/boot/"
    cp "${SEL4_CAMKES_APP_BUILD_DIR}/${KERNEL_SIG_NAME}" "${ISO_STAGING_DIR}/boot/"
    cp "${SEL4_CAMKES_APP_BUILD_DIR}/${PAYLOAD_SIG_NAME}" "${ISO_STAGING_DIR}/boot/"

    # Guest OS media (e.g., OpenCore ISO, Linux ISO, Windows ISO for installation by GuestVmm)
    # would typically be embedded within the CAmkES VMM component (PqPayload.bin)
    # or provided via a separate mechanism if too large for the initial boot payload.
    # If they needed to be on the boot ISO directly (less common for this VMM architecture):
    # mkdir -p "${ISO_STAGING_DIR}/guest_media"
    # cp path/to/opencore.iso "${ISO_STAGING_DIR}/guest_media/"
    # cp path/to/linux_install.iso "${ISO_STAGING_DIR}/guest_media/"
    echo "    (Skipping direct copy of guest OS media to ISO staging - assumed embedded in VMM or handled separately)"

    echo "--- ISO staging directory prepared."
}

create_bootable_iso() {
    echo ">>> Creating bootable ISO image: ${FINAL_ISO_PATH}"
    echo "    Volume ID: ${ISO_VOLID}"
    echo "    Staging directory: ${ISO_STAGING_DIR}"

    # Actual xorriso command (commented out for simulation)
    # xorriso -as mkisofs \
    #     -r -V "${ISO_VOLID}" \
    #     -o "${FINAL_ISO_PATH}" \
    #     -J -joliet-long \
    #     -isohybrid-mbr --interval:local_fs:0s-0s:: \
    #     -partition_cyl_align off \
    #     -efi-boot-part --efi-boot-image \
    #     -efi-boot EFI/BOOT/BOOTX64.EFI \
    #     "${ISO_STAGING_DIR}"

    # Simulate ISO creation
    touch "${FINAL_ISO_PATH}"
    echo "--- Bootable ISO image created (simulated): ${FINAL_ISO_PATH}"
}

# --- Main Script Logic ---
echo "=== Starting ISO Build Process ==="

build_pq_uefi_loader
build_sel4_camkes_app
sign_sel4_artifacts
prepare_iso_staging
create_bootable_iso

echo "=== ISO Build Process Finished Successfully ==="
echo "Final ISO (simulated): ${FINAL_ISO_PATH}"
echo "Staging Area: ${ISO_STAGING_DIR}"
echo "Done."
