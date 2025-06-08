# CMakeLists.txt for the LinuxVMM CAmkES Application (linux_vm_app)

cmake_minimum_required(VERSION 3.10) # Or a version appropriate for your CAmkES

project(LinuxVmApp C)

# Find the CAmkES package. This provides CAmkES CMake functions.
# The CAmkES environment should set CMAKE_MODULE_PATH or CAmkES_DIR for this to work.
find_package(CAmkES REQUIRED)

# Define the CAmkES application target.
# The name "linux_vm_app" will be the name of the final executable.
camkes_add_application(linux_vm_app
    # List all CAmkES language source files for the application.
    # This includes the top-level assembly and any imported component definitions.
    SOURCES
        linux_vm_app.camkes      # The main application assembly
        LinuxVMM.camkes          # The VMM component definition
        # Add other imported .camkes files if they are not in standard component paths, e.g.:
        # path/to/MyOtherComponent.camkes

    # C source files for components are typically found automatically if they are
    # in the same directory as the .camkes file and have the same basename.
    # If not, or if you have additional C files for a component, list them:
    # COMPONENT_SOURCES
    #   LinuxVMM LinuxVMM.c
    #   MyOtherComponent path/to/MyOtherComponent.c path/to/another_source.c

    # Specify dependencies on pre-built CAmkES components/libraries if not automatic.
    # Standard components like Timer and Serial are often part of the platform
    # and might not need to be explicitly listed here, but it depends on the CAmkES setup.
    # COMPONENTS Timer Serial # Example if explicit linking is needed
)

# --- Define ELF Segments for Guest Binaries ---
# These commands make binary files available as data segments in the ELF image
# of the CAmkES application. The symbols ("embedded_linux_kernel", "embedded_linux_initrd")
# are then used in the linux_vm_app.camkes configuration block to link these
# segments to the VMM's dataports.

# The path to the binary files is relative to this CMakeLists.txt file,
# or you can use absolute paths or other CMake path variables.
# Assume 'binaries/' is a subdirectory next to this CMakeLists.txt.
set(LINUX_KERNEL_BIN_PATH "${CMAKE_CURRENT_SOURCE_DIR}/binaries/linux-kernel.bin" CACHE FILEPATH "Path to Linux kernel binary")
set(LINUX_INITRD_BIN_PATH "${CMAKE_CURRENT_SOURCE_DIR}/binaries/linux-initrd.cpio" CACHE FILEPATH "Path to Linux initrd CPIO")

if(NOT EXISTS ${LINUX_KERNEL_BIN_PATH})
    message(FATAL_ERROR "Linux kernel binary not found at: ${LINUX_KERNEL_BIN_PATH}\nPlease set LINUX_KERNEL_BIN_PATH.")
endif()
if(NOT EXISTS ${LINUX_INITRD_BIN_PATH})
    message(FATAL_ERROR "Linux initrd binary not found at: ${LINUX_INITRD_BIN_PATH}\nPlease set LINUX_INITRD_BIN_PATH.")
endif()

# This function declares that the content of the specified file should be embedded
# into an ELF segment with the given symbolic name.
camkes_add_elf_segment_source(embedded_linux_kernel ${LINUX_KERNEL_BIN_PATH})
camkes_add_elf_segment_source(embedded_linux_initrd ${LINUX_INITRD_BIN_PATH})

# Associate these ELF segment sources with your CAmkES application target.
# This step ensures they are linked into the 'linux_vm_app' executable.
# The exact command might vary slightly based on CAmkES versions or if using
# older CAmkES CMake APIs (e.g., target_link_libraries or CAmkESAddObjects).
# With modern CAmkES, `camkes_add_elf_segment_source` might automatically handle
# the linking to all CAmkES applications in the project, or you might need:
# target_link_libraries(linux_vm_app PRIVATE embedded_linux_kernel embedded_linux_initrd)
# However, often just declaring them is enough if the build system is set up for it.
# For clarity and robustness, explicitly linking them to the target is good if available/needed.
# The CAmkES build system usually processes these sources and makes the symbols
# (e.g., `_binary_embedded_linux_kernel_start`, `_binary_embedded_linux_kernel_end`)
# available for the dataport population mechanism specified by `elf_segment` attributes.

# If your CAmkES project uses a different way to link these (e.g. through properties
# on the target or a different function), adapt accordingly.
# Example using a property (less common for this specific use case now):
# set_property(TARGET linux_vm_app APPEND PROPERTY CAMKES_ELF_SEGMENTS embedded_linux_kernel)
# set_property(TARGET linux_vm_app APPEND PROPERTY CAMKES_ELF_SEGMENTS embedded_linux_initrd)


# Include general CAmkES rules and configurations.
# This typically sets up include paths, links against CAmkES libraries, etc.
# The exact include might vary (e.g., CAmkESKernelMacros, CAmkESProject).
# CAmkESGeneral is a common one.
include(CAmkESGeneral)

# Add other application-specific CMake configurations, include directories,
# or library links if needed.
# target_include_directories(linux_vm_app PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
# target_link_libraries(linux_vm_app PRIVATE some_other_lib)
