# FindLibPCAP.cmake — locate libpcap headers and library
#
# Defines:
#   LibPCAP_FOUND
#   LibPCAP::LibPCAP  (imported target)

find_path(PCAP_INCLUDE_DIR
    NAMES pcap.h pcap/pcap.h
    PATHS /usr/include /usr/local/include
)

find_library(PCAP_LIBRARY
    NAMES pcap
    PATHS /usr/lib /usr/local/lib /usr/lib/x86_64-linux-gnu
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LibPCAP
    REQUIRED_VARS PCAP_LIBRARY PCAP_INCLUDE_DIR
)

if(LibPCAP_FOUND)
    set(LibPCAP_LIBRARIES    ${PCAP_LIBRARY})
    set(LibPCAP_INCLUDE_DIRS ${PCAP_INCLUDE_DIR})

    if(NOT TARGET LibPCAP::LibPCAP)
        add_library(LibPCAP::LibPCAP UNKNOWN IMPORTED)
        set_target_properties(LibPCAP::LibPCAP PROPERTIES
            IMPORTED_LOCATION             "${PCAP_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${PCAP_INCLUDE_DIR}"
        )
    endif()
endif()

mark_as_advanced(PCAP_INCLUDE_DIR PCAP_LIBRARY)
