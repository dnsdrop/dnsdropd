add_executable        (ddrop-http-resolvr ddrop-http-resolvr.c)
add_dependencies      (ddrop-http-resolvr AppDependencies)
target_link_libraries (ddrop-http-resolvr
    ddrop_dnsJSON
    ddrop_dnsResolver
    ddrop_dnsRBL
    lz_json
    lz_core
    ldns
    evhtp
    event
    event_pthreads
    event_openssl
    pthread
    z
    ${OPENSSL_LIBRARIES})


add_executable        (ddrop-dns-query2j ddrop-dns-query2j.c)
add_dependencies      (ddrop-dns-query2j AppDependencies)

target_link_libraries (ddrop-dns-query2j
    ddrop_dnsJSON
    lz_json
    lz_core
    ldns)


add_executable(ddrop-dns-forwarder ddrop-dns-forwarder.c)
target_link_libraries(ddrop-dns-forwarder
    ddrop_dnsResolver
    ddrop_dnsD
    ddrop_socket
    ddrop_dnsJSON
    lz_json
    lz_core
    ldns
    evhtp
    event
    event_pthreads
    pthread
    ${OPENSSL_LIBRARIES})

add_executable(ddrop-dns-sniffer ddrop-dns-sniffer.c)
target_link_libraries(ddrop-dns-sniffer
    lz_json
    lz_core
    ddrop_dnsJSON
    ddrop_dnsSniff
    ldns
    event
    pcap)

include(FindSetcap)

add_custom_command(TARGET ddrop-dns-forwarder POST_BUILD
    POST_BUILD
    COMMAND
    sudo ${SETCAP_EXECUTABLE}
    "cap_net_raw+ep cap_net_bind_service+ep"
    ${PROJECT_BINARY_DIR}/bin/ddrop-dns-forwarder)


