add_custom_target     (examples)

set (DNS_TYPE_LIBS
    ddrop_dnsJSON
    lz_json
    lz_core
    ldns
    ${OPENSSL_LIBRARIES})

add_executable        (example_lzjson EXCLUDE_FROM_ALL example_lzjson.c)
target_link_libraries (example_lzjson lz_json lz_core)

add_executable        (example_dns_to_json EXCLUDE_FROM_ALL example_dns_to_json.c)
target_link_libraries (example_dns_to_json ${DNS_TYPE_LIBS})

add_executable        (example_json_to_dns EXCLUDE_FROM_ALL example_json_to_dns.c)
target_link_libraries (example_json_to_dns ${DNS_TYPE_LIBS})

add_executable        (example_dns_shim    EXCLUDE_FROM_ALL example_dns_shim.c)
target_link_libraries (example_dns_shim    event ddrop_dnsSHIM ddrop_socket ${DNS_TYPE_LIBS})

add_executable        (example_dnsd        EXCLUDE_FROM_ALL example_dnsd.c)
target_link_libraries (example_dnsd        event ddrop_dnsD    ddrop_socket ${DNS_TYPE_LIBS})

add_executable        (example_dnsd_proxy  EXCLUDE_FROM_ALL example_dnsd_proxy.c)
target_link_libraries (example_dnsd_proxy
    ddrop_dnsJSON
    lz_json
    lz_core
    ddrop_dnsResolver
    ddrop_dnsD
    ddrop_socket
    ldns
    evhtp
    event
    event_pthreads
    pthread
    ${OPENSSL_LIBRARIES})

add_executable        (example_dns_sniff   EXCLUDE_FROM_ALL example_dns_sniff.c)
target_link_libraries (example_dns_sniff
    lz_json
    lz_core
    ddrop_dnsSniff
    ldns
    event
    pcap
    ${OPENSSL_LIBRARIES})

add_executable        (example_https_query EXCLUDE_FROM_ALL example_https_query.c)
target_link_libraries (example_https_query
    ${DNS_TYPE_LIBS}
    evhtp
    event
    event_openssl
    pthread
    ldns
    ${OPENSSL_LIBRARIES})

include(FindSetcap)
add_custom_command(TARGET example_dnsd_proxy POST_BUILD
    COMMAND
    sudo ${SETCAP_EXECUTABLE}
    "cap_net_raw+ep cap_net_bind_service+ep"
    ${PROJECT_BINARY_DIR}/bin/example_dnsd_proxy)

add_custom_command(TARGET example_dnsd POST_BUILD
    COMMAND
    sudo ${SETCAP_EXECUTABLE}
    "cap_net_raw+ep cap_net_bind_service+ep"
    ${PROJECT_BINARY_DIR}/bin/example_dnsd)

add_custom_command(TARGET example_dns_sniff POST_BUILD
    COMMAND
    sudo ${SETCAP_EXECUTABLE}
    "cap_net_raw,cap_net_admin=eip"
    ${PROJECT_BINARY_DIR}/bin/example_dns_sniff)


add_executable        (example_resolver    EXCLUDE_FROM_ALL example_resolver.c)
target_link_libraries (example_resolver    ddrop_dnsResolver evhtp event event_pthreads ${DNS_TYPE_LIBS} pthread)

add_dependencies      (examples
                       example_lzjson
                       example_dns_to_json
                       example_json_to_dns
                       example_dns_shim
                       example_dnsd
                       example_dnsd_proxy
                       example_resolver
                       example_https_query
                       example_dns_sniff AppDependencies)
