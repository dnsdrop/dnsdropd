add_library(ddrop_dnsJSON     SHARED json.c)
add_library(ddrop_dnsSHIM     SHARED shim.c)
add_library(ddrop_dnsD        SHARED dnsd.c)
add_library(ddrop_dnsResolver SHARED resolver.c)
add_library(ddrop_dnsSniff    SHARED sniff.c)

add_library(ddrop_dns SHARED json.c dnsd.c resolver.c sniff.c)
target_link_libraries(ddrop_dns PRIVATE pcap ldns event)
