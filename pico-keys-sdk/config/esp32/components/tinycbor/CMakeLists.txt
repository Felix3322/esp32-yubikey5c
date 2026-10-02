set(PICO_KEYS_SDK_DIR ${CMAKE_CURRENT_LIST_DIR}/../../../..)
idf_component_register(
    SRCS ${CBOR_SOURCES}
    INCLUDE_DIRS ${PICO_KEYS_SDK_DIR}/tinycbor/src
)
idf_component_set_property(${COMPONENT_NAME} WHOLE_ARCHIVE ON)
# CTAP messages nest at most ~6 levels; a low limit keeps hostile deeply
# nested CBOR from exhausting the card thread stack in cbor_value_advance().
target_compile_definitions(${COMPONENT_LIB} PRIVATE CBOR_PARSER_MAX_RECURSIONS=16)
