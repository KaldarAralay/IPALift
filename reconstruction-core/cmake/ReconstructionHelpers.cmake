include_guard(GLOBAL)
include(CMakeParseArguments)

function(reconstruction_enable_warnings target)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4 /permissive-)
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
  endif()
endfunction()


function(reconstruction_stage_assets)
  set(one_value TARGET SOURCE_ROOT OUTPUT_ROOT MANIFEST PROVENANCE)
  set(multi_value FILES)
  cmake_parse_arguments(ARG "" "${one_value}" "${multi_value}" ${ARGN})
  foreach(required TARGET SOURCE_ROOT PROVENANCE)
    if(NOT ARG_${required})
      message(FATAL_ERROR "reconstruction_stage_assets requires ${required}")
    endif()
  endforeach()
  if(NOT ARG_FILES)
    message(FATAL_ERROR "reconstruction_stage_assets requires FILES")
  endif()
  if(NOT ARG_OUTPUT_ROOT)
    set(ARG_OUTPUT_ROOT "$<TARGET_FILE_DIR:${ARG_TARGET}>/assets")
  endif()
  if(NOT ARG_MANIFEST)
    set(ARG_MANIFEST "${ARG_OUTPUT_ROOT}/conversion-manifest.json")
  endif()
  set(normalizer "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/../tools/normalize_png.py")
  set_property(TARGET ${ARG_TARGET} APPEND PROPERTY LINK_DEPENDS "${normalizer}")
  foreach(asset IN LISTS ARG_FILES)
    set_property(TARGET ${ARG_TARGET} APPEND PROPERTY LINK_DEPENDS
      "${ARG_SOURCE_ROOT}/${asset}")
  endforeach()
  add_custom_command(TARGET ${ARG_TARGET} POST_BUILD
    COMMAND ${Python3_EXECUTABLE}
            "${normalizer}"
            --source-root "${ARG_SOURCE_ROOT}"
            --output-root "${ARG_OUTPUT_ROOT}"
            --manifest "${ARG_MANIFEST}"
            --provenance "${ARG_PROVENANCE}"
            ${ARG_FILES}
    VERBATIM
  )
endfunction()

function(reconstruction_stage_directory)
  set(one_value TARGET SOURCE DESTINATION)
  cmake_parse_arguments(ARG "" "${one_value}" "" ${ARGN})
  foreach(required TARGET SOURCE DESTINATION)
    if(NOT ARG_${required})
      message(FATAL_ERROR "reconstruction_stage_directory requires ${required}")
    endif()
  endforeach()
  add_custom_command(TARGET ${ARG_TARGET} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory "${ARG_SOURCE}" "${ARG_DESTINATION}"
    VERBATIM
  )
endfunction()
