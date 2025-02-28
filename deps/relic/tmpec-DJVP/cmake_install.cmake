# Install script for directory: /home/ubuntu/testbed/openabe/deps/relic/relic-toolkit-0.5.0

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/home/ubuntu/testbed/openabe/deps/root")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/relic_ec" TYPE FILE FILES
    "/home/ubuntu/testbed/openabe/deps/relic/relic-toolkit-0.5.0/include/relic.h"
    "/home/ubuntu/testbed/openabe/deps/relic/relic-toolkit-0.5.0/include/relic_arch.h"
    "/home/ubuntu/testbed/openabe/deps/relic/relic-toolkit-0.5.0/include/relic_bc.h"
    "/home/ubuntu/testbed/openabe/deps/relic/relic-toolkit-0.5.0/include/relic_bench.h"
    "/home/ubuntu/testbed/openabe/deps/relic/relic-toolkit-0.5.0/include/relic_bn.h"
    "/home/ubuntu/testbed/openabe/deps/relic/relic-toolkit-0.5.0/include/relic_core.h"
    "/home/ubuntu/testbed/openabe/deps/relic/relic-toolkit-0.5.0/include/relic_cp.h"
    "/home/ubuntu/testbed/openabe/deps/relic/relic-toolkit-0.5.0/include/relic_dv.h"
    "/home/ubuntu/testbed/openabe/deps/relic/relic-toolkit-0.5.0/include/relic_eb.h"
    "/home/ubuntu/testbed/openabe/deps/relic/relic-toolkit-0.5.0/include/relic_ec.h"
    "/home/ubuntu/testbed/openabe/deps/relic/relic-toolkit-0.5.0/include/relic_ed.h"
    "/home/ubuntu/testbed/openabe/deps/relic/relic-toolkit-0.5.0/include/relic_ep.h"
    "/home/ubuntu/testbed/openabe/deps/relic/relic-toolkit-0.5.0/include/relic_epx.h"
    "/home/ubuntu/testbed/openabe/deps/relic/relic-toolkit-0.5.0/include/relic_err.h"
    "/home/ubuntu/testbed/openabe/deps/relic/relic-toolkit-0.5.0/include/relic_fb.h"
    "/home/ubuntu/testbed/openabe/deps/relic/relic-toolkit-0.5.0/include/relic_fbx.h"
    "/home/ubuntu/testbed/openabe/deps/relic/relic-toolkit-0.5.0/include/relic_fp.h"
    "/home/ubuntu/testbed/openabe/deps/relic/relic-toolkit-0.5.0/include/relic_fpx.h"
    "/home/ubuntu/testbed/openabe/deps/relic/relic-toolkit-0.5.0/include/relic_label.h"
    "/home/ubuntu/testbed/openabe/deps/relic/relic-toolkit-0.5.0/include/relic_md.h"
    "/home/ubuntu/testbed/openabe/deps/relic/relic-toolkit-0.5.0/include/relic_pc.h"
    "/home/ubuntu/testbed/openabe/deps/relic/relic-toolkit-0.5.0/include/relic_pp.h"
    "/home/ubuntu/testbed/openabe/deps/relic/relic-toolkit-0.5.0/include/relic_rand.h"
    "/home/ubuntu/testbed/openabe/deps/relic/relic-toolkit-0.5.0/include/relic_test.h"
    "/home/ubuntu/testbed/openabe/deps/relic/relic-toolkit-0.5.0/include/relic_trace.h"
    "/home/ubuntu/testbed/openabe/deps/relic/relic-toolkit-0.5.0/include/relic_types.h"
    "/home/ubuntu/testbed/openabe/deps/relic/relic-toolkit-0.5.0/include/relic_util.h"
    )
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/relic_ec/low" TYPE FILE FILES
    "/home/ubuntu/testbed/openabe/deps/relic/relic-toolkit-0.5.0/include/low/relic_bn_low.h"
    "/home/ubuntu/testbed/openabe/deps/relic/relic-toolkit-0.5.0/include/low/relic_dv_low.h"
    "/home/ubuntu/testbed/openabe/deps/relic/relic-toolkit-0.5.0/include/low/relic_fb_low.h"
    "/home/ubuntu/testbed/openabe/deps/relic/relic-toolkit-0.5.0/include/low/relic_fp_low.h"
    "/home/ubuntu/testbed/openabe/deps/relic/relic-toolkit-0.5.0/include/low/relic_fpx_low.h"
    )
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/relic_ec" TYPE DIRECTORY FILES "/home/ubuntu/testbed/openabe/deps/relic/tmpec-DJVP/include/")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/cmake" TYPE FILE FILES "/home/ubuntu/testbed/openabe/deps/relic/relic-toolkit-0.5.0/cmake/relic-config.cmake")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for each subdirectory.
  include("/home/ubuntu/testbed/openabe/deps/relic/tmpec-DJVP/src/cmake_install.cmake")

endif()

if(CMAKE_INSTALL_COMPONENT)
  set(CMAKE_INSTALL_MANIFEST "install_manifest_${CMAKE_INSTALL_COMPONENT}.txt")
else()
  set(CMAKE_INSTALL_MANIFEST "install_manifest.txt")
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
file(WRITE "/home/ubuntu/testbed/openabe/deps/relic/tmpec-DJVP/${CMAKE_INSTALL_MANIFEST}"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
