# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.10

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/ubuntu/testbed/openabe/deps/relic/relic-toolkit-0.5.0

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/ubuntu/testbed/openabe/deps/relic/tmpbp-xpj5

# Include any dependencies generated for this target.
include test/CMakeFiles/test_pp.dir/depend.make

# Include the progress variables for this target.
include test/CMakeFiles/test_pp.dir/progress.make

# Include the compile flags for this target's objects.
include test/CMakeFiles/test_pp.dir/flags.make

test/CMakeFiles/test_pp.dir/test_pp.c.o: test/CMakeFiles/test_pp.dir/flags.make
test/CMakeFiles/test_pp.dir/test_pp.c.o: /home/ubuntu/testbed/openabe/deps/relic/relic-toolkit-0.5.0/test/test_pp.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/ubuntu/testbed/openabe/deps/relic/tmpbp-xpj5/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object test/CMakeFiles/test_pp.dir/test_pp.c.o"
	cd /home/ubuntu/testbed/openabe/deps/relic/tmpbp-xpj5/test && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/test_pp.dir/test_pp.c.o   -c /home/ubuntu/testbed/openabe/deps/relic/relic-toolkit-0.5.0/test/test_pp.c

test/CMakeFiles/test_pp.dir/test_pp.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/test_pp.dir/test_pp.c.i"
	cd /home/ubuntu/testbed/openabe/deps/relic/tmpbp-xpj5/test && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/ubuntu/testbed/openabe/deps/relic/relic-toolkit-0.5.0/test/test_pp.c > CMakeFiles/test_pp.dir/test_pp.c.i

test/CMakeFiles/test_pp.dir/test_pp.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/test_pp.dir/test_pp.c.s"
	cd /home/ubuntu/testbed/openabe/deps/relic/tmpbp-xpj5/test && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/ubuntu/testbed/openabe/deps/relic/relic-toolkit-0.5.0/test/test_pp.c -o CMakeFiles/test_pp.dir/test_pp.c.s

test/CMakeFiles/test_pp.dir/test_pp.c.o.requires:

.PHONY : test/CMakeFiles/test_pp.dir/test_pp.c.o.requires

test/CMakeFiles/test_pp.dir/test_pp.c.o.provides: test/CMakeFiles/test_pp.dir/test_pp.c.o.requires
	$(MAKE) -f test/CMakeFiles/test_pp.dir/build.make test/CMakeFiles/test_pp.dir/test_pp.c.o.provides.build
.PHONY : test/CMakeFiles/test_pp.dir/test_pp.c.o.provides

test/CMakeFiles/test_pp.dir/test_pp.c.o.provides.build: test/CMakeFiles/test_pp.dir/test_pp.c.o


# Object files for target test_pp
test_pp_OBJECTS = \
"CMakeFiles/test_pp.dir/test_pp.c.o"

# External object files for target test_pp
test_pp_EXTERNAL_OBJECTS =

bin/test_pp: test/CMakeFiles/test_pp.dir/test_pp.c.o
bin/test_pp: test/CMakeFiles/test_pp.dir/build.make
bin/test_pp: lib/librelic_s.a
bin/test_pp: /usr/lib/aarch64-linux-gnu/libgmp.so
bin/test_pp: test/CMakeFiles/test_pp.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/ubuntu/testbed/openabe/deps/relic/tmpbp-xpj5/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable ../bin/test_pp"
	cd /home/ubuntu/testbed/openabe/deps/relic/tmpbp-xpj5/test && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/test_pp.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
test/CMakeFiles/test_pp.dir/build: bin/test_pp

.PHONY : test/CMakeFiles/test_pp.dir/build

test/CMakeFiles/test_pp.dir/requires: test/CMakeFiles/test_pp.dir/test_pp.c.o.requires

.PHONY : test/CMakeFiles/test_pp.dir/requires

test/CMakeFiles/test_pp.dir/clean:
	cd /home/ubuntu/testbed/openabe/deps/relic/tmpbp-xpj5/test && $(CMAKE_COMMAND) -P CMakeFiles/test_pp.dir/cmake_clean.cmake
.PHONY : test/CMakeFiles/test_pp.dir/clean

test/CMakeFiles/test_pp.dir/depend:
	cd /home/ubuntu/testbed/openabe/deps/relic/tmpbp-xpj5 && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/ubuntu/testbed/openabe/deps/relic/relic-toolkit-0.5.0 /home/ubuntu/testbed/openabe/deps/relic/relic-toolkit-0.5.0/test /home/ubuntu/testbed/openabe/deps/relic/tmpbp-xpj5 /home/ubuntu/testbed/openabe/deps/relic/tmpbp-xpj5/test /home/ubuntu/testbed/openabe/deps/relic/tmpbp-xpj5/test/CMakeFiles/test_pp.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : test/CMakeFiles/test_pp.dir/depend

