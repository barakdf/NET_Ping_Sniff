# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

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
CMAKE_SOURCE_DIR = /mnt/c/Users/barak/Documents/GitHub/NET_Ping_Sniff

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /mnt/c/Users/barak/Documents/GitHub/NET_Ping_Sniff/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/NET_Ping_Sniff.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/NET_Ping_Sniff.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/NET_Ping_Sniff.dir/flags.make

CMakeFiles/NET_Ping_Sniff.dir/myPing.c.o: CMakeFiles/NET_Ping_Sniff.dir/flags.make
CMakeFiles/NET_Ping_Sniff.dir/myPing.c.o: ../myPing.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/c/Users/barak/Documents/GitHub/NET_Ping_Sniff/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/NET_Ping_Sniff.dir/myPing.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/NET_Ping_Sniff.dir/myPing.c.o   -c /mnt/c/Users/barak/Documents/GitHub/NET_Ping_Sniff/myPing.c

CMakeFiles/NET_Ping_Sniff.dir/myPing.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/NET_Ping_Sniff.dir/myPing.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /mnt/c/Users/barak/Documents/GitHub/NET_Ping_Sniff/myPing.c > CMakeFiles/NET_Ping_Sniff.dir/myPing.c.i

CMakeFiles/NET_Ping_Sniff.dir/myPing.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/NET_Ping_Sniff.dir/myPing.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /mnt/c/Users/barak/Documents/GitHub/NET_Ping_Sniff/myPing.c -o CMakeFiles/NET_Ping_Sniff.dir/myPing.c.s

CMakeFiles/NET_Ping_Sniff.dir/Sniffer.c.o: CMakeFiles/NET_Ping_Sniff.dir/flags.make
CMakeFiles/NET_Ping_Sniff.dir/Sniffer.c.o: ../Sniffer.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/c/Users/barak/Documents/GitHub/NET_Ping_Sniff/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/NET_Ping_Sniff.dir/Sniffer.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/NET_Ping_Sniff.dir/Sniffer.c.o   -c /mnt/c/Users/barak/Documents/GitHub/NET_Ping_Sniff/Sniffer.c

CMakeFiles/NET_Ping_Sniff.dir/Sniffer.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/NET_Ping_Sniff.dir/Sniffer.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /mnt/c/Users/barak/Documents/GitHub/NET_Ping_Sniff/Sniffer.c > CMakeFiles/NET_Ping_Sniff.dir/Sniffer.c.i

CMakeFiles/NET_Ping_Sniff.dir/Sniffer.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/NET_Ping_Sniff.dir/Sniffer.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /mnt/c/Users/barak/Documents/GitHub/NET_Ping_Sniff/Sniffer.c -o CMakeFiles/NET_Ping_Sniff.dir/Sniffer.c.s

# Object files for target NET_Ping_Sniff
NET_Ping_Sniff_OBJECTS = \
"CMakeFiles/NET_Ping_Sniff.dir/myPing.c.o" \
"CMakeFiles/NET_Ping_Sniff.dir/Sniffer.c.o"

# External object files for target NET_Ping_Sniff
NET_Ping_Sniff_EXTERNAL_OBJECTS =

NET_Ping_Sniff: CMakeFiles/NET_Ping_Sniff.dir/myPing.c.o
NET_Ping_Sniff: CMakeFiles/NET_Ping_Sniff.dir/Sniffer.c.o
NET_Ping_Sniff: CMakeFiles/NET_Ping_Sniff.dir/build.make
NET_Ping_Sniff: CMakeFiles/NET_Ping_Sniff.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/mnt/c/Users/barak/Documents/GitHub/NET_Ping_Sniff/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking C executable NET_Ping_Sniff"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/NET_Ping_Sniff.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/NET_Ping_Sniff.dir/build: NET_Ping_Sniff

.PHONY : CMakeFiles/NET_Ping_Sniff.dir/build

CMakeFiles/NET_Ping_Sniff.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/NET_Ping_Sniff.dir/cmake_clean.cmake
.PHONY : CMakeFiles/NET_Ping_Sniff.dir/clean

CMakeFiles/NET_Ping_Sniff.dir/depend:
	cd /mnt/c/Users/barak/Documents/GitHub/NET_Ping_Sniff/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /mnt/c/Users/barak/Documents/GitHub/NET_Ping_Sniff /mnt/c/Users/barak/Documents/GitHub/NET_Ping_Sniff /mnt/c/Users/barak/Documents/GitHub/NET_Ping_Sniff/cmake-build-debug /mnt/c/Users/barak/Documents/GitHub/NET_Ping_Sniff/cmake-build-debug /mnt/c/Users/barak/Documents/GitHub/NET_Ping_Sniff/cmake-build-debug/CMakeFiles/NET_Ping_Sniff.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/NET_Ping_Sniff.dir/depend

