set(CURRENT_LIST_DIR ${CMAKE_CURRENT_LIST_DIR})
if (NOT DEFINED pre_configure_dir)
	set(pre_configure_dir ${CMAKE_CURRENT_LIST_DIR})
endif ()

if (NOT DEFINED post_configure_dir)
	set(post_configure_dir ${CMAKE_BINARY_DIR}/generated)
endif ()

set(pre_configure_file ${pre_configure_dir}/git_version.cc.in)
set(post_configure_file ${post_configure_dir}/git_version.cc)

function(CheckGitWrite git_hash git_branch git_status)
	file(WRITE ${CMAKE_BINARY_DIR}/git-state.txt "${git_hash}\n${git_branch}\n${git_status}")
endfunction()

function(CheckGitRead git_hash git_branch git_status)
	if (EXISTS ${CMAKE_BINARY_DIR}/git-state.txt)
		file(STRINGS ${CMAKE_BINARY_DIR}/git-state.txt CONTENT)
		LIST(GET CONTENT 0 var1)
		LIST(GET CONTENT 1 var2)
		LIST(GET CONTENT 2 var3)
		set(${git_hash} ${var1} PARENT_SCOPE)
		set(${git_branch} ${var2} PARENT_SCOPE)
		set(${git_status} ${var3} PARENT_SCOPE)
	endif ()
endfunction()

function(CheckGitVersion)
	find_package(Git QUIET)
	if (GIT_FOUND)
		# Get the latest abbreviated commit hash of the working branch
		execute_process (
			COMMAND ${GIT_EXECUTABLE} log -1 --format=%h
			WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
			OUTPUT_VARIABLE GIT_HASH
			OUTPUT_STRIP_TRAILING_WHITESPACE
			ERROR_QUIET
		)
		execute_process(
			COMMAND ${GIT_EXECUTABLE} symbolic-ref --short -q HEAD
			WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
			OUTPUT_VARIABLE GIT_BRANCH
			OUTPUT_STRIP_TRAILING_WHITESPACE
			ERROR_QUIET
		)
		execute_process(
			COMMAND ${GIT_EXECUTABLE} status -s
			WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
			OUTPUT_VARIABLE GIT_STATUS
			OUTPUT_STRIP_TRAILING_WHITESPACE
			ERROR_QUIET
		)
		string(LENGTH "${GIT_HASH}" GIT_HASH_LENGTH)
		if (${GIT_HASH_LENGTH} EQUAL 0)
			set(GIT_HASH "<no>")
		endif ()
		string(LENGTH "${GIT_BRANCH}" GIT_BRANCH_LENGTH)
		if (${GIT_BRANCH_LENGTH} EQUAL 0)
			set(GIT_BRANCH "<no>")
		endif ()
		string(LENGTH "${GIT_STATUS}" GIT_STATUS_LENGTH)
		if (${GIT_STATUS_LENGTH} EQUAL 0)
			set(GIT_STATUS " ")
		else ()
			set(GIT_STATUS "*")
		endif ()
	else ()
		set(GIT_HASH ".")
		set(GIT_BRANCH ".")
		set(GIT_STATUS ".")
	endif ()

	CheckGitRead(GIT_HASH_CACHE GIT_BRANCH_CACHE GIT_STATUS_CACHE)

	if (NOT EXISTS ${post_configure_dir})
		file(MAKE_DIRECTORY ${post_configure_dir})
	endif ()

	if (NOT EXISTS ${post_configure_dir}/git_version.h)
		file(COPY ${pre_configure_dir}/git_version.h DESTINATION ${post_configure_dir})
	endif ()

	if (NOT DEFINED GIT_HASH_CACHE)
		set(GIT_HASH_CACHE "none")
	endif ()

	if (NOT DEFINED GIT_BRANCH_CACHE)
		set(GIT_BRANCH_CACHE "none")
	endif ()

	if (NOT DEFINED GIT_STATUS_CACHE)
		set(GIT_STATUS_CACHE "none")
	endif ()

	# Only update the git_version.cpp if the hash has changed. This will
	# prevent us from rebuilding the project more than we need to.
	if (
			(NOT ${GIT_HASH} STREQUAL ${GIT_HASH_CACHE}) OR
			(NOT ${GIT_BRANCH} STREQUAL ${GIT_BRANCH_CACHE}) OR
			(NOT ${GIT_STATUS} STREQUAL ${GIT_STATUS_CACHE}) OR
			(NOT EXISTS ${post_configure_file})
		)
		# Set che GIT_HASH_CACHE variable the next build won't have
		# to regenerate the source file.
		CheckGitWrite(${GIT_HASH} ${GIT_BRANCH} ${GIT_STATUS})
		configure_file(${pre_configure_file} ${post_configure_file} @ONLY)
	endif ()

endfunction()

function(CheckGitSetup)
	add_custom_target(AlwaysCheckGit COMMAND ${CMAKE_COMMAND}
		-DRUN_CHECK_GIT_VERSION=1
		-Dpre_configure_dir=${pre_configure_dir}
		-Dpost_configure_file=${post_configure_dir}
		-DGIT_HASH_CACHE=${GIT_HASH_CACHE}
		-DGIT_BRANCH_CACHE=${GIT_BRANCH_CACHE}
		-DGIT_STATUS_CACHE=${GIT_STATUS_CACHE}
		-P ${CURRENT_LIST_DIR}/CheckGit.cmake
		BYPRODUCTS ${post_configure_file}
	)

	add_library(git_version ${CMAKE_BINARY_DIR}/generated/git_version.cc)
	target_include_directories(git_version PUBLIC ${CMAKE_BINARY_DIR}/generated)
	add_dependencies(git_version AlwaysCheckGit)

	CheckGitVersion()
endfunction()

# This is used to run this function from an external cmake process.
if (RUN_CHECK_GIT_VERSION)
	CheckGitVersion()
endif ()
