
find_path(concurrentqueue_INCLUDE concurrentqueue/blockingconcurrentqueue.h HINTS "${PROJECT_SOURCE_DIR}/dependency/")

if (concurrentqueue_INCLUDE)
    set(CONCURRENTQUEUE_FOUND TRUE)
    message(STATUS "${Green}Found Concurrentqueue include at: ${concurrentqueue_INCLUDE}${Reset}")
else()
    message(FATAL_ERROR "${Red}Failed to locate Concurrentqueue module.${Reset}" )
endif()
