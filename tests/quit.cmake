cmake_minimum_required(VERSION 2.8)

execute_process(COMMAND sleep 4)
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "quit\r")
execute_process(COMMAND sleep 1)
