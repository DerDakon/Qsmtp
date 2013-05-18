cmake_minimum_required(VERSION 2.8)

execute_process(COMMAND sleep 2)
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "quit\r")
execute_process(COMMAND sleep 1)
