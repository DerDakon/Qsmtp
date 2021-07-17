cmake_minimum_required(VERSION 3.0)

execute_process(COMMAND ${CMAKE_COMMAND} -E sleep 15) # long enough for DNS query to time out
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "quit\r")
execute_process(COMMAND ${CMAKE_COMMAND} -E sleep 1)
