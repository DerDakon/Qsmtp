cmake_minimum_required(VERSION 3.0...3.27)

execute_process(COMMAND sleep 15)
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "helo test.example.net\r")
execute_process(COMMAND sleep 1)
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "noop\r\nnoop\r\nnoop\r")
execute_process(COMMAND sleep 1)
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "noop\r\nquit\r")
execute_process(COMMAND sleep 1)
