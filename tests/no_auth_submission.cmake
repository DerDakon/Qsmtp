cmake_minimum_required(VERSION 3.0)

execute_process(COMMAND sleep 15)
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "EHLO [203.0.113.24]\r")
execute_process(COMMAND sleep 1)
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "mail from:<>\r")
execute_process(COMMAND sleep 1)
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "quit\r")
execute_process(COMMAND sleep 1)
