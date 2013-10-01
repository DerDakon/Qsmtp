cmake_minimum_required(VERSION 2.8)

execute_process(COMMAND sleep 2)
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "HELO nonsense.example.org\r")
execute_process(COMMAND sleep 1)
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "noop\r")
execute_process(COMMAND sleep 1)
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "rSET\r")
execute_process(COMMAND sleep 1)
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "EHLO nonsense.example.org\r")
execute_process(COMMAND sleep 1)
# pipelining
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "mail from:<>\r\nrcpt to:<postmaster>\r\nRset\r")
execute_process(COMMAND sleep 1)
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "DATA\r")
execute_process(COMMAND sleep 1)
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "quit\r")
execute_process(COMMAND sleep 1)