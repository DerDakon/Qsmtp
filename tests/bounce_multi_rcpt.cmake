cmake_minimum_required(VERSION 3.0...3.27)

execute_process(COMMAND sleep 15)
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "EHLO nonsense.example.org\r")
execute_process(COMMAND sleep 1)
# pipelining
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "mail from:<>\r\nrcpt to:<postmaster>\r\nrcpt to:<postmaster>\r\ndata\r")
execute_process(COMMAND sleep 1)
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "quit\r")
execute_process(COMMAND sleep 1)
