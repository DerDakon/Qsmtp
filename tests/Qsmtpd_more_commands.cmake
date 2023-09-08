cmake_minimum_required(VERSION 3.0...3.27)

execute_process(COMMAND sleep 15)
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "EHLO remote.example.org\r")
execute_process(COMMAND sleep 1)
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "AUTH PLAIN AGEAYg==\r")
execute_process(COMMAND sleep 1)
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "mail from:<> size=1025\r")
execute_process(COMMAND sleep 1)
# HELO will act like reset
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "HELO remote.example.org\r")
execute_process(COMMAND sleep 1)
# not permitted in plain SMTP mode
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "STARTTLS\r")
execute_process(COMMAND sleep 1)
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "quit\r")
execute_process(COMMAND sleep 1)
