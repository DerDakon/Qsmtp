cmake_minimum_required(VERSION 3.0...3.27)

execute_process(COMMAND sleep 15)
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "EHLOxy\r")
execute_process(COMMAND sleep 1)
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "EHLO xy\r")
execute_process(COMMAND sleep 1)
# pipelining
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "vrfy\r\nvrfy x\r\nvrfyx\r\nnoopx\r\nnoop\r")
execute_process(COMMAND sleep 1)
# now some commands that do not expect arguments
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "noop foo\r\nnoop\r")
execute_process(COMMAND sleep 1)
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "rset foo\r\nRSET\r")
execute_process(COMMAND sleep 1)
# the next 2 are syntactically correct, but should trigger some antispam codepath internally
# TODO: move to their own test where those result codes are actually checked
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "helo 127.0.0.1\r")
execute_process(COMMAND sleep 1)
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "mail from:<someone@example.invalid>\r")
execute_process(COMMAND sleep 1)
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "quit\r")
execute_process(COMMAND sleep 1)
