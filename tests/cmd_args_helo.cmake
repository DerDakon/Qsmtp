cmake_minimum_required(VERSION 3.0...3.27)

# The maximum permitted line length without extensions is 510 characters + CRLF.
# The easiest way to have a otherwise valid line that violates this length limit
# is to extend the space bug space.
set(SPACES "    ")
foreach(i 1 2 3 4 5 6 7)
	set(SPACES "${SPACES}${SPACES}")
endforeach()

execute_process(COMMAND sleep 15)
# invalid HELO, but this will be filtered later
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "HELO [foo] \r")
execute_process(COMMAND sleep 1)
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "HELO nonsense.example.org\r")
execute_process(COMMAND sleep 1)
# arguments only allowed in ESMTP mode
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "mail from:<> size=20\r")
execute_process(COMMAND sleep 1)

execute_process(COMMAND ${CMAKE_COMMAND} -E echo "quit\r")
execute_process(COMMAND sleep 1)
