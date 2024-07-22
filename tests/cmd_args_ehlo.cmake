cmake_minimum_required(VERSION 3.0...3.27)

# The maximum permitted line length without extensions is 510 characters + CRLF.
# The easiest way to have a otherwise valid line that violates this length limit
# is to extend the space bug space.
set(SPACES "    ")
foreach(i 1 2 3 4 5 6 7)
	set(SPACES "${SPACES}${SPACES}")
endforeach()

execute_process(COMMAND sleep 15)
# local ip as ehlo
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "EHLO [127.0.0.1]\r")
execute_process(COMMAND sleep 1)
# invalid arguments
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "mail from:<> foo=bar nonsense\r")
execute_process(COMMAND sleep 1)
# valid empty auth, valid body
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "mail from:<> auth=<> body=8bitmime\r")
# space bug, rcpt to not in angle brackets
# space bug, rcpt to address has syntax error
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "rcpt to: postmaster\r\nrcpt to: <foo@ju#k>\r\nrset\r")
execute_process(COMMAND sleep 1)
# valid size, another valid body, valid auth
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "mail from:<> size=20 body=7bit auth=foo@example.org\r")
# argument after rcpt, which is not supported
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "rcpt to:<postmaster> invalid\r\nrset\r")
execute_process(COMMAND sleep 1)
# missing angle brackets
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "mail from: foo@example.net\r\nnoop\r")
execute_process(COMMAND sleep 1)
# too long line, noop to reset bad command counter
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "mail from:${SPACES}<>\r\nnoop\r")
execute_process(COMMAND sleep 1)
# mail address with syntax error, noop to reset bad command counter
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "mail from:<foo@junk#>\r\nnoop\r")
execute_process(COMMAND sleep 1)
# invalid body arguments, noop, to reset bad command counter
# pipelining after end of pipelining group
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "mail from:<> body=\r\nnoop\r\nnoop\r\nquit\r")
execute_process(COMMAND sleep 1)
