cmake_minimum_required(VERSION 2.8)

# The maximum permitted line length without extensions is 510 characters + CRLF.
# The easiest way to have a otherwise valid line that violates this length limit
# is to extend the space bug space.
set(SPACES "    ")
foreach(i 1 2 3 4 5 6 7)
	set(SPACES "${SPACES}${SPACES}")
endforeach(i)

execute_process(COMMAND sleep 2)
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "HELO nonsense.example.org\r")
execute_process(COMMAND sleep 1)
# arguments only allowed in ESMTP mode
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "mail from:<> size=20\r")
execute_process(COMMAND sleep 1)
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "EHLO nonsense.example.org\r")
execute_process(COMMAND sleep 1)
# invalid arguments
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "mail from:<> foo=bar nonsense\r")
execute_process(COMMAND sleep 1)
# valid size, valid body, valid empty auth
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "mail from:<> size=20 body=8bitmime auth=<>\r\nrset\r")
execute_process(COMMAND sleep 1)
# duplicate size
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "mail from:<> size=20 size=20\r")
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
# duplicate body, noop to reset bad command counter
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "mail from:<> body=7bit body=7bit\r\nnoop\r")
execute_process(COMMAND sleep 1)
# invalid size
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "mail from:<> size=a\r\nnoop\r")
execute_process(COMMAND sleep 1)
# invalid size, space bug
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "mail from: <> size=2a\r\nnoop\r")
execute_process(COMMAND sleep 1)
# missing angle brackets
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "mail from: foo@example.net\r\nnoop\r")
execute_process(COMMAND sleep 1)
# invalid body arguments, noop to reset bad command counter
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "mail from:<> body=foo\r\nnoop\r")
execute_process(COMMAND sleep 1)
# invalid auth argument, noop to reset bad command counter
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "mail from:<> auth=\r\nnoop\r")
execute_process(COMMAND sleep 1)
# now some commands that do not expect arguments
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "noop foo\r\nnoop\r")
execute_process(COMMAND sleep 1)
execute_process(COMMAND ${CMAKE_COMMAND} -E echo "rset foo\r\nRSET\r")
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
