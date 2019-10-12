/** @file greeting.h
 @brief definitions for EHLO parsing part of Qremote
 */
#ifndef GREETING_H
#define GREETING_H 1

/**< the SMTP extensions announced by the remote host */
enum ehlo_extensions {
	esmtp_size = 0x1,	/**< SIZE (RfC 1870) */
	esmtp_pipelining = 0x2,	/**< PIPELINING (RfC 2920) */
	esmtp_starttls = 0x4,	/**< STARTTLS (RfC 3207) */
	esmtp_8bitmime = 0x8,	/**< 8BITMIME (RfC 6152) */
	esmtp_auth = 0x10,	/**< AUTH (RfC 2554) */
	esmtp_chunking = 0x20,	/**< CHUNKING (RfC 3030) */
	esmtp_x_final = esmtp_chunking/**< end delimiter */
};

extern unsigned long remotesize;	/**< the maximum size allow by the remote host or 0 if unlimited or unknown */
extern const char *auth_mechs;	/**< the AUTH mechanisms supported by the remote host */

/**
 * @brief check if the line contains a known ESMTP extension
 *
 * @param input the line as sent by the server (ommitting the leading "250 " or "250-")
 * @return the extension code detected
 * @retval 0 no known extension code was found
 * @retval -1 a valid extension code was found, but the line had a parse error
 */
int esmtp_check_extension(const char *input) __attribute__ ((nonnull (1)));

/**
 * @brief greet the server, try EHLO and fall back to HELO if needed
 * @return the SMTP extensions supported
 * @retval <0 error code
 * @retval -EDONE the server reply was syntactically correct, but an error response
 *
 * In case of incoming syntax errors the faulting line will be written to log.
 */
int greeting(void);

#endif /* GREETING_H */
