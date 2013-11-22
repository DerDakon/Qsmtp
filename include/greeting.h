/** \file qremote.h
 \brief definitions for EHLO parsing part of Qremote
 */
#ifndef GREETING_H
#define GREETING_H 1

/**< the SMTP extensions announced by the remote host */
enum ehlo_extensions {
	esmtp_size = 0x1,	/**< SIZE (RfC 1870) */
	esmtp_pipelining = 0x2,	/**< PIPELINING (RfC 2920) */
	esmtp_starttls = 0x4,	/**< STARTTLS (RfC 3207) */
	esmtp_8bitmime = 0x8,	/**< 8BITMIME (RfC 6152) */
	esmtp_chunking = 0x10,	/**< CHUNKING (RfC 3030) */
	esmtp_auth = 0x20,	/**< AUTH (RfC 2554) */
	esmtp_x_final = esmtp_auth/**< end delimiter */
};

#endif /* GREETING_H */
