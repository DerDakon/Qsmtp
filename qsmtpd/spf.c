#include "antispam.h"
#include "sstring.h"
#include "dns.h"

/**
 * spflookup - look up SPF records for domain
 *
 * @domain: no idea what this might be for
 * @result: here the line is stored that should be written into header
 *
 * returns: on of the SPF_* constants defined in include/antispam.h
 */
int
spflookup(const char *domain, string *result)
{
	char *txt;
	int i;

#warning FIXME: add SPF parsing here
	i = dnstxt(&txt, domain);
	if (i && !txt)
		return SPF_NONE;
	if (i)
		return SPF_TEMP_ERROR;
	if (!i)
		free(txt);
	STREMPTY(*result);
	return 0;
}
