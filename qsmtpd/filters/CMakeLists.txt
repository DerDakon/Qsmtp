SET(filterSrc rcpt_filters.c badmailfrom.c check2822.c dnsbl.c ipbl.c badcc.c fromdomain.c spf.c boolean.c soberg.c
	  helo.c usersize.c forceesmtp.c namebl.c wildcardns.c)

ADD_LIBRARY(rcptfilters  ${filterSrc})
