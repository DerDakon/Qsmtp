/** @file cdb_entries.h
 * @brief test patterns for CDB test database
 */

#ifndef _CDB_ENTRIES_H
#define _CDB_ENTRIES_H

#include <stdlib.h>

static struct {
	const char *key;
	const char *value;
	const char *realdomain;
} cdb_testvector[] =  {
	{
		.key = "example.org",
		.value = "/var/vpopmail/domains/example.org",
		.realdomain = "example.org"
	},
	{
		.key = "example.com",
		.value = "/var/vpopmail/domains/example.com",
		.realdomain = "example.com"
	},
	{
		.key = "foo.example.org",
		.value = "/var/vpopmail/domains/foo.example.org",
		.realdomain = "foo.example.org"
	},
	{
		.key = "alias.example.org",
		.value = "/var/vpopmail/domains/foo.example.org",
		.realdomain = "foo.example.org"
	},
	{
		.key = "nonexistent.example.org"
	},
	{ }
};

#endif
