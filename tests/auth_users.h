#pragma once

static struct {
	const char *username;
	const char *password;
} const users[] = {
	{
		.username = "foo",
		.password = "bar"
	},
	{
		.username = "foo@example.com",
		.password = "foo!foo\"foo$foo%foo&"
	},
	{
		.username = "longerfoo@long.foo.and.even.longer.foo.foo.foo.example.com",
		.password = "!\"$%&/&((&%1234567890000ajsdhfkajshdkfajhsdkfbuwbausdfakeufaasdmnb"
	},
	{
		.username = NULL,
		.password = NULL
	}
};

static const char autharg[] = "auth1";
