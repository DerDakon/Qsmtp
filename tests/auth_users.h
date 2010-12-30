#pragma once

static struct {
	const char *testname;
	const char *username;
	const char *password;
} const users[] = {
	{
		.testname = "errors",
		.username = "error",
		.password = "error",
	},
	{
		.testname = "short",
		.username = "foo",
		.password = "bar"
	},
	{
		.testname = "email",
		.username = "foo@example.com",
		.password = "foo!foo\"foo$foo%foo&"
	},
	{
		.testname = "long",
		.username = "longerfoo@long.foo.and.even.longer.foo.foo.foo.example.com",
		.password = "!\"$%&/&((&%1234567890000ajsdhfkajshdkfajhsdkfbuwbausdfakeufaasdmnb"
	},
	{
		.testname = NULL,
		.username = NULL,
		.password = NULL
	}
};

static const char autharg[] = "auth1";
