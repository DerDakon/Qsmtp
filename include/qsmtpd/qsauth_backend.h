/** \file qsauth_backend.h
 \brief function definitions for Qsmtpd's AUTH backend API
 */
#ifndef QSAUTH_BACKEND_H
#define QSAUTH_BACKEND_H

struct string;

extern int auth_backend_setup(int argc, const char **argv);

extern int auth_backend_execute(struct string *user, struct string *pass, struct string *resp);

extern const char *tempnoauth;

#endif
