/** \file qsauth_backend.h
 \brief function definitions for Qsmtpd's AUTH backend API
 */
#ifndef QSAUTH_BACKEND_H
#define QSAUTH_BACKEND_H

struct string;

extern int auth_backend_setup(int argc, const char **argv);

/**
 * @brief authenticate a user with the given credentials
 * @param user user id
 * @param pass password
 * @param resp additional response (e.g. for CRAM authentication)
 * @retval -1 processing error (errno is set)
 * @retval 0 user successfully authenticated
 * @retval 1 authentication error (i.e. invalid user/pass combination)
 *
 * resp may be passed as NULL if no additional information has been collected
 */
extern int auth_backend_execute(const struct string *user, const struct string *pass, const struct string *resp);

extern const char *tempnoauth;

#endif
