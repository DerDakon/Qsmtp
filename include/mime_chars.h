/** \file mime_chars.h
 * \brief definitions of MIME character classes
 */
#ifndef MIMECHARS_H
#define MIMECHARS_H

/**
 * check if the given character is a MIME special one
 *
 * @param a the character to check
 * @return if it is a special character or not
 *
 * This checks if the given character is within the "tspecials" range as
 * defined in RfC 2045.
 */
#define TSPECIAL(a) (((a) == '(') || ((a) == ')') || ((a) == '<') || ((a) == '>') || ((a) == '@') || \
			((a) == ',') || ((a) == ';') || ((a) == ':') || ((a) == '\\') || ((a) == '"') || \
			((a) == '/') || ((a) == '[') || ((a) == ']') || ((a) == '?') || ((a) == '='))

/**
 * check if the given character is whitespace
 *
 * @param a the character to check
 * @return if it is a whitespace character or not
 */
#define WSPACE(a) (((a) == ' ') || ((a) == '\t') || ((a) == '\r') || ((a) == '\n'))

#endif
