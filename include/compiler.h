/** \file compiler.h
 \brief compiler abstractions
 */
#ifndef COMPILER_H
#define COMPILER_H

#define ATTR_ACCESS(a, b, c)

#if defined __has_attribute
#  if __has_attribute (access)
#    undef ATTR_ACCESS
#    define ATTR_ACCESS(a, b, c) __attribute__ ((access (a, b, c)))
#  endif
#endif

#endif /* COMPILER_H */
