/**
 * @file helper.h
 * @author Rune Krauss
 * @author Marvin Hindmarsh
 *
 * Serves as a helper for this program, e. g. for the output of error messages.
 */
#ifndef helper_h
#define helper_h

#include <stdlib.h>

/**
 * Called if an incorrect entry has been made (e. g. e|d as a combined parameter).
 * After this call, the program is terminated.
 *
 * @param msg Error message
 */
void fail(char* msg)
{
    fprintf(stderr, "Usage: ccm -d|-e [-h] <key> <nonce>\n");
    exit(EXIT_FAILURE);
}

#endif /* helper_h */
