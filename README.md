A sha256 library for the c programming language.

This library currently contains the source code and header file for
my implementation of the sha256 algorithm.

Three functions exposed by the API:

    - sha_init() - initialises values for initial context struct
                   including initialising the hash.
    - sha_update() - processes message blocks
    - sha_final() - processes the final block and generates the final
                    hash.

test.c shows a working implementation of the library.  test.c hashes
the latest Ubuntu iso and prints the checksum for the file.

Pending updates
 - Make process algorithm more efficient
 - Extend the library to other hashing functions.