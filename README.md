# MD5 hashed pack

Application used to store any kind of user files in a special container
(md5pack) with the check sum (MD5) in one file. It doesn't replace archiver
program since there is no compression. Theoretical maximum size of a file
can be the maximum of allowed to create within the filesystem where this
application is used, but not greater than the size that can be stored in
a 64-bit number.

# Before you will use it

This application is in the state of WIP (work in progress) and it's created
mostly for the fun, so use it on your own risk without any responsibility.
The code can be used freely, modified etc.

## Building

Requires cmake, gcc, ssl, crypto (other dependencies will be added later).

To build the project:
* `mkdir build && cd build`
* `cmake ..`
* `make`
* `make package` - to generate *.deb installer package

The application can be installed using:
* `dpkg -i %filename%.deb` running dpkg under super user rights.

Enjoy! :)
