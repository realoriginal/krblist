# About

KRBLIST acts a minimal replacement of klist.exe. It prints basic information about the tickets, but is not a complete replacement.

It is designed to work purely with Cobalt Strike through its 'Beacon Object File' format so that you can more easily play with Kerberos tooling without the need for external toolsets. This has been tested in a few different labs to ensure it works properly.

## Build

To build the 'Beacon Object File'  you will need mingw-w64 from musl.cc. Once you've installed the compilers within your PATH for x86_64 and i686, run `make`, which will build the BOF file to be used with Cobalt Strike.

Once you've build the corresponding KRBLIST BOF for their respective architectures, simply import the [KrbList.cna](KrbList.cna) script into your Aggressor script console. You're ready to start using it!


## Usage

Its relatively simple! Simple execute `krblist` from a Cobalt Strike Beacon, and your tickets for your current logon session will be printed!
