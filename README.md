# KMESG: Kolored/Kernel Messages

As `dmesg` is currently not able to support ANSI color escape sequences, i made this simple program to fix this.

# Installation 

To install it just execute: `sudo make install`, and the compiled program will be moved into `/usr/local/sbin`.
If you'd like to change the destination, just modify the destination parameter of the `mv` command in the `Makefile`.

