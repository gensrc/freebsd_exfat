FreeBSD [exFAT](https://learn.microsoft.com/en-us/windows/win32/fileio/exfat-specification)
========

## About

AI generated exFAT file system and utilities

## Requirements

+ FreeBSD 15.x

+ src tree under /usr/src

## Components

|Name            |Description                                     |
|:---------------|:-----------------------------------------------|
|exfat(4)        |exFAT kernel module exfat.ko                    |
|newfs\_exfat(8) |construct a new exFAT file system               |
|mount\_exfat(8) |mount an exFAT file system                      |
|fsck\_exfat(8)  |exFAT file system consistency checker           |

## Build

        $ cd freebsd_exfat
        $ make

## Install

        $ cd freebsd_exfat
        $ make install

## Uninstall

        $ cd freebsd_exfat
        $ make uninstall
