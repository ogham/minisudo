minisudo
========

This is a small sudo-like privilege escalator for Unix-like operating systems. It was written for learning, not to replace sudo.

```
$ minisudo whoami
Password for "ben": [password hidden]
root
```


Installation
------------

minisudo is written in [Rust](https://www.rust-lang.org), and uses [just](https://github.com/casey/just) as its command runner. To build and install:

    $ just build
    $ sudo just install

To uninstall:

    $ sudo just uninstall


How it works
------------

minisudo uses [PAM](https://en.wikipedia.org/wiki/Pluggable_authentication_module) as its authentication mechanism.


Safety
------

Although no unsafe used is present in the `minisudo` crate’s code itself, its dependencies call functions in PAM and libc, so the project can never be entirely free of unsafe code.
