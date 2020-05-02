# minisudo [![Build status](https://travis-ci.org/ogham/minisudo.svg)](https://travis-ci.org/ogham/minisudo)

This is a small sudo-like privilege escalator for Unix-like operating systems.

It was written for learning, not to replace sudo, and has been tested on macOS and Linux.

```
$ minisudo whoami
Password for "ben": [password hidden]
root
```

This project was inspired by [kibi](https://github.com/ilai-deutel/kibi), a text editor written in ≤1024 lines of code. I’ve seen many people with the false impression that `sudo` is “magical” or special in some way, but it doesn’t do anything that’s not available to any other program. minisudo tries to implement its most popular use case — running programs as root after checking against a list of rules — with a couple pages of code and minimal dependencies.


Installation
------------

minisudo is written in [Rust](https://www.rust-lang.org/), and uses [just](https://github.com/casey/just) as its build script runner. To build and install:

    $ just build
    $ sudo just install

To uninstall:

    $ sudo just uninstall

Debian users will need to have the `libpam0g-dev` package installed.


How it works
------------

minisudo uses [PAM](https://en.wikipedia.org/wiki/Pluggable_authentication_module) as its authentication mechanism, which is how it knows what your password is. It installs a file into `/etc/pam.d` to allow it to do this.

The binary is installed with the [setuid bit](https://en.wikipedia.org/wiki/Setuid) set, which is how it’s able to run programs as root.


Rules file
----------

The rules for which users can run which programs are specified in a TOML file, `/etc/minisudo-rules.toml`. Here’s an example:

```toml
# The user ‘ben’ can run ‘ls’, but nothing else.
[[rule]]
user = "ben"
program = "/bin/ls"

# All members of the ‘staff’ group can run ‘whoami’, but nothing else.
[[rule]]
group = "staff"
program = "/usr/bin/whoami"
```

Binaries must be specified by their _full path_, not just their basename. Specify `*` to allow any program to be run.


Safety
------

Although no unsafe Rust code is present in the `minisudo` crate itself, its dependencies call functions in PAM and libc, so the project can never be _entirely_ free of unsafe code.


Security vulnerabilities
------------------------

Probably.


Licence
-------

minisudo’s source code is under the [MIT Licence](LICENCE).
