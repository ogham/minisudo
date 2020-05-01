build:
    cargo build --release

clean:
    cargo clean

install:
    install -o0 -g0 -m4755 -- target/release/minisudo /usr/local/bin/minisudo
    install -o0 -g0 -m444  -- files/etc_pam.d_minisudo /etc/pam.d/minisudo

uninstall:
    rm -f /usr/local/bin/minisudo
    rm -f /etc/pam.d/minisudo
