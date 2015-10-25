# funneld

An SSH service for funneling login users through a single system user.

# Overview

`funneld` is a fairly simple ssh server written in Python. The main use-case is for presenting a specific program to users using ssh to access a host. `funneld` solves the additional problem of needing to run a web-service or other registration mechanism. The first time any username used to login, it is immediately associated with the incoming public key. Subsequent logins for the username will require the original public key. Every user logging in is forced to execute the shell of the configured "funnel user".

# Installation

You can install `funneld` with pip:

    pip install funneld

# Configuration

A system user will be needed for running the desired shell program. In this case we create the user `foobar` with the `htop` program as the shell:

    useradd -s /usr/bin/htop foobar

# Running

The service will route all logins through the shell of the specified user:

    funneld --port 2200 foobar

The service will be made available on port `22` by default. Change it with the `--port` flag.

# Public Keys

The public keys that are bound to usernames are stored in the home directory of the funnel user:

    /home/foobar/.ssh/$login_user.pub

# Logging in

If the funnel user is specified as `foobar` was created with the shell set to `/usr/bin/htop` then logging in as any user will result in running it:

    useradd -s /usr/bin/htop foobar
    funneld --port 2200 foobar

    # login to execute htop
    # and claim the "anything" username
    ssh -p 2200 anything@localhost

    # public key saved to /home/foobar/.ssh/anything.pub

