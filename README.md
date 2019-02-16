# ssher
[![GoDoc](https://godoc.org/github.com/alexhunt7/ssher?status.svg)](https://godoc.org/github.com/alexhunt7/ssher)
[![Go Report Card](https://goreportcard.com/badge/github.com/alexhunt7/ssher)](https://goreportcard.com/report/github.com/alexhunt7/ssher)

Easily create golang.org/x/crypto/ssh connections in golang, using values from your ssh config file.

Most people will already have configured their ssh connections once for openssh, so why do it again manually?

This package is essentially a wrapper around https://github.com/kevinburke/ssh_config,
which attempts to automatically load all required values from your ~/.ssh/config.


Currently supported options:
* Ciphers
* ConnectTimeout
* HostKeyAlgorithms
* Hostname
* IdentityFile
* KexAlgorithms
* MACs
* Port
* User
* UserKnownHostsFile


Currently, only public key auth is attempted and only one IdentityFile will be used.
Host key checking is enforced.
Any limitations that apply to https://github.com/kevinburke/ssh_config also apply here (currently no support for +value syntax).

This module is not ready for production use.
