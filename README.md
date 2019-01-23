# ssher
Easily create ssh connections in golang using values from your ssh config file.

Most people will already have configured their ssh connections once for openssh, so why do it again manually?

I searched all over, but couldn't find any implementations that fully configured an ssh.Config object,
and none that got their values from the ssh config file.

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
