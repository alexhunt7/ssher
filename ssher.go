/*
Package ssher allows you to easily create ssh connections in golang, using values from your ssh config file.

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


Currently, only public key auth is attempted and only the agent and one IdentityFile will be used.
Host key checking is enforced.
Any limitations that apply to https://github.com/kevinburke/ssh_config also apply here (currently no support for +value syntax).
*/
package ssher

import (
	"github.com/kevinburke/ssh_config"
	"github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	"io/ioutil"
	"net"
	"os"
	osuser "os/user"
	"strconv"
	"strings"
	"time"
)

// PublicKeyFile takes a path to an IdentityFile, reads it, and parses it into an ssh.AuthMethod.
func PublicKeyFile(file string) ssh.AuthMethod {
	buffer, err := ioutil.ReadFile(file)
	if err != nil {
		return nil
	}

	key, err := ssh.ParsePrivateKey(buffer)
	if err != nil {
		return nil
	}
	return ssh.PublicKeys(key)
}

type sshConfig interface {
	Get(string, string) string
}

type configWrapper struct {
	config *ssh_config.Config
}

func (cw *configWrapper) Get(alias, key string) string {
	val, err := cw.config.Get(alias, key)
	if err != nil {
		return ""
	}
	return val
}

// SSHAgent connects to the ssh agent defined by the SSH_AUTH_SOCK environment variable,
// and returns an ssh.PublicKeysCallback ssh.AuthMethod if successful.
func SSHAgent() ssh.AuthMethod {
	if sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
		return ssh.PublicKeysCallback(agent.NewClient(sshAgent).Signers)
	}
	return nil
}

func decodeSSHConfig(configFile string) (sshConfig, error) {
	var userConfig sshConfig
	var err error

	if configFile == "" {
		// Use the default ~/.ssh/config and /etc/ssh/ssh_config
		userConfig = ssh_config.DefaultUserSettings
	} else {
		fd, err := os.Open(configFile)
		if err != nil {
			return nil, errors.Wrap(err, "failed to open ssh config file")
		}
		defer fd.Close()

		decodedConfig, err := ssh_config.Decode(fd)
		if err != nil {
			return nil, errors.Wrap(err, "failed to decode ssh config file")
		}

		userConfig = &configWrapper{decodedConfig}
	}
	return userConfig, err
}

func getHostKeyCallback(userKnownHostsFilesPaths []string) (ssh.HostKeyCallback, error) {
	var userKnownHostsFiles []string
	for _, f := range userKnownHostsFilesPaths {
		expandedF, err := homedir.Expand(f)
		if err != nil {
			return nil, errors.Wrap(err, "failed to expand home directory for UserKnownHostsfile")
		}
		_, err = os.Stat(expandedF)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, errors.Wrap(err, "failed to stat UserKnownHostsFile")
		}
		userKnownHostsFiles = append(userKnownHostsFiles, expandedF)
	}
	hostKeyCallback, err := knownhosts.New(userKnownHostsFiles...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to call knownhosts.New")
	}
	return hostKeyCallback, nil
}

// ClientConfig takes in an ssh config file host alias and a path to an ssh config file,
// and returns an ssh.ClientConfig and a connection string (for dialing).
// If passed an empty string for the configFile, it will use the default config file paths:
// ~/.ssh/config and /etc/ssh/ssh_config
func ClientConfig(alias string, configFile string) (*ssh.ClientConfig, string, error) {
	var err error
	var connectHost string

	userConfig, err := decodeSSHConfig(configFile)
	if err != nil {
		return nil, connectHost, errors.Wrap(err, "failed to decode ssh config file")
	}

	/* TODO
	   // Rand
	   // BannerCallback
	   // ClientVersion
	*/

	macs := strings.Split(userConfig.Get(alias, "MACs"), ",")
	keyExchanges := strings.Split(userConfig.Get(alias, "KexAlgorithms"), ",")
	ciphers := strings.Split(userConfig.Get(alias, "Ciphers"), ",")

	config := &ssh.Config{
		MACs:         macs,
		KeyExchanges: keyExchanges,
		Ciphers:      ciphers,
	}

	hostKeyCallback, err := getHostKeyCallback(strings.Split(userConfig.Get(alias, "UserKnownHostsFile"), " "))
	if err != nil {
		return nil, connectHost, errors.Wrap(err, "failed to create host key callback")
	}

	hostname := userConfig.Get(alias, "Hostname")
	if hostname == "" {
		hostname = alias
	}

	port := userConfig.Get(alias, "Port")
	if port == "" {
		port = "22"
	}

	user := userConfig.Get(alias, "User")
	if user == "" {
		currentUser, err := osuser.Current()
		if err != nil {
			return nil, connectHost, errors.Wrap(err, "failed to detect current user")
		}
		user = currentUser.Username
	}

	auth := []ssh.AuthMethod{}
	sshAgent := SSHAgent()
	if sshAgent != nil {
		auth = append(auth, sshAgent)
	}

	identityFile, err := homedir.Expand(userConfig.Get(alias, "IdentityFile"))
	if err != nil {
		return nil, connectHost, errors.Wrap(err, "failed to expand home directory for IdentityFile")
	}
	pubkey := PublicKeyFile(identityFile)
	if pubkey != nil {
		auth = append(auth, pubkey)
	}

	hostKeyAlgorithms := strings.Split(userConfig.Get(alias, "HostKeyAlgorithms"), ",")
	timeoutString := userConfig.Get(alias, "ConnectTimeout")
	var timeout time.Duration
	if timeoutString == "" {
		timeout = 0
	} else {
		timeoutInt, err := strconv.ParseInt(timeoutString, 10, 64)
		if err != nil {
			return nil, connectHost, errors.Wrap(err, "failed to convert ConnectTimeout to int64")
		}
		timeout = time.Duration(timeoutInt) * time.Second
	}

	connectHost = hostname + ":" + port
	return &ssh.ClientConfig{
		Config:            *config,
		User:              user,
		Auth:              auth,
		HostKeyCallback:   hostKeyCallback,
		HostKeyAlgorithms: hostKeyAlgorithms,
		Timeout:           timeout,
	}, connectHost, nil
}
