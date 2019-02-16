/*
Package ssher allows you to easily create ssh connections in golang.

This package is essentially a wrapper around https://github.com/kevinburke/ssh_config,
which attempts to automatically load all values required to create a
https://golang.org/x/crypto/ssh ClientConfig from your ~/.ssh/config.

Most people will already have configured their ssh connections once for openssh, so why do it again manually?


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


Currently, only public key auth is attempted, and only the agent and one IdentityFile will be used.

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

// publicKeyFile takes a path to an IdentityFile, reads it, and parses it into an ssh.AuthMethod.
func publicKeyFile(file string) ssh.Signer {
	buffer, err := ioutil.ReadFile(file)
	if err != nil {
		return nil
	}

	key, err := ssh.ParsePrivateKey(buffer)
	if err != nil {
		return nil
	}
	return key
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

// sshAgentSigners connects to the ssh agent defined by the SSH_AUTH_SOCK environment variable,
// and returns a []ssh.Signer if successful.
func sshAgentSigners() []ssh.Signer {
	if sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
		signers, err := agent.NewClient(sshAgent).Signers()
		if err != nil {
			return nil
		}
		return signers
	}
	return nil
}

func decodeSSHConfig(configFile string) (sshConfig, error) {
	var userConfig sshConfig
	var err error

	if configFile == "" {
		configFile = "~/.ssh/config"
	}

	expandedF, err := homedir.Expand(configFile)
	if err != nil {
		return nil, errors.Wrap(err, "failed to expand home directory for ssh config file")
	}

	fd, err := os.Open(expandedF)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open ssh config file")
	}
	defer fd.Close()

	decodedConfig, err := ssh_config.Decode(fd)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decode ssh config file")
	}

	userConfig = &configWrapper{decodedConfig}
	return userConfig, err
}

func getHostKeyCallback(userKnownHostsFilesPaths []string) (ssh.HostKeyCallback, error) {
	if len(userKnownHostsFilesPaths) == 0 {
		userKnownHostsFilesPaths = append(userKnownHostsFilesPaths, "~/.ssh/known_hosts")
	}
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

	config := &ssh.Config{}
	macs := userConfig.Get(alias, "MACs")
	if macs != "" {
		config.MACs = strings.Split(macs, ",")
	}
	kexs := userConfig.Get(alias, "KexAlgorithms")
	if kexs != "" {
		config.KeyExchanges = strings.Split(kexs, ",")
	}
	ciphers := userConfig.Get(alias, "Ciphers")
	if ciphers != "" {
		config.Ciphers = strings.Split(ciphers, ",")
	}

	clientConfig := &ssh.ClientConfig{
		Config: *config,
	}

	// TODO handle known_hosts2
	// TODO default empty?
	userKnownHostsFile := userConfig.Get(alias, "UserKnownHostsFile")
	if userKnownHostsFile == "" {
		userKnownHostsFile, err = homedir.Expand("~/.ssh/known_hosts")
		if err != nil {
			return nil, connectHost, errors.Wrap(err, "failed to expand ~/.ssh/known_hosts")
		}
	}
	hostKeyCallback, err := getHostKeyCallback(strings.Split(userKnownHostsFile, " "))
	if err != nil {
		return nil, connectHost, errors.Wrap(err, "failed to create host key callback")
	}
	clientConfig.HostKeyCallback = hostKeyCallback

	user := userConfig.Get(alias, "User")
	if user == "" {
		currentUser, err := osuser.Current()
		if err != nil {
			return nil, connectHost, errors.Wrap(err, "failed to detect current user")
		}
		user = currentUser.Username
	}
	clientConfig.User = user

	signers := sshAgentSigners()
	identityFile, err := homedir.Expand(userConfig.Get(alias, "IdentityFile"))
	if err != nil {
		return nil, connectHost, errors.Wrap(err, "failed to expand home directory for IdentityFile")
	}
	pubkey := publicKeyFile(identityFile)
	if pubkey != nil {
		signers = append(signers, pubkey)
	}
	clientConfig.Auth = []ssh.AuthMethod{ssh.PublicKeys(signers...)}

	hostKeyAlgorithms := userConfig.Get(alias, "HostKeyAlgorithms")
	if hostKeyAlgorithms != "" {
		clientConfig.HostKeyAlgorithms = strings.Split(hostKeyAlgorithms, ",")
	}

	timeoutString := userConfig.Get(alias, "ConnectTimeout")
	if timeoutString != "" {
		timeoutInt, err := strconv.ParseInt(timeoutString, 10, 64)
		if err != nil {
			return nil, connectHost, errors.Wrap(err, "failed to convert ConnectTimeout to int64")
		}
		clientConfig.Timeout = time.Duration(timeoutInt) * time.Second
	}

	hostname := userConfig.Get(alias, "Hostname")
	if hostname == "" {
		hostname = alias
	}
	port := userConfig.Get(alias, "Port")
	if port == "" {
		port = "22"
	}
	connectHost = hostname + ":" + port

	return clientConfig, connectHost, nil
}
