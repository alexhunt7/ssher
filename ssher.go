package ssher

import (
	"os"
	osuser "os/user"
	"github.com/kevinburke/ssh_config"
	"github.com/mitchellh/go-homedir"
	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"io/ioutil"
	"strings"
	"strconv"
	"time"
)

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

//func SSHAgent() ssh.AuthMethod {
//	if sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
//		return ssh.PublicKeysCallback(agent.NewClient(sshAgent).Signers)
//	}
//	return nil
//}

func ClientConfig(alias string) (*ssh.ClientConfig, string, error) {
	var err error
	var connectHost string
	/* TODO
	   // Rand
	   // BannerCallback
	   // ClientVersion
	*/

	macs :=              strings.Split(ssh_config.Get(alias, "MACs"), ",")
	keyExchanges :=      strings.Split(ssh_config.Get(alias, "KexAlgorithms"), ",")
	ciphers :=           strings.Split(ssh_config.Get(alias, "Ciphers"), ",")

	config := &ssh.Config{
		MACs:              macs,
		KeyExchanges:      keyExchanges,
		Ciphers:           ciphers,
	}

	var userKnownHostsFiles []string
	for _, f := range strings.Split(ssh_config.Get(alias, "UserKnownHostsFile"), " ") {
		expandedF, err := homedir.Expand(f)
		if err != nil {
			return nil, connectHost, errors.Wrap(err, "failed to expand home directory for UserKnownHostsfile")
		}
		_, err = os.Stat(expandedF)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, connectHost, errors.Wrap(err, "failed to stat UserKnownHostsFile")
		}
		userKnownHostsFiles = append(userKnownHostsFiles, expandedF)
	}
	hostKeyCallback, err := knownhosts.New(userKnownHostsFiles...)
	if err != nil {
		return nil, connectHost, errors.Wrap(err, "failed to create host key callback")
	}

	hostname := ssh_config.Get(alias, "Hostname")
	if hostname == "" {
		hostname = alias
	}

	port := ssh_config.Get(alias, "Port")

	user := ssh_config.Get(alias, "User")
	if user == "" {
		currentUser, err := osuser.Current()
		if err != nil {
			return nil, connectHost, errors.Wrap(err, "failed to detect current user")
		}
		user = currentUser.Username
	}

	identityFile, err := homedir.Expand(ssh_config.Get(alias, "IdentityFile"))
	if err != nil {
		return nil, connectHost, errors.Wrap(err, "failed to expand home directory for IdentityFile")
	}

	auth := []ssh.AuthMethod{PublicKeyFile(identityFile),}
	hostKeyAlgorithms := strings.Split(ssh_config.Get(alias, "HostKeyAlgorithms"), ",")
	timeoutString := ssh_config.Get(alias, "ConnectTimeout")
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
		Config: *config,
		User:              user,
		Auth:              auth,
		HostKeyCallback: hostKeyCallback,
		HostKeyAlgorithms: hostKeyAlgorithms,
		Timeout: timeout,
	}, connectHost, nil
}
