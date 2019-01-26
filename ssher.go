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

type SSHConfig interface {
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

func SSHAgent() ssh.AuthMethod {
	if sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK")); err == nil {
		return ssh.PublicKeysCallback(agent.NewClient(sshAgent).Signers)
	}
	return nil
}

func decodeSSHConfig(configFile string) (SSHConfig, error) {
	var userConfig SSHConfig
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

	var userKnownHostsFiles []string
	for _, f := range strings.Split(userConfig.Get(alias, "UserKnownHostsFile"), " ") {
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
