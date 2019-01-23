package main

import (
	"os"
	osuser "os/user"
	"fmt"
	"github.com/kevinburke/ssh_config"
	"github.com/mitchellh/go-homedir"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"io/ioutil"
	//"path/filepath"
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

func main() {
	var err error
	/* TODO
	   // Rand
	   // BannerCallback
	   // ClientVersion
	*/

	//alias := "102.30.1.3"
	alias := "localhost"
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
			panic(err)
		}
		_, err = os.Stat(expandedF)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			panic(err)
		}
		userKnownHostsFiles = append(userKnownHostsFiles, expandedF)
	}
	fmt.Println(userKnownHostsFiles)
	hostKeyCallback, err := knownhosts.New(userKnownHostsFiles...)
	if err != nil {
		panic(err)
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
			panic(err)
		}
		user = currentUser.Username
	}

	identityFile, err := homedir.Expand(ssh_config.Get(alias, "IdentityFile"))
	if err != nil {
		panic(err)
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
			panic(err)
		}
		timeout = time.Duration(timeoutInt) * time.Second
	}

	fmt.Println(hostname)
	fmt.Println(port)
	fmt.Println(user)
	fmt.Println(identityFile)
	fmt.Println(auth)
	fmt.Println(macs)
	fmt.Println(keyExchanges)
	fmt.Println(ciphers)
	fmt.Println(hostKeyAlgorithms)
	fmt.Println(timeout)

	clientConfig := &ssh.ClientConfig{
		Config: *config,
		User:              user,
		Auth:              auth,
		HostKeyCallback: hostKeyCallback,
		HostKeyAlgorithms: hostKeyAlgorithms,
		Timeout: timeout,
	}

	conn, err := ssh.Dial("tcp", hostname + ":" + port, clientConfig)
	if err != nil {
		panic(err)
	}

	session, err := conn.NewSession()
	if err != nil {
		panic(err)
	}
	defer session.Close()

	_, err = session.StdoutPipe()
	if err != nil {
		panic(err)
	}

	//name := fmt.Sprintf("%s/backup_folder_%v.tar.gz", path, time.Now().Unix())
	//file, err := os.OpenFile(name, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	//if err != nil {
	//    return err
	//}
	//defer file.Close()
	//
	//if err := session.Start(cmd); err != nil {
	//    return err
	//}
	//
	//n, err := io.Copy(file, r)
	//if err != nil {
	//    return err
	//}
	//
	//if err := session.Wait(); err != nil {
	//    return err
	//}
}
