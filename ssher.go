package main

import (
	"os"
	"github.com/kevinburke/ssh_config"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
	"io/ioutil"
	"path/filepath"
)

//func GetConfigs(alias string) []Wrapper {
//	configs := []ssh_config.Config{}
//
//	f, _ := os.Open(filepath.Join(os.Getenv("HOME"), ".ssh", "config"))
//	cfg, _ := ssh_config.Decode(f)
//	for _, host := range cfg.Hosts {
//		if host.Matches(alias) {
//			configs = append(configs,
//				ssh_config.Config{
//					Hosts: []*ssh_config.Host{host},
//				},
//			)
//		}
//	}
//
//	return configs
//}

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

//func GetIdentities(files []string) []ssh.AuthMethod {
//	keys := []ssh.AuthMethod
//	for _, f := range files {
//		keys = append(keys, PublicKeyFile(f))
//	}
//	return keys
//}
//
//func GetAll(configs []ssh_config.Config, param string) []string {
//	values := []string
//	for _, c := range configs {
//		values = append(values, c.Get(param))
//	}
//	return values
//}

func main() {
	/*
	   // config
	   // Rand
	   // RekeyThreshold
	   HostKeyCallback
	   // BannerCallback
	   // ClientVersion
	   HostKeyAlgorithms
	   //Timeout: configs[0].Get("Timeout"),
	*/

	alias := "localhost"
	//configs := GetConfigs(alias)
	//clientConfig := &ssh.ClientConfig{
	//	User: configs[0].Get("User"),
	//	Auth: GetIdentities(GetAll(configs, "IdentityFile")),
	//	MACs: GetAll(configs, "MACs"),
	//	KeyExchanges: GetAll(configs, "KeyExchanges"),
	//	HostKeyAlgorithms: GetAll(configs, "HostKeyAlgorithms"),
	//	Ciphers: GetAll(configs, "Ciphers"),
	//}
	//config := &ssh.Config{
	//	MACs:              ssh_config.Get(alias, "MACs"),
	//	KeyExchanges:      ssh_config.Get(alias, "KeyExchanges"),
	//	Ciphers:           ssh_config.Get(alias, "Ciphers"),
	//}
	hostKeyCallback, err := knownhosts.New(filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts"))
	if err != nil {
		panic(err)
	}
	clientConfig := &ssh.ClientConfig{
		//Config: config,
		User:              ssh_config.Get(alias, "User"),
		Auth:              []ssh.AuthMethod{PublicKeyFile(ssh_config.Get(alias, "IdentityFile")),},
		HostKeyCallback: hostKeyCallback,
		//HostKeyAlgorithms: ssh_config.Get(alias, "HostKeyAlgorithms"),
	}

	conn, err := ssh.Dial("tcp", ssh_config.Get(alias, "Hostname")+":"+ssh_config.Get(alias, "Port"), clientConfig)
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
