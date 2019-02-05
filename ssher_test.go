package ssher

import (
	"golang.org/x/crypto/ssh"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func ExampleClientConfig_defaults() {
	sshConfig, hostPort, err := ClientConfig("myhost.mydomain.com", "")
	if err != nil {
		// Handle error here...
	}
	_, err = ssh.Dial("tcp", hostPort, sshConfig)
	if err != nil {
		// Handle error here...
	}
}

func ExampleClientConfig_custom() {
	sshConfig, hostPort, err := ClientConfig("myhost.mydomain.com", "~/somedir/my_ssh_config")
	if err != nil {
		// Handle error here...
	}
	_, err = ssh.Dial("tcp", hostPort, sshConfig)
	if err != nil {
		// Handle error here...
	}
}

func TestClientConfigDefaults(t *testing.T) {
	config, connectString, err := ClientConfig("asdf", "")
	if err != nil {
		t.Errorf("TestClientConfig defaults: %v", err)
	}
	if config == nil || connectString == "" {
		t.Errorf("TestClientConfig defaults: nothing returned")
	}
}

func TestClientConfigLocalhost(t *testing.T) {
	config, connectString, err := ClientConfig("127.0.1.2", "testdata/config1")
	if err != nil {
		t.Errorf("TestClientConfig: %v", err)
	}
	expectedConnectString := "127.0.0.1:22"
	if connectString != expectedConnectString {
		t.Errorf("TestClientConfig 127.0.1.2: connectString %v != %v", connectString, expectedConnectString)
	}
	if len(config.Auth) < 1 {
		t.Errorf("TestClientConfig 127.0.1.2: config.Auth has no methods")
	}
	if config.User != "testuser" {
		t.Errorf("TestClientConfig 127.0.1.2: config.User %v != %v", config.User, "testuser")
	}
}

func TestClientConfigFallback(t *testing.T) {
	config, connectString, err := ClientConfig("ConnectTimeout", "testdata/config1")
	if err != nil {
		t.Errorf("TestClientConfig ConnectTimeout: %v", err)
	}
	expectedConnectString := "ConnectTimeout:1234"
	if connectString != expectedConnectString {
		t.Errorf("TestClientConfig ConnectTimeout: connectString %v != %v", connectString, expectedConnectString)
	}
	if config.Timeout != time.Duration(1)*time.Second {
		t.Errorf("TestClientConfig ConnectTimeout: config.Timeout != 1 second")
	}
	if config.User != "testuser2" {
		t.Errorf("TestClientConfig ConnectTimeout: config.User %v != %v", config.User, "testuser2")
	}
}

func TestClientConfigFailedTimeout(t *testing.T) {
	_, _, err := ClientConfig("FailedTimeout", "testdata/config1")
	if err == nil {
		t.Errorf("TestClientConfig FailedTimeout: should have errored")
	}
}

func TestClientConfigNonexist(t *testing.T) {
	_, _, err := ClientConfig("asdf", "testdata/configDoesNotExist")
	if err == nil {
		t.Errorf("TestClientConfig Nonexist: should have errored")
	}
}

func TestClientConfigBad(t *testing.T) {
	_, _, err := ClientConfig("asdf", "testdata/configBad")
	if err == nil {
		t.Errorf("TestClientConfig Bad: should have errored")
	}
}

func TestActuallyConnecting(t *testing.T) {
	// I can't use the docker SDK here,
	// since they don't manage their dependencies in a sane way,
	// and it breaks go 1.11 modules.
	port := "32080"

	testdataDir, err := filepath.Abs("testdata")
	if err != nil {
		t.Error(err)
		return
	}
	known_hosts := testdataDir + "/docker_known_hosts"
	identity := testdataDir + "/ssh_host_rsa_key"

	containerIDBytes, err := exec.Command("docker", "run", "-d", "--rm",
		"-p", port+":22",
		"ssher-sshd").Output()
	if err != nil {
		t.Error(err)
		return
	}
	containerID := strings.TrimSpace(string(containerIDBytes))

	hasConnected := false
	cleanup := func() {
		// Docker waits an extra 10 seconds if it hasn't finished launching
		// the process when we try to stop it.
		if !hasConnected {
			time.Sleep(time.Millisecond * 100)
		}
		exec.Command("docker", "stop", containerID).Run()
	}
	defer cleanup()

	f, err := os.Create("testdata/docker")
	if err != nil {
		t.Error(err)
		return
	}
	_, err = f.WriteString("Host docker\nUser testuser\n    Hostname 127.0.0.1\n    Port " + port + "\n    UserKnownHostsFile " + known_hosts + "\n    IdentityFile " + identity + "\n")
	if err != nil {
		t.Error(err)
		return
	}
	f.Sync()

	sshConfig, hostPort, err := ClientConfig("docker", "testdata/docker")
	if err != nil {
		t.Error(err)
		return
	}
	for i := 0; i < 3; i++ {
		_, err = ssh.Dial("tcp", hostPort, sshConfig)
		if err == nil {
			hasConnected = true
			break
		}
		time.Sleep(time.Second * 1)
	}
	if err != nil {
		t.Error(err)
		return
	}
}
