package ssher

import (
	"testing"
	"time"
)

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
