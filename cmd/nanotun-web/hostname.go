package main

import "os"

// hostnameOS:平台无关地拿 os.Hostname,分离便于测试 mock。
func hostnameOS() (string, error) { return os.Hostname() }
