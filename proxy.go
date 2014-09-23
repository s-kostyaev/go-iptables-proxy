package proxy

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

type Proxy struct {
	Source  Node
	Dest    Node
	Enabled bool
}

type Node struct {
	IP   string
	Port int
}

func NewProxy(sourceIP string, sourcePort int, destIP string, destPort int) *Proxy {
	var proxy Proxy
	proxy.Source.IP = sourceIP
	proxy.Source.Port = sourcePort
	proxy.Dest.IP = destIP
	proxy.Dest.Port = destPort
	return &proxy
}

func (proxy *Proxy) Enable() error {
	if proxy.Enabled {
		return nil
	}
	cmd := exec.Command("iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp",
		"-d", proxy.Source.IP, "--dport", fmt.Sprint(proxy.Source.Port),
		"-j", "DNAT", "--to", fmt.Sprintf("%s:%d", proxy.Dest.IP, proxy.Dest.Port))
	cmd.Stdin = strings.NewReader("")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return err
	}
	cmd = exec.Command("iptables", "-A", "FORWARD", "-d", proxy.Dest.IP,
		"-p", "tcp", "--dport", fmt.Sprint(proxy.Dest.Port), "-j", "ACCEPT")
	cmd.Stdin = strings.NewReader("")
	cmd.Stdout = &out
	err = cmd.Run()
	if err != nil {
		return err
	}
	proxy.Enabled = true
	return nil
}

func (proxy *Proxy) Disable() error {
	if !proxy.Enabled {
		return nil
	}
	cmd := exec.Command("iptables", "-t", "nat", "-D", "PREROUTING", "-p", "tcp",
		"-d", proxy.Source.IP, "--dport", fmt.Sprint(proxy.Source.Port),
		"-j", "DNAT", "--to", fmt.Sprintf("%s:%d", proxy.Dest.IP, proxy.Dest.Port))
	cmd.Stdin = strings.NewReader("")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return err
	}
	proxy.Enabled = false
	return nil

}
