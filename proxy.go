package proxy

import (
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

type Proxy struct {
	Source Node
	Dest   Node
}

type Node struct {
	IP   string
	Port int
}

func NewProxy(sourceIP string, sourcePort int,
	destIP string, destPort int) *Proxy {
	var proxy Proxy
	proxy.Source.IP = sourceIP
	proxy.Source.Port = sourcePort
	proxy.Dest.IP = destIP
	proxy.Dest.Port = destPort
	return &proxy
}

func (proxy Proxy) EnableRedirect() error {
	cmd := exec.Command("iptables", "-t", "nat", "-A", "PREROUTING",
		"-p", "tcp", "-d", proxy.Source.IP,
		"--dport", fmt.Sprint(proxy.Source.Port),
		"-j", "DNAT", "--to",
		fmt.Sprintf("%s:%d", proxy.Dest.IP, proxy.Dest.Port))
	err := cmd.Run()
	if err != nil {
		return err
	}
	cmd = exec.Command("iptables", "-A", "FORWARD", "-d", proxy.Dest.IP,
		"-p", "tcp", "--dport",
		fmt.Sprint(proxy.Dest.Port), "-j", "ACCEPT")
	cmd.Stdin = strings.NewReader("")
	err = cmd.Run()
	if err != nil {
		return err
	}
	return nil
}

func (proxy Proxy) DisableRedirect() error {
	cmd := exec.Command("iptables", "-t", "nat", "-D", "PREROUTING",
		"-p", "tcp", "-d", proxy.Source.IP,
		"--dport", fmt.Sprint(proxy.Source.Port),
		"-j", "DNAT", "--to",
		fmt.Sprintf("%s:%d", proxy.Dest.IP, proxy.Dest.Port))
	err := cmd.Run()
	if err != nil {
		return err
	}
	return nil
}

func GetEnabledProxies() ([]Proxy, error) {
	proxies := []Proxy{}
	cmd := exec.Command("iptables", "-t", "nat", "-L", "PREROUTING")
	cmd.Stdout = &bytes.Buffer{}
	err := cmd.Run()
	if err != nil {
		return proxies, err
	}
	raw := strings.Split(strings.Trim(
		cmd.Stdout.(*bytes.Buffer).String(), "\n"), "\n")[2:]
	for _, str := range raw {
		tmp := strings.Fields(str)
		if tmp[0] != "DNAT" {
			continue
		}
		if tmp[1] != "tcp" {
			continue
		}
		sourcePort := 0
		sPort := strings.Split(tmp[6], ":")[1]
		if sPort == "http" {
			sourcePort = 80
		} else {
			sourcePort, err = strconv.Atoi(sPort)
			if err != nil {
				continue
			}
		}
		dst := strings.Split(tmp[7], ":")
		dPort, err := strconv.Atoi(dst[2])
		if err != nil {
			continue
		}
		proxies = append(proxies, *NewProxy(
			tmp[4], sourcePort, dst[1], dPort))
	}
	return proxies, nil
}
