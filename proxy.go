package proxy

import (
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

var re = regexp.MustCompile("/\\* (.*) \\*/")

type Proxy struct {
	Source  Node
	Dest    Node
	Comment string
}

type Node struct {
	IP   string
	Port int
}

func NewProxy(sourceIP string, sourcePort int,
	destIP string, destPort int, comment string,
) *Proxy {
	var proxy Proxy
	proxy.Source.IP = sourceIP
	proxy.Source.Port = sourcePort
	proxy.Dest.IP = destIP
	proxy.Dest.Port = destPort
	proxy.Comment = comment
	return &proxy
}

func (proxy Proxy) EnableForwarding() error {
	cmd := exec.Command("iptables", "-t", "nat", "-A", "PREROUTING",
		"-p", "tcp", "-d", proxy.Source.IP,
		"--dport", fmt.Sprint(proxy.Source.Port),
		"-j", "DNAT", "--to",
		fmt.Sprintf("%s:%d", proxy.Dest.IP, proxy.Dest.Port),
		"-m", "comment", "--comment", proxy.Comment,
	)
	err := cmd.Run()
	if err != nil {
		return err
	}
	return nil
}

func (proxy Proxy) DisableForwarding() error {
	cmd := exec.Command("iptables", "-t", "nat", "-D", "PREROUTING",
		"-p", "tcp", "-d", proxy.Source.IP,
		"--dport", fmt.Sprint(proxy.Source.Port),
		"-j", "DNAT", "--to",
		fmt.Sprintf("%s:%d", proxy.Dest.IP, proxy.Dest.Port),
		"-m", "comment", "--comment", proxy.Comment,
	)
	err := cmd.Run()
	if err != nil {
		return err
	}
	return nil
}

func GetEnabledProxies() ([]Proxy, error) {
	result := []Proxy{}
	cmd := exec.Command("iptables", "-t", "nat", "-L", "PREROUTING")
	cmd.Stdout = &bytes.Buffer{}
	err := cmd.Run()
	if err != nil {
		return result, err
	}
	raw := strings.Split(strings.Trim(
		cmd.Stdout.(*bytes.Buffer).String(), "\n"), "\n")[2:]
	for _, str := range raw {
		com := re.FindStringSubmatch(str)[1]
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
		dst := strings.Split(tmp[len(tmp)-1], ":")
		dPort, err := strconv.Atoi(dst[2])
		if err != nil {
			continue
		}
		result = append(result, *NewProxy(
			tmp[4], sourcePort, dst[1], dPort, com))
	}
	return result, nil
}

func FilterByComment(proxies []Proxy, comment string) []Proxy {
	result := []Proxy{}
	for _, prx := range proxies {
		if prx.Comment == comment {
			result = append(result, prx)
		}
	}
	return result
}
