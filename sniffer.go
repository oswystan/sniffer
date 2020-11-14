package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-redis/redis"
)

type Sniffer interface {
	Sniff()
	Succ() bool
	Message() string
}

type TcpSniffer struct {
	Address string
	Port    uint16
	Timeout uint16
	Retry   uint16
	Service string
	succ    bool
}

type HttpSniffer struct {
	Service string
	Url     string
	Timeout uint16
	Retry   uint16
	succ    bool
}

type RedisSniffer struct {
	Service  string
	Url      string
	Timeout  uint16
	Retry    uint16
	Password string
	DB       int
	succ     bool
}

func NewTcpSniffer(conf *ConfItem, address string) *TcpSniffer {
	return &TcpSniffer{
		Service: conf.Service,
		Address: address,
		Port:    conf.Port,
		Timeout: conf.Timeout,
		Retry:   conf.Retry,
		succ:    false,
	}
}

func NewHttpSniffer(conf *ConfItem) *HttpSniffer {
	return &HttpSniffer{
		Service: conf.Service,
		Url:     conf.Url,
		Timeout: conf.Timeout,
		Retry:   conf.Retry,
		succ:    false,
	}
}

func NewRedisSniffer(conf *ConfItem) *RedisSniffer {
	return &RedisSniffer{
		Service:  conf.Service,
		Url:      conf.Url,
		Password: conf.Password,
		DB:       conf.DB,
		Retry:    conf.Retry,
		succ:     false,
	}
}

func PopSnifferFromFile(conf *ConfItem) []Sniffer {
	var sniffers []Sniffer
	file, err := os.Open(conf.File)
	if err != nil {
		return sniffers
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	for {
		line, _, err := reader.ReadLine()
		if err == io.EOF {
			break
		}
		one := strings.TrimSpace(string(line))
		if len(one) == 0 {
			continue
		}
		sniffers = append(sniffers, NewTcpSniffer(conf, one))
	}
	return sniffers
}

func NewSniffer(conf *ConfItem) []Sniffer {
	var sniffers []Sniffer
	switch conf.Type {
	case "tcp":
		if len(conf.File) != 0 {
			sniffersFromFile := PopSnifferFromFile(conf)
			if sniffersFromFile != nil {
				sniffers = append(sniffers, sniffersFromFile...)
			}
		} else {
			sniffers = append(sniffers, NewTcpSniffer(conf, conf.Address))
		}
	case "http":
		sniffers = append(sniffers, NewHttpSniffer(conf))
	case "redis":
		sniffers = append(sniffers, NewRedisSniffer(conf))
	}

	return sniffers
}

func (s *TcpSniffer) Sniff() {
	addr := fmt.Sprintf("%s:%d", s.Address, s.Port)
DONE:
	for i := uint16(0); i < s.Retry; i++ {
		conn, err := net.DialTimeout("tcp", addr, time.Duration(s.Timeout)*time.Millisecond)
		if err != nil {
			s.succ = false
		} else {
			s.succ = true
			defer conn.Close()
			break DONE
		}
	}
}

func (s *TcpSniffer) Succ() bool {
	return s.succ
}

func (s *TcpSniffer) Message() string {
	return fmt.Sprintf("%s %s %d", s.Service, s.Address, s.Port)
}

func (s *HttpSniffer) Sniff() {
DONE:
	for i := uint16(0); i < s.Retry; i++ {
		client := http.Client{
			Timeout: time.Duration(2 * time.Second),
		}
		resp, err := client.Get(s.Url)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				s.succ = true
			}
			break DONE
		}
	}
}

func (s *HttpSniffer) Succ() bool {
	return s.succ
}

func (s *HttpSniffer) Message() string {
	return fmt.Sprintf("%s %s", s.Service, s.Url)
}

func (s *RedisSniffer) Sniff() {
	cli := redis.NewClient(&redis.Options{
		Addr:     s.Url,
		Password: s.Password, // no password set
		DB:       s.DB,       // use default DB
	})

	_, err := cli.Ping().Result()
	if err == nil {
		s.succ = true
	}
}

func (s *RedisSniffer) Succ() bool {
	return s.succ
}

func (s *RedisSniffer) Message() string {
	return fmt.Sprintf("%s %s", s.Service, s.Url)
}
