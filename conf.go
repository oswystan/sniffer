package main

import (
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

type ConfItem struct {
	Type     string
	Service  string
	Address  string
	Port     uint16
	Timeout  uint16
	Retry    uint16
	File     string
	Url      string
	Password string
	DB       int
}

type SniffConf struct {
	FileName  string
	Cocurrent int        `yaml:"cocurrent"`
	Interval  int        `yaml:"interval"`
	Services  []ConfItem `yaml:"services"`
}

func NewSniffConf(fn string) *SniffConf {
	return &SniffConf{
		FileName: fn,
	}
}

func (conf *SniffConf) Propagate() []Sniffer {
	all := make([]Sniffer, 0, 10)
	data, err := ioutil.ReadFile(conf.FileName)
	if err != nil {
		return nil
	}
	err = yaml.Unmarshal(data, conf)
	for _, srv := range conf.Services {
		sniffer := NewSniffer(&srv)
		if sniffer != nil {
			all = append(all, sniffer...)
		}
	}

	return all
}
