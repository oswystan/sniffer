package main

import (
	"fmt"
	"os"
	"sync"
	"time"
)

type YachText struct {
	Content string `json:"content"`
}
type YachData struct {
	MsgType string   `json:"msgtype"`
	Text    YachText `json:"text"`
}

func sniff(ch <-chan Sniffer) {
DONE:
	for {
		select {
		case val, ok := <-ch:
			if ok {
				val.Sniff()
			} else {
				break DONE
			}
		}
	}
}

func consoleReport(sniffers []Sniffer) {
	for _, one := range sniffers {
		if one.Succ() {
			// fmt.Printf("[SUCC] %s\n", one.Message())
		} else {
			fmt.Printf("[FAIL] %s\n", one.Message())
		}
	}
}

func fileReport(sniffers []Sniffer, fn string) {
	file, err := os.OpenFile(fn, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer file.Close()

	for _, one := range sniffers {
		if one.Succ() {
			// fmt.Printf("[SUCC] %s\n", one.Message())
		} else {
			file.WriteString(fmt.Sprintln(time.Now().Format("2006-01-02T15:04:05.000Z07:00"), "[FAIL]", one.Message()))
		}
	}
}

func main() {
	for {
		conf := NewSniffConf("sniffer.yaml")
		sniffers := conf.Propagate()

		ch := make(chan Sniffer, conf.Cocurrent)
		wg := &sync.WaitGroup{}
		wg.Add(conf.Cocurrent)
		for i := 0; i < conf.Cocurrent; i++ {
			go func() {
				sniff(ch)
				wg.Done()
			}()
		}
		for _, sniffer := range sniffers {
			ch <- sniffer
		}
		close(ch)
		wg.Wait()

		consoleReport(sniffers)
		fileReport(sniffers, "./sniffer.log")

		wg = nil
		sniffers = nil
		time.Sleep(time.Duration(conf.Interval) * time.Second)
	}
}
