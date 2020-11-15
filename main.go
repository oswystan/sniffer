package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
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

func yachReport(sniffers []Sniffer) {
	const yachUrl = ""
	const key = ""
	timestamp := time.Now().UnixNano() / 1000000
	sign := fmt.Sprintf("%d\n%s", timestamp, key)
	hash := hmac.New(sha256.New, []byte(key))
	hash.Write([]byte(sign))

	sign = base64.StdEncoding.EncodeToString(hash.Sum(nil))
	sign = url.QueryEscape(sign)
	targetUrl := fmt.Sprintf("%s&timestamp=%d&sign=%s", yachUrl, timestamp, sign)

	for _, one := range sniffers {
		data, _ := json.Marshal(&YachData{
			MsgType: "text",
			Text: YachText{
				Content: one.Message() + " port check failed",
			},
		})
		fmt.Println(string(data))
		resp, err := http.Post(targetUrl, "application/json", bytes.NewReader(data))
		if err == nil {
			defer resp.Body.Close()
		}
		data = nil
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

		fileReport(sniffers, "./sniffer.log")
		yachReport(sniffers)

		wg = nil
		sniffers = nil
		time.Sleep(time.Duration(conf.Interval) * time.Second)
	}
}
