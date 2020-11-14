package main

import (
	"fmt"
	"sync"
	"time"
)

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

func dumpResult(sniffers []Sniffer) {
	for _, one := range sniffers {
		if one.Succ() {
			// fmt.Printf("[SUCC] %s\n", one.Message())
		} else {
			fmt.Printf("[FAIL] %s\n", one.Message())
		}
	}
}

func main() {
	for {
		conf := NewSniffConf("sniffer.yaml")
		sniffers := conf.Propagate()

		ch := make(chan Sniffer, 10)
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

		dumpResult(sniffers)

		time.Sleep(time.Duration(conf.Interval) * time.Second)
	}
}
