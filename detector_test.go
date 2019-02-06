package main

// import "fmt"
import (
	"encoding/json"
	dt "github.com/trustnetworks/analytics-common/datatypes"
	"github.com/trustnetworks/analytics-common/worker"
	"io/ioutil"
	"testing"
	"time"
)

func TestIndicatorAddedToEvent(t *testing.T) {
	var dd dynamicDetector
	dd.Init()

	if len(dd.alerts) != 0 {
		t.Error("Alerts should be empty after init")
	}
	srcIp := "10.8.0.44"
	destIp := "8.8.8.8"
	srcIpVal := "ipv4:" + srcIp
	destIpVal := "ipv4:" + destIp
	a := Alert{
		Device: "theatregoing-mac",
		Type:   "dns",
		Indicator: dt.Indicator{
			Type:        "hostname",
			Value:       "blah.com",
			Category:    "covert.dns-tunnel",
			Probability: 0.9,
			Id:          "b1769a6b-80c0-40e5-9287-a9a5d4262741",
		},
		TTL: 10,
		Src: CommsInfo{
			IP: srcIpVal,
		},
		Dest: CommsInfo{
			IP: destIpVal,
		},
	}
	dd.AddAlert(a)

	event := loadEventFromFile("test_data/single-dns-tunnel-event.json", t)

	dd.handleEvent(event)

	if event.Indicators == nil || len(*event.Indicators) != 1 {
		t.Error("Event did not have an indicator added to it")
	} else {
		ind := (*event.Indicators)[0]
		if ind.Id != "b1769a6b-80c0-40e5-9287-a9a5d4262741" {
			t.Error("indicator ID for DNS tunnelling has been corrupted on event")
		}
		if ind.Type != "hostname" {
			t.Error("Incorrect type on indicator, expected 'host', got '", ind.Type, "'")
		}
		if ind.Value != "blah.com" {
			t.Error("Incorrect value on indicator, expected 'blah.com', got '", ind.Value, "'")
		}
		if ind.Category != "covert.dns-tunnel" {
			t.Error("incorrect category on indicator, expected 'covert.dns-tunnel', got '", ind.Category, "'")
		}
		if ind.Probability != 0.9 {
			t.Error("incorrect probability on indicator, expected 0.9 but got ", ind.Probability)
		}
	}
	dd.cleanup()
}

func TestIndicatorAppendedToEvent(t *testing.T) {
	var dd dynamicDetector
	dd.Init()

	if len(dd.alerts) != 0 {
		t.Error("Alerts should be empty after init")
	}
	srcIp := "10.8.0.44"
	destIp := "8.8.8.8"
	srcIpVal := "ipv4:" + srcIp
	destIpVal := "ipv4:" + destIp
	a := Alert{
		Device: "theatregoing-mac",
		Type:   "dns",
		Indicator: dt.Indicator{
			Type:        "hostname",
			Value:       "blah.com",
			Category:    "covert.dns-tunnel",
			Probability: 0.9,
			Id:          "b1769a6b-80c0-40e5-9287-a9a5d4262741",
		},
		TTL: 10,
		Src: CommsInfo{
			IP: srcIpVal,
		},
		Dest: CommsInfo{
			IP: destIpVal,
		},
	}
	dd.AddAlert(a)

	event := loadEventFromFile("test_data/single-dns-tunnel-event.json", t)
	inds := make([]*dt.Indicator, 0)
	inds = append(inds, &dt.Indicator{
		Id:          "a-test-ioc",
		Description: "a test ioc",
		Type:        "test",
		Value:       "string",
		Category:    "badness",
		Source:      "Trust Networks tests",
	})
	event.Indicators = &inds

	dd.handleEvent(event)

	if len(*event.Indicators) != 2 {
		t.Error("indicator should be appended to existing indicators not overwrite them")
	}
	dd.cleanup()
}

func TestHandleFormatsEventCorrectly(t *testing.T) {
	var dd dynamicDetector
	dd.Init()

	if len(dd.alerts) != 0 {
		t.Error("Alerts should be empty after init")
	}
	srcIp := "10.8.0.44"
	destIp := "8.8.8.8"
	srcIpVal := "ipv4:" + srcIp
	destIpVal := "ipv4:" + destIp
	a := Alert{
		Device: "theatregoing-mac",
		Type:   "dns",
		Indicator: dt.Indicator{
			Type:        "hostname",
			Value:       "blah.com",
			Category:    "covert.dns-tunnel",
			Probability: 0.9,
			Id:          "b1769a6b-80c0-40e5-9287-a9a5d4262741",
		},
		TTL: 10,
		Src: CommsInfo{
			IP: srcIpVal,
		},
		Dest: CommsInfo{
			IP: destIpVal,
		},
	}
	dd.AddAlert(a)

	eventBytes := loadEventAsUint8sFromFile("test_data/single-dns-tunnel-event.json", t)

	// change Send function to save data in variable
	var outputEventBytes *[]byte
	Send = func(_ *worker.Worker, _ string, bs *[]byte) {
		outputEventBytes = bs
	}
	dd.Handle(*eventBytes, nil)

	// read event from send output
	var event dt.Event
	err := json.Unmarshal(*outputEventBytes, &event)
	if err != nil {
		t.Log("JSON unmarshal error: ", err.Error())
	}

	if event.Indicators == nil || len(*event.Indicators) != 1 {
		t.Error("Event did not have an indicator added to it")
	} else {
		ind := (*event.Indicators)[0]
		if ind.Id != "b1769a6b-80c0-40e5-9287-a9a5d4262741" {
			t.Error("indicator ID for DNS tunnelling has been corrupted on event")
		}
		if ind.Type != "hostname" {
			t.Error("Incorrect type on indicator, expected 'host', got '", ind.Type, "'")
		}
		if ind.Value != "blah.com" {
			t.Error("Incorrect value on indicator, expected 'blah.com', got '", ind.Value, "'")
		}
		if ind.Category != "covert.dns-tunnel" {
			t.Error("incorrect category on indicator, expected 'covert.dns-tunnel', got '", ind.Category, "'")
		}
	}
	dd.cleanup()
}

func TestHandleTriggersTimeout(t *testing.T) {
	var dd dynamicDetector
	dd.Init()
	timeoutChan := make(chan time.Time, 1)
	// replace timeout with channel for test purposes
	dd.timeout = timeoutChan

	if len(dd.alerts) != 0 {
		t.Error("Alerts should be empty after init")
	}
	srcIp := "10.8.0.44"
	destIp := "8.8.8.8"
	srcIpVal := "ipv4:" + srcIp
	destIpVal := "ipv4:" + destIp
	a := Alert{
		Device: "theatregoing-mac",
		Type:   "dns",
		Indicator: dt.Indicator{
			Type:        "hostname",
			Value:       "blah.com",
			Category:    "covert.dns-tunnel",
			Probability: 0.9,
			Id:          "b1769a6b-80c0-40e5-9287-a9a5d4262741",
		},
		TTL: 10,
		Src: CommsInfo{
			IP: srcIpVal,
		},
		Dest: CommsInfo{
			IP: destIpVal,
		},
	}
	// mock out the now function
	now := time.Now()
	Now = func() time.Time {
		return now
	}
	dd.AddAlert(a)

	eventBytes := loadEventAsUint8sFromFile("test_data/single-dns-tunnel-event.json", t)

	// change Send function to save data in variable
	outputEventCount := 0
	var outputEventBytes *[]byte
	Send = func(_ *worker.Worker, _ string, bs *[]byte) {
		outputEventBytes = bs
		outputEventCount += 1
	}

	dd.Handle(*eventBytes, nil)

	if len(dd.alerts) != 1 {
		t.Error("Alert should not be timed out until after the TTL")
	}
	if outputEventCount != 1 {
		t.Error("Event should be sent for each received")
	}

	// read event from send output
	var event dt.Event
	err := json.Unmarshal(*outputEventBytes, &event)
	if err != nil {
		t.Log("JSON unmarshal error: ", err.Error())
	}

	if event.Indicators == nil || len(*event.Indicators) != 1 {
		t.Error("Event should have had indicator added whilst alert active")
	}

	// change now time to be past TTL
	Now = func() time.Time {
		return now.Add(time.Second * 15)
	}

	// trigger the timeout timer (dont care what the value is)
	timeoutChan <- now

	dd.Handle(*eventBytes, nil)

	if len(dd.alerts) != 0 {
		t.Error("Alert should be timed out by handle after the TTL")
	}
	if outputEventCount != 2 {
		t.Error("Event should be sent for each received")
	}

	// read event from send output
	var event2 dt.Event
	err = json.Unmarshal(*outputEventBytes, &event2)
	if err != nil {
		t.Log("JSON unmarshal error: ", err.Error())
	}

	if event2.Indicators != nil && len(*event2.Indicators) != 0 {
		t.Error("Event should not have indicator added after alert timed out")
		t.Log(event2.Indicators)
		t.Log(*(*event2.Indicators)[0])
		t.Log(dd.detectorLib.PrintState())
	}
	dd.cleanup()
}

func loadEventFromFile(filename string, t *testing.T) *dt.Event {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Log("File load error: ", err.Error())
		return nil
	}

	var event dt.Event
	err = json.Unmarshal(data, &event)
	if err != nil {
		t.Log("JSON unmarshal error: ", err.Error())
		return nil
	}

	return &event
}

func loadEventAsUint8sFromFile(filename string, t *testing.T) *[]uint8 {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Log("File load error: ", err.Error())
		return nil
	}

	return &data
}
