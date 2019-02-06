package main

// import "fmt"
import (
	"encoding/json"
	dt "github.com/trustnetworks/analytics-common/datatypes"
	ind "github.com/trustnetworks/indicators"
	"io/ioutil"
	"testing"
	"time"
)

func TestHandleNewAlert(t *testing.T) {
	var dd dynamicDetector
	dd.Init()

	if len(dd.alerts) != 0 {
		t.Error("Alerts should be empty after init")
	}
	srcIp := "123.123.123.123"
	destIp := "321.321.321.321"
	srcIpVal := "ipv4:" + srcIp
	destIpVal := "ipv4:" + destIp
	a := Alert{
		Device: "a-dev",
		Type:   "dns",
		Indicator: dt.Indicator{
			Type:        "hostname",
			Value:       "blah",
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
	now := time.Now()
	dd.AddAlert(a)

	if len(dd.alerts) != 1 {
		t.Error("Alert has not been added to detector state")
	}

	if dd.alerts[a] != now.Unix()+a.TTL {
		t.Error("Alert expiry should be time added + TTL")
	}

	dd.cleanup()
}

func TestTimeoutAlerts(t *testing.T) {
	var dd dynamicDetector
	dd.Init()

	if len(dd.alerts) != 0 {
		t.Error("Alerts should be empty after init")
	}
	srcIp := "123.123.123.123"
	destIp := "321.321.321.321"
	srcIpVal := "ipv4:" + srcIp
	destIpVal := "ipv4:" + destIp
	a := Alert{
		Device: "a-dev",
		Type:   "dns",
		Indicator: dt.Indicator{
			Type:        "hostname",
			Value:       "blah",
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

	// mock out the now function to be 15 mins in future
	now := time.Now()
	Now = func() time.Time {
		return now.Add(time.Second * time.Duration(15))
	}

	if len(dd.alerts) != 1 {
		t.Error("Alert has not been added to detector state")
	}

	dd.TimeoutAlerts()

	if len(dd.alerts) != 0 {
		t.Error("TimeoutAlerts should remove any ")
	}
	dd.cleanup()
}

func TestDuplicateAlertIncreaseTimeout(t *testing.T) {
	var dd dynamicDetector
	dd.Init()

	if len(dd.alerts) != 0 {
		t.Error("Alerts should be empty after init")
	}
	srcIp := "123.123.123.123"
	destIp := "321.321.321.321"
	srcIpVal := "ipv4:" + srcIp
	destIpVal := "ipv4:" + destIp
	a := Alert{
		Device: "a-dev",
		Type:   "dns",
		Indicator: dt.Indicator{
			Type:        "hostname",
			Value:       "blah",
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
	// mock out the now function to be 15 mins in future
	now := time.Now()
	Now = func() time.Time {
		return now
	}
	dd.AddAlert(a)

	// change now time to be 5 seconds ahead
	Now = func() time.Time {
		return now.Add(time.Second * 5)
	}

	dd.AddAlert(a)

	if len(dd.alerts) != 1 {
		t.Error("Duplicate alerts should not affect the number of alerts")
	}

	// expected timeout is the 5 seconds time change + the TTL
	expected := 5 + int(a.TTL)
	if dd.alerts[a] != now.Add(time.Second*time.Duration(expected)).Unix() {
		t.Error("Alert expiry should be updated for new alert")
	}
	dd.cleanup()

}

func TestNegativeTTLError(t *testing.T) {
	var dd dynamicDetector
	dd.Init()

	if len(dd.alerts) != 0 {
		t.Error("Alerts should be empty after init")
	}
	srcIp := "123.123.123.123"
	destIp := "321.321.321.321"
	srcIpVal := "ipv4:" + srcIp
	destIpVal := "ipv4:" + destIp
	a := Alert{
		Device: "a-dev",
		Type:   "dns",
		Indicator: dt.Indicator{
			Type:        "hostname",
			Value:       "blah",
			Category:    "covert.dns-tunnel",
			Probability: 0.9,
			Id:          "b1769a6b-80c0-40e5-9287-a9a5d4262741",
		},
		TTL: -10,
		Src: CommsInfo{
			IP: srcIpVal,
		},
		Dest: CommsInfo{
			IP: destIpVal,
		},
	}
	dd.AddAlert(a)

	if len(dd.alerts) != 0 {
		t.Error("Alert should not be added to state if it has negative TTL")
	}
	dd.cleanup()

}

func TestAlertCreatesIOC(t *testing.T) {
	var dd dynamicDetector
	dd.Init()

	if len(dd.alertToIOCMap) != 0 {
		t.Error("IOCs should empty after init")
	}
	srcIp := "123.123.123.123"
	destIp := "321.321.321.321"
	srcIpVal := "ipv4:" + srcIp
	destIpVal := "ipv4:" + destIp
	dnsName := "blah.com"
	device := "a-dev"

	a := Alert{
		Device: device,
		Type:   "dns",
		Indicator: dt.Indicator{
			Type:        "hostname",
			Value:       dnsName,
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

	if len(dd.alertToIOCMap) == 0 {
		t.Error("Alert should create an IOC")
	}
	dd.cleanup()

}

func TestDuplicateIOCsNotCreated(t *testing.T) {
	var dd dynamicDetector
	dd.Init()

	if len(dd.alertToIOCMap) != 0 {
		t.Error("IOCs should empty after init")
	}
	srcIp := "123.123.123.123"
	destIp := "321.321.321.321"
	srcIpVal := "ipv4:" + srcIp
	destIpVal := "ipv4:" + destIp
	dnsName := "blah.com"
	device := "a-dev"

	a := Alert{
		Device: device,
		Type:   "dns",
		Indicator: dt.Indicator{
			Type:        "hostname",
			Value:       dnsName,
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
	dd.AddAlert(a)

	if len(dd.alertToIOCMap) != 1 {
		t.Error("only 1 IOC should be created for duplicate alerts")
	}
	dd.cleanup()

}

func TestTimedOutEventsShouldRemoveIOCs(t *testing.T) {
	var dd dynamicDetector
	dd.Init()

	if len(dd.alertToIOCMap) != 0 {
		t.Error("IOCs should empty after init")
	}
	srcIp := "123.123.123.123"
	destIp := "321.321.321.321"
	srcIpVal := "ipv4:" + srcIp
	destIpVal := "ipv4:" + destIp
	dnsName := "blah.com"
	device := "a-dev"

	a := Alert{
		Device: device,
		Type:   "dns",
		Indicator: dt.Indicator{
			Type:        "hostname",
			Value:       dnsName,
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
	// mock out the now function to be 15 mins in future
	now := time.Now()
	Now = func() time.Time {
		return now
	}
	dd.AddAlert(a)

	// change now time to be 15 seconds ahead (past TTL)
	Now = func() time.Time {
		return now.Add(time.Second * 15)
	}

	dd.TimeoutAlerts()

	if len(dd.alertToIOCMap) != 0 {
		t.Error("IOC should be removed when alert timesout")
	}
	dd.cleanup()

}

func TestIOCsLoadedIntoDetectorLib(t *testing.T) {
	var dd dynamicDetector
	dd.Init()

	if dd.detectorLib.GetNumberOfNodes() != 0 {
		t.Error("number of IOC nodes should be empty when started")
	}

	srcIp := "123.123.123.123"
	destIp := "321.321.321.321"
	srcIpVal := "ipv4:" + srcIp
	destIpVal := "ipv4:" + destIp
	dnsName := "blah.com"
	device := "a-dev"

	a := Alert{
		Device: device,
		Type:   "dns",
		Indicator: dt.Indicator{
			Type:        "hostname",
			Value:       dnsName,
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

	if dd.detectorLib.GetNumberOfNodes() != 5 {
		t.Error("number of IOC nodes should be the number of nodes in IOC added")
	}
	dd.cleanup()

}

func TestIOCsRemovedShouldBeRemovedFromDetectorLib(t *testing.T) {
	var dd dynamicDetector
	dd.Init()

	if dd.detectorLib.GetNumberOfNodes() != 0 {
		t.Error("number of IOC nodes should be empty when started")
	}

	srcIp := "123.123.123.123"
	destIp := "321.321.321.321"
	srcIpVal := "ipv4:" + srcIp
	destIpVal := "ipv4:" + destIp
	dnsName := "blah.com"
	device := "a-dev"

	a := Alert{
		Device: device,
		Type:   "dns",
		Indicator: dt.Indicator{
			Type:        "hostname",
			Value:       dnsName,
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
	now := time.Now()
	Now = func() time.Time {
		return now
	}
	dd.AddAlert(a)

	// change now time to be 15 seconds ahead (past TTL)
	Now = func() time.Time {
		return now.Add(time.Second * 15)
	}

	dd.TimeoutAlerts()

	if dd.detectorLib.GetNumberOfNodes() != 0 {
		t.Error("number of IOC nodes should be empty after IOC is removed")
	}
	dd.cleanup()

}

func TestMultiAddMultiTimeout(t *testing.T) {
	var dd dynamicDetector
	dd.Init()

	if len(dd.alerts) != 0 {
		t.Error("Alerts should be empty after init")
	}
	if dd.detectorLib.GetNumberOfNodes() != 0 {
		t.Error("number of IOC nodes should be empty when started")
	}

	srcIp := "123.123.123.123"
	destIp := "321.321.321.321"
	srcIpVal := "ipv4:" + srcIp
	destIpVal := "ipv4:" + destIp
	dnsName := "blah.com"
	device := "a-dev"

	a := Alert{
		Device: device,
		Type:   "dns",
		Indicator: dt.Indicator{
			Type:        "hostname",
			Value:       dnsName,
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
	now := time.Now()
	Now = func() time.Time {
		return now
	}
	dd.AddAlert(a)

	srcIp2 := "23.123.123.123"
	destIp2 := "21.321.321.321"
	srcIpVal2 := "ipv4:" + srcIp2
	destIpVal2 := "ipv4:" + destIp2
	dnsName2 := "a.tunnel.com"
	device2 := "a-n-other-dev"

	a2 := Alert{
		Device: device2,
		Type:   "dns",
		Indicator: dt.Indicator{
			Type:        "hostname",
			Value:       dnsName2,
			Category:    "covert.dns-tunnel",
			Probability: 0.9,
			Id:          "b1769a6b-80c0-40e5-9287-a9a5d4262741",
		},
		TTL: 20,
		Src: CommsInfo{
			IP: srcIpVal2,
		},
		Dest: CommsInfo{
			IP: destIpVal2,
		},
	}

	// add second alert
	dd.AddAlert(a2)

	if len(dd.alerts) != 2 {
		t.Error("All alerts added should be stored in alert list")
	}
	if dd.detectorLib.GetNumberOfNodes() != 10 {
		t.Error("number of IOC nodes should be 10, 5 for each ioc")
	}

	// change now time to be 15 seconds ahead (past 1 TTL)
	Now = func() time.Time {
		return now.Add(time.Second * 15)
	}

	dd.TimeoutAlerts()

	if len(dd.alerts) != 1 {
		t.Error("1 alert should remain after timing out")
	}
	if dd.detectorLib.GetNumberOfNodes() != 5 {
		t.Error("number of IOC nodes should be 5 for each ioc for just 1 alert")
	}

	// change now time to be 25 seconds ahead (past both TTL)
	Now = func() time.Time {
		return now.Add(time.Second * 25)
	}

	dd.TimeoutAlerts()

	if len(dd.alerts) != 0 {
		t.Error("alerts should be empty after everything has timed out")
	}
	if dd.detectorLib.GetNumberOfNodes() != 0 {
		t.Error("ioc nodes should be 0 after all alerts timed out")
	}
	dd.cleanup()

}

func TestRemovalOfIOCWithNOT(t *testing.T) {
	var dd dynamicDetector
	dd.Init()

	srcIp := "123.123.123.123"
	destIp := "321.321.321.321"
	srcIpVal := "ipv4:" + srcIp
	destIpVal := "ipv4:" + destIp
	a := Alert{
		Device: "a-dev",
		Type:   "test",
		Indicator: dt.Indicator{
			Type:        "hostname",
			Value:       "blah",
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
	now := time.Now()

	// as we dont have any alert types (currently) that add NOTs, manual create
	// and add one to state to check timeout and removal of IOC
	ioc := loadIOCFromFile("test_data/not-ioc.json", t)
	dd.alerts[a] = now.Unix() + 10
	dd.alertToIOCMap[a] = ioc
	dd.detectorLib.LoadNode(ioc)

	if len(dd.alerts) != 1 {
		t.Error("Alert should have been added to alert list")
	}
	if dd.detectorLib.GetNumberOfNodes() != 6 {
		t.Error("number of IOC nodes should be 6 for test ioc")
	}
	if dd.detectorLib.GetNumberOfNots() != 1 {
		t.Error("there should be 1 NOT node")
	}

	// change now time to be 15 seconds ahead (past TTL)
	Now = func() time.Time {
		return now.Add(time.Second * 15)
	}

	dd.TimeoutAlerts()

	if len(dd.alerts) != 0 {
		t.Error("Alert should have been removed from alert list")
	}
	if dd.detectorLib.GetNumberOfNodes() != 0 {
		t.Error("all IOC nodes should have been removed")
	}
	if dd.detectorLib.GetNumberOfNots() != 0 {
		t.Error("all NOT nodes should have been removed")
	}
	dd.cleanup()

}

func TestUAIOCLoadedIntoDetectorLib(t *testing.T) {
	var dd dynamicDetector
	dd.Init()

	if dd.detectorLib.GetNumberOfNodes() != 0 {
		t.Error("number of IOC nodes should be empty when started")
	}

	userAgent := "Testing 123"

	a := Alert{
		Type:   "dns",
		Indicator: dt.Indicator{
			Type:        "useragent",
			Value:       userAgent,
			Category:    "anomaly.useragent",
			Probability: 0.9,
			Id:          "aaaa9a6b-80c0-40e5-9287-a9a5d4262741",
		},
		TTL: 10,
	}
	dd.AddAlert(a)
	if dd.detectorLib.GetNumberOfNodes() != 2 {
		t.Error("number of IOC nodes should be the number of nodes in IOC added")
	}
	dd.cleanup()

}

func loadIOCFromFile(filename string, t *testing.T) *ind.IndicatorNode {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Log("File load error: ", err.Error())
		return nil
	}

	var node ind.IndicatorNode
	err = json.Unmarshal(data, &node)
	if err != nil {
		t.Log("JSON unmarshal error: ", err.Error())
		return nil
	}

	return &node
}
