package main

import (
	dt "github.com/trustnetworks/analytics-common/datatypes"
	"strconv"
	"testing"
)

func TestDnsTunnelToIOC(t *testing.T) {
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

	ioc := convertAlertToIOC(a)

	if ioc == nil {
		t.Fatal("ioc returned is nil, ioc type must not be handled correctly")
	}
	// verify IOC indicator
	if ioc.Indicator == nil {
		t.Fatal("dns tunnel IOC should have indicator at top level")
	}
	if ioc.Indicator.Value != dnsName {
		t.Error("dns tunnel IOC indicator should be the value in the alert")
	}
	if ioc.Indicator.Type != "hostname" || ioc.Indicator.Category != "covert.dns-tunnel" || ioc.Indicator.Id != "b1769a6b-80c0-40e5-9287-a9a5d4262741" {
		t.Error("dns tunnel IOC indicator has incorrect values, should be type = host and category = covert.dns-tunnel" +
			"ID = b1769a6b-80c0-40e5-9287-a9a5d4262741")
	}

	// check top node is correctly formed
	if ioc.Operator != "AND" {
		t.Error("dns tunnel IOC use Boolean AND to combine multiple parts of the indicator")
	}
	if len(ioc.Children) != 4 {
		t.Error("dns tunnel IOC should have 4 children, device, dns, and both IPs")
	}

	// verify the child nodes
	seenDevice := false
	seenDns := false
	seenSrcIP := false
	seenDestIP := false
	for _, node := range ioc.Children {
		switch node.Pattern.Type {
		case "device":
			seenDevice = true
			if node.Pattern.Value != device {
				t.Error("device pattern on dns tunnel IOC should contain the device from the alert")
			}
		case "hostname":
			seenDns = true
			if node.Pattern.Value != dnsName {
				t.Error("hostname pattern on dns tunnel IOC should contain the dns value from the alert")
			}
			if node.Pattern.Match != "dns" {
				t.Error("hostname pattern on dns tunnel IOC should use dns match algorithm")
			}
		case "src.ipv4":
			seenSrcIP = true
			if node.Pattern.Value != srcIp {
				t.Error("src ip pattern on dns tunnel IOC should contain the src ip from the alert")
			}
		case "dest.ipv4":
			seenDestIP = true
			if node.Pattern.Value != destIp {
				t.Error("dest ip pattern on dns tunnel IOC should contain the dest ip from the alert")
			}
		}
	}

	if (!seenDevice) || (!seenDns) || (!seenSrcIP) || (!seenDestIP) {
		t.Error("have not seen all the child IOCs that were expected on a DNS tunnel IOC")
	}

	// verify IDs are unique
	idSet := make(map[string]bool)
	idSet[ioc.ID] = true
	idSet[ioc.Children[0].ID] = true
	idSet[ioc.Children[1].ID] = true
	idSet[ioc.Children[2].ID] = true
	idSet[ioc.Children[3].ID] = true
	if len(idSet) != 5 {
		t.Error("ids are not unique on each node of IOC")
	}
}

func TestIPsToIOC(t *testing.T) {
	srcIp := "123.123.123.123"
	destIp := "321.321.321.321"
	srcIpVal := "ipv4:" + srcIp
	destIpVal := "ipv4:" + destIp
	device := "a-dev"

	a := Alert{
		Device: device,
		Type:   "ip-comms",
		Indicator: dt.Indicator{
			Type:        "ip-comms",
			Value:       destIp,
			Category:    "rat.dark-comet",
			Probability: 0.9,
			Id:          "31485536-9517-4ffb-bc4d-8c5369029cbb",
		},
		TTL: 10,
		Src: CommsInfo{
			IP: srcIpVal,
		},
		Dest: CommsInfo{
			IP: destIpVal,
		},
	}

	ioc := convertAlertToIOC(a)

	if ioc == nil {
		t.Fatal("ioc returned is nil, ioc type must not be handled correctly")
	}
	// verify IOC indicator
	if ioc.Indicator == nil {
		t.Fatal("dark-comet IOC should have indicator at top level")
	}
	if ioc.Indicator.Type != "ip-comms" || ioc.Indicator.Category != "rat.dark-comet" || ioc.Indicator.Id != "31485536-9517-4ffb-bc4d-8c5369029cbb" {
		t.Error("dark-comet IOC indicator has incorrect values, should be type = ip-comms and category = rat.dark-comet, "+
			"id = 31485536-9517-4ffb-bc4d-8c5369029cbb"+
			"got : ", ioc.Indicator.Type, ", ", ioc.Indicator.Category, ", ", ioc.Indicator.Id)
	}

	// check top node is correctly formed
	if ioc.Operator != "AND" {
		t.Error("dark-comet IOC use Boolean AND to combine multiple parts of the indicator")
	}
	if len(ioc.Children) != 3 {
		t.Error("dark-comet IOC should have 3 children, device, and both IPs")
	}

	// verify the child nodes
	seenDevice := false
	seenSrcIP := false
	seenDestIP := false
	for _, node := range ioc.Children {
		switch node.Pattern.Type {
		case "device":
			seenDevice = true
			if node.Pattern.Value != device {
				t.Error("device pattern on dark-comet IOC should contain the device from the alert")
			}
		case "src.ipv4":
			seenSrcIP = true
			if node.Pattern.Value != srcIp {
				t.Error("src ip pattern on dark-comet IOC should contain the src ip from the alert")
			}
		case "dest.ipv4":
			seenDestIP = true
			if node.Pattern.Value != destIp {
				t.Error("dest ip pattern on dark-comet IOC should contain the dest ip from the alert")
			}
		}
	}

	if (!seenDevice) || (!seenSrcIP) || (!seenDestIP) {
		t.Error("have not seen all the child IOCs that were expected on a Dark Comet IOC")
	}

	// verify IDs are unique
	idSet := make(map[string]bool)
	idSet[ioc.ID] = true
	idSet[ioc.Children[0].ID] = true
	idSet[ioc.Children[1].ID] = true
	idSet[ioc.Children[2].ID] = true
	if len(idSet) != 4 {
		t.Error("ids are not unique on each node of IOC")
	}
}

func TestDnsTunnelNoIpsToIOC(t *testing.T) {
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
	}

	ioc := convertAlertToIOC(a)

	if ioc == nil {
		t.Fatal("ioc returned is nil, ioc type must not be handled correctly")
	}
	// verify IOC indicator
	if ioc.Indicator == nil {
		t.Fatal("dns tunnel IOC should have indicator at top level")
	}
	if ioc.Indicator.Value != dnsName {
		t.Error("dns tunnel IOC indicator should be the value in the alert")
	}
	if ioc.Indicator.Type != "hostname" || ioc.Indicator.Category != "covert.dns-tunnel" || ioc.Indicator.Id != "b1769a6b-80c0-40e5-9287-a9a5d4262741" {
		t.Error("dns tunnel IOC indicator has incorrect values, should be type = host and category = covert.dns-tunnel" +
			"ID = b1769a6b-80c0-40e5-9287-a9a5d4262741")
	}

	// check top node is correctly formed
	if ioc.Operator != "AND" {
		t.Error("dns tunnel IOC use Boolean AND to combine multiple parts of the indicator")
	}
	if len(ioc.Children) != 2 {
		t.Error("dns tunnel IOC should have 2 children, device, dns")
	}

	// verify the child nodes
	seenDevice := false
	seenDns := false
	for _, node := range ioc.Children {
		switch node.Pattern.Type {
		case "device":
			seenDevice = true
			if node.Pattern.Value != device {
				t.Error("device pattern on dns tunnel IOC should contain the device from the alert")
			}
		case "hostname":
			seenDns = true
			if node.Pattern.Value != dnsName {
				t.Error("hostname pattern on dns tunnel IOC should contain the dns value from the alert")
			}
			if node.Pattern.Match != "dns" {
				t.Error("hostname pattern on dns tunnel IOC should use dns match algorithm")
			}
		}
	}

	if (!seenDevice) || (!seenDns) {
		t.Error("have not seen all the child IOCs that were expected on a DNS tunnel IOC")
	}

	// verify IDs are unique
	idSet := make(map[string]bool)
	idSet[ioc.ID] = true
	idSet[ioc.Children[0].ID] = true
	idSet[ioc.Children[1].ID] = true
	if len(idSet) != 3 {
		t.Error("ids are not unique on each node of IOC")
	}
}

func TestBidirectIPsToIOC(t *testing.T) {
	srcIp := "123.123.123.123"
	destIp := "321.321.321.321"
	srcIpVal := "ipv4:" + srcIp
	destIpVal := "ipv4:" + destIp
	dPort := 12345
	device := "a-dev"

	a := Alert{
		Device: device,
		Type:   "bidirect-ip-comms",
		Indicator: dt.Indicator{
			Type:        "ip-comms",
			Value:       destIp,
			Category:    "rat.dark-comet",
			Probability: 0.9,
			Id:          "31485536-9517-4ffb-bc4d-8c5369029cbb",
		},
		TTL: 10,
		Src: CommsInfo{
			IP: srcIpVal,
		},
		Dest: CommsInfo{
			IP:   destIpVal,
			Port: dPort,
		},
	}

	ioc := convertAlertToIOC(a)

	if ioc == nil {
		t.Fatal("ioc returned is nil, ioc type must not be handled correctly")
	}
	// verify IOC indicator
	if ioc.Indicator == nil {
		t.Fatal("dark-comet IOC should have indicator at top level")
	}

	// check top node is correctly formed
	if ioc.Operator != "AND" {
		t.Error("dark-comet IOC use Boolean AND to combine multiple parts of the indicator")
	}
	if len(ioc.Children) != 3 {
		t.Error("dark-comet IOC should have 3 children, device, src and dest")
	}

	// verify the child nodes
	seenDevice := false
	seenORs := 0
	for _, node := range ioc.Children {
		if node.Operator == "" {
			if node.Pattern.Type == "device" {
				seenDevice = true
				if node.Pattern.Value != device {
					t.Error("device pattern on dark-comet IOC should contain the device from the alert")
				}
			}
		} else if node.Operator == "OR" {
			seenORs++
			// expecting 2 children from each OR, 1 just IP and 1 IP AND Port
			justIpNode := node.Children[0]
			if justIpNode.Pattern == nil {
				t.Error("expected first node to be just an IP pattern node, but didnt have a pattern")
			} else {
				if justIpNode.Pattern.Value != srcIp {
					t.Error("expected first node to be the src IP, but got ", justIpNode.Pattern.Value)
				}
			}
			ipPortNode := node.Children[1]
			if ipPortNode.Operator != "AND" {
				t.Error("expected second node to be just an AND node, but it isn't")
			} else {
				if ipPortNode.Children[0].Pattern == nil {
					t.Error("expected second node child to have IP, but pattern empty ")
				} else {
					if ipPortNode.Children[0].Pattern.Value != destIp {
						t.Error("expected first node to be the dest IP, but got ", ipPortNode.Children[0].Pattern)
					}
				}
				if ipPortNode.Children[1].Pattern == nil {
					t.Error("expected second node child to have port, but pattern empty ")
				} else {
					if ipPortNode.Children[1].Pattern.Value != strconv.Itoa(dPort) {
						t.Error("expected first node to be the port, but got ", ipPortNode.Children[1].Pattern)
					}
				}
			}
		}
	}

	if (!seenDevice) || (seenORs != 2) {
		t.Error("have not seen all the child IOCs that were expected on a Bi directional IOC")
	}
}
