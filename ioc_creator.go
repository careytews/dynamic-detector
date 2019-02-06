package main

import (
	log "github.com/sirupsen/logrus"
	ind "github.com/trustnetworks/indicators"
	"strconv"
	"strings"
)

var (
	current_id = 0
)

func createID() string {
	id := "dynamic_IOC_" + strconv.Itoa(current_id)
	current_id += 1
	return id
}

func convertAlertToIOC(a Alert) *ind.IndicatorNode {
	var i *ind.IndicatorNode
	switch a.Type {
	case "dns":
		i = createDNSIOC(a)
	case "ip-comms":
		i = createIPsIOC(a)
	case "bidirect-ip-comms":
		i = createBidirectIPsIOC(a)
	case "useragent":
		i = createUserAgentIOC(a)
	}

	return i
}

func createDNSIOC(a Alert) *ind.IndicatorNode {

	sIp, dIp := createIPNodes(&a)

	dns := ind.IndicatorNode{
		ID: createID(),
		Pattern: &ind.Pattern{
			Type:  "hostname",
			Value: a.Indicator.Value,
			Match: "dns",
		},
	}

	ioc := ind.IndicatorNode{
		ID:        createID(),
		Comment:   "dynamically created " + a.Indicator.Category + " IOC",
		Indicator: &a.Indicator,
		Operator:  "AND",
		Children:  []*ind.IndicatorNode{&dns},
	}
	if a.Device != "" {
		device := createDevNode(&a)
		ioc.Children = append(ioc.Children, device)
	}
	if sIp != nil {
		ioc.Children = append(ioc.Children, sIp)
	}
	if dIp != nil {
		ioc.Children = append(ioc.Children, dIp)
	}

	return &ioc
}

func createUserAgentIOC(a Alert) *ind.IndicatorNode {

	sIp, dIp := createIPNodes(&a)

	ua := ind.IndicatorNode{
		ID: createID(),
		Pattern: &ind.Pattern{
			Type:  "useragent",
			Value: a.Indicator.Value,
			Match: "string",
		},
	}

	ioc := ind.IndicatorNode{
		ID:        createID(),
		Comment:   "dynamically created " + a.Indicator.Category + " IOC",
		Indicator: &a.Indicator,
		Operator:  "AND",
		Children:  []*ind.IndicatorNode{&ua},
	}
	if a.Device != "" {
		device := createDevNode(&a)
		ioc.Children = append(ioc.Children, device)
	}
	if sIp != nil {
		ioc.Children = append(ioc.Children, sIp)
	}
	if dIp != nil {
		ioc.Children = append(ioc.Children, dIp)
	}

	return &ioc
}

func createIPsIOC(a Alert) *ind.IndicatorNode {

	sIp, dIp := createIPNodes(&a)

	if sIp == nil || dIp == nil {
		log.Error("creating ip comms IOC without src or dest IP information. Alert: ", a)
		return nil
	}

	ioc := ind.IndicatorNode{
		ID:        createID(),
		Comment:   "dynamically created " + a.Indicator.Category + " IOC",
		Indicator: &a.Indicator,
		Operator:  "AND",
		Children:  []*ind.IndicatorNode{sIp, dIp},
	}
	if a.Device != "" {
		device := createDevNode(&a)
		ioc.Children = append(ioc.Children, device)
	}

	return &ioc
}

func createBidirectIPsIOC(a Alert) *ind.IndicatorNode {

	ip1Src := createIPAndPortNode(&a.Src, "src")
	ip1Dest := createIPAndPortNode(&a.Src, "dest")
	ip2Src := createIPAndPortNode(&a.Dest, "src")
	ip2Dest := createIPAndPortNode(&a.Dest, "dest")

	srcNode := &ind.IndicatorNode{
		ID:       createID(),
		Operator: "OR",
		Children: []*ind.IndicatorNode{ip1Src, ip2Src},
	}
	destNode := &ind.IndicatorNode{
		ID:       createID(),
		Operator: "OR",
		Children: []*ind.IndicatorNode{ip1Dest, ip2Dest},
	}

	ioc := ind.IndicatorNode{
		ID:        createID(),
		Indicator: &a.Indicator,
		Operator:  "AND",
		Children:  []*ind.IndicatorNode{srcNode, destNode},
	}
	if a.Device != "" {
		device := createDevNode(&a)
		ioc.Children = append(ioc.Children, device)
	}

	return &ioc
}

// this is a useful debugging function, pass it a root IOC node and indentation
// (string of spaces), and it will return a sting representation of the entire
// IOC tree showing the operator, patterns and children for each node
// example usage:
//    log.Info("ioc created: " + printNode(ioc, ""))
func printNode(n *ind.IndicatorNode, ident string) string {
	var l strings.Builder
	if n.Operator != "" {
		l.WriteString(ident + "Operator: " + n.Operator + "\n")
	}
	if n.Pattern != nil {
		l.WriteString(ident + "Pattern:\n")
		l.WriteString(ident + "  type: " + n.Pattern.Type + "\n")
		l.WriteString(ident + "  value: " + n.Pattern.Value + "\n")
	}
	if len(n.Children) > 0 {
		l.WriteString(ident + "Children: [\n")
		for i, child := range n.Children {
			l.WriteString(ident + strconv.Itoa(i) + "\n" + printNode(child, ident+"  "))
		}
		l.WriteString(ident + "]\n")
	}

	return l.String()
}

func createIPNodes(a *Alert) (*ind.IndicatorNode, *ind.IndicatorNode) {

	sIp := createIPNode(&a.Src, "src")
	dIp := createIPNode(&a.Dest, "dest")

	return sIp, dIp
}

func createIPAndPortNode(c *CommsInfo, direction string) *ind.IndicatorNode {

	ip := createIPNode(c, direction)
	node := ip
	if c.Port != 0 {
		proto := c.Proto
		if proto == "" {
			proto = "tcp"
		}
		port := &ind.IndicatorNode{
			ID: createID(),
			Pattern: &ind.Pattern{
				Type:  direction + "." + proto,
				Value: strconv.Itoa(c.Port),
				Match: "int",
			},
		}
		node = &ind.IndicatorNode{
			ID:       createID(),
			Operator: "AND",
			Children: []*ind.IndicatorNode{ip, port},
		}
	}

	return node
}

func createIPNode(c *CommsInfo, direction string) *ind.IndicatorNode {
	var ip *ind.IndicatorNode
	ip = nil

	if c.IP != "" {
		ipInfo := strings.Split(c.IP, ":")
		ip = &ind.IndicatorNode{
			ID: createID(),
			Pattern: &ind.Pattern{
				Type:  direction + "." + ipInfo[0],
				Value: ipInfo[1],
			},
		}
	}

	return ip
}

func createDevNode(a *Alert) *ind.IndicatorNode {
	device := ind.IndicatorNode{
		ID: createID(),
		Pattern: &ind.Pattern{
			Type:  "device",
			Value: a.Device,
		},
	}
	return &device
}
