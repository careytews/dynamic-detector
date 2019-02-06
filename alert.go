package main

import (
	dt "github.com/trustnetworks/analytics-common/datatypes"
)

type CommsInfo struct {
	IP    string `json:"ip,omitempty"`
	Port  int    `json:"port,omitempty"`
	Proto string `json:"proto,omitempty"`
}

type Alert struct {
	Type      string       `json:"type"`
	TTL       int64        `json:"ttl"`
	Src       CommsInfo    `json:"src"`
	Dest      CommsInfo    `json:"dest"`
	Device    string       `json:"device"`
	Indicator dt.Indicator `json:"indicator"`
}

type AlertData struct {
	Alert   Alert `json:"alert"`
	Timeout int64 `json:"timeout"`
}

type AlertsMessage struct {
	Alerts []AlertData `json:"alerts"`
}
