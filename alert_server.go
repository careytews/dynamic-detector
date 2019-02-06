package main

import (
	"encoding/json"
	log "github.com/sirupsen/logrus"
	"net/http"
)

type alertServer struct {
	alerts *map[Alert]int64
}

func (as *alertServer) initAlertServer(alerts *map[Alert]int64) {
	as.alerts = alerts

	go as.run()
}

func (as *alertServer) run() {
	log.Info("starting alert server")
	http.HandleFunc("/alerts", as.handle)
	log.Fatal(http.ListenAndServe(":8081", nil))
}

func (as *alertServer) getAlertData() AlertsMessage {
	var alerts AlertsMessage
	alerts.Alerts = make([]AlertData, 0)
	for k, v := range *(as.alerts) {
		alerts.Alerts = append(alerts.Alerts, AlertData{Alert: k, Timeout: v})
	}

	return alerts
}

func (as *alertServer) handle(w http.ResponseWriter, r *http.Request) {
	log.Info("Another dynamic detector is requesting an initial load, returning current state")
	alerts := as.getAlertData()
	js, err := json.Marshal(alerts)
	if err != nil {
		log.Error("Error marshalling current state to send alerts to other dynamic detector: ", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Write(js)
}
