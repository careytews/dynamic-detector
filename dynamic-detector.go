package main

import (
	"context"
	"encoding/json"
	log "github.com/sirupsen/logrus"
	dt "github.com/trustnetworks/analytics-common/datatypes"
	"github.com/trustnetworks/analytics-common/utils"
	"github.com/trustnetworks/analytics-common/worker"
	detLib "github.com/trustnetworks/detectorlib"
	ind "github.com/trustnetworks/indicators"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

const (
	// Program name, used for log entries.
	pgm = "dynamic-detector"
)

var (
	Now = time.Now
)

type dynamicDetector struct {
	alerts        map[Alert]int64
	detectorLib   detLib.Detector
	alertToIOCMap map[Alert]*ind.IndicatorNode

	timeout <-chan time.Time

	alertsCh    <-chan Alert
	alertErrors <-chan error

	indicatorsAddedCounter *worker.Counter
	alertDBSizeGauge       *worker.Gauge
}

func (dd *dynamicDetector) Init() {
	dd.alerts = make(map[Alert]int64)
	dd.alertToIOCMap = make(map[Alert]*ind.IndicatorNode)
	dd.detectorLib = detLib.GetDetector()
	dd.timeout = time.After(5 * time.Second)
	dd.indicatorsAddedCounter = worker.CreateCounter(
		worker.CounterOpts{
			Name: "indicators_added_to_events",
			Help: "number of indicators added to events",
		}, []string{"analytic", "type"},
	)
	dd.alertDBSizeGauge = worker.CreateGauge(
		worker.GaugeOpts{
			Name: "alert_db_size",
			Help: "number of alerts currently stored",
		}, []string{"analytic"},
	)
	dd.alertDBSizeGauge.Set(0, worker.MetricLabels{"analytic": pgm})
}

func (dd *dynamicDetector) AddAlert(a Alert) {
	if a.TTL > 0 {
		dd.alerts[a] = Now().Unix() + a.TTL
		_, ok := dd.alertToIOCMap[a]
		if !ok {
			log.Info("alert not seen before, create new iocl")
			ioc := convertAlertToIOC(a)
			dd.alertToIOCMap[a] = ioc
			dd.detectorLib.LoadNode(ioc)
		}
	}
	dd.alertDBSizeGauge.Set(float64(len(dd.alerts)), worker.MetricLabels{"analytic": pgm})
}

// same functionality as add alert except the timeout is already specified so do not
// work out the TTL
func (dd *dynamicDetector) AddExistingAlert(a Alert, timeout int64) {
	if timeout > Now().Unix() {
		dd.alerts[a] = timeout
		_, ok := dd.alertToIOCMap[a]
		if !ok {
			log.Info("alert not seen before, create new iocl")
			ioc := convertAlertToIOC(a)
			dd.alertToIOCMap[a] = ioc
			dd.detectorLib.LoadNode(ioc)
		}
	}
	dd.alertDBSizeGauge.Set(float64(len(dd.alerts)), worker.MetricLabels{"analytic": pgm})
}

func (dd *dynamicDetector) TimeoutAlerts() {
	before := len(dd.alerts)
	now := Now().Unix()
	for a, exp := range dd.alerts {
		if exp < now {
			delete(dd.alerts, a)
			ioc, _ := dd.alertToIOCMap[a]
			dd.removeIOC(ioc)
			delete(dd.alertToIOCMap, a)
		}
	}
	after := len(dd.alerts)
	if after != before {
		log.Info("timed out ", before-after, " alerts")
	}
	dd.alertDBSizeGauge.Set(float64(len(dd.alerts)), worker.MetricLabels{"analytic": pgm})
}

func (dd *dynamicDetector) removeIOC(ioc *ind.IndicatorNode) {
	dd.detectorLib.RemoveNode(ioc)
}

func (dd *dynamicDetector) handleEvent(event *dt.Event) {
	indicators := dd.detectorLib.Lookup(event)
	if len(indicators) > 0 {
		// metricate the hits
		go func() {
			for _, itor := range indicators {
				dd.indicatorsAddedCounter.Inc(worker.MetricLabels{"analytic": pgm, "type": itor.Type})
			}
		}()
		if event.Indicators == nil {
			inds := make([]*dt.Indicator, 0)
			event.Indicators = &inds
		}
		// Set indicator probability to 1.0 (if not set)
		for i, _ := range indicators {
			if indicators[i].Probability == 0 {
				indicators[i].Probability = 1.0
			}
		}
		newInds := append(*event.Indicators, indicators...)
		event.Indicators = &newInds
	}
}

// helper for testing
var (
	Send = func(w *worker.Worker, dest string, bs *[]byte) {
		w.Send("output", *bs)
	}
)

func (dd *dynamicDetector) parseAlertData(alerts AlertsMessage) {
	for _, alert := range alerts.Alerts {
		dd.AddExistingAlert(alert.Alert, alert.Timeout)
	}
}

func (dd *dynamicDetector) initialAlertLoad() {
	resp, err := http.Get("http://dynamicdetector:8081/alerts")
	if err != nil {
		// error getting the current state, assume that means there is
		// no state to load
		log.Warn("No state to load from http://dynamicdetector:8081/alerts, assuming " +
			"this is the first dynamic detector and starting with empty state")
		log.Info("error during initial load - ", err.Error())
		return
	}
	alertJsonData, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		log.Fatal(err)
	}
	// Read alerts.
	var am AlertsMessage
	err = json.Unmarshal(alertJsonData, &am)
	if err != nil {
		log.Fatal("Couldn't unmarshal json: %s", err.Error())
	}
	log.Info("loading initial state of ", len(am.Alerts), " alerts")
	dd.parseAlertData(am)
}

func (dd *dynamicDetector) cleanup() {
	worker.RemoveCounter(dd.indicatorsAddedCounter)
	worker.RemoveGauge(dd.alertDBSizeGauge)
}

// iterate through all actions there are to take
func (dd *dynamicDetector) updateState() error {
	for {
		select {
		case err := <-dd.alertErrors:
			// cannot continue without alert receiver working, exit
			log.Error("Alert receiver has reported an error: ", err)
			return err
		case alert := <-dd.alertsCh:
			dd.AddAlert(alert)
		case <-dd.timeout:
			dd.TimeoutAlerts()
			dd.timeout = time.After(5 * time.Second)
		default:
			return nil
		}
	}
}

func (dd *dynamicDetector) Handle(msg []uint8, w *worker.Worker) error {
	// check if there are other actions that need to happen first
	err := dd.updateState()
	if err != nil {
		return err
	}

	// Read event, decode JSON.
	var ev dt.Event
	err = json.Unmarshal(msg, &ev)
	if err != nil {
		log.Errorf("Couldn't unmarshal json: %s", err.Error())
		return nil
	}

	// update the event to add any IOCs to it
	dd.handleEvent(&ev)

	// Convert event record back to JSON.
	j, err := json.Marshal(ev)
	if err != nil {
		log.Errorf("JSON marshal error: %s", err.Error())
		return nil
	}

	// Forward event record to output queue.
	Send(w, "output", &j)

	return nil
}

func main() {
	var w worker.QueueWorker
	var det dynamicDetector
	var aServer alertServer

	// Initialise.
	det.Init()

	// Initialise.
	var input string
	var output []string

	if len(os.Args) > 0 {
		input = os.Args[1]
	}
	if len(os.Args) > 2 {
		output = os.Args[2:]
	}

	// context to handle control of subroutines
	ctx := context.Background()
	ctx, cancel := utils.ContextWithSigterm(ctx)
	defer cancel()

	det.alertsCh, det.alertErrors = RegisterForAlerts(ctx)
	//   det.alertsCh = alertsCh
	//   det.alertErrors = alertErrors

	det.initialAlertLoad()

	aServer.initAlertServer(&det.alerts)

	err := w.Initialise(ctx, input, output, pgm)
	if err != nil {
		log.Errorf("Error on init: %s", err.Error())
		return
	}

	log.Info("Initialisation complete.")

	// Invoke Wye event handling.
	err = w.Run(ctx, &det)
	if err != nil {
		log.Errorf("error: Event handling failed with err: %s", err.Error())
	}
}
