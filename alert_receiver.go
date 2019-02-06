package main

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/trustnetworks/analytics-common/amqp"
	"github.com/trustnetworks/analytics-common/utils"
	"github.com/trustnetworks/analytics-common/worker"
	"os"
	"time"
)

type AlertReceiver struct {
	broker   string
	exchange string
	queue    string

	ctx context.Context

	alertsUnreadableCounter *worker.Counter
	alertsReceivedCounter   *worker.Counter
	recvLabels              worker.MetricLabels
}

func (a *AlertReceiver) init(ctx context.Context) {

	a.broker = utils.Getenv("AMQP_BROKER", "amqp://guest:guest@localhost:5672/")
	a.exchange = utils.Getenv("AMQP_ALERT_EXCHANGE", "ioc-alert")
	hostname, err := os.Hostname()
	if err != nil {
		// been unable to get hostname. Use random number instead
		hostname = uuid.New().String()
	}
	a.queue = "alert-receiver." + hostname

	// Config Prom Stats
	a.alertsReceivedCounter = worker.CreateCounter(
		worker.CounterOpts{
			Name: "alerts_received",
			Help: "number of alerts received",
		},
		[]string{"analytic", "exchange", "type", "queue", "alert_type"},
	)
	a.alertsUnreadableCounter = worker.CreateCounter(
		worker.CounterOpts{
			Name: "alerts_unreadable",
			Help: "number of alerts unreadable",
		},
		[]string{"analytic", "exchange", "type", "queue"},
	)

	a.recvLabels = worker.MetricLabels{"analytic": pgm, "exchange": a.exchange, "queue": a.queue, "type": "amqp"}

	a.ctx = ctx
}

func RegisterForAlerts(ctx context.Context) (<-chan Alert, <-chan error) {
	ch := make(chan Alert, 100)
	eCh := make(chan error, 1)

	var ar AlertReceiver
	ar.init(ctx)
	go ar.consume(ch, eCh)
	return ch, eCh
}

func (ar *AlertReceiver) consume(ch chan Alert, eCh chan error) {

	consumer := amqp.NewConsumer(
		ar.ctx,
		ar.queue,
		ar.exchange,
		ar.broker,
		500,   // This can be high - as long as the broker/analytic has memory for it
		false, // persistent is false because new queue shoud be created for each pod
	)
	consumer.SetAckThreshold(1)
	handler := func(msg []byte, _ time.Time) {
		// first check the context hasnt been closed
		select {
		case <-ar.ctx.Done():
			return // TODO: probably should do something more that return
		default:
			// do nothing
		}

		// Read event, decode JSON.
		var a Alert
		err := json.Unmarshal(msg, &a)
		if err != nil {
			log.Errorf("Couldn't unmarshal json: %s", err.Error())
			ar.alertsUnreadableCounter.Inc(ar.recvLabels)
			return
		}

		ch <- a

		// Record statss
		go func() {
			lbls := worker.MetricLabels{"analytic": pgm, "exchange": ar.exchange, "queue": ar.queue, "type": "amqp", "alert_type": a.Type}
			ar.alertsReceivedCounter.Inc(lbls)
		}()
	}

	err := consumer.Consume(handler)
	if err != nil {
		log.Errorf("error: Error in reading from queue: %s", err.Error())
		eCh <- errors.New("alert receiver quit unexpectedly")
	}

}
