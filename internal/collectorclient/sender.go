package collectorclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/watchpost-ops/watchpost/internal/collectorcontract"
)

type Sender struct{ Client *http.Client }

func (s Sender) Send(ctx context.Context, config Config, batch collectorcontract.Batch) (collectorcontract.Acknowledgement, error) {
	payload, err := json.Marshal(batch)
	if err != nil {
		return collectorcontract.Acknowledgement{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, config.ServerURL+"/api/collector/v1/observations", bytes.NewReader(payload))
	if err != nil {
		return collectorcontract.Acknowledgement{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+config.Secret)
	client := s.Client
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	response, err := client.Do(request)
	if err != nil {
		return collectorcontract.Acknowledgement{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		return collectorcontract.Acknowledgement{}, fmt.Errorf("collector delivery rejected (%d)", response.StatusCode)
	}
	var ack collectorcontract.Acknowledgement
	if json.NewDecoder(response.Body).Decode(&ack) != nil || ack.Version != 1 || ack.BatchID != batch.BatchID {
		return collectorcontract.Acknowledgement{}, errors.New("invalid collector acknowledgement")
	}
	return ack, nil
}

func Drain(ctx context.Context, sender Sender, config Config, queue *Queue) error {
	for {
		batch, ok := queue.First()
		if !ok {
			return nil
		}
		ack, err := sender.Send(ctx, config, batch)
		if err != nil {
			return err
		}
		if err = queue.Acknowledge(ack.AcceptedThrough); err != nil {
			return err
		}
	}
}
