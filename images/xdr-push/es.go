package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Cursor struct {
	TS int64  `json:"ts"`
	ID string `json:"id"`
}

type Hit struct {
	ID     string         `json:"_id"`
	Source map[string]any `json:"_source"`
	Sort   []any          `json:"sort"`
}

type searchResp struct {
	Hits struct {
		Hits []Hit `json:"hits"`
	} `json:"hits"`
}

type Poller struct {
	host   string
	client *http.Client
	types  []string
}

func NewPoller(host string, cfg Config) *Poller {
	if host == "" {
		host = defaultHost
	}
	return &Poller{
		host: host,
		client: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: insecureTLS(),
			},
		},
		types: cfg.XDR.EventTypes,
	}
}

func (p *Poller) Fetch(c Cursor) ([]Hit, *Cursor, error) {
	should := make([]map[string]any, 0, len(p.types))
	for _, t := range p.types {
		should = append(should, map[string]any{"term": map[string]any{"event.dataset": t}})
	}
	body := map[string]any{
		"size": 100,
		"query": map[string]any{
			"bool": map[string]any{
				"should":               should,
				"minimum_should_match": 1,
			},
		},
		"sort": []any{
			map[string]any{"@timestamp": map[string]any{"order": "asc", "unmapped_type": "long"}},
			map[string]any{"_id": map[string]any{"order": "asc", "unmapped_type": "keyword"}},
		},
	}
	if c.TS != 0 {
		body["search_after"] = []any{c.TS, c.ID}
	}
	data, _ := json.Marshal(body)

	indexes := strings.Join([]string{"logs-suricata.alerts-so", "logs-zeek-so"}, ",")
	req, err := http.NewRequest(http.MethodGet,
		fmt.Sprintf("%s/%s/_search", p.host, indexes), bytes.NewReader(data))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return nil, nil, fmt.Errorf("ES 返回 %d: %s", resp.StatusCode, string(b))
	}

	var sr searchResp
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		return nil, nil, err
	}
	if len(sr.Hits.Hits) == 0 {
		return nil, nil, nil
	}
	last := sr.Hits.Hits[len(sr.Hits.Hits)-1]
	var next *Cursor
	if len(last.Sort) == 2 {
		ts, _ := last.Sort[0].(float64)
		id, _ := last.Sort[1].(string)
		next = &Cursor{TS: int64(ts), ID: id}
	}
	return sr.Hits.Hits, next, nil
}
