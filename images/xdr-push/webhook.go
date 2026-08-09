package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

type WebhookClient struct {
	cfg    Config
	client *http.Client
}

func NewWebhookClient(cfg Config) *WebhookClient {
	return &WebhookClient{
		cfg: cfg,
		client: &http.Client{
			Timeout: time.Duration(cfg.XDR.TimeoutS) * time.Second,
		},
	}
}

func (w *WebhookClient) Push(h Hit) error {
	payload := buildPayload(h, cfg.Probe.ID)
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	var lastErr error
	for attempt := 1; attempt <= w.cfg.XDR.RetryMax; attempt++ {
		req, err := http.NewRequest(http.MethodPost, w.cfg.XDR.Webhook.URL, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		if w.cfg.XDR.Webhook.Secret != "" {
			req.Header.Set("X-NDR-Signature", sign(body, w.cfg.XDR.Webhook.Secret))
		}
		resp, err := w.client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return nil
			}
			lastErr = fmt.Errorf("webhook 返回 %d", resp.StatusCode)
		} else {
			lastErr = err
		}
		time.Sleep(time.Duration(attempt*attempt) * time.Second)
	}
	return fmt.Errorf("重试 %d 次仍失败: %w", w.cfg.XDR.RetryMax, lastErr)
}

func sign(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func appendDLQ(h Hit) error {
	line, _ := json.Marshal(h.Source)
	f, err := os.OpenFile(dlqFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(fmt.Sprintf("%s\t%s\n", h.ID, line))
	return err
}

func insecureTLS() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true}
}
