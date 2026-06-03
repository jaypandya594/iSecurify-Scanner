package models

import "time"

type ScanJob struct {
	ScanID   string `json:"scan_id"`
	Target   string `json:"target"`
	Status   string `json:"status,omitempty"`
	Progress int    `json:"progress,omitempty"`
}

type FixData struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

type FixScanJob struct {
	ScanID  string  `json:"scan_id"`
	OrgID   string  `json:"org_id"`
	Domain  string  `json:"domain"`
	FixType string  `json:"fix_type"`
	Data    FixData `json:"data"`
}

type FixScanResult struct {
	ScanID string      `json:"scan_id"`
	Domain string      `json:"domain"`
	Status string      `json:"status"`
	Data   interface{} `json:"data"`
}
type ScanNotification struct {
	ScanID string `json:"scan_id"`
	Target string `json:"target"`
	Event  string `json:"event"`
	Status string `json:"status"`
}

type ScanResult struct {
	ScanID    string    `json:"scan_id"`
	Target    string    `json:"target"`
	Status    string    `json:"status"`
	Data      any       `json:"data"`
	Timestamp time.Time `json:"timestamp"`
}
