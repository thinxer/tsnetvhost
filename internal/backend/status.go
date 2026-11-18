package backend

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type ExitStatus struct {
	ID        string `json:"id"`
	Required  bool   `json:"required"`
	Available bool   `json:"available"`
}

type Status struct {
	SchemaVersion  int         `json:"schemaVersion"`
	Generation     uint64      `json:"generation"`
	State          string      `json:"state"`
	Hostname       string      `json:"hostname"`
	Socket         string      `json:"socket"`
	Addresses      []string    `json:"addresses"`
	MAC            string      `json:"mac"`
	MTU            int         `json:"mtu"`
	Gateway4       string      `json:"gateway4"`
	Gateway6       string      `json:"gateway6"`
	DNS            []string    `json:"dns"`
	ExitNode       *ExitStatus `json:"exitNode,omitempty"`
	VhostConnected bool        `json:"vhostConnected"`
	UpdatedAt      time.Time   `json:"updatedAt"`
	Error          string      `json:"error,omitempty"`
}

type StatusWriter struct {
	mu     sync.Mutex
	path   string
	status Status
}

func NewStatusWriter(path, hostname, socket, mac string, mtu int) (*StatusWriter, error) {
	writer := &StatusWriter{
		path: path,
		status: Status{
			SchemaVersion: 1,
			Hostname:      hostname,
			Socket:        socket,
			MAC:           mac,
			MTU:           mtu,
			Gateway4:      syntheticIPv4.String(),
			Gateway6:      syntheticIPv6.String(),
			DNS:           []string{},
			Addresses:     []string{},
		},
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	return writer, writer.Publish("starting", nil, nil)
}

func (w *StatusWriter) SetNetwork(addresses, dns []string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.status.Addresses = append([]string{}, addresses...)
	w.status.DNS = append([]string{}, dns...)
}

func (w *StatusWriter) SetExitNode(id string, available bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if id == "" {
		w.status.ExitNode = nil
		return
	}
	w.status.ExitNode = &ExitStatus{ID: id, Required: true, Available: available}
}

func (w *StatusWriter) Publish(state string, connected *bool, publishErr error) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.status.Generation++
	w.status.State = state
	w.status.UpdatedAt = time.Now().UTC()
	w.status.Error = ""
	if connected != nil {
		w.status.VhostConnected = *connected
	}
	if publishErr != nil {
		w.status.Error = publishErr.Error()
	}
	data, err := json.MarshalIndent(w.status, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	temporary := w.path + ".tmp"
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(temporary, w.path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(w.path))
	if err == nil {
		err = directory.Sync()
	}
	if directory != nil {
		_ = directory.Close()
	}
	return err
}
