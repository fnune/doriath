package containers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

type startTarget struct {
	pod bool
	id  string
}

func startTargetOf(method, apiPath string) (startTarget, bool) {
	if method != http.MethodPost {
		return startTarget{}, false
	}
	segments := strings.Split(strings.TrimPrefix(strings.TrimPrefix(apiPath, "/"), "libpod/"), "/")
	if len(segments) != 3 || (segments[2] != "start" && segments[2] != "restart") {
		return startTarget{}, false
	}
	switch segments[0] {
	case "containers":
		return startTarget{id: segments[1]}, true
	case "pods":
		return startTarget{pod: true, id: segments[1]}, true
	}
	return startTarget{}, false
}

type inspectedMount struct {
	Type    string
	Name    string
	Source  string
	Options []string
	RW      bool
}

func (b *Broker) getJSON(ctx context.Context, path string, into any) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://podman/v4.0.0/libpod/"+path, http.NoBody)
	if err != nil {
		return false, err
	}
	resp, err := b.transport.RoundTrip(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, nil
	}
	return true, json.NewDecoder(io.LimitReader(resp.Body, maxInspectedBody)).Decode(into)
}

func (b *Broker) startRefusal(ctx context.Context, c checker, t startTarget) (string, error) {
	ids := []string{t.id}
	if t.pod {
		var pod struct{ Containers []struct{ ID string } }
		found, err := b.getJSON(ctx, "pods/"+url.PathEscape(t.id)+"/json", &pod)
		if err != nil || !found {
			return "", err
		}
		ids = nil
		for _, member := range pod.Containers {
			ids = append(ids, member.ID)
		}
	}
	for _, id := range ids {
		var inspected struct{ Mounts []inspectedMount }
		found, err := b.getJSON(ctx, "containers/"+url.PathEscape(id)+"/json", &inspected)
		if err != nil {
			return "", err
		}
		if !found {
			continue
		}
		for _, m := range inspected.Mounts {
			if reason, err := b.mountRefusal(ctx, c, m); reason != "" || err != nil {
				return reason, err
			}
		}
	}
	return "", nil
}

func (b *Broker) mountRefusal(ctx context.Context, c checker, m inspectedMount) (string, error) {
	switch m.Type {
	case "bind":
		nonRecursive := slices.Contains(m.Options, "bind") && !slices.Contains(m.Options, "rbind")
		return c.bindSource(m.Source, access{write: m.RW, nonRecursive: nonRecursive}), nil
	case "volume":
		var volume struct {
			Driver  string
			Options map[string]string
		}
		found, err := b.getJSON(ctx, "volumes/"+url.PathEscape(m.Name)+"/json", &volume)
		if err != nil || !found {
			return "", err
		}
		if reason := c.volumeDriver(volume.Driver, volume.Options); reason != "" {
			return fmt.Sprintf("volume %s: %s", m.Name, reason), nil
		}
	}
	return "", nil
}
