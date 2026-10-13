package containers

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

func (b *Broker) runPinned(w http.ResponseWriter, r *http.Request, body []byte, ref imageRef) bool {
	if b.cfg.Pins == nil {
		return true
	}
	digest, ok, err := b.cfg.Pins.Pinned(ref.full)
	if err != nil {
		b.refuse(w, r, http.StatusInternalServerError, "cannot read the image pins: "+err.Error())
		return false
	}
	if !ok {
		return true
	}
	body, err = withImage(body, ref.pinned(digest))
	if err != nil {
		b.refuse(w, r, http.StatusBadRequest, "the request body cannot be checked: "+err.Error())
		return false
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.Header.Set("Content-Length", strconv.Itoa(len(body)))
	return true
}

func withImage(body []byte, ref string) ([]byte, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, err
	}
	value, err := json.Marshal(ref)
	if err != nil {
		return nil, err
	}
	for k := range m {
		if strings.EqualFold(k, "image") {
			m[k] = value
		}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (b *Broker) pull(w http.ResponseWriter, r *http.Request, ref imageRef, libpodAPI bool) {
	out := r.Clone(r.Context())
	out.URL.Scheme, out.URL.Host, out.Host, out.RequestURI = "http", "podman", "podman", ""
	resp, err := b.transport.RoundTrip(out)
	if err != nil {
		b.record(Event{Kind: "error", Method: r.Method, Path: r.URL.Path, Reason: err.Error()})
		deny(w, http.StatusBadGateway, fmt.Sprintf("girdle: the podman service failed: %v", err))
		return
	}
	defer resp.Body.Close()
	for k, vs := range resp.Header {
		if k != "Content-Length" && k != "Connection" {
			w.Header()[k] = vs
		}
	}
	w.WriteHeader(resp.StatusCode)
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(w, resp.Body)
		return
	}
	id, ok := relayPull(w, resp.Body)
	if !ok {
		return
	}
	reason := b.pinPull(r, ref, id)
	if reason == "" {
		return
	}
	b.record(Event{Kind: "denied", Method: r.Method, Path: r.URL.Path, Reason: reason, Image: ref.full})
	_, _ = w.Write(pullError("girdle: "+reason, libpodAPI))
}

type pullMessage struct {
	ID    string          `json:"id"`
	Error json.RawMessage `json:"error"`
}

const maxPullLine = 64 << 10

func relayPull(w http.ResponseWriter, body io.Reader) (string, bool) {
	rc := http.NewResponseController(w)
	br := bufio.NewReaderSize(body, maxPullLine)
	last, partial := "", false
	for {
		line, err := br.ReadSlice('\n')
		if len(line) > 0 {
			if _, werr := w.Write(line); werr != nil {
				return "", false
			}
			_ = rc.Flush()
		}
		switch {
		case errors.Is(err, bufio.ErrBufferFull):
			partial = true
			continue
		case len(bytes.TrimSpace(line)) == 0:
		case partial:
			last = ""
		default:
			var m pullMessage
			if json.Unmarshal(line, &m) != nil {
				last = ""
				break
			}
			if e := string(bytes.TrimSpace(m.Error)); e != "" && e != "null" && e != `""` {
				return "", false
			}
			last = m.ID
		}
		partial = false
		if errors.Is(err, io.EOF) {
			return last, true
		}
		if err != nil {
			return "", false
		}
	}
}

func pullError(message string, libpodAPI bool) []byte {
	m := map[string]any{"error": message}
	if !libpodAPI {
		m["errorDetail"] = map[string]string{"message": message}
	}
	data, _ := json.Marshal(m)
	return append(data, '\n')
}

func (b *Broker) pinPull(r *http.Request, ref imageRef, id string) string {
	digest, err := b.imageDigest(r, id)
	if err != nil {
		return fmt.Sprintf("cannot read the digest that %s resolved to, so it cannot be pinned: %v", ref.full, err)
	}
	pinned, ok, err := b.cfg.Pins.Pinned(ref.full)
	switch {
	case err != nil:
		return "cannot read the image pins: " + err.Error()
	case ok && pinned == digest:
		return ""
	case ok:
		summary := fmt.Sprintf("%s changed from %s to %s", ref.full, shortDigest(pinned), shortDigest(digest))
		allowed, message := b.approved(r, ask{
			summary: summary,
			details: fmt.Sprintf("Pinned %s\nPulled %s", pinned, digest),
			scope:   "containers pin " + ref.full + " " + digest,
		})
		if !allowed {
			return message + "; containers of this tag keep running " + shortDigest(pinned)
		}
	}
	if err := b.cfg.Pins.Pin(ref.full, digest); err != nil {
		return "cannot record the image pin: " + err.Error()
	}
	reason := "first pull"
	if ok {
		reason = "changed from " + pinned
	}
	b.record(Event{Kind: "image-pinned", Method: r.Method, Path: r.URL.Path, Reason: reason, Image: ref.full, Digest: digest})
	return ""
}

func shortDigest(d string) string {
	if len(d) > len("sha256:")+12 {
		return d[:len("sha256:")+12] + "…"
	}
	return d
}

func (b *Broker) imageDigest(r *http.Request, id string) (string, error) {
	id = strings.TrimPrefix(id, "sha256:")
	if !imageID.MatchString(id) {
		return "", errors.New("the pull did not name the image it stored")
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, "http://podman/v4.0.0/libpod/images/"+url.PathEscape(id)+"/json", http.NoBody)
	if err != nil {
		return "", err
	}
	resp, err := b.transport.RoundTrip(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("podman answered %s for image %s", resp.Status, id)
	}
	var img struct {
		ID     string `json:"Id"`
		Digest string `json:"Digest"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxInspectedBody)).Decode(&img); err != nil {
		return "", fmt.Errorf("read image %s: %w", id, err)
	}
	if !strings.HasPrefix(img.ID, id) {
		return "", fmt.Errorf("podman described image %s for %s", img.ID, id)
	}
	if !imageDigest.MatchString(img.Digest) {
		return "", fmt.Errorf("image %s has no sha256 digest", id)
	}
	return img.Digest, nil
}
