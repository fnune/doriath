package containers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
)

func dockerPull(c checker, r request) verdict {
	images := queryValues(r.Query, "fromImage")
	if len(images) == 0 {
		for _, src := range queryValues(r.Query, "fromSrc") {
			if src != "-" && !isHTTPURL(src) {
				return refuse("importing an image from %q is not allowed: only the request body and http(s) URLs are", src)
			}
		}
		return verdict{}
	}
	if len(images) > 1 {
		return refuse("a pull that names more than one image cannot be checked")
	}
	ref := withTag(images[0], queryValue(r.Query, "tag"))
	return pulling(c.image(ref), ref)
}

func pulling(reason, ref string) verdict {
	if reason != "" {
		return refuseIf(reason)
	}
	if r, ok := tagged(ref); ok {
		return verdict{pull: &r}
	}
	return verdict{}
}

func withTag(ref, tag string) string {
	if tag == "" || strings.Contains(ref, "@") {
		return ref
	}
	if strings.Contains(tag, ":") {
		return ref + "@" + tag
	}
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		return ref
	}
	return ref + ":" + tag
}

func libpodPull(c checker, r request) verdict {
	refs := queryValues(r.Query, "reference")
	switch {
	case len(refs) == 0:
		return verdict{}
	case len(refs) > 1:
		return refuse("a pull that names more than one image cannot be checked")
	}
	if allTags, _ := strconv.ParseBool(queryValue(r.Query, "allTags")); allTags {
		return refuseIf(c.repository(refs[0]))
	}
	return pulling(c.image(refs[0]), refs[0])
}

func libpodImport(_ checker, r request) verdict {
	for _, src := range queryValues(r.Query, "url") {
		if src != "" && !isHTTPURL(src) {
			return refuse("importing an image from %q is not allowed: only the request body and http(s) URLs are", src)
		}
	}
	return verdict{}
}

func isHTTPURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

func push(_ checker, r request) verdict {
	name := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(r.Path, "/libpod"), "/images/"), "/push")
	dest := name
	if d := queryValue(r.Query, "destination"); d != "" {
		dest = d
	} else if tag := queryValue(r.Query, "tag"); tag != "" {
		dest = withTag(name, tag)
	}
	summary := "Push container image " + dest
	if dest != name {
		summary = fmt.Sprintf("Push container image %s to %s", name, dest)
	}
	return verdict{ask: &ask{summary: summary, scope: "containers push " + dest}}
}

func build(c checker, r request) verdict {
	q := r.Query
	for _, name := range []string{"addcaps", "devices"} {
		if vs := jsonList(queryValues(q, name)); len(vs) > 0 {
			return refuse("builds with %s are not allowed; no profile setting allows them", name)
		}
	}
	for _, name := range []string{"cgroupparent", "rusagelogfile", "sbom-output", "sbom-purl-output", "sbom-image-output", "sbom-image-purl-output"} {
		if v := queryValue(q, name); v != "" {
			return refuse("builds with %s are not allowed: it names a path on the podman service's side", name)
		}
	}
	if v := queryValue(q, "seccomp"); v != "" {
		return refuse("builds with seccomp profile %q are not allowed: builds keep the default seccomp profile", v)
	}
	if reason := first(
		c.apparmor(queryValue(q, "apparmor")),
		c.selinux(jsonList(queryValues(q, "labelopts"))),
		c.securityOpts(jsonList(queryValues(q, "securityopt"))),
		buildIsolation(queryValues(q, "isolation")),
		buildNamespaces(queryValues(q, "nsoptions")),
		c.binds(queryValues(q, "volume")),
		buildFiles(jsonList(queryValues(q, "dockerfile")), "Containerfile"),
		buildSecrets(jsonList(queryValues(q, "secrets"))),
		buildContexts(queryValues(q, "additionalbuildcontexts")),
	); reason != "" {
		return refuseIf(reason)
	}
	return verdict{}
}

func jsonList(values []string) []string {
	var out []string
	for _, v := range values {
		var l []string
		if err := json.Unmarshal([]byte(v), &l); err == nil {
			out = append(out, l...)
			continue
		}
		if v != "" && v != "null" {
			out = append(out, v)
		}
	}
	return out
}

func buildIsolation(values []string) string {
	for _, v := range values {
		switch strings.ToLower(v) {
		case "", "0", "1", "3", "default", "oci", "rootless":
		default:
			return fmt.Sprintf("build isolation %q is not allowed: builds run as OCI containers", v)
		}
	}
	return ""
}

func buildNamespaces(values []string) string {
	for _, v := range values {
		var opts []struct {
			Name string
			Host bool
			Path string
		}
		if err := json.Unmarshal([]byte(v), &opts); err != nil {
			return "the build's nsoptions are not valid JSON"
		}
		for _, o := range opts {
			if o.Path != "" {
				return fmt.Sprintf("builds that join a %s namespace by path are not allowed; no profile setting allows them", o.Name)
			}
			if o.Host && o.Name != "user" && o.Name != "network" && o.Name != "net" {
				return fmt.Sprintf("builds in the host's %s namespace are not allowed; no profile setting allows them", o.Name)
			}
		}
	}
	return ""
}

func buildFiles(files []string, what string) string {
	for _, f := range files {
		if isHTTPURL(f) {
			continue
		}
		if strings.HasPrefix(f, "/") || escapes(f) {
			return fmt.Sprintf("%s %q is not allowed: it must be inside the build context", what, f)
		}
	}
	return ""
}

func buildSecrets(secrets []string) string {
	for _, s := range secrets {
		for _, kv := range strings.Split(s, ",") {
			k, v, ok := strings.Cut(kv, "=")
			if ok && k == "src" && escapes(v) {
				return fmt.Sprintf("build secret source %q is not allowed: it must be inside the build context", v)
			}
		}
	}
	return ""
}

func buildContexts(values []string) string {
	for _, v := range values {
		_, value, _ := strings.Cut(v, "=")
		if !strings.HasPrefix(value, "url:") && !strings.HasPrefix(value, "image:") {
			return fmt.Sprintf("build context %q is not allowed: only URLs, images and uploaded contexts are", v)
		}
	}
	return ""
}

type volumeBody struct {
	Driver     string
	Options    map[string]string
	DriverOpts map[string]string
}

func volumeCreate(c checker, r request) verdict {
	var b volumeBody
	if reason := decodeBody(r.Body, &b); reason != "" {
		return refuseIf(reason)
	}
	opts := b.Options
	if len(b.DriverOpts) > 0 {
		opts = b.DriverOpts
	}
	if len(b.Options) > 0 && len(b.DriverOpts) > 0 {
		return refuse("a volume with both Options and DriverOpts is ambiguous")
	}
	return refuseIf(c.volumeDriver(b.Driver, opts))
}

func (c checker) volumeDriver(driver string, opts map[string]string) string {
	switch strings.ToLower(driver) {
	case "", "local":
	case "image":
		return c.image(lookupFold(opts, "image"))
	default:
		return fmt.Sprintf("volume driver %q is not allowed: only the local driver is", driver)
	}
	device := lookupFold(opts, "device")
	readOnly, isBind := false, false
	for _, o := range strings.Split(lookupFold(opts, "o"), ",") {
		switch strings.TrimSpace(o) {
		case "bind", "rbind":
			isBind = true
		case "ro":
			readOnly = true
		}
	}
	if isBind {
		return c.bindSource(device, access{write: !readOnly})
	}
	if strings.HasPrefix(device, "/") {
		return fmt.Sprintf("a volume on device %s is not allowed; no profile setting allows it", device)
	}
	return ""
}

type secretBody struct {
	Driver *struct {
		Name    string
		Options map[string]string
	}
}

func dockerSecret(_ checker, r request) verdict {
	var b secretBody
	if reason := decodeBody(r.Body, &b); reason != "" {
		return refuseIf(reason)
	}
	if b.Driver != nil {
		return refuseIf(secretDriver(b.Driver.Name, len(b.Driver.Options) > 0))
	}
	return verdict{}
}

func libpodSecret(_ checker, r request) verdict {
	opts := anyOptions(queryValues(r.Query, "driveropts"))
	for _, d := range queryValues(r.Query, "driver") {
		if reason := secretDriver(d, false); reason != "" {
			return refuseIf(reason)
		}
	}
	return refuseIf(secretDriver("", opts))
}

func anyOptions(values []string) bool {
	for _, v := range values {
		var m map[string]string
		if err := json.Unmarshal([]byte(v), &m); (err == nil && len(m) == 0) || v == "" {
			continue
		}
		return true
	}
	return false
}

func secretDriver(name string, hasOptions bool) string {
	if name != "" && !strings.EqualFold(name, "file") {
		return fmt.Sprintf("secret driver %q is not allowed: only the file driver is", name)
	}
	if hasOptions {
		return "secret driver options are not allowed: they name paths and commands on the podman service's side"
	}
	return ""
}

func decodeBody(body []byte, v any) string {
	if len(bytes.TrimSpace(body)) == 0 {
		return ""
	}
	if err := noDuplicateKeys(body); err != nil {
		return "the request body cannot be checked: " + err.Error()
	}
	if err := json.Unmarshal(body, v); err != nil {
		return "the request body cannot be checked: " + err.Error()
	}
	return ""
}

func noDuplicateKeys(body []byte) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := walkValue(dec); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after the JSON value")
	}
	return nil
}

func walkValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	switch tok {
	case json.Delim('{'):
		seen := map[string]bool{}
		for dec.More() {
			k, err := dec.Token()
			if err != nil {
				return err
			}
			name, _ := k.(string)
			key := strings.ToLower(name)
			if seen[key] {
				return fmt.Errorf("key %q appears twice", k)
			}
			seen[key] = true
			if err := walkValue(dec); err != nil {
				return err
			}
		}
		_, err := dec.Token()
		return err
	case json.Delim('['):
		for dec.More() {
			if err := walkValue(dec); err != nil {
				return err
			}
		}
		_, err := dec.Token()
		return err
	}
	return nil
}
