package containers

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

// AnyImage is the [podman] images pattern that allows every image, also
// images referred to by ID.
const AnyImage = "*"

var (
	imageID     = regexp.MustCompile(`^(sha256:)?[a-f0-9]{12,64}$`)
	imageDigest = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
)

// imageRef is a normalized image reference.
type imageRef struct {
	// full is the reference with tag or digest, such as
	// "docker.io/library/alpine:latest".
	full string
	// repo is the part without tag and digest.
	repo   string
	tag    string
	digest string
}

// pinned is the reference to a digest that create bodies are rewritten to.
func (r imageRef) pinned(digest string) string { return r.repo + "@" + digest }

// normalizeImage expands a reference the way Docker does: "alpine" becomes
// "docker.io/library/alpine:latest".
func normalizeImage(ref string) (imageRef, bool) {
	ref = strings.TrimSpace(ref)
	if ref == "" || imageID.MatchString(ref) {
		return imageRef{}, false
	}
	name, digest, hasDigest := strings.Cut(ref, "@")
	tag := ""
	if i := strings.LastIndex(name, ":"); i > strings.LastIndex(name, "/") {
		name, tag = name[:i], name[i+1:]
	}
	domain, rest, found := strings.Cut(name, "/")
	if !found || (!strings.ContainsAny(domain, ".:") && domain != "localhost") {
		domain, rest = "docker.io", name
	}
	if domain == "index.docker.io" {
		domain = "docker.io"
	}
	if domain == "docker.io" && !strings.Contains(rest, "/") {
		rest = "library/" + rest
	}
	r := imageRef{repo: domain + "/" + rest, tag: tag, digest: digest}
	if !hasDigest && tag == "" {
		r.tag = "latest"
	}
	r.full = r.repo
	if r.tag != "" {
		r.full += ":" + r.tag
	}
	if hasDigest {
		r.full += "@" + digest
	}
	return r, true
}

// image checks a reference against the profile's image patterns. A pattern
// without a tag matches every tag of the repositories it names.
func (c checker) image(ref string) string {
	if c.anyImage() {
		return ""
	}
	r, ok := normalizeImage(ref)
	if !ok {
		return fmt.Sprintf("image %q cannot be checked against [podman] images of profile %q; refer to the image by name", ref, c.profile)
	}
	for _, p := range c.policy.Images {
		if m, _ := path.Match(p, r.full); m {
			return ""
		}
		if m, _ := path.Match(p, r.repo); m {
			return ""
		}
	}
	return fmt.Sprintf("image %s is not allowed: add it, or a pattern such as %q, to [podman] images in profile %q (%q allows any image)", r.full, path.Dir(r.repo)+"/*", c.profile, AnyImage)
}

// repository checks a pull of every tag of a repository.
func (c checker) repository(ref string) string {
	if c.anyImage() {
		return ""
	}
	if r, ok := normalizeImage(ref); ok {
		for _, p := range c.policy.Images {
			if m, _ := path.Match(p, r.repo); m {
				return ""
			}
		}
	}
	return fmt.Sprintf("pulling every tag of %s is not allowed: add the repository without a tag to [podman] images in profile %q", ref, c.profile)
}

func (c checker) anyImage() bool {
	for _, p := range c.policy.Images {
		if p == AnyImage {
			return true
		}
	}
	return false
}

// tagged is the reference to pin, or false for references by digest or ID,
// which name their content already. Images under localhost are built or
// loaded in the session and change with each build, which a pin would hold
// back.
func tagged(ref string) (imageRef, bool) {
	r, ok := normalizeImage(ref)
	if !ok || r.digest != "" || r.repo == "localhost" || strings.HasPrefix(r.repo, "localhost/") || strings.HasPrefix(r.repo, "localhost:") {
		return imageRef{}, false
	}
	return r, true
}
