package containers

import (
	"fmt"
	"path"
	"regexp"
	"strings"
)

var imageID = regexp.MustCompile(`^(sha256:)?[a-f0-9]{12,64}$`)

// normalizeImage expands a reference the way Docker does: "alpine" becomes
// "docker.io/library/alpine:latest". It returns the reference and its
// repository, the part without tag and digest.
func normalizeImage(ref string) (full, repo string, ok bool) {
	ref = strings.TrimSpace(ref)
	if ref == "" || imageID.MatchString(ref) {
		return "", "", false
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
	repo = domain + "/" + rest
	full = repo
	switch {
	case tag != "":
		full += ":" + tag
	case !hasDigest:
		full += ":latest"
	}
	if hasDigest {
		full += "@" + digest
	}
	return full, repo, true
}

// image checks a reference against the profile's image patterns. A pattern
// without a tag matches every tag of the repositories it names.
func (c checker) image(ref string) string {
	if len(c.policy.Images) == 0 {
		return ""
	}
	full, repo, ok := normalizeImage(ref)
	if !ok {
		return fmt.Sprintf("image %q cannot be checked against [podman] images of profile %q; refer to the image by name", ref, c.profile)
	}
	for _, p := range c.policy.Images {
		if m, _ := path.Match(p, full); m {
			return ""
		}
		if m, _ := path.Match(p, repo); m {
			return ""
		}
	}
	return fmt.Sprintf("image %s is not allowed: add it, or a pattern such as %q, to [podman] images in profile %q", full, path.Dir(repo)+"/*", c.profile)
}

// repository checks a pull of every tag of a repository.
func (c checker) repository(ref string) string {
	if len(c.policy.Images) == 0 {
		return ""
	}
	_, repo, ok := normalizeImage(ref)
	if ok {
		for _, p := range c.policy.Images {
			if m, _ := path.Match(p, repo); m {
				return ""
			}
		}
	}
	return fmt.Sprintf("pulling every tag of %s is not allowed: add the repository without a tag to [podman] images in profile %q", ref, c.profile)
}
