package containers

import (
	"encoding/json"
	"fmt"
	"path"
	"strings"
)

// Field names follow the Docker Engine API's container create body and
// podman v5's pkg/specgen. Fields not named here pass through unchanged.

type dockerCreateBody struct {
	Image      string
	HostConfig *dockerHostConfig
}

type dockerHostConfig struct {
	Binds             []string
	Mounts            []dockerMount
	VolumesFrom       []string
	Privileged        bool
	CapAdd            []string
	Devices           []json.RawMessage
	DeviceRequests    []json.RawMessage
	DeviceCgroupRules []string
	SecurityOpt       []string
	PidMode           string
	IpcMode           string
	UTSMode           string
	UsernsMode        string
	CgroupnsMode      string
	NetworkMode       string
	Runtime           string
	Sysctls           map[string]string
	CgroupParent      string
	ContainerIDFile   string
	LogConfig         struct {
		Config map[string]string
	}
}

type dockerMount struct {
	Type        string
	Source      string
	ReadOnly    bool
	BindOptions *struct {
		NonRecursive bool
	}
	VolumeOptions *struct {
		DriverConfig *struct {
			Name    string
			Options map[string]string
		}
	}
}

func dockerCreate(c checker, r request) verdict {
	var b dockerCreateBody
	if reason := decodeBody(r.Body, &b); reason != "" {
		return refuseIf(reason)
	}
	if reason := c.image(b.Image); reason != "" {
		return refuseIf(reason)
	}
	h := b.HostConfig
	if h == nil {
		return running(b.Image)
	}
	if reason := first(
		banFlag(h.Privileged, "privileged containers"),
		banList(h.CapAdd, "added capabilities"),
		banList(h.Devices, "host devices"),
		banList(h.DeviceRequests, "device requests"),
		banList(h.DeviceCgroupRules, "device cgroup rules"),
		banList(h.VolumesFrom, "volumes from other containers"),
		c.securityOpts(h.SecurityOpt),
		c.dockerNamespace("pid", h.PidMode),
		c.dockerNamespace("ipc", h.IpcMode),
		c.dockerNamespace("uts", h.UTSMode),
		c.dockerNamespace("user", h.UsernsMode),
		c.dockerNamespace("cgroup", h.CgroupnsMode),
		c.dockerNetwork(h.NetworkMode),
		banText(h.Runtime, "another OCI runtime"),
		banMap(h.Sysctls, "sysctls"),
		banText(h.CgroupParent, "a cgroup parent"),
		banText(h.ContainerIDFile, "a container ID file on the podman service's side"),
		c.writablePath(lookupFold(h.LogConfig.Config, "path"), "the log path"),
		c.binds(h.Binds),
		c.dockerMounts(h.Mounts),
	); reason != "" {
		return refuseIf(reason)
	}
	return running(b.Image)
}

func (c checker) binds(bs []string) string {
	for _, b := range bs {
		if reason := c.bindArgument(b); reason != "" {
			return reason
		}
	}
	return ""
}

func (c checker) dockerMounts(ms []dockerMount) string {
	for _, m := range ms {
		switch strings.ToLower(m.Type) {
		case "bind", "":
			nonRecursive := m.BindOptions != nil && m.BindOptions.NonRecursive
			if reason := c.bindSource(m.Source, access{write: !m.ReadOnly, nonRecursive: nonRecursive}); reason != "" {
				return reason
			}
		case "volume":
			if m.VolumeOptions != nil && m.VolumeOptions.DriverConfig != nil {
				d := m.VolumeOptions.DriverConfig
				if reason := c.volumeDriver(d.Name, d.Options); reason != "" {
					return reason
				}
			}
		case "tmpfs":
		case "image":
			if reason := c.image(m.Source); reason != "" {
				return reason
			}
		default:
			return fmt.Sprintf("mounts of type %q are not allowed", m.Type)
		}
	}
	return ""
}

// dockerNamespace checks modes such as "host", "container:<id>" and
// "ns:<path>". Joining the host's or a path's namespace leaves the
// container's isolation.
func (c checker) dockerNamespace(kind, mode string) string {
	m, _, _ := strings.Cut(strings.ToLower(mode), ":")
	switch m {
	case "host":
		return fmt.Sprintf("containers in the host's %s namespace are not allowed; no profile setting allows them", kind)
	case "ns", "path":
		return fmt.Sprintf("containers that join a %s namespace by path are not allowed; no profile setting allows them", kind)
	}
	return ""
}

// dockerNetwork allows "host": the session already shares one network
// namespace, whose only way out is the proxy.
func (c checker) dockerNetwork(mode string) string {
	m, _, _ := strings.Cut(strings.ToLower(mode), ":")
	if m == "ns" || m == "path" {
		return "containers that join a network namespace by path are not allowed; no profile setting allows them"
	}
	return ""
}

// securityOpts checks Docker-style options, "name=value" or the older
// "name:value".
func (c checker) securityOpts(opts []string) string {
	for _, o := range opts {
		i := strings.IndexAny(o, "=:")
		name, value := o, ""
		if i >= 0 {
			name, value = o[:i], o[i+1:]
		}
		name, value = strings.ToLower(strings.TrimSpace(name)), strings.TrimSpace(value)
		switch {
		case name == "seccomp" && value != "":
			return fmt.Sprintf("security option %q is not allowed: containers keep the default seccomp profile", o)
		case name == "apparmor" && strings.EqualFold(value, "unconfined"):
			return fmt.Sprintf("security option %q is not allowed: containers keep their AppArmor profile", o)
		case name == "label":
			if reason := selinuxOption(value); reason != "" {
				return reason
			}
		case name == "no-new-privileges" && strings.EqualFold(value, "false"):
			return fmt.Sprintf("security option %q is not allowed", o)
		case name == "unmask", name == "systempaths" && strings.EqualFold(value, "unconfined"):
			return fmt.Sprintf("security option %q is not allowed: it exposes masked kernel paths", o)
		}
	}
	return ""
}

func selinuxOption(value string) string {
	v := strings.ToLower(value)
	if v == "disable" || strings.HasPrefix(v, "type:") {
		return fmt.Sprintf("SELinux option %q is not allowed: containers keep their SELinux label", value)
	}
	return ""
}

type specNamespace struct {
	NSMode string `json:"nsmode"`
}

type specMount struct {
	Type    string   `json:"type"`
	Source  string   `json:"source"`
	Options []string `json:"options"`
}

type overlayVolume struct {
	Source  string   `json:"source"`
	Options []string `json:"options"`
}

type imageVolume struct {
	Source string `json:"source"`
}

// libpodSpec holds the fields of podman's SpecGenerator that reach outside a
// container, and the PodSpecGenerator fields that carry over to a pod's infra
// container.
type libpodSpec struct {
	Image                string            `json:"image"`
	Privileged           *bool             `json:"privileged"`
	CapAdd               []string          `json:"cap_add"`
	Devices              []json.RawMessage `json:"devices"`
	DeviceCgroupRule     []json.RawMessage `json:"device_cgroup_rule"`
	DevicesFrom          []string          `json:"devices_from"`
	HostDeviceList       []json.RawMessage `json:"host_device_list"`
	Mounts               []specMount       `json:"mounts"`
	OverlayVolumes       []overlayVolume   `json:"overlay_volumes"`
	ImageVolumes         []imageVolume     `json:"image_volumes"`
	VolumesFrom          []string          `json:"volumes_from"`
	PidNS                specNamespace     `json:"pidns"`
	IpcNS                specNamespace     `json:"ipcns"`
	UtsNS                specNamespace     `json:"utsns"`
	UserNS               specNamespace     `json:"userns"`
	CgroupNS             specNamespace     `json:"cgroupns"`
	NetNS                specNamespace     `json:"netns"`
	SeccompPolicy        string            `json:"seccomp_policy"`
	SeccompProfilePath   string            `json:"seccomp_profile_path"`
	ApparmorProfile      string            `json:"apparmor_profile"`
	SelinuxOpts          []string          `json:"selinux_opts"`
	Rootfs               string            `json:"rootfs"`
	OCIRuntime           string            `json:"oci_runtime"`
	Sysctl               map[string]string `json:"sysctl"`
	CgroupParent         string            `json:"cgroup_parent"`
	InitPath             string            `json:"init_path"`
	ConmonPidFile        string            `json:"conmon_pid_file"`
	Unmask               []string          `json:"unmask"`
	BaseHostsFile        string            `json:"base_hosts_file"`
	HealthLogDestination string            `json:"healthLogDestination"`
	LogConfiguration     *struct {
		Path string `json:"path"`
	} `json:"log_configuration"`

	PodDevices         []string `json:"pod_devices"`
	SecurityOpt        []string `json:"security_opt"`
	InfraImage         string   `json:"infra_image"`
	InfraConmonPidFile string   `json:"infra_conmon_pid_file"`
	HostsFile          string   `json:"hostsFile"`
}

func libpodCreate(c checker, r request) verdict {
	var s libpodSpec
	if reason := decodeBody(r.Body, &s); reason != "" {
		return refuseIf(reason)
	}
	if s.Rootfs != "" {
		return refuse("containers with a host directory as their root file system (rootfs) are not allowed; use an image")
	}
	if reason := first(c.image(s.Image), c.spec(s)); reason != "" {
		return refuseIf(reason)
	}
	return running(s.Image)
}

func podCreate(c checker, r request) verdict {
	var s libpodSpec
	if reason := decodeBody(r.Body, &s); reason != "" {
		return refuseIf(reason)
	}
	infra := ""
	if s.InfraImage != "" {
		infra = c.image(s.InfraImage)
	}
	return refuseIf(first(infra, c.spec(s)))
}

func (c checker) spec(s libpodSpec) string {
	log := ""
	if s.LogConfiguration != nil {
		log = s.LogConfiguration.Path
	}
	return first(
		banFlag(s.Privileged != nil && *s.Privileged, "privileged containers"),
		banList(s.CapAdd, "added capabilities"),
		banList(s.Devices, "host devices"),
		banList(s.PodDevices, "host devices"),
		banList(s.DeviceCgroupRule, "device cgroup rules"),
		banList(s.DevicesFrom, "devices from other containers"),
		banList(s.HostDeviceList, "host devices"),
		banList(s.VolumesFrom, "volumes from other containers"),
		banList(s.Unmask, "unmasked kernel paths"),
		c.specNamespace("pid", s.PidNS),
		c.specNamespace("ipc", s.IpcNS),
		c.specNamespace("uts", s.UtsNS),
		c.specNamespace("user", s.UserNS),
		c.specNamespace("cgroup", s.CgroupNS),
		c.specNetwork(s.NetNS),
		c.seccomp(s.SeccompPolicy, s.SeccompProfilePath),
		c.apparmor(s.ApparmorProfile),
		c.selinux(s.SelinuxOpts),
		c.securityOpts(s.SecurityOpt),
		banText(s.OCIRuntime, "another OCI runtime"),
		banMap(s.Sysctl, "sysctls"),
		banText(s.CgroupParent, "a cgroup parent"),
		banText(s.InitPath, "an init binary from the podman service's side"),
		banText(s.ConmonPidFile, "a conmon PID file on the podman service's side"),
		banText(s.InfraConmonPidFile, "a conmon PID file on the podman service's side"),
		c.writablePath(log, "the log path"),
		c.hostsFile(s.BaseHostsFile),
		c.hostsFile(s.HostsFile),
		c.healthLog(s.HealthLogDestination),
		c.specMounts(s.Mounts),
		c.overlays(s.OverlayVolumes),
		c.imageVolumes(s.ImageVolumes),
	)
}

func (c checker) specNamespace(kind string, ns specNamespace) string {
	switch strings.ToLower(ns.NSMode) {
	case "host":
		return fmt.Sprintf("containers in the host's %s namespace are not allowed; no profile setting allows them", kind)
	case "path":
		return fmt.Sprintf("containers that join a %s namespace by path are not allowed; no profile setting allows them", kind)
	}
	return ""
}

func (c checker) specNetwork(ns specNamespace) string {
	if strings.EqualFold(ns.NSMode, "path") {
		return "containers that join a network namespace by path are not allowed; no profile setting allows them"
	}
	return ""
}

// seccomp refuses custom profiles as well as "unconfined": an agent can write
// a profile that allows everything into its worktree.
func (c checker) seccomp(policy, profile string) string {
	if strings.EqualFold(policy, "image") {
		return "the seccomp profile from the image is not allowed: containers keep the default seccomp profile"
	}
	if profile != "" {
		return fmt.Sprintf("seccomp profile %q is not allowed: containers keep the default seccomp profile", profile)
	}
	return ""
}

func (c checker) apparmor(profile string) string {
	if strings.EqualFold(profile, "unconfined") {
		return "AppArmor profile \"unconfined\" is not allowed: containers keep their AppArmor profile"
	}
	return ""
}

func (c checker) selinux(opts []string) string {
	for _, o := range opts {
		if reason := selinuxOption(o); reason != "" {
			return reason
		}
	}
	return ""
}

func (c checker) specMounts(ms []specMount) string {
	for _, m := range ms {
		bind := false
		for _, o := range m.Options {
			if o == "bind" || o == "rbind" {
				bind = true
			}
		}
		switch t := strings.ToLower(m.Type); {
		case t == "bind" || t == "glob" || bind:
			a, reason := bindAccess(m.Options)
			if reason != "" {
				return reason
			}
			if reason := c.bindSource(globBase(m.Source), a); reason != "" {
				return reason
			}
		case t == "tmpfs", t == "ramfs", t == "devpts", t == "mqueue":
		case t == "volume":
			if !volumeName.MatchString(m.Source) {
				return fmt.Sprintf("volume source %q is not a volume name", m.Source)
			}
		case t == "image":
			if reason := c.image(m.Source); reason != "" {
				return reason
			}
		default:
			return fmt.Sprintf("mounts of type %q are not allowed", m.Type)
		}
	}
	return ""
}

// globBase is the directory part of a glob mount's source before the first
// pattern character, which bounds every path the glob can match.
func globBase(src string) string {
	i := strings.IndexAny(src, "*?[")
	if i < 0 {
		return src
	}
	return path.Dir(src[:i] + "x")
}

// overlays only need read access: writes go to a temporary upper layer.
func (c checker) overlays(vs []overlayVolume) string {
	for _, v := range vs {
		a, reason := bindAccess(v.Options)
		if reason != "" {
			return reason
		}
		a.write = false
		if reason := c.bindSource(v.Source, a); reason != "" {
			return reason
		}
	}
	return ""
}

func (c checker) imageVolumes(vs []imageVolume) string {
	for _, v := range vs {
		if reason := c.image(v.Source); reason != "" {
			return reason
		}
	}
	return ""
}

func (c checker) hostsFile(p string) string {
	switch strings.ToLower(p) {
	case "", "image", "none":
		return ""
	}
	return c.bindSource(p, access{})
}

func (c checker) healthLog(dest string) string {
	switch strings.ToLower(dest) {
	case "", "local", "events_logger":
		return ""
	}
	return c.writablePath(dest, "the health check log")
}

func (c checker) writablePath(p, what string) string {
	if p == "" {
		return ""
	}
	if reason := c.bindSource(p, access{write: true}); reason != "" {
		return fmt.Sprintf("%s %s: %s", what, p, reason)
	}
	return ""
}

type execBody struct {
	Privileged bool
}

func execCreate(c checker, r request) verdict {
	var b execBody
	if reason := decodeBody(r.Body, &b); reason != "" {
		return refuseIf(reason)
	}
	return refuseIf(banFlag(b.Privileged, "privileged exec sessions"))
}

func banFlag(set bool, what string) string {
	if set {
		return what + " are not allowed; no profile setting allows them"
	}
	return ""
}

func banList[T any](items []T, what string) string {
	if len(items) > 0 {
		return what + " are not allowed; no profile setting allows them"
	}
	return ""
}

func banMap(m map[string]string, what string) string {
	if len(m) > 0 {
		return what + " are not allowed; no profile setting allows them"
	}
	return ""
}

func banText(v, what string) string {
	if v != "" {
		return fmt.Sprintf("%s (%q) is not allowed; no profile setting allows it", what, v)
	}
	return ""
}

func lookupFold(m map[string]string, key string) string {
	for k, v := range m {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}
