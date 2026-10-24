package profile

const defaultsSource = "doriath"

var defaults = layer{
	source: defaultsSource,
	Env: envLayer{
		Pass: []string{
			"PATH", "TERM", "COLORTERM", "TERM_PROGRAM", "TERMINFO", "TERMINFO_DIRS",
			"LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "LC_MESSAGES", "TZ", "LOCALE_ARCHIVE",
			"USER", "LOGNAME", "SHELL", "EDITOR", "VISUAL", "PAGER",
			"NO_COLOR", "FORCE_COLOR", "CLICOLOR",
			"XDG_DATA_DIRS", "XDG_CONFIG_DIRS", "NIX_PATH", "NIX_PROFILES",
		},
		Set: map[string]string{"AWS_EC2_METADATA_DISABLED": "true"},
	},
}
