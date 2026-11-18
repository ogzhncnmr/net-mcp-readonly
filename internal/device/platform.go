package device

import "regexp"

// driver holds what the runner needs to know about a CLI.
//
// The paging commands and prompt patterns below come from vendor CLI
// conventions and were exercised only against the mock device in this
// repository, not against real hardware. Override paging_command per device
// in the inventory if your software release differs.
type driver struct {
	pagingCommand string
	// prompt must match the operational-mode prompt (the last line of
	// output) and must NOT match configuration-mode prompts where the CLI
	// marks them on the same line.
	prompt *regexp.Regexp
}

var drivers = map[string]driver{
	// RP/0/RP0/CPU0:pe1#   (config mode: RP/0/RP0/CPU0:pe1(config)#)
	"iosxr": {
		pagingCommand: "terminal length 0",
		prompt:        regexp.MustCompile(`^[A-Za-z0-9_./:-]+#\s?$`),
	},
	// user@pe1>            (config mode: user@pe1#)
	"junos": {
		pagingCommand: "set cli screen-length 0",
		prompt:        regexp.MustCompile(`^[A-Za-z0-9_.-]+@[A-Za-z0-9_.:-]+>\s?$`),
	},
	// <pe1>                (system-view: [pe1] or [~pe1])
	"vrp": {
		pagingCommand: "screen-length 0 temporary",
		prompt:        regexp.MustCompile(`^<[A-Za-z0-9_.:-]+>\s?$`),
	},
	// A:pe1#  or  A:admin@pe1#   (classic config: A:pe1>config#)
	// MD-CLI shows the edit mode on the line above the prompt, so for MD-CLI
	// this pattern cannot tell operational from configuration mode.
	"sros": {
		pagingCommand: "environment no more",
		prompt:        regexp.MustCompile(`^\*?[AB]:[A-Za-z0-9_.@-]+#\s?$`),
	},
}
