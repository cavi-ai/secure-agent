package agents

import (
	"path/filepath"
	"strings"
)

func nodeExecutable(exe string) bool {
	name := strings.ToLower(filepath.Base(exe))
	return name == "node" || name == "nodejs"
}

// nodeProgram keeps only a named program or entry-point path. Unknown options,
// eval/print code and stdin do not establish a harness identity.
func nodeProgram(argv []string, cwd string) string {
	if len(argv) == 0 {
		return ""
	}
	// Node applications may replace argv[0] with their process title.
	switch strings.ToLower(argv[0]) {
	case "openclaw", "openclaw-gateway", "openclaw-tui":
		return argv[0]
	}
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		option, _, assigned := strings.Cut(arg, "=")
		switch {
		case arg == "--":
			i++
			if i == len(argv) {
				return ""
			}
			arg = argv[i]
		case option == "-r" || option == "--require" || option == "--import" || option == "--loader" || option == "--experimental-loader" || option == "--conditions" || option == "-C" || option == "--title" || option == "--disable-warning" || option == "--env-file" || option == "--env-file-if-exists" || option == "--max-old-space-size":
			if !assigned {
				i++
			}
			continue
		case option == "--inspect" || option == "--inspect-brk":
			continue
		case arg == "--no-warnings" || arg == "--enable-source-maps" || arg == "--experimental-strip-types":
			continue
		case strings.HasPrefix(arg, "-"):
			return ""
		}
		if arg == "" || arg == "-" {
			return ""
		}
		if !filepath.IsAbs(arg) && cwd != "" {
			arg = filepath.Join(cwd, arg)
		}
		return filepath.Clean(arg)
	}
	return ""
}
