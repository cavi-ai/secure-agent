package apiroutes

import "testing"

// The console's allow-path action posts /guard/path-allow on the proxy
// listener: the console token admits it, and POST is a pinned-UI mutation.
func TestGuardPathAllowConsoleAdmittedAndMutating(t *testing.T) {
	if !ConsoleAllowed("/guard/path-allow") {
		t.Fatal("/guard/path-allow must be console-admitted")
	}
	if !IsMutation("POST", "/guard/path-allow") {
		t.Fatal("POST /guard/path-allow must be a mutation")
	}
	for _, m := range []string{"GET", "DELETE"} {
		if IsMutation(m, "/guard/path-allow") {
			t.Fatalf("%s /guard/path-allow must not be a pinned-UI mutation (GET reads, DELETE stays owner-level)", m)
		}
	}
	if ConsoleAllowed("/guard/path-allow/x") {
		t.Fatal("only the exact path is admitted")
	}
}
