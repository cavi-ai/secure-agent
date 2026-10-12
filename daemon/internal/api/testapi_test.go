package api

// newTestAPI exercises the same construction interface as production.
func newTestAPI(deps Deps) *API { return New(deps) }
