package advisor

// CatalogEntry is one advisor model the daemon can run itself (mlx_lm). Bytes
// is the download (safetensors) size; Match names the family tokens an
// installed model must carry to count as the same model; Rank orders
// preference among models that fit.
type CatalogEntry struct {
	ID    string
	Label string
	Match []string
	Bytes int64
	Rank  int
}

// Catalog: ids and sizes verified on Hugging Face (mlx-community,
// api/models/<id>?blobs=true, safetensors total) on 2026-09-23. Highest rank
// first.
var Catalog = []CatalogEntry{
	{ID: "mlx-community/Qwen3.8-27B-8bit", Label: "Qwen3.8 27B · 8-bit", Match: []string{"qwen3.8", "27b"}, Bytes: 29501218479, Rank: 50},
	{ID: "mlx-community/Qwen3.8-27B-4bit", Label: "Qwen3.8 27B · 4-bit", Match: []string{"qwen3.8", "27b"}, Bytes: 16054541349, Rank: 40},
	{ID: "mlx-community/Qwen3.6-35B-A3B-4bit", Label: "Qwen3.6 35B-A3B · 4-bit", Match: []string{"qwen3.6", "35b"}, Bytes: 20402204271, Rank: 30},
	{ID: "mlx-community/Qwen3.5-9B-MLX-4bit", Label: "Qwen3.5 9B · 4-bit", Match: []string{"qwen3.5", "9b"}, Bytes: 5950221072, Rank: 20},
	{ID: "mlx-community/Qwen3.5-4B-MLX-4bit", Label: "Qwen3.5 4B · 4-bit", Match: []string{"qwen3.5", "4b"}, Bytes: 3034300695, Rank: 10},
}

// DefaultManagedModels lists the catalog ids the managed server can run.
var DefaultManagedModels = func() []string {
	ids := make([]string, 0, len(Catalog))
	for _, c := range Catalog {
		ids = append(ids, c.ID)
	}
	return ids
}()
