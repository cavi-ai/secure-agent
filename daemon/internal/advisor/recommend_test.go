package advisor

import "testing"

const gb = int64(1_000_000_000)

func recByID(recs []Recommendation, id string) (Recommendation, bool) {
	for _, r := range recs {
		if r.ID == id {
			return r, true
		}
	}
	return Recommendation{}, false
}

func recommended(recs []Recommendation) []string {
	var out []string
	for _, r := range recs {
		if r.Recommended {
			out = append(out, r.ID)
		}
	}
	return out
}

func TestFitThresholds(t *testing.T) {
	ram := uint64(100 * gb)
	for _, c := range []struct {
		bytes int64
		ram   uint64
		want  string
	}{
		{41 * gb, ram, "fits"},    // need 49.2 ≤ 50
		{42 * gb, ram, "tight"},   // need 50.4
		{62 * gb, ram, "tight"},   // need 74.4 ≤ 75
		{63 * gb, ram, "too-big"}, // need 75.6
		{0, ram, "unknown"},       // size unknown
		{10 * gb, 0, "unknown"},   // RAM unknown
	} {
		if got := fit(c.bytes, c.ram); got != c.want {
			t.Errorf("fit(%d, %d) = %s, want %s", c.bytes, c.ram, got, c.want)
		}
	}
}

// On a 128 GB Mac with Ollama models installed, the installed catalog-family
// model that fits is recommended; a model too large is marked so; embedding
// models never appear.
func TestRecommendPrefersInstalledCatalogFamily(t *testing.T) {
	m := Machine{Chip: "Apple M5 Max", RAMBytes: 137438953472}
	servers := []DiscoveredServer{{
		Endpoint: "http://127.0.0.1:11434", Kind: "ollama",
		Models: []string{"llama3.1:70b", "qwen3-embedding:8b", "qwen3.8-flash-next:125b-mlx", "qwen3.8:27b-mlx"},
		Sizes: map[string]int64{
			"qwen3.8:27b-mlx": 18174721847, "llama3.1:70b": 42520412561,
			"qwen3.8-flash-next:125b-mlx": 104852026135, "qwen3-embedding:8b": 4676805193,
		},
	}}
	recs := Recommend(m, servers)
	if got := recommended(recs); len(got) != 1 || got[0] != "qwen3.8:27b-mlx" {
		t.Fatalf("recommended = %v, want [qwen3.8:27b-mlx]", got)
	}
	if recs[0].ID != "qwen3.8:27b-mlx" || recs[0].Source != "installed" || recs[0].Endpoint != "http://127.0.0.1:11434" || recs[0].Fit != "fits" {
		t.Fatalf("first = %+v", recs[0])
	}
	if r, ok := recByID(recs, "qwen3.8-flash-next:125b-mlx"); !ok || r.Fit != "too-big" {
		t.Fatalf("125b = %+v ok=%v, want too-big", r, ok)
	}
	if _, ok := recByID(recs, "qwen3-embedding:8b"); ok {
		t.Fatal("embedding model must not be offered")
	}
	if r, ok := recByID(recs, "mlx-community/Qwen3.8-27B-8bit"); !ok || r.Source != "managed" || r.Fit != "fits" {
		t.Fatalf("managed 27B-8bit = %+v ok=%v", r, ok)
	}
}

// With no server, the highest-rank catalog model that fits is recommended.
func TestRecommendManagedByRAM(t *testing.T) {
	for _, c := range []struct {
		ramGB uint64
		want  string
	}{
		{8, "mlx-community/Qwen3.5-4B-MLX-4bit"},
		{16, "mlx-community/Qwen3.5-9B-MLX-4bit"},
		{64, "mlx-community/Qwen3.8-27B-4bit"},
		{128, "mlx-community/Qwen3.8-27B-8bit"},
	} {
		recs := Recommend(Machine{RAMBytes: c.ramGB << 30}, nil)
		if got := recommended(recs); len(got) != 1 || got[0] != c.want {
			t.Errorf("%d GB: recommended %v, want %s", c.ramGB, got, c.want)
		}
		if len(recs) != len(Catalog) {
			t.Errorf("%d GB: %d recommendations, want the %d catalog models", c.ramGB, len(recs), len(Catalog))
		}
	}
	if r, _ := recByID(Recommend(Machine{RAMBytes: 8 << 30}, nil), "mlx-community/Qwen3.8-27B-4bit"); r.Fit != "too-big" {
		t.Fatalf("27B on 8 GB = %s, want too-big", r.Fit)
	}
}

// An unknown RAM size or an unknown model size never produces a
// recommendation.
func TestRecommendUnknownSizes(t *testing.T) {
	recs := Recommend(Machine{}, nil)
	if got := recommended(recs); len(got) != 0 {
		t.Fatalf("RAM unknown: recommended %v, want none", got)
	}
	for _, r := range recs {
		if r.Fit != "unknown" {
			t.Fatalf("RAM unknown: %s fit %s", r.ID, r.Fit)
		}
	}
	srv := []DiscoveredServer{{Endpoint: "http://127.0.0.1:8080", Kind: "openai-compatible", Models: []string{"qwen3.8-27b"}}}
	recs = Recommend(Machine{RAMBytes: 64 << 30}, srv)
	if r, ok := recByID(recs, "qwen3.8-27b"); !ok || r.Fit != "unknown" || r.Recommended {
		t.Fatalf("size-less server model = %+v ok=%v", r, ok)
	}
	if got := recommended(recs); len(got) != 1 || got[0] != "mlx-community/Qwen3.8-27B-4bit" {
		t.Fatalf("recommended %v, want the managed 27B", got)
	}
}

func TestMachineProfileReadsRAM(t *testing.T) {
	if m := MachineProfile(); m.RAMBytes == 0 {
		t.Fatalf("MachineProfile() = %+v, want RAM", m)
	}
}
