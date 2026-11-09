package modelservice

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cavi-ai/secure-agent/internal/localservice"
)

type Preview struct {
	ID           string   `json:"id"`
	Hash         string   `json:"preview_hash"`
	Source       string   `json:"source"`
	Label        string   `json:"label"`
	Change       Change   `json:"change"`
	Endpoint     string   `json:"endpoint"`
	ClientFields []string `json:"client_fields"`
	Settings     []string `json:"settings"`
	Warnings     []string `json:"warnings"`
}

type Receipt struct {
	Preview
	State        string    `json:"state"`
	VerifiedAt   time.Time `json:"verified_at,omitzero"`
	Checks       []string  `json:"checks"`
	SourceSHA    string    `json:"source_sha256"`
	ClientSHA    string    `json:"client_sha256"`
	OriginalMode uint32    `json:"original_mode"`
	ClientMode   uint32    `json:"client_mode"`
	OriginalSHA  string    `json:"original_sha256"`
	ClientOldSHA string    `json:"client_original_sha256"`
	Failure      string    `json:"failure,omitempty"`
	KeySHA       string    `json:"key_sha256,omitempty"`
}

type plan struct {
	preview                                      Preview
	created                                      time.Time
	job                                          jobState
	original, updated, clients, clientsUpdated   []byte
	sourceMode, clientMode                       os.FileMode
	binary, binarySHA, engine, engineSHA, keySHA string
}

type Manager struct {
	root, configPath string
	engine           func() string
	mu               sync.Mutex
	operation        sync.Mutex
	plans            map[string]*plan
}

func New(configPath string, engine func() string) *Manager {
	return &Manager{root: filepath.Join(filepath.Dir(configPath), "model-services"), configPath: configPath, engine: engine, plans: map[string]*plan{}}
}

func (m *Manager) keyPath(label string) string {
	return filepath.Join(m.root, "keys", digest([]byte(label))+".key")
}
func (m *Manager) jobDir(label string) string {
	return filepath.Join(m.root, "jobs", digest([]byte(label)))
}

func (m *Manager) Preview(ctx context.Context, source string) (Preview, error) {
	p, err := m.prepare(ctx, source)
	if err != nil {
		return Preview{}, err
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return Preview{}, err
	}
	p.preview.ID = hex.EncodeToString(id)
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, existing := range m.plans {
		if time.Since(existing.created) > 5*time.Minute {
			delete(m.plans, id)
		}
	}
	if len(m.plans) >= 16 {
		return Preview{}, errors.New("too many remediation previews; retry after earlier previews expire")
	}
	m.plans[p.preview.ID] = p
	return p.preview, nil
}

func (m *Manager) prepare(ctx context.Context, source string) (*plan, error) {
	if runtime.GOOS != "darwin" {
		return nil, errors.New("automatic remediation supports current-user macOS launchd jobs only")
	}
	raw, mode, err := ownedFile(source, maxDefinition, false)
	if err != nil {
		return nil, err
	}
	job, err := definition(raw)
	if err != nil {
		return nil, err
	}
	label, ok := job["Label"].(string)
	if !ok || !labelPattern.MatchString(label) {
		return nil, errors.New("invalid service label")
	}
	state, err := inspectJob(ctx, label)
	if err != nil {
		return nil, err
	}
	if state.PID < 1 {
		return nil, errors.New("selected service must be running before preview")
	}
	a, err := filepath.EvalSymlinks(state.Path)
	b, pathErr := filepath.EvalSymlinks(source)
	if err != nil || pathErr != nil || a != b {
		return nil, errors.New("running service definition does not match the selected file")
	}
	source = b
	args, err := arguments(job)
	if err != nil {
		return nil, err
	}
	encodedArgs, _ := json.Marshal(args)
	if state.Program != args[0] || state.ArgsSHA != digest(encodedArgs) {
		return nil, errors.New("loaded service arguments differ from its definition; reload it through its owner before remediation")
	}
	binarySHA, err := executableDigest(args[0])
	if err != nil {
		return nil, err
	}
	engine, engineSHA := "", ""
	if filepath.Base(args[0]) == "mlx_lm.server" {
		if m.engine != nil {
			engine = m.engine()
		}
		caps, err := engineIdentity(ctx, engine)
		if err != nil {
			return nil, err
		}
		engineSHA = caps
	}
	change, err := adapt(job, m.keyPath(label), engine)
	if err != nil {
		return nil, err
	}
	inventory := localservice.DiscoverListeners(ctx)
	if inventory.State != "available" || inventory.Truncated {
		return nil, errors.New("original listener inventory is incomplete")
	}
	originalOwned := false
	for _, listener := range inventory.Listeners {
		if listener.PID == state.PID {
			_, port, _ := net.SplitHostPort(listener.Address)
			if port == strconv.Itoa(change.Port) {
				originalOwned = true
			}
		}
	}
	if !originalOwned {
		return nil, errors.New("the running service does not own the configured original port")
	}
	if change.Runtime == "llama.cpp" {
		help, err := native(ctx, nil, args[0], "--help")
		if err != nil {
			return nil, errors.New("llama-server capabilities unavailable")
		}
		for _, flag := range []string{"--api-key-file", "--cors-origins", "--no-cors-credentials"} {
			if !bytesContain(help, flag) {
				return nil, errors.New("installed llama-server does not support the required protection settings")
			}
		}
	}
	updated, err := encodeDefinition(job)
	if err != nil {
		return nil, err
	}
	clients, clientMode, err := ownedFile(m.configPath, maxDefinition, false)
	if err != nil {
		return nil, err
	}
	clientsUpdated, fields, err := clientConfiguration(m.configPath, clients, change, m.keyPath(label))
	if err != nil {
		return nil, err
	}
	keySHA := "new"
	if change.Scope == "authenticated_inference" {
		if key, _, err := ownedFile(m.keyPath(label), 512, true); err == nil {
			keySHA = digest(key)
		} else if _, err := os.Lstat(m.keyPath(label)); !os.IsNotExist(err) {
			return nil, errors.New("existing service key is unavailable or unsafe")
		}
	}
	preview := Preview{Source: source, Label: label, Change: change, Endpoint: "http://127.0.0.1:" + strconv.Itoa(change.Port), ClientFields: fields,
		Settings: []string{"Bind only to 127.0.0.1 on the existing port."},
		Warnings: []string{"The selected service will restart and active requests can be interrupted.", "On failure or rollback, the original configuration is restored and the service stays stopped. Restarting an unprotected original is a separate owner action."}}
	if change.Scope == "browser_hardening" {
		preview.Settings = append(preview.Settings, "Clear additional OLLAMA_ORIGINS entries; built-in allowed origins remain.")
		preview.Warnings = append(preview.Warnings, "Ollama retains built-in allowed origins and unauthenticated local access. This operation verifies browser hardening only.")
	} else {
		preview.Settings = append(preview.Settings, "Require the private API key file: "+m.keyPath(label), "Refuse foreign browser origins.")
		if change.Runtime == "mlx" {
			preview.Settings = append(preview.Settings, "Use the protected MLX gateway with an inherited Unix-socket model worker.")
		}
		preview.Warnings = append(preview.Warnings, "Verification can load existing local weights for one authorized output token; no model download is performed.", "Other clients must use the new key. Matching Secure Agent client fields are updated; unrelated configuration is preserved.")
	}
	p := &plan{preview: preview, created: time.Now(), job: state, original: raw, updated: updated, clients: clients, clientsUpdated: clientsUpdated, sourceMode: mode, clientMode: clientMode, binary: args[0], binarySHA: binarySHA, engine: engine, engineSHA: engineSHA, keySHA: keySHA}
	bound, _ := json.Marshal([]any{source, label, change, state, digest(raw), digest(updated), digest(clients), digest(clientsUpdated), binarySHA, engineSHA, keySHA})
	p.preview.Hash = digest(bound)
	return p, nil
}

func engineIdentity(ctx context.Context, executable string) (string, error) {
	if !filepath.IsAbs(executable) {
		return "", errors.New("compatible protected MLX runtime is unavailable")
	}
	binary, err := executableDigest(executable)
	if err != nil {
		return "", err
	}
	raw, err := native(ctx, nil, executable, "serve", "protected-service", "--describe")
	var value struct {
		Protocol string `json:"protocol"`
		Source   string `json:"source_sha256"`
	}
	if err != nil || len(raw) > 4096 || json.Unmarshal(raw, &value) != nil || value.Protocol != "protected-service-v1" || len(value.Source) != 64 {
		return "", errors.New("compatible protected MLX runtime is unavailable")
	}
	return digest([]byte(binary + value.Source)), nil
}

func bytesContain(raw []byte, value string) bool { return strings.Contains(string(raw), value) }

func (m *Manager) Apply(ctx context.Context, id, hash string) (Receipt, error) {
	if !m.operation.TryLock() {
		return Receipt{}, errors.New("a service operation is already running")
	}
	defer m.operation.Unlock()
	m.mu.Lock()
	p := m.plans[id]
	delete(m.plans, id)
	m.mu.Unlock()
	if p == nil || time.Since(p.created) > 5*time.Minute || hash != p.preview.Hash {
		return Receipt{}, errors.New("remediation preview is missing, expired or changed")
	}
	fresh, err := m.prepare(ctx, p.preview.Source)
	if err != nil || fresh.preview.Hash != hash {
		return Receipt{}, errors.New("service, client configuration, process, key or runtime changed; review a new preview")
	}
	for _, directory := range []string{m.root, filepath.Join(m.root, "keys"), filepath.Join(m.root, "jobs"), m.jobDir(p.preview.Label)} {
		if err := privateDirectory(directory); err != nil {
			return Receipt{}, err
		}
	}
	if previous, err := m.Status(p.preview.Label); err == nil && previous.State != "restored_stopped" && previous.State != "failed_restored_stopped" && previous.State != "failed_no_change" {
		return Receipt{}, errors.New("a previous operation requires review or rollback first")
	}
	if _, err := os.Lstat(filepath.Join(m.jobDir(p.preview.Label), "receipt.json")); err == nil {
		if _, err := m.Status(p.preview.Label); err != nil {
			return Receipt{}, errors.New("previous remediation state is unreadable; original files were retained")
		}
	} else if !os.IsNotExist(err) {
		return Receipt{}, errors.New("previous remediation state is unavailable")
	} else if entries, err := os.ReadDir(m.jobDir(p.preview.Label)); err != nil || len(entries) > 0 {
		return Receipt{}, errors.New("unrecorded remediation files require owner review; original files were retained")
	}
	dir := m.jobDir(p.preview.Label)
	if err := atomicFile(filepath.Join(dir, "original.plist"), p.original, 0600); err != nil {
		return Receipt{}, err
	}
	if err := atomicFile(filepath.Join(dir, "original.yaml"), p.clients, 0600); err != nil {
		return Receipt{}, err
	}
	r := Receipt{Preview: p.preview, State: "prepared", Checks: []string{}, SourceSHA: digest(p.updated), ClientSHA: digest(p.clientsUpdated), OriginalSHA: digest(p.original), ClientOldSHA: digest(p.clients), OriginalMode: uint32(p.sourceMode), ClientMode: uint32(p.clientMode)}
	if err := m.save(r); err != nil {
		return r, err
	}
	if p.preview.Change.Scope == "authenticated_inference" && p.keySHA == "new" {
		if err := localservice.CreateKeyFile(m.keyPath(p.preview.Label)); err != nil {
			r.State = "failed_no_change"
			_ = m.save(r)
			return r, err
		}
	}
	if p.preview.Change.Scope == "authenticated_inference" {
		key, _, err := ownedFile(m.keyPath(p.preview.Label), 512, true)
		if err != nil {
			return r, err
		}
		if p.keySHA != "new" && digest(key) != p.keySHA {
			return r, errors.New("service key changed before restart")
		}
		p.keySHA = digest(key)
		r.KeySHA = p.keySHA
	}
	current, err := inspectJob(ctx, r.Label)
	if err != nil || current != p.job {
		r.State = "failed_no_change"
		_ = m.save(r)
		return r, errors.New("service identity changed before restart")
	}
	if err := unchanged(r.Source, p.original); err != nil {
		return r, err
	}
	if err := unchanged(m.configPath, p.clients); err != nil {
		return r, err
	}
	if err := stopJob(ctx, r.Label); err != nil {
		r.State = "failed_no_change"
		_ = m.save(r)
		return r, err
	}
	r.State = "applying"
	fail := func(cause error) (Receipt, error) {
		cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := stopSelectedJob(cleanup, r.Label, r.Source); err != nil {
			r.State = "rollback_required"
			r.Failure = "new service could not be stopped; private original retained"
			_ = m.save(r)
			return r, errors.New(r.Failure)
		}
		if err := m.restore(&r); err != nil {
			r.State = "rollback_required"
		} else {
			r.State = "failed_restored_stopped"
		}
		r.Failure = cause.Error()
		_ = m.save(r)
		return r, cause
	}
	if err := m.save(r); err != nil {
		return fail(err)
	}
	if err := unchanged(r.Source, p.original); err != nil {
		return fail(err)
	}
	if err := unchanged(m.configPath, p.clients); err != nil {
		return fail(err)
	}
	if err := atomicFile(r.Source, p.updated, 0600); err != nil {
		return fail(err)
	}
	if digest(p.clients) != digest(p.clientsUpdated) {
		if err := atomicFile(m.configPath, p.clientsUpdated, 0600); err != nil {
			return fail(err)
		}
	}
	if err := startJob(ctx, r.Source); err != nil {
		return fail(err)
	}
	_, err = native(ctx, nil, "/bin/launchctl", "kickstart", "gui/"+strconv.Itoa(os.Getuid())+"/"+r.Label)
	if err != nil {
		return fail(err)
	}
	checks, err := m.verify(ctx, p)
	if err != nil {
		return fail(err)
	}
	if err := unchanged(r.Source, p.updated); err != nil {
		return fail(err)
	}
	if err := unchanged(m.configPath, p.clientsUpdated); err != nil {
		return fail(err)
	}
	if p.preview.Change.Scope == "authenticated_inference" {
		key, _, err := ownedFile(m.keyPath(p.preview.Label), 512, true)
		if err != nil || digest(key) != p.keySHA {
			return fail(errors.New("service key changed during verification"))
		}
	}
	r.State = "verified"
	r.Checks = checks
	r.VerifiedAt = time.Now().UTC()
	if err := m.save(r); err != nil {
		return fail(err)
	}
	return r, nil
}

func privateDirectory(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return errors.New("private remediation state unavailable")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("remediation state directory must be private and not a symlink")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() {
		return errors.New("remediation state owner mismatch")
	}
	return nil
}

func unchanged(path string, expected []byte) error {
	raw, _, err := ownedFile(path, maxDefinition, false)
	if err != nil || digest(raw) != digest(expected) {
		return errors.New("configuration changed during remediation; refusing overwrite")
	}
	return nil
}

func (m *Manager) save(r Receipt) error {
	data, _ := json.Marshal(r)
	return atomicFile(filepath.Join(m.jobDir(r.Label), "receipt.json"), data, 0600)
}

func (m *Manager) Status(label string) (Receipt, error) {
	var r Receipt
	if !labelPattern.MatchString(label) {
		return r, errors.New("invalid service label")
	}
	raw, _, err := ownedFile(filepath.Join(m.jobDir(label), "receipt.json"), maxDefinition, true)
	if err != nil || json.Unmarshal(raw, &r) != nil || r.Label != label {
		return Receipt{}, errors.New("remediation receipt unavailable")
	}
	return r, nil
}

type restoreInput struct {
	path              string
	current, original []byte
	mode              os.FileMode
}

func (m *Manager) rollbackInputs(r *Receipt) ([]restoreInput, error) {
	dir := m.jobDir(r.Label)
	inputs := []restoreInput{}
	for _, item := range []struct {
		path, backup, oldHash, newHash string
		mode                           uint32
	}{
		{r.Source, "original.plist", r.OriginalSHA, r.SourceSHA, r.OriginalMode},
		{m.configPath, "original.yaml", r.ClientOldSHA, r.ClientSHA, r.ClientMode},
	} {
		raw, _, err := ownedFile(item.path, maxDefinition, false)
		if err != nil || digest(raw) != item.newHash && digest(raw) != item.oldHash {
			return nil, errors.New("rollback refuses configuration drift; private original retained")
		}
		original, _, err := ownedFile(filepath.Join(dir, item.backup), maxDefinition, true)
		if err != nil || digest(original) != item.oldHash {
			return nil, errors.New("rollback original unavailable")
		}
		inputs = append(inputs, restoreInput{item.path, raw, original, os.FileMode(item.mode)})
	}
	return inputs, nil
}

func (m *Manager) restore(r *Receipt) error {
	inputs, err := m.rollbackInputs(r)
	if err != nil {
		return err
	}
	for _, item := range inputs {
		if err := unchanged(item.path, item.current); err != nil {
			return err
		}
		if digest(item.current) != digest(item.original) {
			if err := atomicFile(item.path, item.original, item.mode); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *Manager) Rollback(ctx context.Context, label string) (Receipt, error) {
	if !m.operation.TryLock() {
		return Receipt{}, errors.New("a service operation is already running")
	}
	defer m.operation.Unlock()
	r, err := m.Status(label)
	if err != nil {
		return r, err
	}
	if r.State != "verified" && r.State != "rollback_required" && r.State != "prepared" && r.State != "applying" && r.State != "failed_no_change" {
		return r, errors.New("no active remediation to roll back")
	}
	if _, err := m.rollbackInputs(&r); err != nil {
		return r, err
	}
	if err := stopSelectedJob(ctx, label, r.Source); err != nil {
		return r, err
	}
	if err := m.restore(&r); err != nil {
		r.State = "rollback_required"
		_ = m.save(r)
		return r, err
	}
	r.State = "restored_stopped"
	r.VerifiedAt = time.Time{}
	return r, m.save(r)
}
