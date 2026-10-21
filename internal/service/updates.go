package service

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

var updateVersion = regexp.MustCompile(`^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$`)
var updateName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,160}$`)
var updateDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)

type releaseArtifact struct {
	File   string `json:"file"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}
type releasePayload struct {
	Version string `json:"version"`
	Targets map[string]struct {
		ASAR      releaseArtifact  `json:"asar"`
		Installer releaseArtifact  `json:"installer"`
		RPM       *releaseArtifact `json:"rpm,omitempty"`
	} `json:"targets"`
}

// Preserve the publisher's signed envelope byte for byte. Authenticity and
// rollback protection remain enforced by the desktop's pinned publisher key.
func releaseManifest(root *os.Root, name string) ([]byte, releasePayload, error) {
	var payload releasePayload
	file, err := root.Open(name)
	if err != nil {
		return nil, payload, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 128*1024+1))
	if err != nil || len(data) > 128*1024 {
		return nil, payload, errors.New("invalid manifest size")
	}
	var envelope struct {
		Schema    int    `json:"schema"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	if json.Unmarshal(data, &envelope) != nil || envelope.Schema != 1 {
		return nil, payload, errors.New("invalid envelope")
	}
	sig, err := base64.StdEncoding.DecodeString(envelope.Signature)
	if err != nil || len(sig) != 64 {
		return nil, payload, errors.New("invalid signature encoding")
	}
	decoded, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil || json.Unmarshal(decoded, &payload) != nil || !updateVersion.MatchString(payload.Version) || len(payload.Targets) != 4 {
		return nil, payload, errors.New("invalid release")
	}
	for _, name := range []string{"win32-x64", "linux-x64", "linux-arm64", "darwin-arm64"} {
		target, ok := payload.Targets[name]
		if !ok {
			return nil, payload, errors.New("missing target")
		}
		assets := []releaseArtifact{target.ASAR, target.Installer}
		if target.RPM != nil {
			if !strings.HasPrefix(name, "linux-") || !strings.HasSuffix(target.RPM.File, ".rpm") {
				return nil, payload, errors.New("invalid RPM installer")
			}
			assets = append(assets, *target.RPM)
		}
		for _, asset := range assets {
			if !updateName.MatchString(asset.File) || !updateDigest.MatchString(asset.SHA256) || asset.Size < 1 || asset.Size > 1<<30 {
				return nil, payload, errors.New("invalid artifact")
			}
		}
	}
	return data, payload, nil
}

func updateHandler(directory string) http.Handler {
	downloads := make(chan struct{}, 4)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		unavailable := func() { fail(w, problem(404, "client_update_unavailable")) }
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			fail(w, problem(405, "method_not_allowed"))
			return
		}
		if directory == "" {
			unavailable()
			return
		}
		root, err := os.OpenRoot(directory)
		if err != nil {
			unavailable()
			return
		}
		defer root.Close()
		path := strings.TrimPrefix(r.URL.Path, "/client-updates/")
		manifest := "haunt-updates.json"
		parts := strings.Split(path, "/")
		if len(parts) == 2 && strings.HasPrefix(parts[0], "client-v") && updateVersion.MatchString(strings.TrimPrefix(parts[0], "client-v")) && updateName.MatchString(parts[1]) {
			manifest = parts[0] + "/haunt-updates.json"
		} else if path != manifest {
			unavailable()
			return
		}
		data, payload, err := releaseManifest(root, manifest)
		if err != nil {
			unavailable()
			return
		}
		if len(parts) == 2 && parts[0] != "client-v"+payload.Version {
			unavailable()
			return
		}
		if path == "haunt-updates.json" || len(parts) == 2 && parts[1] == "haunt-updates.json" {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "public, max-age=60")
			http.ServeContent(w, r, "haunt-updates.json", time.Time{}, strings.NewReader(string(data)))
			return
		}
		var artifact releaseArtifact
		for _, target := range payload.Targets {
			assets := []releaseArtifact{target.ASAR, target.Installer}
			if target.RPM != nil {
				assets = append(assets, *target.RPM)
			}
			for _, asset := range assets {
				if asset.File == parts[1] {
					artifact = asset
				}
			}
		}
		if artifact.File == "" {
			unavailable()
			return
		}
		file, err := root.Open(path)
		if err != nil {
			unavailable()
			return
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() != artifact.Size {
			unavailable()
			return
		}
		select {
		case downloads <- struct{}{}:
			defer func() { <-downloads }()
		default:
			w.Header().Set("Retry-After", "30")
			fail(w, problem(503, "update_download_capacity"))
			return
		}
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(15 * time.Minute))
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		w.Header().Set("ETag", `"`+artifact.SHA256+`"`)
		http.ServeContent(w, r, artifact.File, info.ModTime(), file)
	})
}
