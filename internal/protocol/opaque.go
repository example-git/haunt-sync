// Package protocol fixes the authentication suite and its application identities.
package protocol

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"github.com/bytemare/opaque"
)

const Version = "haunt-sync-v1"

func Configuration() *opaque.Configuration { return opaque.DefaultConfiguration() }
func ServerIdentity(issuer string) []byte  { return []byte(Version + " " + issuer) }

// Bind the successful AKE to the selected device proof key and login challenge.
// This key is shared with the server; it is never a backup-encryption key.
func LoginBinding(sessionKey []byte, issuer, challenge, thumbprint string) string {
	mac := hmac.New(sha512.New, sessionKey)
	mac.Write([]byte(Version + "\x00" + issuer + "\x00" + challenge + "\x00" + thumbprint))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
