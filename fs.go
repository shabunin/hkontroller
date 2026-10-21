package hkontroller

import (
	"github.com/shabunin/hkontroller/log"

	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

type fsStore struct {
	Path string
}

func NewFsStore(dir string) Store {
	// Prepare filesystem directory
	// Ensure that execute permission bit is set on all created dirs
	// Read http://unix.stackexchange.com/questions/21251/why-do-directories-need-the-executable-x-permission-to-be-opened
	err := os.MkdirAll(dir, 0755)
	if err != nil {
		log.Info.Panic(err)
	}

	return &fsStore{dir}
}

// Set writes value to temporary file and renames it, so crash during write
// never leaves file half written: keypair would be lost with all pairings.
func (fs *fsStore) Set(key string, value []byte) error {
	path := fs.filePathToFile(key)
	// suffix differs from keys, so KeysWithSuffix never lists temporary files
	file, err := os.CreateTemp(fs.Path, filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := file.Name()
	defer os.Remove(tmp) // no-op after rename

	if _, err := file.Write(value); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (fs *fsStore) Get(key string) ([]byte, error) {
	return os.ReadFile(fs.filePathToFile(key))
}

// Delete removes the file for the corresponding key.
func (fs *fsStore) Delete(key string) error {
	return os.Remove(fs.filePathToFile(key))
}

func (fs *fsStore) KeysWithSuffix(suffix string) (keys []string, err error) {
	var entries []os.DirEntry

	if entries, err = os.ReadDir(fs.Path); err == nil {
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), suffix) {
				keys = append(keys, e.Name())
			}
		}
	}

	return
}

func (fs *fsStore) filePathToFile(file string) string {
	return filepath.Join(fs.Path, sanitizeFilename(file))
}

type storer struct {
	Store
}

func (st *storer) SetString(key string, value string) error {
	return st.Set(key, []byte(value))
}

func (st *storer) GetString(key string) (string, error) {
	b, err := st.Get(key)
	return string(b), err
}

func (st *storer) KeyPair() (KeyPair, error) {
	var kp KeyPair
	b, err := st.Get("keypair")
	if err != nil {
		return kp, err
	}

	if err := json.Unmarshal(b, &kp); err != nil {
		return kp, err
	}
	if len(kp.Public) != ed25519.PublicKeySize || len(kp.Private) != ed25519.PrivateKeySize {
		return kp, errors.New("invalid keypair")
	}

	return kp, nil
}

// hasKey reports if value for key is stored.
func (st *storer) hasKey(key string) (bool, error) {
	keys, err := st.KeysWithSuffix(key)
	if err != nil {
		return false, err
	}
	for _, k := range keys {
		if k == key {
			return true, nil
		}
	}
	return false, nil
}

func (st *storer) SaveKeyPair(kp KeyPair) error {
	b, err := json.Marshal(&kp)
	if err != nil {
		return err
	}

	return st.Set("keypair", b)
}

func (st *storer) DeleteKeyPair(name string) error {
	return st.Delete("keypair")
}

// Pairing returns the pairing with the given name.
func (st *storer) Pairing(name string) (Pairing, error) {
	return st.pairingForKey(keyForPairingName(name))
}

// SavePairing saves the given pairing.
func (st *storer) SavePairing(pairing Pairing) error {
	b, err := json.Marshal(&pairing)
	if err != nil {
		return err
	}

	return st.Set(keyForPairingName(pairing.Id), b)
}

// DeletePairing deletes the pairing with a given name.
func (st *storer) DeletePairing(name string) error {
	return st.Delete(keyForPairingName(name))
}

// Pairings returns all known devices.
func (st *storer) Pairings() []Pairing {
	var arr []Pairing
	if ks, err := st.KeysWithSuffix(".pairing"); err == nil {
		for _, k := range ks {
			if p, err := st.pairingForKey(k); err == nil {
				arr = append(arr, p)
			}
		}
	}

	return arr
}

// eneity is used in older versions to store public & private keys
// of the accessory and devices clients.
// Use Keypair and Pairing instead.
type entity struct {
	Name       string
	PublicKey  []byte
	PrivateKey []byte
}

func (st *storer) pairingForKey(key string) (p Pairing, err error) {
	var b []byte
	if b, err = st.Get(key); err == nil {
		// Decoder ignores data after json value: files were not truncated
		// on overwrite before, so shorter pairing may be followed by tail of older one
		err = json.NewDecoder(bytes.NewReader(b)).Decode(&p)
	}
	return
}

func (st *storer) entityForKey(key string) (e entity, err error) {
	var b []byte

	if b, err = st.Get(key); err == nil {
		err = json.Unmarshal(b, &e)
	}

	return
}

func keyForName(s string) string {
	return hex.EncodeToString([]byte(s)) + ".entity"
}

func keyForPairingName(s string) string {
	return hex.EncodeToString([]byte(s)) + ".pairing"
}

// sanitizeFilename returns a valid file name by removing invalidcharacters (e.g. colon ":" which is not allowed in file names on Window)
func sanitizeFilename(filename string) string {
	return strings.Replace(filename, ":", "", -1)
}
