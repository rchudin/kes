package lockbox

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/minio/kes"
	"github.com/minio/kes/internal/headers"
	xhttp "github.com/minio/kes/internal/http"
	"github.com/minio/kes/internal/keystore"
)

type Config struct {
	Endpoint  string
	FolderID  string
	AccountID string
	KeyID     string
	KeyFile   string
}

type Store struct {
	cacheSecretsIDs *expirable.LRU[string, string]
	client          *http.Client
	endpoint        string
	folderID        string
}

type authTransport struct {
	next      http.RoundTripper
	endpoint  string
	accountID string
	keyID     string
	keyFile   string
	token     string
	expire    time.Time
	mu        sync.Mutex
}

func (t *authTransport) get(ctx context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if len(t.token) > 0 && t.expire.After(time.Now()) {
		return t.token, nil
	}

	token, err := t.auth(ctx)
	if err != nil {
		return "", err
	}

	t.token = token
	t.expire = time.Now().Add(10 * time.Hour)
	return t.token, nil
}

func (t *authTransport) auth(ctx context.Context) (string, error) {
	claims := jwt.RegisteredClaims{
		Issuer:    t.accountID,
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(1 * time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		NotBefore: jwt.NewNumericDate(time.Now().UTC()),
		Audience:  []string{fmt.Sprintf("https://iam.%s/iam/v1/tokens", t.endpoint)},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodPS256, claims)
	token.Header["kid"] = t.keyID

	data, err := os.ReadFile(t.keyFile)
	if err != nil {
		return "", fmt.Errorf("failed to read key file: %w", err)
	}

	var keyData key
	err = json.Unmarshal(data, &keyData)
	if err != nil {
		return "", fmt.Errorf("failed to parse key file: %w", err)
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(keyData.PrivateKey))
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	signed, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		fmt.Sprintf("https://iam.%s/iam/v1/tokens", t.endpoint),
		strings.NewReader(fmt.Sprintf(`{"jwt":"%s"}`, signed)),
	)
	req.Header.Set(headers.ContentType, "application/json")

	var resp authResponse
	err = do(http.DefaultClient, req, &resp)
	if err != nil {
		return "", fmt.Errorf("failed to fetch token: %w", err)
	}

	return resp.IAMToken, nil
}

func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	token, err := t.get(req.Context())
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token)

	return t.next.RoundTrip(req)
}

func Connect(config *Config) (*Store, error) {
	s := Store{
		cacheSecretsIDs: expirable.NewLRU[string, string](25, nil, 10*time.Minute),
		endpoint:        config.Endpoint,
		folderID:        config.FolderID,
	}

	s.client = &http.Client{
		Transport: &authTransport{
			next:      http.DefaultTransport,
			endpoint:  config.Endpoint,
			accountID: config.AccountID,
			keyID:     config.KeyID,
			keyFile:   config.KeyFile,
		},
	}

	return &s, nil
}

func (s *Store) String() string {
	return "Yandex LockBox"
}

// Close closes the Store.
func (s *Store) Close() error { return nil }

// Status returns the current state of the Yandex LockBox instance.
// In particular, whether it is reachable and the network latency.
func (s *Store) Status(ctx context.Context) (kes.KeyStoreState, error) {
	start := time.Now()

	_, err := s.list(ctx, "ping", 0)
	if err != nil {
		return kes.KeyStoreState{}, &keystore.ErrUnreachable{Err: err}
	}

	return kes.KeyStoreState{
		Latency: time.Since(start),
	}, nil
}

// Create creates the given key-value pair at Yandex LockBox if and only
// if the given key does not exist. If such an entry already exists
// it returns kes.ErrKeyExists.
func (s *Store) Create(ctx context.Context, name string, value []byte) error {
	panic("not implemented")
}

// Get returns the value associated with the given key.
// If no entry for the key exists it returns kes.ErrKeyNotFound.
func (s *Store) Get(ctx context.Context, name string) ([]byte, error) {
	panic("not implemented")
}

// Delete removes a the value associated with the given key
// from Yandex LockBox, if it exists.
func (s *Store) Delete(ctx context.Context, name string) error {
	return &keystore.ErrUnreachable{Err: fmt.Errorf("not implemented")}
}

// List returns the first n key names, that start with the given
// prefix, and the next prefix from which the listing should
// continue.
//
// It returns all keys with the prefix if n < 0 and less than n
// names if n is greater than the number of keys with the prefix.
//
// An empty prefix matches any key name. At the end of the listing
// or when there are no (more) keys starting with the prefix, the
// returned prefix is empty.
func (s *Store) List(ctx context.Context, prefix string, n int) ([]string, string, error) {
	if n > -1 {
		return nil, "", &keystore.ErrUnreachable{Err: fmt.Errorf("cannot list than %d items", n)}
	}

	secrets, err := s.list(ctx, prefix, n)
	if err != nil {
		return nil, "", &keystore.ErrUnreachable{Err: err}
	}

	names := make([]string, 0, len(secrets))
	for _, sec := range secrets {
		names = append(names, sec.Name)
	}

	return names, "", nil
}

func (s *Store) find(ctx context.Context, name string) (*secret, error) {
	secrets, err := s.list(ctx, name, -1)
	if err != nil {
		return nil, err
	}

	for _, sec := range secrets {
		if sec.Name != name {
			continue
		}

		return sec, nil
	}

	return nil, fmt.Errorf("secret %s not found", name)
}

func (s *Store) list(ctx context.Context, prefix string, n int) ([]*secret, error) {
	query := url.Values{
		"folderId": []string{s.folderID},
	}

	var (
		nextToken string
		secrets   []*secret
	)

	for {
		if len(nextToken) > 0 {
			query.Set("pageToken", nextToken)
		}

		link := fmt.Sprintf("https://lockbox.%s/lockbox/v1/secrets?%s", s.endpoint, query.Encode())

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, link, nil)
		if err != nil {
			return nil, err
		}

		var resp listResponse
		err = s.do(req, &resp)
		if err != nil {
			return nil, err
		}

		for _, sec := range resp.Secrets {
			if len(secrets) == n {
				return secrets, nil
			}

			if !strings.HasPrefix(sec.Name, prefix) {
				continue
			}

			secrets = append(secrets, sec)
		}

		nextToken = resp.NextPageToken
		if len(nextToken) < 1 {
			return secrets, nil
		}

		secrets = append(secrets, &secret{})
	}
}

func (s *Store) do(req *http.Request, dst interface{}) error {
	return do(s.client, req, dst)
}

func do(client *http.Client, req *http.Request, dst interface{}) error {
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer xhttp.DrainBody(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	err = json.Unmarshal(body, &dst)
	if err != nil {
		return err
	}

	return nil
}

type key struct {
	PrivateKey string `json:"private_key"`
}

type authResponse struct {
	IAMToken string `json:"iamToken"`
}

type secret struct {
	ID       string `json:"id,omitempty"`
	FolderID string `json:"folderId,omitempty"`
	Name     string `json:"name,omitempty"`
}

type listResponse struct {
	Secrets       []*secret `json:"secrets"`
	NextPageToken string    `json:"nextPageToken"`
}
