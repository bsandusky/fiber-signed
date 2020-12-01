package signed

import (
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/gofiber/fiber/v2"
)

var cfg Config

// New creates a new middleware handler
func New(config ...Config) fiber.Handler {
	// Set default config
	cfg = configDefault(config...)

	// Return new handler
	return func(c *fiber.Ctx) error {
		// Don't execute middleware if Next returns true
		if cfg.Next != nil && cfg.Next(c) {
			return c.Next()
		}

		// validate request before continuing to next handler
		ok, err := validateRequest(c)
		if !ok {
			return fiber.NewError(fiber.StatusForbidden, err.Error())
		}

		// Continue stack
		return c.Next()
	}
}

// External Interface to get Signed URLs. Middleware package must be initialized
// (i.e. signed.New() must be called) before the following can be called

// GetSignedURLFromHTTPRequest takes an instance of *http.Request and returns
// full URL with calculated signature
func GetSignedURLFromHTTPRequest(r *http.Request) (string, error) {

	baseURL := fmt.Sprintf("%s://%s", r.URL.Scheme, r.Host)
	originalURL := fmt.Sprintf("%s?%s", r.URL.Path, r.URL.RawQuery)

	// Read body if exists
	var body []byte
	var err error
	if r.Body != nil {
		body, err = ioutil.ReadAll(r.Body)
		if err != nil {
			return "", err
		}
	}

	// Throw error if reserved query params are used in signature request
	q := r.URL.Query()
	if q.Get(cfg.SignatureQueryKey) != "" {
		return "", fmt.Errorf("%s is a reserved query parameter when generating signed routes", cfg.SignatureQueryKey)
	} else if q.Get(cfg.PrivateKeyQueryKey) != "" {
		return "", fmt.Errorf("%s is a reserved query parameter when generating signed routes", cfg.PrivateKeyQueryKey)
	} else if q.Get(cfg.BodyHashQueryKey) != "" {
		return "", fmt.Errorf("%s is a reserved query parameter when generating signed routes", cfg.BodyHashQueryKey)
	}

	// Get signature
	signature, _ := getSignature(r.Method, baseURL, originalURL, body)

	// Append signature to query params
	q.Add("signature", signature)
	r.URL.RawQuery = q.Encode()

	return r.URL.String(), nil
}
