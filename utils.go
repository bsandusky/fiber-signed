package signed

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
)

// getHash returns a hashed string based on the algorithm set in the config
func getHash(hashString string) string {

	// Get appropriate hash function from config
	var hash hash.Hash
	switch cfg.Algorithm {
	case AlgorithmSHA1:
		hash = sha1.New()
		break
	case AlgorithmSHA256:
		hash = sha256.New()
		break
	case AlgorithmMD5:
		hash = md5.New()
		break
	default:
		hash = sha1.New()
	}

	// Run hash function
	hash.Write([]byte(hashString))

	// Return result of hashing algorithm
	return fmt.Sprintf("%x", hash.Sum(nil))
}

// orderQueryParams alphatically reorders query params for hashing purposes
func orderQueryParams(q url.Values) string {

	var keys []string
	for k := range q {
		if k == cfg.SignatureQueryKey {
			continue // ignore signature query param when reconstructing query string for hashing
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var ordered []string
	for _, key := range keys {
		sort.Strings(q[key])
		for _, val := range q[key] {
			ordered = append(ordered, fmt.Sprintf("%s=%s", key, val))
		}
	}
	joined := strings.Join(ordered, "&")

	return joined
}

// getSignature takes prepared paramters and returns hashed signature
func getSignature(method, baseURL, originalURL string, body []byte) (string, error) {

	// Parse full request URL
	parsed, err := url.ParseRequestURI(fmt.Sprintf("%s%s", baseURL, originalURL))
	if err != nil {
		return "", errors.New("cannot parse provided URL")
	}

	// Add trailing slash to / if not alredy present
	if len(parsed.Path) < 1 {
		parsed.Path = fmt.Sprintf("%s/", parsed.Path)
	}

	// Get existing query params
	var q url.Values
	if strings.Contains(originalURL, "?") {
		split := strings.Split(originalURL, "?")
		q, _ = url.ParseQuery(split[1])
	} else {
		q, _ = url.ParseQuery(originalURL)
	}

	// Add privateKey query param for use in calculating signature
	privateKey := cfg.GetPrivateKeyFunc()
	q.Set(cfg.PrivateKeyQueryKey, privateKey)

	// Hash body if present in request
	if len(body) > 0 {
		bodyHash := getHash(string(body))
		q.Set(cfg.BodyHashQueryKey, bodyHash)
	}

	// Order query params alphabetically
	params := orderQueryParams(q)

	// Get hashed signature
	hashString := fmt.Sprintf("%s&%s://%s%s?%s", method, parsed.Scheme, parsed.Host, parsed.Path, params)
	hashedSignature := getHash(hashString)

	return hashedSignature, nil
}

// validateRequest handles middleware layer from fiber handlers to confirm
// signatures match calculated values
func validateRequest(c *fiber.Ctx) (bool, error) {

	// Check for existence of 'signature' query param in request
	signature := c.Query(cfg.SignatureQueryKey)
	if signature == "" {
		return false, fmt.Errorf("%s is a required query param for a signed URL route", cfg.SignatureQueryKey)
	}

	// Check for existence of 'expires' query param in request and determine if
	// url has passed expiration
	expires := c.Query(cfg.ExpiresQueryKey)
	if expires != "" {
		i, err := strconv.ParseInt(expires, 10, 64)
		if err != nil {
			return false, fmt.Errorf("%s value must be valid integer", cfg.ExpiresQueryKey)
		}
		when := time.Unix(i, 0)
		if when.Before(time.Now()) {
			return false, errors.New("url signature has expired")
		}
	}

	method := c.Method()
	baseURL := c.BaseURL()
	originalURL := c.OriginalURL()
	body := c.Body()

	// Get hashed signture from context
	hashedSignature, _ := getSignature(method, baseURL, originalURL, body)

	// Compare signature given with calculated value
	if hashedSignature != signature {
		return false, errors.New("invalid signature")
	}

	return true, nil
}
