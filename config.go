package signed

import (
	"os"

	"github.com/gofiber/fiber/v2"
)

// Algorithm type defines options for hash function options
type Algorithm string

// Hash function algorithmic option values
const (
	AlgorithmSHA1   Algorithm = "SHA-1"
	AlgorithmSHA256 Algorithm = "SHA-256"
	AlgorithmMD5    Algorithm = "MD-5"
)

// Config defines the config for middleware.
type Config struct {
	// Next defines a function to skip this middleware when returned true.
	//
	// Optional. Default: nil
	Next func(c *fiber.Ctx) bool

	// Algorithm defines the hash function used to create signatures. Options
	// are AlgorithmSHA1, AlgorithmSHA256, AlgorithmMD5.
	//
	// Optional. Default: SHA-1
	Algorithm Algorithm

	// GetPrivateKeyFunc defines a function to obtain a string value for use as
	// the private key in hash functions.
	//
	// Optional. Default: func() string { return
	// os.Getenv("FIBER_SIGNED_PRIVATE_KEY") }
	GetPrivateKeyFunc func() string

	// SignatureQueryKey accepts a string value to use in URL query params for
	// the signature value
	//
	// Optional. Default: "signature"
	SignatureQueryKey string

	// PrivateKeyQueryKey accepts a string value to use in URL query params for
	// the private key value
	//
	// Optional. Default: "privateKey"
	PrivateKeyQueryKey string

	// ExpiresQueryKey accepts a string value to use in URL query params for the
	// expiration key value (expects a UNIX timestamp)
	//
	// Optional. Default: "expires"
	ExpiresQueryKey string

	// BodyHashQueryKey accepts a string value to use in URL query params for
	// the body hash value
	//
	// Optional. Default: "bodyHash"
	BodyHashQueryKey string
}

// ConfigDefault is the default config
var ConfigDefault = Config{
	Next:               nil,
	Algorithm:          AlgorithmSHA1,
	GetPrivateKeyFunc:  func() string { return os.Getenv("FIBER_SIGNED_PRIVATE_KEY") },
	SignatureQueryKey:  "signature",
	PrivateKeyQueryKey: "privateKey",
	ExpiresQueryKey:    "expires",
	BodyHashQueryKey:   "bodyHash",
}

// Helper function to set default values
func configDefault(config ...Config) Config {
	// Return default config if nothing provided
	if len(config) < 1 {
		return ConfigDefault
	}

	// Override default config
	cfg := config[0]

	// Set default values for missing fields in overrides
	if cfg.Next == nil {
		cfg.Next = ConfigDefault.Next
	}

	if cfg.Algorithm == "" {
		cfg.Algorithm = ConfigDefault.Algorithm
	}

	if cfg.GetPrivateKeyFunc == nil {
		cfg.GetPrivateKeyFunc = ConfigDefault.GetPrivateKeyFunc
	}

	if cfg.SignatureQueryKey == "" {
		cfg.SignatureQueryKey = ConfigDefault.SignatureQueryKey
	}

	if cfg.PrivateKeyQueryKey == "" {
		cfg.PrivateKeyQueryKey = ConfigDefault.PrivateKeyQueryKey
	}

	if cfg.ExpiresQueryKey == "" {
		cfg.ExpiresQueryKey = ConfigDefault.ExpiresQueryKey
	}

	if cfg.BodyHashQueryKey == "" {
		cfg.BodyHashQueryKey = ConfigDefault.BodyHashQueryKey
	}

	return cfg
}
