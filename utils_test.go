package signed

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/gofiber/fiber/v2/utils"
)

func TestGetHash(t *testing.T) {

	t.Run("it should return a SHA-1 hash with default config", func(t *testing.T) {
		// Initalize default config
		_ = New()

		hash := sha1.New()
		hash.Write([]byte("test string"))
		expected := fmt.Sprintf("%x", hash.Sum(nil))

		got := getHash("test string")

		utils.AssertEqual(t, expected, got)
	})

	t.Run("it should return a SHA-256 hash with custom config", func(t *testing.T) {
		// Initalize config
		_ = New(Config{Algorithm: AlgorithmSHA256})

		hash := sha256.New()
		hash.Write([]byte("test string"))
		expected := fmt.Sprintf("%x", hash.Sum(nil))

		got := getHash("test string")

		utils.AssertEqual(t, expected, got)
	})

	t.Run("it should return an MD-5 hash with custom config", func(t *testing.T) {
		// Initalize config
		_ = New(Config{Algorithm: AlgorithmMD5})

		hash := md5.New()
		hash.Write([]byte("test string"))
		expected := fmt.Sprintf("%x", hash.Sum(nil))

		got := getHash("test string")

		utils.AssertEqual(t, expected, got)
	})

	t.Run("it should return a SHA-1 hash as default value", func(t *testing.T) {
		// Initalize config
		_ = New(Config{Algorithm: "Otherwise"})

		hash := sha1.New()
		hash.Write([]byte("test string"))
		expected := fmt.Sprintf("%x", hash.Sum(nil))

		got := getHash("test string")

		utils.AssertEqual(t, expected, got)
	})
}

func TestOrderQueryParams(t *testing.T) {

	t.Run("it should alphabetically reorder query string", func(t *testing.T) {

		v := url.Values{}
		v.Set("c", "789")
		v.Set("a", "123")
		v.Set("b", "456")
		expected := "a=123&b=456&c=789"

		got := orderQueryParams(v)

		utils.AssertEqual(t, expected, got)
	})

	t.Run("it should ignore signature query param", func(t *testing.T) {

		v := url.Values{}
		v.Set("c", "789")
		v.Set("a", "123")
		v.Set("b", "456")
		v.Set("signature", "something")
		expected := "a=123&b=456&c=789"

		got := orderQueryParams(v)

		utils.AssertEqual(t, expected, got)
	})
}

func TestGetSignature(t *testing.T) {
	// Initalize config
	_ = New(Config{
		GetPrivateKeyFunc: func() string { return "secret" },
	})

	t.Run("it should not parse incorrectly formed url input", func(t *testing.T) {

		expected := "cannot parse provided URL"

		_, err := getSignature("BAD", "something not a url", "also weird", nil)

		utils.AssertEqual(t, expected, err.Error())
	})

	t.Run("it should add trailing slash to / if not present", func(t *testing.T) {
		hash := sha1.New()
		hash.Write([]byte("GET&http://127.0.0.1:3000/?privateKey=secret"))
		expected := fmt.Sprintf("%x", hash.Sum(nil))

		got, _ := getSignature(http.MethodGet, "http://127.0.0.1:3000", "", nil)

		utils.AssertEqual(t, expected, got)
	})

	t.Run("it should set private key to correct value", func(t *testing.T) {

		hash := sha1.New()
		hash.Write([]byte("GET&http://127.0.0.1:3000/signature?privateKey=secret&q=something"))
		expected := fmt.Sprintf("%x", hash.Sum(nil))

		got, _ := getSignature(http.MethodGet, "http://127.0.0.1:3000", "/signature?q=something", nil)

		utils.AssertEqual(t, expected, got)
	})

	t.Run("it should parse body if present", func(t *testing.T) {

		hash := sha1.New()
		hash.Write([]byte("body"))
		bodyHash := fmt.Sprintf("%x", hash.Sum(nil))

		hash = sha1.New()
		hash.Write([]byte(fmt.Sprintf("GET&http://127.0.0.1:3000/?bodyHash=%s&privateKey=secret&q=something", bodyHash)))
		expected := fmt.Sprintf("%x", hash.Sum(nil))

		got, _ := getSignature(http.MethodGet, "http://127.0.0.1:3000", "/?q=something", []byte("body"))

		utils.AssertEqual(t, expected, got)
	})
}
