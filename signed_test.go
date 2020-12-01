package signed

import (
	"crypto/sha1"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/utils"
)

type errReader int

func (errReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("test error")
}

func TestValidateRequest(t *testing.T) {

	// Initalize config
	app := fiber.New()

	app.Use(New(Config{
		Next:              func(c *fiber.Ctx) bool { return true },
		GetPrivateKeyFunc: func() string { return "secret" },
	}))

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Hello, world!")
	})

	t.Run("it should not run middleware logic if Next func returns true", func(t *testing.T) {
		expected := "Hello, world!"

		req := httptest.NewRequest(http.MethodGet, "/?signature=d07242c7ef0dfb2e22c5339faa8317fe1f3f670e", nil)
		resp, _ := app.Test(req)
		body, _ := ioutil.ReadAll(resp.Body)

		utils.AssertEqual(t, fiber.StatusOK, resp.StatusCode)
		utils.AssertEqual(t, expected, string(body))
	})

	app.Use(New(Config{
		GetPrivateKeyFunc: func() string { return "secret" },
	}))

	t.Run("it should not validate a request missing the signature param", func(t *testing.T) {

		expected := "signature is a required query param for a signed URL route"

		req := httptest.NewRequest("GET", "/", nil)
		resp, _ := app.Test(req)
		body, _ := ioutil.ReadAll(resp.Body)

		utils.AssertEqual(t, fiber.StatusForbidden, resp.StatusCode)
		utils.AssertEqual(t, expected, string(body))
	})

	t.Run("it should not validate a request with an expired timestamp", func(t *testing.T) {

		expected := "url signature has expired"

		req := httptest.NewRequest(http.MethodGet, "/?signature=something&expires=123", nil)
		resp, _ := app.Test(req)
		body, _ := ioutil.ReadAll(resp.Body)

		utils.AssertEqual(t, fiber.StatusForbidden, resp.StatusCode)
		utils.AssertEqual(t, expected, string(body))
	})

	t.Run("it should not accept a non integer value for expiration timestamp", func(t *testing.T) {

		expected := "expires value must be valid integer"

		req := httptest.NewRequest(http.MethodGet, "/?signature=something&expires=abc", nil)
		resp, _ := app.Test(req)
		body, _ := ioutil.ReadAll(resp.Body)

		utils.AssertEqual(t, fiber.StatusForbidden, resp.StatusCode)
		utils.AssertEqual(t, expected, string(body))
	})

	t.Run("it should succeed with correct signature", func(t *testing.T) {

		expected := "Hello, world!"

		req := httptest.NewRequest(http.MethodGet, "/?signature=d07242c7ef0dfb2e22c5339faa8317fe1f3f670e", nil)
		resp, _ := app.Test(req)
		body, _ := ioutil.ReadAll(resp.Body)

		utils.AssertEqual(t, fiber.StatusOK, resp.StatusCode)
		utils.AssertEqual(t, expected, string(body))
	})

	t.Run("it should not succeed with incorrect signature", func(t *testing.T) {

		expected := "invalid signature"

		req := httptest.NewRequest(http.MethodGet, "/?signature=wrong", nil)
		resp, _ := app.Test(req)
		body, _ := ioutil.ReadAll(resp.Body)

		utils.AssertEqual(t, fiber.StatusForbidden, resp.StatusCode)
		utils.AssertEqual(t, expected, string(body))
	})
}

func TestGetSignedURLFromHTTPRequest(t *testing.T) {
	// Initalize config
	app := fiber.New()

	app.Use(New(Config{
		GetPrivateKeyFunc: func() string { return "secret" },
	}))

	t.Run("it should return valid signature when given properly formed URL", func(t *testing.T) {

		hash := sha1.New()
		hash.Write([]byte("GET&http://example.com/?privateKey=secret"))
		expected := fmt.Sprintf("%s%x", "http://example.com/?signature=", hash.Sum(nil))

		req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		got, _ := GetSignedURLFromHTTPRequest(req)
		utils.AssertEqual(t, expected, got)
	})

	t.Run("it should parse body if present", func(t *testing.T) {
		hash := sha1.New()
		hash.Write([]byte("body"))
		bodyHash := fmt.Sprintf("%x", hash.Sum(nil))

		hash = sha1.New()
		hash.Write([]byte(fmt.Sprintf("GET&http://example.com/?bodyHash=%s&privateKey=secret", bodyHash)))
		expected := fmt.Sprintf("%s%x", "http://example.com/?signature=", hash.Sum(nil))

		body := strings.NewReader("body")
		req := httptest.NewRequest(http.MethodGet, "http://example.com/", body)
		got, _ := GetSignedURLFromHTTPRequest(req)
		utils.AssertEqual(t, expected, got)
	})

	t.Run("it should not parse mal-formed body if present", func(t *testing.T) {
		expected := "test error"
		req := httptest.NewRequest(http.MethodGet, "http://example.com/", errReader(0))
		_, err := GetSignedURLFromHTTPRequest(req)
		utils.AssertEqual(t, expected, err.Error())
	})

	t.Run("it should not allow requests to contain protected query param 'signature'", func(t *testing.T) {
		expected := "signature is a reserved query parameter when generating signed routes"
		req := httptest.NewRequest(http.MethodGet, "http://example.com/?signature=something", nil)
		_, err := GetSignedURLFromHTTPRequest(req)
		utils.AssertEqual(t, expected, err.Error())
	})

	t.Run("it should not allow requests to contain protected query param 'privateKey'", func(t *testing.T) {
		expected := "privateKey is a reserved query parameter when generating signed routes"
		req := httptest.NewRequest(http.MethodGet, "http://example.com/?privateKey=something", nil)
		_, err := GetSignedURLFromHTTPRequest(req)
		utils.AssertEqual(t, expected, err.Error())
	})

	t.Run("it should not allow requests to contain protected query param 'bodyHash'", func(t *testing.T) {
		expected := "bodyHash is a reserved query parameter when generating signed routes"
		req := httptest.NewRequest(http.MethodGet, "http://example.com/?bodyHash=something", nil)
		_, err := GetSignedURLFromHTTPRequest(req)
		utils.AssertEqual(t, expected, err.Error())
	})
}
