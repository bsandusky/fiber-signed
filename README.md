# fiber-signed

The package adds support for signed URLs to the excellent [Fiber](https://gofiber.io/) framework. Once applied, `fiber-signed` middleware will check for correct signature values based on a shared private key for individual routes, route groups, or entire apps.

## Table of Contents

- [Description](#description)
- [Process](#process)
- [Signatures](#signatures)
- [Examples](#examples)
- [Config](#config)
- [Default Config](#default-config)

## Description

Signed URLs are a common way to secure unauthenticated and publicly available routes in a way that ensures that no changes have been made to URL parameters prior to the request being received. A common use case is an unsubscribe route. Where an application may provide a route at `<app host>/user/:id/unsubscribe`, a malicious actor could change the `:id` value and unsubscribe other users as well. Instead, this public route can be made secure by validating a signature which is based on a number of operations (see below) and can only be generated with the unique values included in the URL itself and a shared private key. In this case the URL will look something like `<app host>/user/:id/unsubscribe?signature=<signature value>` and any changes to the URL string will provoke a 403 - Forbidden response.

In keeping with the spirit of Fiber's prioritization of performance, zero memory allocations, and minimal interface, package `fiber-signed` has no runtime dependencies beyond Go's standard lib and `github.com/gofiber/fiber/v2` itself. `github.com/gofiber/fiber/v2/utils` is also a dependency for tests.

## Process

In order to validate a URL signature, package `fiber-signed` does the following:

1. Checks for the existence of the signature value based on the key provided in the config, eg. "signature"
2. Checks for the existence of expiration date based on the key provided in the config, eg. "expires"
3. Checks that expiration (if present) has not already passed
4. Makes a copy of the request URL from the inbound `*fiber.Ctx` object and parses all current query params
5. Adds the private key string value as an additional query param based on string returned from `GetPrivateKeyFunc()` in config
6. Adds a hash of the request body (if present) as an additional query param based on the hashing algorithm specified in the config, eg. SHA-1
7. Orders all query params alphabetically, omitting the signature key and value
8. Prepends HTTP method + `&` before request scheme
9. Generates hashed signature with full prepared URL
10. Checks that the signature provided in the original request matches the calculated value

## Signatures

```go
func New(config ...Config) fiber.Handler
func GetSignedURLFromHTTPRequest(r *http.Request) (string, error)
```

## Examples

### Basic Usage as Middleware

```go
    app := fiber.New()

    // Unsigned routes
    routes.ApiRoutes(app)

    // Initialize default config
    app.Use(signed.New())

    // Or extend default config with customizations
    app.Use(signed.New(signed.Config{
        SignatureQueryKey: "sign",
        Algorithm: "SHA-256",
    }))

    // Signed routes
    app.Get("/user/:id/unsubscribe", func(c *fiber.Ctx) error {
        return c.SendString("You've successfully unsubscribed!")
    })

```

### Getting a signed URL to use with your Fiber app

```go
    req, _ := http.NewRequest(http.MethodGet, "https://127.0.0.1:3000/?q=search", nil)

    signedURL, err := signed.GetSignedURLFromHTTPRequest(req)
    if err != nil {
        // handle err
    }

    // use signedURL as needed

```

## Config

```go
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
```

## Default Config

```go
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
```
