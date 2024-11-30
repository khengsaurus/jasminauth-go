## About

Middleware and utility functions for [JasminAuth](https://jasminauth.com)

## Installation

```bash
go get github.com/khengsaurus/jasminauth-go
```

## Middleware

The middleware and utility functions offered here allow user-information to be retrieved from your requests' `Ea-User-Token` header. If you do not provide your api-key to the middleware, the `Ea-Api-Key` header from your requests will be used instead. Both user-token and api-key are required to retrieve user information.

```go
import (
  "github.com/go-chi/chi/v5"
  JasminAuth "github.com/khengsaurus/jasminauth-go"
)

func main() {
  router := chi.NewRouter()

  router.Route("/user", func(r chi.Router) {
    r.Group(func(r chi.Router) {
      r.Use(JasminAuth.WithUser("your-api-key", 1 /* version */))
      r.Get("/", getUser)
    })
  })

  http.ListenAndServe(":8080", router)
}

func getUser(w http.ResponseWriter, r *http.Request) {
  ctx := r.Context()
  user, _ := JasminAuth.CheckUser(ctx)
  res, _ := json.Marshal(user)
  w.Header().Set("Content-Type", "application/json")
  w.WriteHeader(http.StatusOK)
  w.Write(res)
}

```

The user object will have the following shape:

```go
type Provider string

type User struct {
  Id         string                 `json:"id"`
  Provider   Provider               `json:"provider"` // Google | Facebook | LinkedIn
  ProviderId string                 `json:"providerId"`
  Domain     string                 `json:"domain"`
  Username   string                 `json:"username"`
  CreatedAt  int64                  `json:"createdAt"` // unix epoch time
  Contents   map[string]interface{} `json:"contents"`
}

```
