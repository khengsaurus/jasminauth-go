package jasminauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

type ContextKey string

var (
	client       = http.Client{Timeout: 5 * time.Second}
	eaContextKey = ContextKey("ea_context")
	urlBase      = "https://ice-milo.com/ea-api/api/"

	headerApiKey    = "Ea-Api-Key"
	headerUserToken = "Ea-User-Token"

	ErrorEaContextError    = "jasminauth: failed to create/retrieve request context"
	ErrorInvalidKeyOrToken = "jasminauth: invalid api-key or user-token"
	ErrorUserInfoMissing   = "jasminauth: failed to retrieve user info"
)

type reqContext struct {
	apiKey    string
	userToken string
	version   int
	user      *User
	mutex     *sync.Mutex
}

// A middleware which allows retrieving user info from incoming requests with a "Ea-User-Token" header
func WithUser(apiKey string, version int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// create a new reqContext for each request, store apiKey, userToken, a mutex
			userToken := r.Header.Get(headerUserToken)
			if apiKey == "" {
				apiKey = r.Header.Get(headerApiKey)
			}

			eaContext := &reqContext{
				apiKey:    apiKey,
				userToken: userToken,
				version:   version,
				user:      nil,
				mutex:     &sync.Mutex{},
			}

			ctx := context.WithValue(r.Context(), eaContextKey, eaContext)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Will make at most 1 API call (if successful) per context and store the retrieved user-information
// in the context to be referenced again if needed.
func GetUser(ctx context.Context) (*User, error) {
	eaContext, ok := ctx.Value(eaContextKey).(*reqContext)
	if !ok {
		return nil, fmt.Errorf(ErrorEaContextError)
	}

	// if apiKey or userToken are missing, return error
	if eaContext.apiKey == "" || eaContext.userToken == "" {
		return nil, fmt.Errorf(ErrorInvalidKeyOrToken)
	}

	// if user exists, return it
	if eaContext.user != nil {
		return eaContext.user, nil
	}

	eaContext.mutex.Lock()
	defer eaContext.mutex.Unlock()

	// check again - if user exists now, return it
	if eaContext.user != nil {
		return eaContext.user, nil
	}

	user, err := validateToken(eaContext.apiKey, eaContext.userToken, eaContext.version)
	if err != nil || user == nil || user.Id == "" || user.Username == "" {
		if err == nil {
			return nil, fmt.Errorf(ErrorUserInfoMissing)
		}
		return nil, err
	}

	// user was retrieved - set it in context
	eaContext.user = user

	return user, nil
}

type validateRes struct {
	Data User
}

func validateToken(apiKey string, userToken string, version int) (*User, error) {
	url := fmt.Sprintf("%s/v%d/ea_validate/%s", urlBase, version, userToken)
	ssoReq, err := http.NewRequest(http.MethodGet, url, nil)
	ssoReq.Header.Set("Content-Type", "application/json")
	ssoReq.Header.Set(headerApiKey, apiKey)
	if err != nil {
		return nil, err
	}

	ssoRes, err := client.Do(ssoReq)
	if err != nil {
		return nil, err
	}
	defer ssoRes.Body.Close()

	if ssoRes.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf(ErrorInvalidKeyOrToken)
	}

	body, err := io.ReadAll(ssoRes.Body)
	if err != nil {
		return nil, err
	}

	var p validateRes
	err = json.Unmarshal(body, &p)
	return &p.Data, err
}
