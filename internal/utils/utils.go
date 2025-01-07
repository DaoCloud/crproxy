package utils

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"

	"github.com/docker/distribution/registry/api/errcode"
)

func ResponseAPIBase(w http.ResponseWriter, r *http.Request) {
	const emptyJSON = "{}"
	// Provide a simple /v2/ 200 OK response with empty json response.
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", fmt.Sprint(len(emptyJSON)))

	fmt.Fprint(w, emptyJSON)
}

func ResponseEmptyTagsList(w http.ResponseWriter, r *http.Request) {
	const emptyTagsList = `{"name":"disable-list-tags","tags":[]}`

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", fmt.Sprint(len(emptyTagsList)))
	fmt.Fprint(w, emptyTagsList)
}

func GetIP(str string) string {
	host, _, err := net.SplitHostPort(str)
	if err == nil && host != "" {
		return host
	}
	return str
}

func ServeError(rw http.ResponseWriter, r *http.Request, err error, sc int) error {
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")

	switch errs := err.(type) {
	case errcode.Errors:
		if len(errs) < 1 {
			break
		}

		if err, ok := errs[0].(errcode.ErrorCoder); ok {
			sc = err.ErrorCode().Descriptor().HTTPStatusCode
		}
	case errcode.ErrorCoder:
		sc = errs.ErrorCode().Descriptor().HTTPStatusCode
		err = errcode.Errors{err} // create an envelope.
	default:
		err = errcode.Errors{err}
	}

	if sc == 0 {
		if r.Context().Err() != nil {
			sc = 499
		} else {
			sc = http.StatusInternalServerError
		}
	}

	rw.WriteHeader(sc)

	if r.Method == http.MethodHead {
		return nil
	}
	return json.NewEncoder(rw).Encode(err)
}
