package gateway

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/daocloud/crproxy/agent"
	"github.com/daocloud/crproxy/token"
)

func (c *Gateway) blob(rw http.ResponseWriter, r *http.Request, info *PathInfo, t *token.Token, authData string) {
	if t.Attribute.BlobsURL != "" {
		values := url.Values{
			"referer":       {r.RemoteAddr},
			"authorization": {authData},
		}

		blobURL := fmt.Sprintf("%s/v2/%s/%s/blobs/%s?%s", t.Attribute.BlobsURL, info.Host, info.Image, info.Blobs, values.Encode())
		http.Redirect(rw, r, blobURL, http.StatusTemporaryRedirect)
		return
	}

	if c.agent != nil {
		c.agent.Serve(rw, r, &agent.BlobInfo{
			Host:  info.Host,
			Image: info.Image,
			Blobs: info.Blobs,
		}, t)
		return
	}

	c.forward(rw, r, info, t)
}
