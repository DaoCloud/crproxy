package gateway

import (
	"fmt"
	"net/http"

	"github.com/daocloud/crproxy/agent"
	"github.com/daocloud/crproxy/token"
)

func (c *Gateway) blob(rw http.ResponseWriter, r *http.Request, info *PathInfo, t *token.Token) {
	if t.Attribute.BlobsURL != "" {
		referer := r.RemoteAddr
		blobURL := fmt.Sprintf("%s/v2/%s/%s/blobs/%s?referer=%s", t.Attribute.BlobsURL, info.Host, info.Image, info.Blobs, referer)
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
