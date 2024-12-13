package gateway

import (
	"fmt"
	"net/http"
)

func (c *Gateway) blob(rw http.ResponseWriter, r *http.Request, info *PathInfo) {
	host := c.blobsHosts[0]
	referer := r.RemoteAddr
	blobURL := fmt.Sprintf("%s/v2/%s/%s/blobs/%s?referer=%s", host, info.Host, info.Image, info.Blobs, referer)
	http.Redirect(rw, r, blobURL, http.StatusTemporaryRedirect)
}
