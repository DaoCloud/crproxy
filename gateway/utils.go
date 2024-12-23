package gateway

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/daocloud/crproxy/internal/format"
)

func addPrefixToImageForPagination(oldLink string, host string) string {
	linkAndRel := strings.SplitN(oldLink, ";", 2)
	if len(linkAndRel) != 2 {
		return oldLink
	}
	linkURL := strings.SplitN(strings.Trim(linkAndRel[0], "<>"), "/v2/", 2)
	if len(linkURL) != 2 {
		return oldLink
	}
	mirrorPath := prefix + host + "/" + linkURL[1]
	return fmt.Sprintf("<%s>;%s", mirrorPath, linkAndRel[1])
}

type PathInfo struct {
	Host  string
	Image string

	TagsList  bool
	Manifests string
	Blobs     string
}

func (p PathInfo) Path() (string, error) {
	if p.TagsList {
		return prefix + p.Image + "/tags/list", nil
	}
	if p.Manifests != "" {
		return prefix + p.Image + "/manifests/" + p.Manifests, nil
	}
	if p.Blobs != "" {
		return prefix + p.Image + "/blobs/" + p.Blobs, nil
	}
	return "", fmt.Errorf("unknow kind %#v", p)
}

func parseOriginPathInfo(path string) (*PathInfo, bool) {
	path = strings.TrimPrefix(path, prefix)
	i := strings.IndexByte(path, '/')
	if i <= 0 {
		return nil, false
	}
	host := path[:i]
	tail := path[i+1:]

	var tails = []string{}
	var image = ""

	if !format.IsDomainName(host) || !strings.Contains(host, ".") {
		// if host is not a domain name, it is a image.
		tails = strings.Split(tail, "/")
		if len(tails) < 2 {
			// should be more then 2 parts. like <image>/manifests/latest
			return nil, false
		}
		image = strings.Join(tails[:len(tails)-2], "/")
		if image == "" {
			// the url looks like /v2/[busybox]/manifests/latest.
			image = host
		} else {
			// the url looks like /v2/[pytorch/pytorch/...]/[manifests/latest].
			image = host + "/" + image
		}
		host = ""
	} else {

		tails = strings.Split(tail, "/")
		if len(tails) < 3 {
			return nil, false
		}
		image = strings.Join(tails[:len(tails)-2], "/")
		if image == "" {
			return nil, false
		}
	}

	info := &PathInfo{
		Host:  host,
		Image: image,
	}
	switch tails[len(tails)-2] {
	case "tags":
		info.TagsList = tails[len(tails)-1] == "list"
	case "manifests":
		info.Manifests = tails[len(tails)-1]
	case "blobs":
		info.Blobs = tails[len(tails)-1]
		if len(info.Blobs) != 7+64 {
			return nil, false
		}
	}
	return info, true
}

func dumpResponse(resp *http.Response) string {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return fmt.Sprintf("%d %d %q", resp.StatusCode, resp.ContentLength, string(body))
}
