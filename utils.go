package crproxy

import (
	"fmt"
	"strings"
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

func ParseOriginPathInfo(path string, defaultRegistry string) (*PathInfo, bool) {
	path = strings.TrimPrefix(path, prefix)
	i := strings.IndexByte(path, '/')
	if i <= 0 {
		return nil, false
	}
	host := path[:i]
	tail := path[i+1:]

	var tails = []string{}
	var image = ""

	if !isDomainName(host) || !strings.Contains(host, ".") {
		//  disable while non default registry seted.
		if defaultRegistry == "" {
			return nil, false
		}
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
		host = defaultRegistry
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

// isDomainName checks if a string is a presentation-format domain name
// (currently restricted to hostname-compatible "preferred name" LDH labels and
// SRV-like "underscore labels"; see golang.org/issue/12421).
func isDomainName(s string) bool {
	// See RFC 1035, RFC 3696.
	// Presentation format has dots before every label except the first, and the
	// terminal empty label is optional here because we assume fully-qualified
	// (absolute) input. We must therefore reserve space for the first and last
	// labels' length octets in wire format, where they are necessary and the
	// maximum total length is 255.
	// So our _effective_ maximum is 253, but 254 is not rejected if the last
	// character is a dot.
	l := len(s)
	if l == 0 || l > 254 || l == 254 && s[l-1] != '.' {
		return false
	}

	last := byte('.')
	nonNumeric := false // true once we've seen a letter or hyphen
	partlen := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		default:
			return false
		case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || c == '_':
			nonNumeric = true
			partlen++
		case '0' <= c && c <= '9':
			// fine
			partlen++
		case c == '-':
			// Byte before dash cannot be dot.
			if last == '.' {
				return false
			}
			partlen++
			nonNumeric = true
		case c == '.':
			// Byte before dot cannot be dot, dash.
			if last == '.' || last == '-' {
				return false
			}
			if partlen > 63 || partlen == 0 {
				return false
			}
			partlen = 0
		}
		last = c
	}
	if last == '-' || partlen > 63 {
		return false
	}

	return nonNumeric
}
