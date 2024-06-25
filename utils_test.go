package crproxy

import (
	"reflect"
	"testing"
)

func TestParseOriginPathInfo(t *testing.T) {

	testDefaultRegistry := "non_docker.io"

	type args struct {
		path string
	}
	tests := []struct {
		name            string
		args            args
		defaultRegistry string
		want            *PathInfo
		wantOk          bool
	}{
		{
			args: args{
				path: "/v2/busybox/manifests/1",
			},
			defaultRegistry: testDefaultRegistry,
			want: &PathInfo{
				Host:      testDefaultRegistry,
				Image:     "busybox",
				Manifests: "1",
			},
			wantOk: true,
		},
		{
			args: args{
				path: "/v2/pytorch/pytorch/manifests/1",
			},
			defaultRegistry: testDefaultRegistry,
			want: &PathInfo{
				Host:      testDefaultRegistry,
				Image:     "pytorch/pytorch",
				Manifests: "1",
			},
			wantOk: true,
		},
		{
			args: args{
				path: "/v2/v2/manifests/latest",
			},
			defaultRegistry: testDefaultRegistry,
			want: &PathInfo{
				Host:      testDefaultRegistry,
				Image:     "v2",
				Manifests: "latest",
			},
			wantOk: true,
		},
		{
			args: args{
				path: "/v2/docker.io/busybox/manifests/1",
			},
			want: &PathInfo{
				Host:      "docker.io",
				Image:     "busybox",
				Manifests: "1",
			},
			wantOk: true,
		},
		{
			args: args{
				path: "/v2/docker.io/library/busybox/manifests/1",
			},
			want: &PathInfo{
				Host:      "docker.io",
				Image:     "library/busybox",
				Manifests: "1",
			},
			wantOk: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotOk := ParseOriginPathInfo(tt.args.path, tt.defaultRegistry)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseOriginPathInfo() got = %v, want %v", got, tt.want)
			}
			if gotOk != tt.wantOk {
				t.Errorf("ParseOriginPathInfo() gotOk = %v, want %v", gotOk, tt.wantOk)
			}
		})
	}
}

func Test_addPrefixToImageForPagination(t *testing.T) {
	type args struct {
		oldLink string
		host    string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			args: args{
				oldLink: "</v2/image/tags/list>; ref=other",
				host:    "prefix",
			},
			want: "</v2/prefix/image/tags/list>; ref=other",
		},
		{
			args: args{
				oldLink: "<http://domain/v2/image/tags/list>; ref=other",
				host:    "prefix",
			},
			want: "</v2/prefix/image/tags/list>; ref=other",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := addPrefixToImageForPagination(tt.args.oldLink, tt.args.host); got != tt.want {
				t.Errorf("addPrefixToImageForPagination() = %v, want %v", got, tt.want)
			}
		})
	}
}
