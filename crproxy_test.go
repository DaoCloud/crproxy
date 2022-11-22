package crproxy

import (
	"reflect"
	"testing"
)

func TestParseOriginPathInfo(t *testing.T) {
	type args struct {
		path string
	}
	tests := []struct {
		name   string
		args   args
		want   *PathInfo
		wantOk bool
	}{
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
			got, gotOk := ParseOriginPathInfo(tt.args.path)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseOriginPathInfo() got = %v, want %v", got, tt.want)
			}
			if gotOk != tt.wantOk {
				t.Errorf("ParseOriginPathInfo() gotOk = %v, want %v", gotOk, tt.wantOk)
			}
		})
	}
}
