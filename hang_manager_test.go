package crproxy

import (
	"testing"
	"time"

	"github.com/wzshiming/geario"
)

func TestGetSleepDuration(t *testing.T) {
	type args struct {
		s     geario.B
		limit geario.B
		r     time.Duration
	}
	tests := []struct {
		name string
		args args
		want time.Duration
	}{
		{
			args: args{
				s:     100,
				limit: 100,
				r:     time.Second,
			},
			want: time.Second,
		},
		{
			args: args{
				s:     200,
				limit: 100,
				r:     time.Second,
			},
			want: 2 * time.Second,
		},
		{
			args: args{
				s:     100,
				limit: 50,
				r:     time.Second,
			},
			want: 2 * time.Second,
		},
		{
			args: args{
				s:     100,
				limit: 100,
				r:     2 * time.Second,
			},
			want: 2 * time.Second,
		},
		{
			args: args{
				s:     100 * geario.MiB,
				limit: geario.MiB,
				r:     time.Second,
			},
			want: 100 * time.Second,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetSleepDuration(tt.args.s, tt.args.limit, tt.args.r); got != tt.want {
				t.Errorf("GetSleepDuration() = %v, want %v", got, tt.want)
			}
		})
	}
}
