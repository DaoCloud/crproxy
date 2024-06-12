package crproxy

import (
	"time"

	"github.com/wzshiming/geario"
)

func GetSleepDuration(s geario.B, limit geario.B, r time.Duration) time.Duration {
	return time.Duration(s/(limit/geario.B(r)*geario.B(time.Second))) * time.Second
}
