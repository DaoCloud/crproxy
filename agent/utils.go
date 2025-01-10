package agent

import (
	"math/bits"
)

func sizeToGroupAndWeight(size int64) (group uint, weight int) {
	l := int(bits.Len64(uint64(size)))

	switch l {
	case 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11: // <= 1 KiB
		group, weight = 0, 100
	case 12, 13, 14, 15, 16, 17, 18, 19, 20, 21: // <= 1 MiB
		group, weight = 0, 50
	case 22: // <= 2 MiB
		group, weight = 0, 10
	case 23: // <= 4 MiB
		group, weight = 0, 2
	case 24: // <= 8 MiB
		group, weight = 0, 1
	case 25: // <= 16 MiB
		group, weight = 1, 3
	case 26: // <= 32 MiB
		group, weight = 1, 2
	case 27: // <= 64 MiB
		group, weight = 1, 1
	case 28: // <= 128 MiB
		group, weight = 2, 4
	case 29: // <= 256 MiB
		group, weight = 2, 3
	case 30: // <= 512 MiB
		group, weight = 2, 2
	case 31: // <= 1 GiB
		group, weight = 2, 1
	case 32: // <= 2 GiB
		group, weight = 3, 3
	case 33: // <= 4 GiB
		group, weight = 3, 2
	case 34: // <= 8 GiB
		group, weight = 3, 1
	case 35: // <= 16 GiB
		group, weight = 3, 1
	case 36: // <= 32 GiB
		group, weight = 3, 1
	case 37: // <= 64 GiB
		group, weight = 3, 1
	case 38: // <= 128 GiB
		group, weight = 3, 1
	default: // > 128 GiB
		group, weight = 3, 1
	}

	return group, weight
}
