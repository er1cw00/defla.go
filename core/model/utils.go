package model

import (
	"strconv"
)

func HexStringToUint64(s string) (uint64, error) {
	var u64 uint64 = 0
	var err error = nil
	if len(s) > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		if u64, err = strconv.ParseUint(s[2:], 16, 64); err != nil {
			return 0, err
		}
	} else {
		if u64, err = strconv.ParseUint(s, 16, 64); err != nil {
			return 0, err
		}
	}
	return u64, nil
}
