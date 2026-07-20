package util

import (
	"testing"
)

func TestSmuxClientStreamIDToIndex(t *testing.T) {
	tests := []struct {
		streamID uint32
		want     uint32
	}{
		{3, 0},
		{5, 1},
		{7, 2},
		{9, 3},
		{11, 4},
		{13, 5},
		{15, 6},
	}
	for _, tt := range tests {
		got := SmuxClientStreamIDToIndex(tt.streamID)
		if got != tt.want {
			t.Errorf("SmuxClientStreamIDToIndex(%d) = %d, want %d", tt.streamID, got, tt.want)
		}
	}
}
