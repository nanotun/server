package util

// SmuxClientStreamIDToIndex 将 smux 客户端 stream ID 转为数组索引。
// 客户端 OpenStream() 分配的 ID 为 3, 5, 7, ...，对应索引 0, 1, 2, ...
// 公式：index = (streamID - 3) / 2
func SmuxClientStreamIDToIndex(streamID uint32) uint32 {
	return (streamID - 3) / 2
}
