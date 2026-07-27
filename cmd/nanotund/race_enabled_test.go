//go:build race

package main

// raceDetectorEnabled 让测试能判断自己是不是跑在 -race 下。
//
// 用途:耗时测量类的测试在竞态检测器下没有意义 —— map / SQLite 访问都被插桩拖慢,
// 且慢的幅度与访问次数相关,于是「随规模增长」这类比值会被成倍放大。
const raceDetectorEnabled = true
