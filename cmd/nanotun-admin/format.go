package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"text/tabwriter"
	"time"
)

// printJSON 将任意可序列化值以 JSON 形式写出，缩进 2 空格。
func printJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// table 是一个最小化的 tabwriter 包装：第一行 header，后续行对应字段。
type table struct {
	tw     *tabwriter.Writer
	header []string
}

func newTable(w io.Writer, header ...string) *table {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	t := &table{tw: tw, header: header}
	for i, h := range header {
		if i > 0 {
			fmt.Fprint(tw, "\t")
		}
		fmt.Fprint(tw, h)
	}
	fmt.Fprintln(tw)
	return t
}

func (t *table) row(cols ...any) {
	for i, c := range cols {
		if i > 0 {
			fmt.Fprint(t.tw, "\t")
		}
		fmt.Fprintf(t.tw, "%v", c)
	}
	fmt.Fprintln(t.tw)
}

func (t *table) flush() error { return t.tw.Flush() }

// fmtTimeUnix 把 unix 秒打印成本地时间（"2006-01-02 15:04:05"）；0 显示 "-"。
func fmtTimeUnix(sec int64) string {
	if sec <= 0 {
		return "-"
	}
	return time.Unix(sec, 0).Format("2006-01-02 15:04:05")
}

// fmtBool 把 bool 打成可读字符串。
func fmtBool(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// dashIfEmpty 把空串变成 "-"，便于 tabwriter 列对齐。
func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// parseInt64 是简短包装，命令行参数解析失败给到 stderr 用。
func parseInt64(s string) (int64, error) {
	return strconv.ParseInt(s, 10, 64)
}
