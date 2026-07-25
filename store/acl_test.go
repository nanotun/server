package store

import (
	"errors"
	"testing"
)

// TestAddACLPair_WildcardDuplicateRejected 覆盖第二十三轮深扫 MED:通配规则(src/dst 为 NULL)此前能重复插入
// —— 0003 的表约束 UNIQUE 在 SQLite 里把 NULL 视作彼此不等,而它注释里承诺的「应用层守卫」从未实现。
// 后果:管理员删掉一条后孪生行仍在生效表里,UI 显示"已删"而流量照旧按老规则走。现由 0030 的表达式唯一索引兜住。
func TestAddACLPair_WildcardDuplicateRejected(t *testing.T) {
	s := newTestStore(t)
	ctx := t.Context()
	u, err := s.CreateUser(ctx, NewUser{Username: "aclw", PSKHash: "h"})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		in   NewACLPair
	}{
		{"both-wildcard", NewACLPair{Action: "allow", DstKind: "user"}},
		{"src-wildcard", NewACLPair{DstUserID: u.ID, Action: "deny", DstKind: "user"}},
		{"dst-wildcard", NewACLPair{SrcUserID: u.ID, Action: "allow", DstKind: "exit"}},
		{"ported-wildcard", NewACLPair{Action: "allow", Proto: "tcp", DstPortLo: 80, DstPortHi: 80, DstKind: "user"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := s.AddACLPair(ctx, tc.in); err != nil {
				t.Fatalf("首次插入应成功: %v", err)
			}
			_, err := s.AddACLPair(ctx, tc.in)
			if !errors.Is(err, ErrDuplicate) {
				t.Fatalf("重复插入通配规则应回 ErrDuplicate,got %v", err)
			}
		})
	}
}
