package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nanotun/server/auth"
	"github.com/nanotun/server/store"
	"github.com/nanotun/server/util"
)

// cmdInit 是首次部署用的交互向导，**默认幂等**：
//
//  1. users 表为空 / setup_completed != "1"：进入交互向导，创建 admin、置 setup_completed=1、
//     输出 PSK 明文（这是 PSK 唯一的明文出现机会）。
//  2. setup_completed == "1" 且同名用户已存在：默认 **noop**，不重置 PSK，仅打印
//     现有 admin 信息（脚本可据此判断已就绪）。
//  3. 加 `--reset-psk` 才真正重置（要求同名用户已存在；不存在则报错让用户走 `user create`）。
//
// 这样 install.sh / Ansible / Terraform 这类「重复部署」工具可以无脑反复跑 init，
// 而不会悄悄修改管理员凭证（之前 `--yes init` 的行为是「再跑一次就重置」，是一个隐患）。
func cmdInit(ctx context.Context, st *store.Store, opts *globalOpts, args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(opts.stderr)
	resetPSK := fs.Bool("reset-psk", false, opts.T("init.flag.resetPSK"))
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return errors.New(opts.usage("nanotun-admin init [--reset-psk]"))
	}

	n, err := st.CountUsers(ctx)
	if err != nil {
		return err
	}
	// 深扫第八轮 MED:此前吞掉 SettingsGet 的 error —— 一次瞬时 DB 抖动会让 setupDone
	// 读成空串,alreadySetup=false,init 于是穿过幂等 noop 分支;若同名 admin 已存在,
	// 就会静默**轮换其 PSK**(把线上管理员密钥改掉)。这里显式传播真错误(非「key 缺失」
	// 由 ok=false 表达,不是 err),读失败即中止,绝不因误判而改 PSK。
	setupDone, _, serr := st.SettingsGet(ctx, "setup_completed")
	if serr != nil {
		return fmt.Errorf("read setup_completed: %w", serr)
	}
	alreadySetup := n > 0 && setupDone == "1"

	r := bufio.NewReader(opts.stdin)
	username := promptString(r, opts, opts.T("init.promptUsername"), "admin")

	if alreadySetup && !*resetPSK {
		// 幂等路径：不动 PSK，把现有 admin 信息输出给脚本
		existing, gerr := st.GetUserByUsername(ctx, username)
		if gerr != nil {
			// setup 完成但同名用户不存在 → 提示用户走显式命令，避免脚本悄悄新建管理员
			return errors.New(opts.T("init.setupDoneNoUser", username, username))
		}
		if opts.json {
			return printJSON(opts.stdout, map[string]any{
				"id":             existing.ID,
				"username":       existing.Username,
				"setup_complete": true,
				"noop":           true,
			})
		}
		fmt.Fprintln(opts.stdout, opts.T("init.noop", username))
		fmt.Fprintf(opts.stdout, "  username: %s\n", existing.Username)
		return nil
	}

	psk := promptString(r, opts, opts.T("init.promptPSK"), "")
	autogen := false
	if psk == "" {
		gen, err := util.GeneratePSK()
		if err != nil {
			return err
		}
		psk = gen
		autogen = true
	}

	hash, err := auth.HashPSK(psk)
	if err != nil {
		return err
	}

	// 同名用户已存在：「重置 PSK」路径（首次部署里如果 users>0 但 setup_completed!=1 也会落到这）。
	// 不破坏其它字段，也不创建新用户。
	var u *store.User
	if existing, gerr := st.GetUserByUsername(ctx, username); gerr == nil {
		if alreadySetup && !*resetPSK {
			// 兜底守门（理论上前面已 return 不会到这里）
			return errors.New(opts.T("init.refuseReset", username))
		}
		// 0013(2026-05-25):RotateUserPSK 内部刷 credential_created_at;若 existing 是
		// 老 user(credential_id 空),helper 顺手生成 UUID v4 backfill —— 这样 init
		// --reset-psk 后,用户立刻能扫 credentials show 拿到完整 (UUID, PSK, created_at)。
		if _, _, err := st.RotateUserPSKAndEnsureCredential(ctx, existing, hash); err != nil {
			// 第七轮深扫 P1:init --reset-psk 极不可能跟另一个 admin 并发(setup 阶段
			// 通常只有 root 在跑),但万一撞上时给可读提示,而不是 sentinel 原文。
			if errors.Is(err, store.ErrPSKConcurrentRotation) {
				return errors.New(opts.T("init.resetRaced", username))
			}
			return fmt.Errorf("reset existing admin: %w", err)
		}
		u = existing
		fmt.Fprintln(opts.stdout, opts.T("init.resetOnly", username))
	} else {
		// 第八轮深扫 MED:--reset-psk 语义是「重置**已存在**用户的 PSK」。用户名打错(查不到)时,此前会静默
		// 落到这条新建分支、凭空造出一个新 admin —— 违背 25 行契约,且线上多出个未预期的管理员账号。这里显式
		// 报错并引导走 `user create`。不带 --reset-psk 的首次向导仍走本分支创建首位 admin,不受影响。
		if *resetPSK {
			return errors.New(opts.T("init.resetNoUser", username, username))
		}
		// 0013(2026-05-25):新建 user 时同步分配 UUID v4 + now 作为 credential_id /
		// credential_created_at,免去后续首次 `credentials show` 的 lazy backfill,
		// admin 一开始就能直接出完整 credentials QR。
		credID := uuid.NewString()
		now := time.Now().UTC().Unix()
		u, err = st.CreateUser(ctx, store.NewUser{
			Username:            username,
			PSKHash:             hash,
			IsAdmin:             true,
			ExitAllowed:         true,
			CredentialID:        credID,
			CredentialCreatedAt: now,
		})
		if err != nil {
			return fmt.Errorf("create admin user: %w", err)
		}
	}
	if err := st.SettingsSet(ctx, "setup_completed", "1"); err != nil {
		return err
	}

	if opts.json {
		return printJSON(opts.stdout, map[string]any{
			"id":             u.ID,
			"username":       u.Username,
			"psk":            psk,
			"psk_autogen":    autogen,
			"setup_complete": true,
		})
	}
	fmt.Fprintln(opts.stdout, "")
	fmt.Fprintln(opts.stdout, opts.T("init.adminCreated"))
	fmt.Fprintf(opts.stdout, "  username: %s\n", u.Username)
	fmt.Fprintf(opts.stdout, "  PSK:      %s\n", psk)
	if autogen {
		fmt.Fprintln(opts.stdout, opts.T("init.pskOnce"))
	}
	fmt.Fprintln(opts.stdout, "")
	fmt.Fprintln(opts.stdout, opts.T("init.nextStep"))
	return nil
}

func promptString(r *bufio.Reader, opts *globalOpts, label, def string) string {
	if def != "" {
		fmt.Fprintf(opts.stdout, "%s [%s]: ", label, def)
	} else {
		fmt.Fprintf(opts.stdout, "%s: ", label)
	}
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		return def
	}
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return def
	}
	return line
}
