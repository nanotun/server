package main

import (
	"fmt"
	"strconv"
	"strings"

	hyutils "github.com/apernet/hysteria/extras/v2/utils"
)

// planHy2PortHopDportRules 返回需 REDIRECT 到主端口的 iptables --dport 参数列表（跳过与 primary 相同的单口）。
func planHy2PortHopDportRules(primaryPort uint16, portUnion string) ([]string, error) {
	pu := hyutils.ParsePortUnion(strings.TrimSpace(portUnion))
	if len(pu) == 0 {
		return nil, fmt.Errorf("invalid port union %q", portUnion)
	}
	var rules []string
	for _, r := range pu {
		if r.Start == primaryPort && r.End == primaryPort {
			continue
		}
		rules = append(rules, formatIPTablesDport(r.Start, r.End))
	}
	return rules, nil
}

func formatIPTablesDport(start, end uint16) string {
	if start == end {
		return strconv.FormatUint(uint64(start), 10)
	}
	return fmt.Sprintf("%d:%d", start, end)
}
