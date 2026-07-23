package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/nanotun/server/store"

	"github.com/sirupsen/logrus"
)

// port-forward handlers — FRP 式反向端口转发（server 侧发布 mesh 服务到公网端口）。
//
//	GET  /port-forwards               → 列表 + 新增表单
//	POST /port-forwards/new           → 创建
//	POST /port-forwards/{id}/delete   → 删除
//	POST /port-forwards/{id}/enable   → 启用
//	POST /port-forwards/{id}/disable  → 停用
//
// 目标两类：node 目标（target_ip = 设备 vIP，节点自身端口）/ LAN 目标（target_ip = 设备 LAN 后某 IP，
// 须在该设备已批准宣告网段内）。改动后经 control-socket /reload?what=portforward 让 server 即时启停监听。

// reservedPublicPorts：不允许作为公网转发端口（与 server / web 自身监听冲突，或高危系统端口）。
// server 数据面(8080/8443)、DNS(53)、SSH(22)、HTTP/S(80/443)。web 自身端口另从 cfg.ListenAddr 动态加。
var reservedPublicPorts = map[int]bool{
	22: true, 53: true, 80: true, 443: true, 8080: true, 8443: true,
}

// portForwardView：列表页每行的展示模型（映射 + 解析出的设备名 + server 端实时运行态，便于识别）。
type portForwardView struct {
	store.PortForward
	DeviceName string
	DeviceID   int64
	// LiveState：server 端该监听的真实运行态（listening / bind_failed / route_degraded），
	// 空串 = 运行态未知（server 不可达 / 该映射停用未上报）。LiveErr 是对应的错误详情。
	LiveState string
	LiveErr   string
}

func (s *Server) handlePortForwardList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	pfs, err := s.store.ListPortForwards(r.Context())
	if err != nil {
		s.renderInternalError(w, r, "portforward:list", err)
		return
	}
	devs, err := s.store.ListAllDevices(r.Context())
	if err != nil {
		s.renderInternalError(w, r, "portforward:list_devices", err)
		return
	}
	byUUID := make(map[string]*store.Device, len(devs))
	for _, d := range devs {
		byUUID[strings.ToLower(d.DeviceUUID)] = d
	}
	// server 端实时运行态（best-effort）：拉不到就降级为「状态未知」，不阻断列表渲染。
	var live map[int]PortForwardStatusItem
	if s.control != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		if st, lerr := s.control.PortForwardStatus(ctx); lerr == nil {
			live = st
		} else {
			logrus.WithError(lerr).Debug("[web] 拉取端口转发运行态失败，列表降级为状态未知")
		}
		cancel()
	}
	views := make([]portForwardView, 0, len(pfs))
	// 页顶统计格(2026-07-18 暗色改版):总数 / 监听中 / 异常(bind 失败 + LAN 路由降级)/
	// 停用。运行态未知(server 不可达)不计入 listening 也不计入 degraded —— 宁可少报。
	var stats struct{ Total, Listening, Degraded, Disabled int }
	for _, pf := range pfs {
		v := portForwardView{PortForward: pf}
		if d := byUUID[strings.ToLower(pf.TargetDeviceUUID)]; d != nil {
			v.DeviceName = d.DisplayName()
			v.DeviceID = d.ID
		}
		if st, ok := live[pf.PublicPort]; ok {
			v.LiveState = st.State
			v.LiveErr = st.Err
		}
		views = append(views, v)
		stats.Total++
		if !v.Enabled {
			stats.Disabled++
			continue
		}
		switch v.LiveState {
		case "listening":
			stats.Listening++
		case "bind_failed", "route_degraded":
			stats.Degraded++
		}
	}
	s.renderPage(w, r, "port_forwards.html", PageData{
		Title: tr(r, "page.portForwards.title"),
		Flash: flashFromQuery(r),
		Data: map[string]any{
			"Forwards": views,
			"Devices":  devs,
			"Stats":    stats,
		},
		Nav: NavContext{Active: "portforward"},
	})
}

func (s *Server) handlePortForwardNew(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAdminRole(w, r) {
		return
	}
	publicPort, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("public_port")))
	targetPort, _ := strconv.Atoi(strings.TrimSpace(r.FormValue("target_port")))
	targetIP := strings.TrimSpace(r.FormValue("target_ip"))
	deviceUUID := strings.ToLower(strings.TrimSpace(r.FormValue("device_uuid")))
	comment := strings.TrimSpace(r.FormValue("comment"))

	if msg := s.validatePortForwardInput(r, publicPort, targetPort, targetIP, deviceUUID); msg != "" {
		s.renderError(w, r, http.StatusBadRequest, msg)
		return
	}

	pf, err := s.store.CreatePortForward(r.Context(), store.PortForward{
		PublicPort:       publicPort,
		Proto:            "tcp",
		TargetDeviceUUID: deviceUUID,
		TargetIP:         targetIP,
		TargetPort:       targetPort,
		Enabled:          true,
		Comment:          comment,
	})
	if err != nil {
		s.renderError(w, r, http.StatusBadRequest, tr(r, "pf.createFailed")+trErr(r, err))
		return
	}
	s.audit.WriteFromRequest(r, "port_forward_create",
		FormatTarget("port_forward", strconv.FormatInt(pf.ID, 10)),
		FormatDetail("public_port", strconv.Itoa(publicPort), "target", targetIP+":"+strconv.Itoa(targetPort), "device_uuid", deviceUUID))
	tryReloadPortForwardsBackground(s.control)
	flashRedirect(w, r, "/port-forwards", tr(r, "flash.portForwardAdded", publicPort), "")
}

func (s *Server) handlePortForwardAction(w http.ResponseWriter, r *http.Request) {
	segs := pathSegments(r.URL.Path) // [port-forwards, id, verb]
	if len(segs) < 3 {
		s.renderError(w, r, http.StatusBadRequest, tr(r, "pf.needPathVerb"))
		return
	}
	id, err := strconv.ParseInt(segs[1], 10, 64)
	if err != nil || id <= 0 {
		s.renderError(w, r, http.StatusBadRequest, tr(r, "pf.invalidId"))
		return
	}
	verb := segs[2]
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.requireAdminRole(w, r) {
		return
	}
	switch verb {
	case "delete":
		if err := s.store.DeletePortForward(r.Context(), id); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				s.renderError(w, r, http.StatusNotFound, tr(r, "err.pfNotFound"))
				return
			}
			s.renderInternalError(w, r, "portforward:delete", err)
			return
		}
		s.audit.WriteFromRequest(r, "port_forward_delete", FormatTarget("port_forward", segs[1]), "")
		tryReloadPortForwardsBackground(s.control)
		flashRedirect(w, r, "/port-forwards", tr(r, "flash.portForwardDeleted"), "")
	case "enable", "disable":
		enabled := verb == "enable"
		if err := s.store.SetPortForwardEnabled(r.Context(), id, enabled); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				s.renderError(w, r, http.StatusNotFound, tr(r, "err.pfNotFound"))
				return
			}
			s.renderInternalError(w, r, "portforward:set_enabled:"+verb, err)
			return
		}
		s.audit.WriteFromRequest(r, "port_forward_"+verb, FormatTarget("port_forward", segs[1]), "")
		tryReloadPortForwardsBackground(s.control)
		msg := tr(r, "flash.portForwardDisabled")
		if enabled {
			msg = tr(r, "flash.portForwardEnabled")
		}
		flashRedirect(w, r, "/port-forwards", msg, "")
	default:
		s.renderError(w, r, http.StatusBadRequest, tr(r, "err.unknownAction"))
	}
}

// validatePortForwardInput 校验创建入参，返回空串=通过，否则=错误信息。
//   - 端口范围 1..65535；public_port 不与 server/web 自身端口冲突；
//   - device_uuid 必须是已注册设备；
//   - target_ip 必须是合法 IP，且要么 = 该设备 vIP（node 目标），要么落在该设备**已批准宣告网段**内（LAN 目标）。
func (s *Server) validatePortForwardInput(r *http.Request, publicPort, targetPort int, targetIP, deviceUUID string) string {
	if publicPort <= 0 || publicPort > 65535 {
		return tr(r, "pf.publicPortRange")
	}
	if targetPort <= 0 || targetPort > 65535 {
		return tr(r, "pf.targetPortRange")
	}
	if reservedPublicPorts[publicPort] || publicPort == s.listenPort() {
		return tr(r, "pf.publicPortConflict")
	}
	ip, err := netip.ParseAddr(targetIP)
	if err != nil {
		return tr(r, "pf.targetIpInvalid", targetIP)
	}
	if deviceUUID == "" {
		return tr(r, "pf.mustSelectDevice")
	}
	devs, err := s.store.ListAllDevices(r.Context())
	if err != nil {
		return tr(r, "pf.queryDevicesFailed", err.Error())
	}
	var dev *store.Device
	for _, d := range devs {
		if strings.EqualFold(d.DeviceUUID, deviceUUID) {
			dev = d
			break
		}
	}
	if dev == nil {
		return tr(r, "pf.deviceNotFound")
	}
	// 歧义拦截（#5）：同一 target_ip 不能同时被指向**不同设备**——数据面按 dst 精确路由，一个目的 IP 只能对应一台
	// 设备；两条映射同 IP 不同设备时无法区分该投给谁。同一 IP 同一设备（不同端口）允许。
	if msg := s.checkPortForwardTargetDeviceConflict(r, ip, deviceUUID); msg != "" {
		return msg
	}
	// node 目标：target_ip == 该设备 vIP（fixed 或 lease）。
	if s.ipIsDeviceVIP(r, dev, ip) {
		return ""
	}
	// LAN 目标：target_ip 必须落在该设备**已批准**的宣告网段内（防越权/SSRF，与数据面 lookupSubnetRoute 同口径）。
	if s.ipInApprovedAdvertisedSubnet(r, dev.ID, ip) {
		return ""
	}
	return tr(r, "pf.targetNotVipOrSubnet")
}

// checkPortForwardTargetDeviceConflict 检查是否已有映射把**同一 target_ip 指向另一台设备**（#5 歧义拦截）。
// 数据面按 dst 精确路由到映射指定的设备，故一个目的 IP 只能绑一台设备；命中冲突返回错误信息，否则空串。
// 同 IP 同设备（不同端口）不算冲突。IP 用 netip.Addr 归一比较（避免 v6 大小写/压缩写法漏判）。
func (s *Server) checkPortForwardTargetDeviceConflict(r *http.Request, ip netip.Addr, deviceUUID string) string {
	existing, err := s.store.ListPortForwards(r.Context())
	if err != nil {
		return tr(r, "pf.queryExistingFailed", err.Error())
	}
	ipKey := ip.Unmap() // 与数据面 frpTargetTable 的 key 口径一致：v4 与 v4-in-v6 视为同一 IP，避免绕过冲突检测
	for _, e := range existing {
		ea, perr := netip.ParseAddr(strings.TrimSpace(e.TargetIP))
		if perr != nil || ea.Unmap() != ipKey {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(e.TargetDeviceUUID), deviceUUID) {
			return tr(r, "pf.targetIpConflict", ip.String(), e.PublicPort)
		}
	}
	return ""
}

// ipIsDeviceVIP 判断 ip 是否为该设备的 vIP（FixedVIPv4/V6 或当前 lease 的 v4/v6）。
func (s *Server) ipIsDeviceVIP(r *http.Request, dev *store.Device, ip netip.Addr) bool {
	cands := []string{dev.FixedVIPv4, dev.FixedVIPv6}
	if lease, err := s.store.GetLeaseByDevice(r.Context(), dev.ID); err == nil && lease != nil {
		cands = append(cands, lease.VIPv4, lease.VIPv6)
	}
	for _, c := range cands {
		if c == "" {
			continue
		}
		if a, err := netip.ParseAddr(c); err == nil && a == ip {
			return true
		}
	}
	return false
}

// ipInApprovedAdvertisedSubnet 判断 ip 是否落在该设备**已批准**（非默认路由）的宣告网段内。
func (s *Server) ipInApprovedAdvertisedSubnet(r *http.Request, deviceID int64, ip netip.Addr) bool {
	routes, err := s.store.ListRoutesByDevice(r.Context(), deviceID)
	if err != nil {
		return false
	}
	for _, rt := range routes {
		if rt.Status != store.RouteStatusApproved {
			continue
		}
		p, perr := netip.ParsePrefix(rt.CIDR)
		if perr != nil || p.Bits() == 0 { // 跳过 0.0.0.0/0 / ::/0（出口默认路由，非 LAN 子网）
			continue
		}
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// listenPort 解析 web 自身监听端口（cfg.ListenAddr 形如 "0.0.0.0:7443"）；解析失败返回 0。
func (s *Server) listenPort() int {
	_, portStr, err := net.SplitHostPort(s.cfg.ListenAddr)
	if err != nil {
		return 0
	}
	p, _ := strconv.Atoi(portStr)
	return p
}
