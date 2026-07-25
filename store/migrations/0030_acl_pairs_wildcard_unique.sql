-- 0030_acl_pairs_wildcard_unique.sql
--
-- 第二十三轮深扫 MED:补上 0003 自己点名却从未实现的那道守卫 —— 通配 ACL 规则可以重复插入。
--
-- 0003 建表时的 `UNIQUE(src_user_id, dst_user_id, action, proto, dst_port_lo, dst_port_hi, dst_kind)`
-- 挡不住通配规则:src_user_id / dst_user_id 是可空列,而 SQLite 的 UNIQUE 把 NULL 视作**彼此不等**,
-- 于是 `* → *`、`alice → *`、`* → exit` 这类带 NULL 的行想插几遍就能插几遍。0003 的注释写着
-- 「应用层(admin CLI acl add)负责防止重复加同名通配」,但 AddACLPair / CLI / web 里都没有这个检查
-- (只有非通配行会撞 UNIQUE 并被归一成 ErrDuplicate)。
--
-- 后果不只是列表里多一行:管理员删掉其中一条后,孪生行仍在生效表里 —— reload 后流量按老规则放行/拒绝,
-- 而 UI 与 `acl ls` 都显示"已删"。对 deny 规则是"以为封了其实没封",对 allow 规则是"以为撤了其实还通"。
--
-- 处理:与 0023/0025/0027/0029 同一套路 —— 先归一存量,再建索引。
--   1. 按「逻辑键」(把 NULL 折叠成 -1;user id 恒为正的 AUTOINCREMENT,故 -1 不可能与真实 id 相撞)
--      去重,每组只留 id 最小(最早创建)的一行;
--   2. 建一条**表达式唯一索引**兜住 NULL 组合。表约束里的隐式索引(sqlite_autoindex)无法 DROP,
--      所以这里是在它旁边**新增**一条,二者并存不冲突。
--
-- 建索引前必须先去重,否则存量已有重复的库会在 CREATE 时直接失败 → Migrate 永久卡住。
-- proto / dst_port_lo / dst_port_hi / dst_kind / action 都是 NOT NULL DEFAULT,无需 COALESCE。
DELETE FROM acl_pairs
 WHERE id NOT IN (
   SELECT MIN(id) FROM acl_pairs
    GROUP BY COALESCE(src_user_id, -1), COALESCE(dst_user_id, -1),
             action, proto, dst_port_lo, dst_port_hi, dst_kind
 );

CREATE UNIQUE INDEX IF NOT EXISTS idx_acl_pairs_logical ON acl_pairs(
    COALESCE(src_user_id, -1), COALESCE(dst_user_id, -1),
    action, proto, dst_port_lo, dst_port_hi, dst_kind
);
