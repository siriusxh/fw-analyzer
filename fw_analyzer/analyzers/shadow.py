"""
fw_analyzer/analyzers/shadow.py

影子规则检测。

定义：规则 B 是规则 A 的影子规则，当且仅当：
  1. A 在 B 之前（seq_A < seq_B）
  2. A 的流量覆盖范围完全包含 B 的覆盖范围（A ⊇ B）
  3. 如果 A 与 B 动作相同 → B 是冗余型影子（SHADOW）
  4. 如果 A 与 B 动作不同 → B 是冲突型影子（SHADOW_CONFLICT）

覆盖语义（B 被 A 完全覆盖）：
  - 对于 B 的每个源地址对象，A 中存在某个对象完全包含它
  - 对于 B 的每个目的地址对象，A 中存在某个对象完全包含它
  - 对于 B 的每个服务对象，A 中存在某个服务对象完全包含它

性能优化：
  - 跳过 disabled 规则
  - 索引 + 剪枝：
    - /16 前缀分桶索引（src 和 dst 各一套），大幅减少实际比较次数
    - 协议分桶索引，快速过滤不相关协议
    - FQDN/range/unknown/any 地址保守策略：加入所有桶
  - 最坏情况仍为 O(n²)，但对 1000-5000 条规则规模实际比较量大幅降低
"""
from __future__ import annotations

from ipaddress import IPv4Network

from ..models.rule import FlatRule, Warning, WarningSeverity
from ..models.object_store import AddressObject, ServiceObject
from ..models.port_range import PortRange
from ..models.ip_utils import network_contains

# 用于标记"任意 /16 桶"的特殊哨兵值
_WILDCARD_BUCKET = -1


class ShadowAnalyzer:
    """
    影子规则分析器。

    调用 analyze(rules) 后，规则的 analysis_tags 会被原地修改。
    """

    def analyze(self, rules: list[FlatRule]) -> None:
        """
        检测影子规则，将标签写入 rule.analysis_tags。

        标签格式：
          "SHADOW:by={rule_id}"         - 被完全覆盖且动作相同
          "SHADOW_CONFLICT:by={rule_id}" - 被完全覆盖但动作不同

        URL 分类规则处理：
          带 url_category 的规则（非 any）在 L7 层面限制了流量范围，
          工具无法判断其匹配关系，因此：
          - 不参与影子检测（不作为覆盖者，也不被标记为被覆盖者）
          - 标记 URL_CATEGORY_SKIP 标签

        性能优化：使用 /16 前缀索引 + 协议分桶，将候选集限制在
        可能匹配的规则子集上，减少不必要的 _a_covers_b 调用。
        """
        # 处理 url_category 规则：标记并排除
        for r in rules:
            if r.enabled and r.url_category:
                tag = "URL_CATEGORY_SKIP"
                if tag not in r.analysis_tags:
                    r.analysis_tags.append(tag)

        enabled = [r for r in rules if r.enabled and not r.url_category]
        n = len(enabled)
        if n <= 1:
            return

        # 构建索引
        src_buckets, dst_buckets, proto_buckets, any_proto_rules = (
            self._build_index(enabled)
        )

        for i, rule_b in enumerate(enabled):
            # --- 通过索引计算候选集 ---
            candidates = self._get_candidates(
                i, rule_b, enabled,
                src_buckets, dst_buckets,
                proto_buckets, any_proto_rules,
            )

            for j in candidates:
                rule_a = enabled[j]

                # --- 协议剪枝（精确检查）---
                if not self._protocols_may_overlap(rule_a, rule_b):
                    continue

                # --- IP 快速 overlap 剪枝（任意 src 对有 overlap 才继续）---
                if not self._ips_may_overlap(rule_a.src_ip, rule_b.src_ip):
                    continue
                if not self._ips_may_overlap(rule_a.dst_ip, rule_b.dst_ip):
                    continue

                # --- 精确覆盖检查 ---
                if self._a_covers_b(rule_a, rule_b):
                    if rule_a.action == rule_b.action:
                        tag = f"SHADOW:by={rule_a.raw_rule_id}"
                    else:
                        tag = f"SHADOW_CONFLICT:by={rule_a.raw_rule_id}"
                    if tag not in rule_b.analysis_tags:
                        rule_b.analysis_tags.append(tag)

    # ------------------------------------------------------------------
    # 索引构建与候选集检索
    # ------------------------------------------------------------------

    @staticmethod
    def _addr_to_prefix16_buckets(addrs: list[AddressObject]) -> set[int]:
        """
        提取地址列表涉及的 /16 前缀桶编号。

        对于可解析的网络地址，计算其覆盖的所有 /16 桶。
        对于 any/fqdn/range/unknown 或空列表，返回 {_WILDCARD_BUCKET}
        表示需要与所有桶匹配。
        """
        if not addrs:
            return {_WILDCARD_BUCKET}

        buckets: set[int] = set()
        for addr in addrs:
            if addr.type == "any":
                return {_WILDCARD_BUCKET}
            if addr.network is None or addr.type in ("fqdn", "range", "unknown"):
                # 保守策略：无法判断 IP 范围的对象视为通配
                return {_WILDCARD_BUCKET}
            net = addr.network
            # 计算该网络覆盖的 /16 范围
            start_16 = int(net.network_address) >> 16
            end_16 = int(net.broadcast_address) >> 16
            # 对于非常大的网络（如 /8 覆盖 256 个 /16），
            # 退化为通配以避免桶膨胀
            if end_16 - start_16 > 255:
                return {_WILDCARD_BUCKET}
            for b in range(start_16, end_16 + 1):
                buckets.add(b)
        return buckets

    @staticmethod
    def _build_index(
        enabled: list[FlatRule],
    ) -> tuple[
        dict[int, list[int]],  # src_buckets
        dict[int, list[int]],  # dst_buckets
        dict[str, set[int]],   # proto_buckets
        set[int],              # any_proto_rules
    ]:
        """
        为 enabled 规则列表构建三种索引。

        返回:
            src_buckets:     /16 前缀 → 规则索引列表（源地址）
            dst_buckets:     /16 前缀 → 规则索引列表（目的地址）
            proto_buckets:   协议名 → 规则索引集合
            any_proto_rules: 协议为 any/ip 的规则索引集合
        """
        src_buckets: dict[int, list[int]] = {}
        dst_buckets: dict[int, list[int]] = {}
        proto_buckets: dict[str, set[int]] = {}
        any_proto_rules: set[int] = set()

        for idx, rule in enumerate(enabled):
            # --- 源地址 /16 桶 ---
            src_b = ShadowAnalyzer._addr_to_prefix16_buckets(rule.src_ip)
            if _WILDCARD_BUCKET in src_b:
                src_buckets.setdefault(_WILDCARD_BUCKET, []).append(idx)
            else:
                for b in src_b:
                    src_buckets.setdefault(b, []).append(idx)

            # --- 目的地址 /16 桶 ---
            dst_b = ShadowAnalyzer._addr_to_prefix16_buckets(rule.dst_ip)
            if _WILDCARD_BUCKET in dst_b:
                dst_buckets.setdefault(_WILDCARD_BUCKET, []).append(idx)
            else:
                for b in dst_b:
                    dst_buckets.setdefault(b, []).append(idx)

            # --- 协议桶 ---
            if not rule.services:
                any_proto_rules.add(idx)
            else:
                has_any = False
                for svc in rule.services:
                    proto = svc.protocol.lower()
                    if proto in ("any", "ip"):
                        has_any = True
                        break
                    if proto == "tcp-udp":
                        proto_buckets.setdefault("tcp", set()).add(idx)
                        proto_buckets.setdefault("udp", set()).add(idx)
                    else:
                        proto_buckets.setdefault(proto, set()).add(idx)
                if has_any:
                    any_proto_rules.add(idx)

        return src_buckets, dst_buckets, proto_buckets, any_proto_rules

    @staticmethod
    def _get_candidates(
        i: int,
        rule_b: FlatRule,
        enabled: list[FlatRule],
        src_buckets: dict[int, list[int]],
        dst_buckets: dict[int, list[int]],
        proto_buckets: dict[str, set[int]],
        any_proto_rules: set[int],
    ) -> list[int]:
        """
        获取可能覆盖 rule_b 的候选规则索引（seq < i）。

        候选集 = (src 桶匹配) ∩ (dst 桶匹配) ∩ (协议桶匹配) 中 < i 的规则。
        """
        # --- 源地址候选 ---
        src_b = ShadowAnalyzer._addr_to_prefix16_buckets(rule_b.src_ip)
        src_candidates: set[int] = set()
        # 通配桶中的规则总是候选
        for j in src_buckets.get(_WILDCARD_BUCKET, []):
            if j < i:
                src_candidates.add(j)
        if _WILDCARD_BUCKET in src_b:
            # rule_b 的源地址是通配，所有 < i 的规则都是候选
            src_candidates.update(range(i))
        else:
            for b in src_b:
                for j in src_buckets.get(b, []):
                    if j < i:
                        src_candidates.add(j)

        if not src_candidates:
            return []

        # --- 目的地址候选 ---
        dst_b = ShadowAnalyzer._addr_to_prefix16_buckets(rule_b.dst_ip)
        dst_candidates: set[int] = set()
        for j in dst_buckets.get(_WILDCARD_BUCKET, []):
            if j < i:
                dst_candidates.add(j)
        if _WILDCARD_BUCKET in dst_b:
            dst_candidates.update(range(i))
        else:
            for b in dst_b:
                for j in dst_buckets.get(b, []):
                    if j < i:
                        dst_candidates.add(j)

        candidates = src_candidates & dst_candidates
        if not candidates:
            return []

        # --- 协议候选 ---
        proto_candidates: set[int] = set(any_proto_rules)
        b_protos = ShadowAnalyzer._get_protocols(rule_b)
        if "any" in b_protos or "ip" in b_protos:
            # rule_b 协议是 any，所有规则都可能匹配
            proto_candidates.update(range(i))
        else:
            expanded = set()
            for p in b_protos:
                if p == "tcp-udp":
                    expanded.add("tcp")
                    expanded.add("udp")
                else:
                    expanded.add(p)
            for p in expanded:
                proto_candidates.update(proto_buckets.get(p, set()))

        candidates &= proto_candidates

        # 过滤 < i 并排序（保持原始顺序）
        return sorted(j for j in candidates if j < i)

    # ------------------------------------------------------------------
    # 覆盖检查
    # ------------------------------------------------------------------

    def _a_covers_b(self, rule_a: FlatRule, rule_b: FlatRule) -> bool:
        """
        判断 rule_a 是否完全覆盖 rule_b。

        覆盖 = zone/interface 匹配 + 对于 B 的每一个地址/服务对象，A 中都有某个对象包含它。

        Zone 覆盖语义：
          - 空字符串 = 无域限制（相当于"所有域"），可以覆盖任何域集合
          - 非空域使用 "; " 分隔多域，A 的域集必须是 B 域集的超集
          - 即 A.zones ⊇ B.zones 时 A 才在该维度覆盖 B

        Interface 覆盖语义同理：空 = 无限制，非空需要精确匹配或 A 为空。
        """
        # Zone / interface 检查
        if not self._zone_a_covers_b(rule_a.src_zone, rule_b.src_zone):
            return False
        if not self._zone_a_covers_b(rule_a.dst_zone, rule_b.dst_zone):
            return False
        if not self._zone_a_covers_b(rule_a.interface, rule_b.interface):
            return False

        # 源地址：B 的每个 src 对象必须被 A 的某个 src 对象包含
        if not self._addr_list_b_covered_by_a(rule_b.src_ip, rule_a.src_ip):
            return False

        # 目的地址
        if not self._addr_list_b_covered_by_a(rule_b.dst_ip, rule_a.dst_ip):
            return False

        # 服务
        if not self._svc_list_b_covered_by_a(rule_b.services, rule_a.services):
            return False

        return True

    @staticmethod
    def _zone_a_covers_b(a_zone: str, b_zone: str) -> bool:
        """
        判断 zone/interface 维度 A 是否覆盖 B。

        - 空字符串 = 无限制（覆盖一切）
        - A 为空 → True（A 不限域，覆盖 B 的任何域）
        - B 为空 → 只有 A 也为空才 True（B 不限域=所有域，A 必须也不限才能覆盖）
        - 非空 → A 的域集必须是 B 域集的超集
        """
        if not a_zone:
            return True
        if not b_zone:
            return False  # A 有域限制，B 无限制 → A 无法覆盖 B
        a_set = {z.strip() for z in a_zone.split(";")}
        b_set = {z.strip() for z in b_zone.split(";")}
        return a_set >= b_set

    def _addr_list_b_covered_by_a(
        self,
        b_addrs: list[AddressObject],
        a_addrs: list[AddressObject],
    ) -> bool:
        """
        对于 B 的每个地址对象，A 中是否存在某个地址对象完全包含它。
        """
        # B 为空 = any；A 需要也是 any 才算覆盖
        if not b_addrs:
            return self._addr_list_is_any(a_addrs)

        # A 为 any，直接覆盖
        if self._addr_list_is_any(a_addrs):
            return True

        for b_obj in b_addrs:
            covered = False
            for a_obj in a_addrs:
                if self._addr_a_covers_b(a_obj, b_obj):
                    covered = True
                    break
            if not covered:
                return False
        return True

    def _addr_a_covers_b(self, a: AddressObject, b: AddressObject) -> bool:
        """判断地址对象 a 是否包含 b。"""
        if a.type == "any":
            return True
        if b.type == "any":
            return a.type == "any"

        # FQDN/range/unknown 无法判断，保守返回 False
        if a.type in ("fqdn", "range", "unknown") or b.type in ("fqdn", "range", "unknown"):
            return False

        if a.network is None or b.network is None:
            return False

        return network_contains(a.network, b.network)

    @staticmethod
    def _addr_list_is_any(addrs: list[AddressObject]) -> bool:
        if not addrs:
            return True
        for a in addrs:
            if a.type == "any":
                return True
        return False

    def _svc_list_b_covered_by_a(
        self,
        b_svcs: list[ServiceObject],
        a_svcs: list[ServiceObject],
    ) -> bool:
        """
        对于 B 的每个服务对象，A 中是否存在某个服务对象完全包含它。
        """
        # 空 = any
        if not b_svcs:
            return not a_svcs  # A 也必须是 any

        if not a_svcs:  # A 是 any，覆盖一切
            return True

        for b_svc in b_svcs:
            covered = False
            for a_svc in a_svcs:
                if self._svc_a_covers_b(a_svc, b_svc):
                    covered = True
                    break
            if not covered:
                return False
        return True

    def _svc_a_covers_b(self, a: ServiceObject, b: ServiceObject) -> bool:
        """判断服务对象 a 是否包含 b。"""
        # 协议匹配
        a_proto = a.protocol.lower()
        b_proto = b.protocol.lower()

        if a_proto not in ("any", "ip"):
            if b_proto in ("any", "ip"):
                return False  # A 是具体协议，B 是 any，A 不能覆盖 B
            if a_proto == "tcp-udp":
                if b_proto not in ("tcp", "udp"):
                    return False
            elif a_proto != b_proto:
                return False

        # 端口匹配：a 的端口范围必须包含 b 的端口范围
        if not a.dst_port.contains(b.dst_port):
            return False
        if not a.src_port.contains(b.src_port):
            return False

        return True

    # ------------------------------------------------------------------
    # 剪枝方法
    # ------------------------------------------------------------------

    def _protocols_may_overlap(self, rule_a: FlatRule, rule_b: FlatRule) -> bool:
        """快速检查两条规则的协议集合是否可能有交集。"""
        a_protos = self._get_protocols(rule_a)
        b_protos = self._get_protocols(rule_b)

        # any 与任何协议都有交集
        if "any" in a_protos or "any" in b_protos:
            return True

        # tcp-udp 展开
        if "tcp-udp" in a_protos:
            a_protos = (a_protos - {"tcp-udp"}) | {"tcp", "udp"}
        if "tcp-udp" in b_protos:
            b_protos = (b_protos - {"tcp-udp"}) | {"tcp", "udp"}

        return bool(a_protos & b_protos)

    @staticmethod
    def _get_protocols(rule: FlatRule) -> set[str]:
        if not rule.services:
            return {"any"}
        return {s.protocol.lower() for s in rule.services}

    def _ips_may_overlap(
        self,
        a_addrs: list[AddressObject],
        b_addrs: list[AddressObject],
    ) -> bool:
        """快速检查两个地址列表是否存在 IP 重叠（用于剪枝）。"""
        if not a_addrs or not b_addrs:
            return True  # any 与任何地址都可能重叠

        for a in a_addrs:
            if a.type == "any":
                return True
            for b in b_addrs:
                if b.type == "any":
                    return True
                if a.network and b.network:
                    if a.network.overlaps(b.network):
                        return True
        return False
