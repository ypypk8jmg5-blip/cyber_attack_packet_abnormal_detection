const pptxgen = require("pptxgenjs");
const QR = require("qrcode");

const DARK = "0F1E33", DARK2 = "1B2D4A";
const INK = "1E2A3A", MUTED = "5C6B7E";
const TEAL = "0D9488", TEALBR = "2DD4BF";
const CORAL = "D85A30", CORALBR = "E2574C";
const PURPLE = "5B4FC0", PURPLELT = "EDEBFA", PURPLEBR = "8B80E8";
const CARD = "F4F6F9", LINE = "DDE4EC";
const ICE = "E8EEF7", ICE2 = "9FB3CE";
const KR = "Apple SD 산돌고딕 Neo", MONO = "Menlo";

const REPO_URL = "https://github.com/ypypk8jmg5-blip/cyber_attack_packet_abnormal_detection";

async function main() {
  await QR.toFile("/tmp/qr_repo.png", REPO_URL, {
    width: 660, margin: 2,
    color: { dark: "#0F1E33", light: "#FFFFFF" }
  });

  const pres = new pptxgen();
  pres.layout = "LAYOUT_16x9";
  pres.author = "Sangbom Yun";
  pres.title = "AdaptiveNIDS — AI 에이전트로 구축한 적응형 침입 탐지";

  const T = (s, t, o) => s.addText(t, Object.assign({ fontFace: KR, margin: 0 }, o));
  const R = (s, o) => s.addShape(pres.shapes.RECTANGLE, o);
  const O = (s, o) => s.addShape(pres.shapes.OVAL, o);

  function numCircle(s, x, y, n, color) {
    O(s, { x, y, w: 0.42, h: 0.42, fill: { color } });
    T(s, String(n), { x, y: y + 0.01, w: 0.42, h: 0.42, fontSize: 15, bold: true, color: "FFFFFF", align: "center", valign: "middle" });
  }

  function agentGrid(s, x0, y0, sq, pitch, accents) {
    for (let r = 0; r < 4; r++) for (let c = 0; c < 8; c++) {
      const k = r * 8 + c;
      let color = "243A5E";
      if (accents.teal.includes(k)) color = TEALBR;
      else if (accents.coral.includes(k)) color = CORALBR;
      else if (accents.purple.includes(k)) color = PURPLEBR;
      R(s, { x: x0 + c * pitch, y: y0 + r * pitch, w: sq, h: sq, fill: { color } });
    }
  }

  // ───────────────────────── S1 타이틀 (dark)
  let s = pres.addSlide();
  s.background = { color: DARK };
  T(s, "NETWORK INTRUSION DETECTION  ×  MLOPS  ×  MULTI-AGENT", { x: 0.65, y: 1.32, w: 6.0, h: 0.3, fontSize: 9.5, color: TEALBR, charSpacing: 2, fontFace: "Helvetica Neue" });
  T(s, "AdaptiveNIDS", { x: 0.62, y: 1.62, w: 6.2, h: 0.95, fontSize: 52, bold: true, color: "FFFFFF", fontFace: "Helvetica Neue" });
  T(s, [
    { text: "스스로 품질을 감시하고 재학습하는", options: { breakLine: true } },
    { text: "적응형 네트워크 침입 탐지 시스템", options: {} },
  ], { x: 0.65, y: 2.75, w: 5.85, h: 0.72, fontSize: 16, color: ICE, fontFace: KR, margin: 0, lineSpacingMultiple: 1.2 });
  T(s, "Borderline-Aware Training(BAT)  ·  32-에이전트 오케스트레이션  ·  CIC-IDS2018 검증", { x: 0.65, y: 3.62, w: 5.85, h: 0.35, fontSize: 11.5, color: ICE2 });
  agentGrid(s, 6.62, 1.95, 0.26, 0.33, { teal: [1, 6, 11, 16, 21, 26, 30], coral: [13, 23], purple: [4, 9, 18, 28] });
  T(s, "32 agents · 7 layers", { x: 6.62, y: 3.32, w: 2.57, h: 0.28, fontSize: 9.5, color: ICE2, fontFace: MONO, align: "center" });
  T(s, "윤상범  —  AdaptiveNIDS 연구 프로토타입  ·  2026. 06", { x: 0.65, y: 5.02, w: 6.5, h: 0.3, fontSize: 10, color: ICE2 });
  s.addNotes(
`[0:00–0:25 · 약 25초]

안녕하세요, 윤상범입니다. 오늘 소개할 AdaptiveNIDS는 침입 탐지기를 "한 번 학습하고 끝나는 모델"이 아니라, 스스로 품질을 감시하고 재학습하는 운영 시스템으로 만든 연구입니다.

오른쪽 32개의 사각형이 오늘의 주인공입니다. 이 시스템 안에서 실제로 협업하는 32개의 AI 에이전트인데요 — 한 가지 더, 이 시스템을 "만드는 과정"에도 AI 에이전트를 활용했습니다. 그 이야기는 마지막에 드리겠습니다.

(전환) 먼저, 왜 "적응형"이어야 하는지부터 보겠습니다.`);

  // ───────────────────────── S2 문제 제기 (light)
  s = pres.addSlide();
  s.background = { color: "FFFFFF" };
  T(s, "한 번 학습한 탐지기는, 다른 날의 트래픽 앞에서 무너집니다", { x: 0.6, y: 0.42, w: 8.8, h: 0.5, fontSize: 24, bold: true, color: INK });
  T(s, "CIC-IDS2018 캡처 데이 홀드아웃 — 학습한 날짜와 다른 날짜의 트래픽으로 평가한 결과", { x: 0.62, y: 1.0, w: 8.8, h: 0.32, fontSize: 12, color: MUTED });
  R(s, { x: 0.6, y: 1.55, w: 4.55, h: 3.45, fill: { color: CARD } });
  T(s, "같은 모델, 평가 트래픽만 변경했을 때의 F1", { x: 0.85, y: 1.78, w: 4.05, h: 0.3, fontSize: 11.5, color: MUTED });
  T(s, "0.994", { x: 0.78, y: 2.28, w: 1.22, h: 0.62, fontSize: 30, bold: true, color: INK, align: "center" });
  T(s, "→", { x: 2.0, y: 2.32, w: 0.32, h: 0.5, fontSize: 20, color: MUTED, align: "center" });
  T(s, "0.013", { x: 2.32, y: 2.2, w: 1.3, h: 0.7, fontSize: 34, bold: true, color: CORAL, align: "center" });
  T(s, "→", { x: 3.62, y: 2.32, w: 0.32, h: 0.5, fontSize: 20, color: MUTED, align: "center" });
  T(s, "0.998", { x: 3.94, y: 2.28, w: 1.1, h: 0.62, fontSize: 30, bold: true, color: TEAL, align: "center" });
  T(s, "학습일 트래픽", { x: 0.78, y: 2.98, w: 1.22, h: 0.28, fontSize: 10, color: MUTED, align: "center" });
  T(s, "다른 날 트래픽", { x: 2.32, y: 2.98, w: 1.3, h: 0.28, fontSize: 10, bold: true, color: CORAL, align: "center" });
  T(s, "30% 재학습 후", { x: 3.94, y: 2.98, w: 1.1, h: 0.28, fontSize: 10, color: TEAL, align: "center" });
  s.addShape(pres.shapes.LINE, { x: 0.85, y: 3.55, w: 4.05, h: 0, line: { color: LINE, width: 1 } });
  T(s, "드리프트는 예외가 아니라 기본값 — 감지·복구 체계가 없으면 F1 1%대인 채 운영됩니다", { x: 0.85, y: 3.75, w: 4.05, h: 1.0, fontSize: 11.5, color: INK, lineSpacingMultiple: 1.25 });
  const probs = [
    ["트래픽 드리프트", "날짜만 바뀌어도 분포가 변하고, recall은 그대로 무너집니다"],
    ["회피형 트래픽", "정상을 흉내 낸 공격은 결정 경계 부근에 숨어 탐지를 피합니다"],
    ["운영 공백", "성능 저하를 감지하고 복구하는 절차가 모델 바깥에 없습니다"],
  ];
  probs.forEach((p, i) => {
    const y = 1.55 + i * 1.18;
    numCircle(s, 5.5, y + 0.04, i + 1, INK);
    T(s, p[0], { x: 6.08, y: y, w: 3.3, h: 0.32, fontSize: 14, bold: true, color: INK });
    T(s, p[1], { x: 6.08, y: y + 0.36, w: 3.3, h: 0.62, fontSize: 11, color: MUTED, lineSpacingMultiple: 1.15 });
  });
  T(s, "출처: capture-day holdout 실험 (scripts/capture_day_retrain.py) · CIC-IDS2018 공통 4클래스 · 평가 22,654 플로우", { x: 0.6, y: 5.18, w: 8.8, h: 0.28, fontSize: 9.5, color: MUTED });
  s.addNotes(
`[0:25–1:15 · 약 50초]

가운데 세 숫자가 오늘 발표에서 가장 중요한 숫자입니다.

같은 모델을 CIC-IDS2018에서 학습한 날짜의 트래픽으로 평가하면 F1 0.994입니다. 그런데 평가 트래픽을 다른 날짜로만 바꾸면 0.013 — 사실상 탐지가 안 됩니다. 모델이 망가진 게 아니라 트래픽 분포가 변한 겁니다. 다행히 새 데이터의 30%만으로 재학습하면 0.998로 회복됩니다.

정리하면 문제는 세 가지입니다. 드리프트는 예외가 아니라 기본값이고, 회피형 공격은 결정 경계 부근에 숨고, 그런데 이걸 감지하고 복구하는 절차가 모델 바깥에 없다는 것.

(전환) 그렇다면, 막아야 할 위협부터 정의하고 시작하겠습니다.`);

  // ───────────────────────── S3 위협 모델 (light)
  s = pres.addSlide();
  s.background = { color: "FFFFFF" };
  T(s, "위협 모델 — 14종 공격, 5개 계열", { x: 0.6, y: 0.42, w: 8.8, h: 0.5, fontSize: 24, bold: true, color: INK });
  T(s, "모든 위협은 12차원 플로우 특징(트래픽률 · 포트 · 실패율 · 방향성 …)의 이상 패턴으로 관측됩니다", { x: 0.62, y: 1.0, w: 8.8, h: 0.32, fontSize: 11.5, color: MUTED });
  const threats = [
    ["가용성 마비 (5종)", "DDoS · SYN플러드 · HTTP플러드 · Slowloris · DNS증폭", "대량 트래픽과 연결 자원 고갈로 서비스를 멈춥니다", "관측 — pps · bps 급증, SYN 비율 ↑"],
    ["정찰 · 크리덴셜 (3종)", "포트스캔 · 브루트포스 · 크리덴셜 스터핑", "공격 표면을 훑은 뒤 인증을 반복 시도해 계정을 탈취합니다", "관측 — 고유 목적지 포트, 실패 시도율 ↑"],
    ["은닉 채널 · 유출 (2종)", "데이터 유출 · DNS 터널링", "정상 프로토콜로 위장해 내부 데이터를 반출합니다", "관측 — 아웃바운드 비율, DNS 패킷 크기 ↑"],
    ["감염 후 활동 (3종)", "봇넷 C&C · 랜섬웨어 · 크립토마이닝", "침투 이후 원격 제어 · 암호화 · 자원 도용을 수행합니다", "관측 — C2 포트 연결, 비컨 패턴"],
    ["네트워크 기만 (1종)", "ARP 스푸핑", "주소 위조로 트래픽을 가로채는 중간자(MITM) 공격입니다", "관측 — 비정상 ARP · ICMP 패턴"],
  ];
  const tcardX = [0.6, 3.575, 6.55], tcardY = [1.45, 3.42];
  threats.forEach((t, i) => {
    const x = tcardX[i % 3], y = tcardY[Math.floor(i / 3)];
    R(s, { x, y, w: 2.85, h: 1.85, fill: { color: CARD } });
    R(s, { x, y, w: 0.07, h: 1.85, fill: { color: CORAL } });
    T(s, t[0], { x: x + 0.2, y: y + 0.13, w: 2.5, h: 0.3, fontSize: 12.5, bold: true, color: INK });
    T(s, t[1], { x: x + 0.2, y: y + 0.45, w: 2.5, h: 0.42, fontSize: 9.5, bold: true, color: CORAL, lineSpacingMultiple: 1.1 });
    T(s, t[2], { x: x + 0.2, y: y + 0.92, w: 2.5, h: 0.4, fontSize: 9.5, color: MUTED, lineSpacingMultiple: 1.1 });
    T(s, t[3], { x: x + 0.2, y: y + 1.4, w: 2.5, h: 0.36, fontSize: 9, color: TEAL });
  });
  R(s, { x: 6.55, y: 3.42, w: 2.85, h: 1.85, fill: { color: CARD } });
  R(s, { x: 6.55, y: 3.42, w: 0.07, h: 1.85, fill: { color: TEAL } });
  T(s, "정상 베이스라인 (10종)", { x: 6.75, y: 3.55, w: 2.5, h: 0.3, fontSize: 12.5, bold: true, color: INK });
  T(s, "DNS · HTTP/S · FTP · SMTP · SSH · NTP · VoIP · 스트리밍 · DB", { x: 6.75, y: 3.87, w: 2.5, h: 0.42, fontSize: 9.5, bold: true, color: TEAL, lineSpacingMultiple: 1.1 });
  T(s, "공격이 아닌 기준 분포 — 회피형 변종은 이 경계에 숨고, BAT가 그 경계를 직접 학습합니다", { x: 6.75, y: 4.34, w: 2.5, h: 0.78, fontSize: 9.5, color: MUTED, lineSpacingMultiple: 1.15 });
  T(s, "공격 14종 + 정상 10종이 혼재된 트래픽에서 학습·평가 (scripts/generate_packets.py 기준)", { x: 0.6, y: 5.36, w: 8.8, h: 0.26, fontSize: 9.5, color: MUTED });
  s.addNotes(
`[1:15–2:00 · 약 45초]

막아야 할 것부터 정의하겠습니다. 14종 공격을 5개 계열로 묶었습니다.

서비스를 마비시키는 플러딩 계열 5종, 포트스캔에서 크리덴셜 스터핑으로 이어지는 정찰·계정 탈취 3종, 정상 프로토콜로 위장하는 은닉 유출 2종, 감염 이후의 C&C·랜섬웨어·크립토마이닝 3종, 그리고 주소를 속이는 ARP 스푸핑입니다.

중요한 건 오른쪽 아래입니다 — 정상 트래픽 10종이 함께 정의되어 있습니다. 회피형 공격은 바로 이 정상 분포의 경계에 숨기 때문에, 이 베이스라인이 곧 BAT 학습의 기준이 됩니다.

(전환) 그럼 이 위협들에 시스템이 어떻게 대응하는지 보겠습니다.`);

  // ───────────────────────── S4 대응 흐름 (light)
  s = pres.addSlide();
  s.background = { color: "FFFFFF" };
  T(s, "공격 계열별 대응 흐름", { x: 0.6, y: 0.42, w: 8.8, h: 0.5, fontSize: 24, bold: true, color: INK });
  T(s, "공통 파이프라인이 탐지하고 — 계열별 심각도, MITRE ATT&CK 컨텍스트, 대응 플레이북이 알림에 자동 첨부됩니다", { x: 0.62, y: 1.0, w: 8.8, h: 0.32, fontSize: 11.5, color: MUTED });
  const flowChips = ["수집 L1", "병렬 분석 L2 ×8", "판정 L3", "심각도·알림 L5", "피드백 L6"];
  flowChips.forEach((c, i) => {
    const x = 0.6 + i * 1.81;
    R(s, { x, y: 1.42, w: 1.55, h: 0.46, fill: { color: "E8EDF4" } });
    T(s, c, { x, y: 1.42, w: 1.55, h: 0.46, fontSize: 11, bold: true, color: INK, align: "center", valign: "middle" });
    if (i < 4) T(s, "→", { x: x + 1.55, y: 1.42, w: 0.26, h: 0.46, fontSize: 12, color: MUTED, align: "center", valign: "middle" });
  });
  const respCols = [
    ["공격 계열", 0.6, 1.85], ["기본 심각도", 2.52, 1.32], ["MITRE 전술", 3.92, 1.5], ["대응 플레이북 권고 (알림 첨부)", 5.5, 3.9],
  ];
  respCols.forEach(c => {
    T(s, c[0], { x: c[1] + 0.12, y: 2.12, w: c[2] - 0.18, h: 0.28, fontSize: 10, bold: true, color: MUTED });
  });
  const resp = [
    ["가용성 마비", "CRITICAL", true, "Impact", "출발지 차단 · 속도 제한 · SYN 쿠키 · 스크러빙"],
    ["정찰 · 크리덴셜", "HIGH · MEDIUM", false, "Recon · Cred. Access", "계정 잠금 · MFA · IP 차단 목록 추가"],
    ["은닉 채널 · 유출", "HIGH · MEDIUM", false, "Exfiltration · C2", "DLP 점검 · DNS 쿼리 제한 · 관련 계정 감사"],
    ["감염 후 활동", "CRITICAL · MEDIUM", true, "C2 · Impact", "호스트 격리 · C2 포트 차단 · 백업 무결성 확인"],
    ["네트워크 기만", "HIGH", false, "Cred. Access", "동적 ARP 검사(DAI) · 정적 ARP · 세그멘테이션"],
  ];
  resp.forEach((r, i) => {
    const y = 2.48 + i * 0.525;
    R(s, { x: 0.6, y, w: 8.8, h: 0.49, fill: { color: CARD } });
    T(s, r[0], { x: 0.72, y, w: 1.73, h: 0.49, fontSize: 11, bold: true, color: INK, valign: "middle" });
    T(s, r[1], { x: 2.64, y, w: 1.36, h: 0.49, fontSize: 9.5, bold: true, color: r[2] ? CORAL : INK, valign: "middle" });
    T(s, r[3], { x: 4.04, y, w: 1.38, h: 0.49, fontSize: 9.5, color: MUTED, valign: "middle" });
    T(s, r[4], { x: 5.62, y, w: 3.7, h: 0.49, fontSize: 9.5, color: INK, valign: "middle" });
  });
  T(s, "심각도는 Agent-21 분류 기준(계열 내 유형별 상이) · 신뢰도 0.50–0.60 탐지는 한 단계 자동 강등 — 오탐 피로 억제", { x: 0.6, y: 5.16, w: 8.8, h: 0.22, fontSize: 9.5, color: MUTED });
  T(s, "모든 알림에 MITRE ATT&CK 전술·기법과 대응 플레이북 자동 첨부(Agent-24) · 탐지 취약 유형은 L0 적응형 생성으로 재학습에 반영", { x: 0.6, y: 5.38, w: 8.8, h: 0.22, fontSize: 9.5, color: MUTED });
  s.addNotes(
`[2:00–2:45 · 약 45초]

대응은 공통 파이프라인 하나로 흐릅니다. 수집, 8개 에이전트 병렬 분석, 증거 통합 판정, 심각도 분류와 알림, 그리고 피드백입니다.

계열별로 달라지는 건 세 가지입니다. 심각도 — DDoS·랜섬웨어처럼 즉시 피해를 주는 유형은 CRITICAL, 정찰형은 HIGH부터 시작합니다. MITRE 매핑 — 모든 알림에 ATT&CK 전술과 기법이 자동 태깅됩니다. 그리고 대응 플레이북 — 차단·격리·계정 잠금 같은 권고 단계가 알림에 함께 첨부됩니다.

디테일 하나만 — 신뢰도가 0.5에서 0.6 사이인 애매한 탐지는 심각도를 한 단계 자동 강등합니다. 운영자가 오탐에 지치지 않게 하는 장치입니다.

(전환) 이 모든 것이 실제 운영에서 어떻게 맞물리는지, 전체 그림 한 장으로 보겠습니다.`);

  // ───────────────────────── S5 운용 개념 (light)
  s = pres.addSlide();
  s.background = { color: "FFFFFF" };
  T(s, "운용 개념 — 위협 · 방어 · 운영 피드백의 순환", { x: 0.6, y: 0.42, w: 8.8, h: 0.5, fontSize: 24, bold: true, color: INK });
  T(s, "공격자의 특징 공간 회피(좌) → AdaptiveNIDS 방어(중) → 분석가 피드백과 재학습(우)", { x: 0.62, y: 1.0, w: 8.8, h: 0.32, fontSize: 11.5, color: MUTED });
  R(s, { x: 0.585, y: 1.385, w: 6.58, h: 3.69, fill: { color: "FFFFFF" }, line: { color: LINE, width: 1 } });
  s.addImage({ path: "/Users/yunsangbeom/project/anomaly-detection-mlops/docs/운용개념.png", x: 0.6, y: 1.4, w: 6.55, h: 3.66 });
  const opNotes = [
    ["1. 위협 모델", "블랙·그레이박스 공격자가 정상 트래픽을 모사한 회피 변종을 생성", CORAL],
    ["2. 프레임워크 방어", "멀티에이전트 탐지 · 운영 품질 게이트 · BAT가 특징 공간 회피를 방어", TEAL],
    ["3. 운영 피드백 루프", "분석가의 지연 피드백을 지속 재학습 루프가 흡수해 모델 갱신", PURPLE],
  ];
  opNotes.forEach((n, i) => {
    const y = 1.4 + i * 1.24;
    R(s, { x: 7.35, y, w: 2.05, h: 1.06, fill: { color: CARD } });
    R(s, { x: 7.35, y, w: 0.07, h: 1.06, fill: { color: n[2] } });
    T(s, n[0], { x: 7.53, y: y + 0.1, w: 1.8, h: 0.28, fontSize: 11.5, bold: true, color: INK });
    T(s, n[1], { x: 7.53, y: y + 0.4, w: 1.78, h: 0.6, fontSize: 9, color: MUTED, lineSpacingMultiple: 1.1 });
  });
  T(s, "범위 제외(Out of Scope): 화이트박스 공격 · 파이프라인 침해 · 페이로드 의미 회피 · 자동 차단 집행 — 탐지와 권고까지가 시스템의 책임", { x: 0.6, y: 5.18, w: 8.8, h: 0.26, fontSize: 9.5, color: MUTED });
  s.addNotes(
`[2:45–3:25 · 약 40초]

지금까지의 위협과 대응을 한 장으로 모은 운용 개념도입니다.

왼쪽이 위협 모델 — 공격자는 내부를 모르는 블랙·그레이박스 상태에서, 정상 트래픽을 모사한 회피 변종을 만들어 옵니다. 가운데가 우리 프레임워크 — 멀티에이전트 탐지, 품질 게이트, 그리고 BAT가 특징 공간 회피를 방어합니다. 오른쪽이 운영 루프 — 보안 분석가의 피드백이 지연되어 도착해도, 재학습 루프가 이를 흡수해 모델을 갱신합니다.

아래 명시했듯 화이트박스 공격과 자동 차단 집행은 범위 밖입니다 — 탐지와 권고까지가 이 시스템의 책임입니다.

(전환) 이 그림의 심장인 두 가지 처방을 자세히 보겠습니다.`);

  // ───────────────────────── S6 처방 — 핵심 아이디어 (light)
  s = pres.addSlide();
  s.background = { color: "FFFFFF" };
  T(s, "처방 — 경계를 직접 학습하고, 품질이 떨어지면 스스로 재학습", { x: 0.6, y: 0.42, w: 8.8, h: 0.5, fontSize: 24, bold: true, color: INK });
  // Card A: BAT
  R(s, { x: 0.6, y: 1.25, w: 4.25, h: 3.75, fill: { color: CARD } });
  R(s, { x: 0.6, y: 1.25, w: 0.07, h: 3.75, fill: { color: TEAL } });
  T(s, "BAT — 경계 인식 학습", { x: 0.88, y: 1.45, w: 3.8, h: 0.35, fontSize: 16, bold: true, color: INK });
  T(s, "공격 샘플을 정상 트래픽 중심 μ_n 방향으로 보간해, 회피형 변종이 분포하는 결정 경계 위에서 직접 학습합니다", { x: 0.88, y: 1.88, w: 3.78, h: 0.75, fontSize: 11.5, color: MUTED, lineSpacingMultiple: 1.2 });
  R(s, { x: 0.88, y: 2.78, w: 3.78, h: 0.46, fill: { color: "FFFFFF" }, line: { color: LINE, width: 1 } });
  T(s, "x_b = (1−α)·x_i + α·μ_n + ε", { x: 0.88, y: 2.78, w: 3.78, h: 0.46, fontSize: 13, color: INK, fontFace: MONO, align: "center", valign: "middle" });
  // mini scatter
  const atk = [[1.18, 3.7], [1.42, 3.92], [1.12, 4.05], [1.5, 4.18], [1.3, 4.35]];
  const nrm = [[3.85, 3.72], [4.12, 3.9], [3.8, 4.08], [4.2, 4.2], [3.98, 4.38]];
  const bdr = [[2.48, 3.85], [2.82, 4.06], [2.55, 4.26]];
  atk.forEach(p => O(s, { x: p[0], y: p[1], w: 0.13, h: 0.13, fill: { color: CORAL } }));
  nrm.forEach(p => O(s, { x: p[0], y: p[1], w: 0.13, h: 0.13, fill: { color: TEAL } }));
  bdr.forEach(p => O(s, { x: p[0], y: p[1], w: 0.13, h: 0.13, fill: { color: "FFFFFF" }, line: { color: CORAL, width: 1.5 } }));
  s.addShape(pres.shapes.LINE, { x: 2.72, y: 3.62, w: 0, h: 0.88, line: { color: MUTED, width: 1.25, dashType: "dash" } });
  T(s, "공격", { x: 1.05, y: 4.55, w: 0.6, h: 0.24, fontSize: 9, color: CORAL, align: "center" });
  T(s, "경계 샘플(생성)", { x: 2.14, y: 4.64, w: 1.16, h: 0.24, fontSize: 9.5, color: INK, align: "center" });
  T(s, "정상", { x: 3.78, y: 4.55, w: 0.6, h: 0.24, fontSize: 9, color: TEAL, align: "center" });
  // Card B: quality gate loop
  R(s, { x: 5.15, y: 1.25, w: 4.25, h: 3.75, fill: { color: CARD } });
  R(s, { x: 5.15, y: 1.25, w: 0.07, h: 3.75, fill: { color: TEAL } });
  T(s, "품질 게이트 재학습 루프", { x: 5.43, y: 1.45, w: 3.8, h: 0.35, fontSize: 16, bold: true, color: INK });
  T(s, "게이트를 통과할 때까지 학습–평가를 반복하고(최대 20사이클), 운영 중 성능(recall) 저하 시 재학습을 트리거합니다", { x: 5.43, y: 1.88, w: 3.78, h: 0.75, fontSize: 11.5, color: MUTED, lineSpacingMultiple: 1.2 });
  const gates = ["F1 ≥ 0.92", "Recall ≥ 0.90", "Prec ≥ 0.88"];
  gates.forEach((g, i) => {
    const x = 5.43 + i * 1.3;
    R(s, { x, y: 2.78, w: 1.18, h: 0.42, fill: { color: "FFFFFF" }, line: { color: TEAL, width: 1.25 } });
    T(s, g, { x, y: 2.78, w: 1.18, h: 0.42, fontSize: 10.5, bold: true, color: TEAL, align: "center", valign: "middle" });
  });
  const loopBoxes = ["생성", "학습", "평가", "게이트"];
  loopBoxes.forEach((b, i) => {
    const x = 5.43 + i * 1.0;
    R(s, { x, y: 3.5, w: 0.78, h: 0.4, fill: { color: "E8EDF4" } });
    T(s, b, { x, y: 3.5, w: 0.78, h: 0.4, fontSize: 10.5, color: INK, align: "center", valign: "middle" });
    if (i < 3) T(s, "→", { x: x + 0.78, y: 3.5, w: 0.22, h: 0.4, fontSize: 11, color: MUTED, align: "center", valign: "middle" });
  });
  s.addShape(pres.shapes.LINE, { x: 8.82, y: 3.9, w: 0, h: 0.32, line: { color: MUTED, width: 1 } });
  s.addShape(pres.shapes.LINE, { x: 5.82, y: 4.22, w: 3.0, h: 0, line: { color: MUTED, width: 1 } });
  s.addShape(pres.shapes.LINE, { x: 5.82, y: 3.9, w: 0, h: 0.32, line: { color: MUTED, width: 1, endArrowType: "arrow" }, flipV: true });
  T(s, "미달 → 데이터 보강 후 재학습  ·  통과 → 배포", { x: 5.43, y: 4.42, w: 3.78, h: 0.28, fontSize: 10, color: MUTED });
  T(s, "효과 — FPR 0.042 → 0.002 (1/21, 어블레이션)", { x: 0.88, y: 5.12, w: 3.97, h: 0.3, fontSize: 10.5, bold: true, color: TEAL });
  T(s, "효과 — 1사이클 만에 게이트 3종 통과 (F1 0.968)", { x: 5.43, y: 5.12, w: 3.97, h: 0.3, fontSize: 10.5, bold: true, color: TEAL });
  s.addNotes(
`[3:25–4:15 · 약 50초]

첫 번째 처방, BAT — 경계 인식 학습입니다. 공격 샘플을 정상 트래픽 중심 방향으로 보간해서, 회피형 변종이 실제로 분포하는 결정 경계 위에 학습 샘플을 만듭니다. 화면 수식처럼 알파 비율로 섞고 노이즈를 더하는 단순한 방법인데, 하드 테스트셋에서 오탐률이 0.042에서 0.002로 — 21분의 1이 됐습니다.

두 번째, 품질 게이트 재학습 루프입니다. F1 0.92, recall 0.90, precision 0.88 — 세 게이트를 통과할 때까지 생성–학습–평가를 자동 반복하고(최대 20사이클), 운영 중 recall이 떨어져도 같은 루프가 다시 돕니다. 학습이 일회성 이벤트가 아니라 상시 운영 절차가 되는 겁니다.

(전환) 그럼 이 절차를 누가 굴리느냐 — 32개의 에이전트입니다.`);

  // ───────────────────────── S7 아키텍처 (light)
  s = pres.addSlide();
  s.background = { color: "FFFFFF" };
  T(s, "7+1 레이어, 32개 에이전트의 분업", { x: 0.6, y: 0.4, w: 8.8, h: 0.5, fontSize: 24, bold: true, color: INK });
  T(s, "이벤트 큐로 통신하는 독립 에이전트 — 한 에이전트의 장애가 전체를 멈추지 않고, 레이어 단위로 확장합니다", { x: 0.62, y: 0.95, w: 8.8, h: 0.32, fontSize: 11.5, color: MUTED });
  const layers = [
    ["L0", "생성(선택)", "이전 사이클 recall 피드백 기반 적응형 트래픽 생성", 1, false],
    ["L1", "수집", "패킷 수신 · 정규화 · 특징 추출 · 컨텍스트 보강", 4, false],
    ["L2", "분석", "RF · LSTM · 규칙 · 행위 · 통계 · 시계열 · 프로토콜 · 플로우", 8, true],
    ["L3", "판정", "증거 통합 · 충돌 해소 · 신뢰도 산출 · 임계값 관리", 4, false],
    ["L4", "조율", "파이프라인 오케스트레이션 · 로드밸런싱 · 스케줄링", 4, false],
    ["L5", "출력", "심각도 분류 · 알림 생성 · 중복 제거 · 컨텍스트 보강", 4, false],
    ["L6", "학습", "피드백 수집 · 모델 갱신 · 드리프트 감지 · 성능 모니터", 4, false],
    ["L7", "평가", "지표 산출 · 오탐 분석 · 공격 커버리지 · 리포팅", 4, false],
  ];
  layers.forEach((L, i) => {
    const y = 1.36 + i * 0.475;
    const isL0 = i === 0;
    R(s, { x: 0.6, y, w: 8.8, h: 0.4, fill: { color: L[4] ? PURPLELT : CARD }, line: isL0 ? { color: "B9C4D2", width: 1, dashType: "dash" } : undefined });
    R(s, { x: 0.72, y: y + 0.06, w: 0.5, h: 0.28, fill: { color: isL0 ? MUTED : DARK2 } });
    T(s, L[0], { x: 0.72, y: y + 0.06, w: 0.5, h: 0.28, fontSize: 10.5, bold: true, color: "FFFFFF", align: "center", valign: "middle" });
    T(s, L[1], { x: 1.38, y, w: 1.1, h: 0.4, fontSize: 12.5, bold: true, color: INK, valign: "middle" });
    T(s, L[2], { x: 2.55, y, w: 4.7, h: 0.4, fontSize: 10.5, color: MUTED, valign: "middle" });
    const n = L[3];
    for (let k = 0; k < n; k++) {
      const sx = 9.28 - (n - k) * 0.215;
      R(s, { x: sx, y: y + 0.115, w: 0.17, h: 0.17, fill: { color: isL0 ? "B9C4D2" : (L[4] ? PURPLE : PURPLEBR) } });
    }
  });
  T(s, "상시 32개 + 선택형 생성 에이전트 1개  ·  실행: python3 run_pipeline.py --multi-agent", { x: 0.6, y: 5.22, w: 8.8, h: 0.28, fontSize: 10, color: MUTED });
  s.addNotes(
`[4:15–5:00 · 약 45초]

수집부터 평가까지 7개 레이어가 분업합니다. L1이 패킷을 받아 12차원 특징을 추출하고, L2에서는 랜덤 포레스트, LSTM, 규칙, 행위 분석 등 8개 에이전트가 병렬로 탐지합니다. L3가 증거를 통합해 판정하고, L5가 심각도를 매겨 알림을 만들고, L6가 드리프트를 감시하다 재학습을 트리거하고, L7이 전체 성능을 평가합니다.

핵심은 이들이 이벤트 큐로 통신하는 독립 에이전트라는 점입니다. 하나가 멈춰도 전체가 죽지 않고, 부하가 몰리는 레이어만 골라서 늘릴 수 있습니다.

(전환) 말보다 직접 보시는 게 빠르겠죠. 데모입니다.`);

  // ───────────────────────── S8 라이브 데모 (dark)
  s = pres.addSlide();
  s.background = { color: DARK };
  T(s, "라이브 데모 — 에이전트 그리드가 깨어나는 순간", { x: 0.6, y: 0.45, w: 8.8, h: 0.5, fontSize: 24, bold: true, color: "FFFFFF" });
  R(s, { x: 0.6, y: 1.3, w: 4.7, h: 3.45, fill: { color: DARK2 } });
  O(s, { x: 0.82, y: 1.48, w: 0.09, h: 0.09, fill: { color: CORALBR } });
  O(s, { x: 1.0, y: 1.48, w: 0.09, h: 0.09, fill: { color: "F0B429" } });
  O(s, { x: 1.18, y: 1.48, w: 0.09, h: 0.09, fill: { color: TEALBR } });
  const termLines = [
    [["$ ", TEALBR], ["python3 run_pipeline.py --multi-agent", ICE]],
    [["$ ", TEALBR], ["python3 run_gui.py", ICE]],
    [[" ", ICE2]],
    [["[L1] ", TEALBR], ["packet_receiver       ", ICE2], ["● active", TEALBR]],
    [["[L2] ", TEALBR], ["ml_classifier         ", ICE2], ["● active", TEALBR]],
    [["[L3] ", TEALBR], ["evidence_aggregator   ", ICE2], ["● active", TEALBR]],
    [["[L4] ", TEALBR], ["load_balancer         ", ICE2], ["● routing", TEALBR]],
    [["[L5] ", CORALBR], ["alert_generator       ", ICE2], ["▲ CRITICAL ×8", CORALBR]],
    [["[L6] ", PURPLEBR], ["drift_detector        ", ICE2], ["● watching", PURPLEBR]],
  ];
  termLines.forEach((parts, i) => {
    s.addText(parts.map(p => ({ text: p[0], options: { color: p[1] } })), { x: 0.88, y: 1.76 + i * 0.32, w: 4.25, h: 0.3, fontSize: 10.5, fontFace: MONO, margin: 0 });
  });
  const beats = [
    ["기동", "L1→L7 순서로 32개 에이전트가 점등 — 상태 그리드에서 레이어별 활성화 확인", TEAL],
    ["탐지", "스트림 100 플로우 중 16건 식별 — CRITICAL 8건 실시간 알림(실측값)", CORAL],
    ["적응", "recall 저하 감지 → 품질 게이트가 재학습 트리거, 모델 교체까지 자동", PURPLE],
  ];
  beats.forEach((b, i) => {
    const y = 1.3 + i * 1.13;
    numCircle(s, 5.72, y + 0.04, i + 1, b[2]);
    T(s, b[0], { x: 6.3, y: y, w: 3.1, h: 0.32, fontSize: 14, bold: true, color: "FFFFFF" });
    T(s, b[1], { x: 6.3, y: y + 0.36, w: 3.1, h: 0.62, fontSize: 11, color: ICE2, lineSpacingMultiple: 1.15 });
  });
  T(s, "라이브 환경 이슈 대비 — 동일 시나리오 사전 녹화 영상(1:30) 준비", { x: 0.6, y: 4.98, w: 8.8, h: 0.3, fontSize: 10.5, color: ICE2 });
  s.addNotes(
`[5:00–6:20 · 약 80초 — 라이브 데모]

(데모 전환: 터미널에서 python3 run_pipeline.py --multi-agent 실행 후 python3 run_gui.py)

멀티에이전트 모드로 파이프라인을 켜면, 대시보드의 에이전트 그리드가 L1부터 L7까지 순서대로 점등됩니다. — 여기까지가 기동.

스트림으로 100개 플로우를 흘리면 16건이 탐지되고, 그중 8건이 CRITICAL로 분류돼 알림이 올라옵니다. — 여기까지가 탐지.

마지막으로 recall 저하 상황을 주입하면, 드리프트 디텍터가 감지하고 품질 게이트가 재학습을 트리거해 모델이 교체되는 것까지 보실 수 있습니다. — 이게 적응입니다.

(주의) 라이브 환경 문제 시 사전 녹화 영상 1분 30초로 즉시 전환. 영상 파일은 발표 PC 바탕화면에 미리 준비할 것.

(전환) 데모에서 보신 성능, 숫자로 정리하면 이렇습니다.`);

  // ───────────────────────── S9 결과 (light)
  s = pres.addSlide();
  s.background = { color: "FFFFFF" };
  T(s, "합성 14종 공격과 CIC-IDS2018 실데이터 모두에서 검증", { x: 0.6, y: 0.42, w: 8.8, h: 0.5, fontSize: 24, bold: true, color: INK });
  s.addChart(pres.charts.BAR, [{
    name: "Recall",
    labels: ["Cred. Stuffing", "DNS Amplif.", "Cryptomining", "ARP Spoofing", "Ransomware", "Botnet C&C", "Slowloris", "HTTP Flood", "DNS Tunneling", "SYN Flood", "Exfiltration", "Brute Force", "Port Scan", "DDoS"],
    values: [1.0, 1.0, 0.9091, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0],
  }], {
    x: 0.55, y: 1.28, w: 5.45, h: 3.2, barDir: "bar",
    chartColors: [TEAL],
    chartArea: { fill: { color: "FFFFFF" } },
    catAxisLabelColor: MUTED, catAxisLabelFontSize: 8.5, catAxisLabelFontFace: "Helvetica Neue",
    valAxisLabelColor: MUTED, valAxisLabelFontSize: 8, valAxisLabelFontFace: "Helvetica Neue",
    valAxisMaxVal: 1.0, valAxisMinVal: 0,
    valGridLine: { color: "E8EDF2", size: 0.5 }, catGridLine: { style: "none" },
    showValue: true, dataLabelPosition: "inEnd", dataLabelColor: "FFFFFF", dataLabelFontSize: 7.5, dataLabelFontFace: "Helvetica Neue", dataLabelFormatCode: "0.00",
    showLegend: false, showTitle: false, barGapWidthPct: 45,
  });
  T(s, "공격 유형별 recall — 14종 중 13종 1.00, 최저 0.909 (합성 트래픽 · RF · F1 0.968)", { x: 0.55, y: 4.62, w: 5.45, h: 0.3, fontSize: 10, color: MUTED, align: "center" });
  const stats = [
    ["0.994", "CIC-IDS2018 6클래스 F1 (AUC 0.996) — 5개 모델 비교에서 부스팅 계열과 동급 최상위"],
    ["1/21", "BAT 적용 시 오탐률(FPR) 감소 — 0.042 → 0.002, 6조건 어블레이션 (하드 테스트셋)"],
    ["0.013 → 0.998", "캡처 데이 붕괴 후, 새 데이터 30% 재학습만으로 회복한 F1"],
  ];
  stats.forEach((st, i) => {
    const y = 1.28 + i * 1.27;
    R(s, { x: 6.15, y, w: 3.25, h: 1.12, fill: { color: CARD } });
    R(s, { x: 6.15, y, w: 0.07, h: 1.12, fill: { color: TEAL } });
    T(s, st[0], { x: 6.4, y: y + 0.1, w: 2.9, h: 0.42, fontSize: i === 2 ? 19 : 24, bold: true, color: TEAL });
    T(s, st[1], { x: 6.4, y: y + 0.54, w: 2.85, h: 0.52, fontSize: 9.5, color: MUTED, lineSpacingMultiple: 1.1 });
  });
  T(s, "모든 수치는 RF 단일 탐지기 기준 · scripts/ 의 실험 코드로 재현 가능 (어블레이션 · 유의성 검정 · 민감도 · 벤치마크)", { x: 0.6, y: 5.2, w: 8.8, h: 0.28, fontSize: 9.5, color: MUTED });
  s.addNotes(
`[6:20–7:05 · 약 45초]

왼쪽 — 합성 트래픽 14종 공격 중 13종에서 recall 1.0, 가장 낮은 크립토마이닝도 0.909입니다.

오른쪽 위 — 공개 벤치마크 CIC-IDS2018에서 F1 0.994, AUC 0.996. XGBoost 같은 부스팅 계열과 동급 최상위입니다. 가운데 — BAT의 효과, 오탐률 21분의 1. 아래 — 아까 보신 캡처 데이 회복력입니다.

이 수치들은 전부 저장소의 실험 스크립트로 재현됩니다.

(전환) 마지막으로, 처음에 약속드린 이야기입니다.`);

  // ───────────────────────── S10 개발 스토리 (light)
  s = pres.addSlide();
  s.background = { color: "FFFFFF" };
  T(s, "이 시스템 자체도, AI 에이전트와 함께 만들었습니다", { x: 0.6, y: 0.42, w: 8.8, h: 0.5, fontSize: 24, bold: true, color: INK });
  T(s, "시스템 안에서는 32개 에이전트가 협업하고 — 만드는 과정에서는 사람이 설계하고 AI 코딩 에이전트(Claude Code)가 구현을 가속했습니다", { x: 0.62, y: 1.0, w: 8.8, h: 0.32, fontSize: 11.5, color: MUTED });
  const flow = [
    ["요구 · 설계 정의", "사람", false],
    ["모듈 구현 위임", "AI 에이전트", true],
    ["검증 · 실험", "사람", false],
    ["반복 개선", "사람 + AI", true],
  ];
  flow.forEach((f, i) => {
    const x = 0.6 + i * 2.27;
    R(s, { x, y: 1.62, w: 1.98, h: 0.66, fill: { color: f[2] ? PURPLELT : CARD } });
    T(s, f[0], { x, y: 1.7, w: 1.98, h: 0.28, fontSize: 12, bold: true, color: INK, align: "center" });
    T(s, f[1], { x, y: 1.99, w: 1.98, h: 0.24, fontSize: 9.5, color: f[2] ? PURPLE : MUTED, align: "center" });
    if (i < 3) T(s, "→", { x: x + 1.98, y: 1.72, w: 0.29, h: 0.45, fontSize: 14, color: MUTED, align: "center" });
  });
  T(s, "AI 에이전트가 구현을 맡은 것들", { x: 0.6, y: 2.62, w: 5.0, h: 0.3, fontSize: 12.5, bold: true, color: PURPLE });
  const arts = [
    ["32개 에이전트 모듈", "7레이어 오케스트레이션 · 이벤트 큐 통신 · agents/ 모듈"],
    ["PyQt5 실시간 대시보드", "에이전트 상태 그리드 · 학습/탐지 패널 · 라이브 로그 뷰"],
    ["실험 · 검증 코드", "어블레이션 등 논문 실험 스크립트 8종 · pytest 테스트 스위트"],
  ];
  arts.forEach((a, i) => {
    const x = 0.6 + i * 2.97;
    R(s, { x, y: 3.0, w: 2.85, h: 1.32, fill: { color: CARD } });
    R(s, { x, y: 3.0, w: 0.07, h: 1.32, fill: { color: PURPLE } });
    T(s, a[0], { x: x + 0.22, y: 3.16, w: 2.5, h: 0.3, fontSize: 13, bold: true, color: INK });
    T(s, a[1], { x: x + 0.22, y: 3.52, w: 2.5, h: 0.66, fontSize: 10.5, color: MUTED, lineSpacingMultiple: 1.15 });
  });
  T(s, [
    { text: "사람의 몫 — ", options: { bold: true, color: INK } },
    { text: "연구 문제 정의 · BAT 알고리즘 설계 · 실험 설계와 결과 해석 · 최종 검증", options: { color: INK } },
  ], { x: 0.6, y: 4.55, w: 8.8, h: 0.32, fontSize: 11.5, fontFace: KR, margin: 0 });
  T(s, "“AI 에이전트로, AI 에이전트 시스템을 만들다” — 달라지는 건 속도가 아니라 실험의 횟수입니다", { x: 0.6, y: 4.95, w: 8.8, h: 0.32, fontSize: 11.5, color: MUTED });
  s.addNotes(
`[7:05–7:45 · 약 40초]

이 시스템 "안"에는 32개의 에이전트가 있지만, 이 시스템을 "만드는 과정"에도 AI 코딩 에이전트가 있었습니다.

제가 연구 문제와 BAT 알고리즘, 실험을 설계하고 — 32개 에이전트 모듈, 대시보드, 실험 코드 8종의 구현은 AI 코딩 에이전트(Claude Code)에 위임하고 — 결과를 검증해서 다시 요구로 되돌리는 사이클을 반복했습니다.

체감한 차이는 코딩 속도가 아니었습니다. 같은 기간에 시도해볼 수 있는 "실험의 횟수"가 달라졌습니다.

(전환) 정리하겠습니다.`);

  // ───────────────────────── S11 마무리 (dark)
  s = pres.addSlide();
  s.background = { color: DARK };
  T(s, "기억해 주실 세 가지", { x: 0.65, y: 0.55, w: 6.0, h: 0.55, fontSize: 26, bold: true, color: "FFFFFF" });
  const takes = [
    ["경계를 학습하면, 회피형에 강해진다", "BAT — 결정 경계 위 학습 샘플 생성, 오탐률 1/21", TEAL],
    ["탐지기는 모델이 아니라 운영 시스템", "품질 게이트 학습 루프 + 드리프트 감지 재학습", TEAL],
    ["AI 에이전트는 시스템 안에도, 과정에도", "32개 협업 에이전트 + AI 페어 개발", PURPLE],
  ];
  takes.forEach((t, i) => {
    const y = 1.55 + i * 1.05;
    numCircle(s, 0.68, y + 0.03, i + 1, t[2]);
    T(s, t[0], { x: 1.28, y: y, w: 5.3, h: 0.34, fontSize: 15, bold: true, color: "FFFFFF" });
    T(s, t[1], { x: 1.28, y: y + 0.39, w: 5.3, h: 0.3, fontSize: 11.5, color: ICE2 });
  });
  R(s, { x: 7.02, y: 1.42, w: 2.16, h: 2.16, fill: { color: "FFFFFF" } });
  s.addImage({ path: "/tmp/qr_repo.png", x: 7.1, y: 1.5, w: 2.0, h: 2.0 });
  T(s, "github.com/ypypk8jmg5-blip/", { x: 6.35, y: 3.74, w: 3.5, h: 0.22, fontSize: 8, color: ICE2, align: "center", fontFace: MONO });
  T(s, "cyber_attack_packet_abnormal_detection", { x: 6.35, y: 3.96, w: 3.5, h: 0.22, fontSize: 8, color: ICE2, align: "center", fontFace: MONO });
  agentGrid(s, 7.42, 4.55, 0.12, 0.155, { teal: [3, 12, 22, 27], coral: [9], purple: [6, 17, 30] });
  T(s, "감사합니다 — 데모 · 코드 · 실험 재현은 저장소에서 확인하실 수 있습니다", { x: 0.65, y: 4.95, w: 6.2, h: 0.32, fontSize: 12, color: ICE });
  s.addNotes(
`[7:45–8:10 · 약 25초]

세 가지만 기억해 주시면 됩니다.

경계를 학습하면 회피형에 강해진다. 탐지기는 모델이 아니라 운영 시스템이다. 그리고 AI 에이전트는 시스템 안에도, 만드는 과정에도 있다.

코드와 실험 전체는 QR의 저장소에 공개돼 있습니다. 감사합니다.

(Q&A 대비)
- 오탐률 1/21 근거: 6조건 어블레이션, 하드 테스트셋 (scripts/ablation_study.py)
- 데모 수치(100중 16건, CRITICAL 8): 2026-05-24 실측 런 (data/alerts/summary.json)
- CIC-IDS2018 클래스: 벤치마크는 6클래스, 캡처 데이 실험은 두 날짜 공통 4클래스
- 재학습 비용: 새 데이터 30%(9,708 플로우), RF 학습 1초 미만`);

  await pres.writeFile({ fileName: "/tmp/AdaptiveNIDS_발표자료_7min_v1.2.pptx" });
  console.log("done");
}

main().catch(e => { console.error(e); process.exit(1); });
