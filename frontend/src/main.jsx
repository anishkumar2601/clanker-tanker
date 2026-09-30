import React, { useMemo, useState } from 'react'
import { createRoot } from 'react-dom/client'
import {
  Activity,
  AlertTriangle,
  ArrowDown,
  ArrowUpRight,
  Bot,
  Check,
  ChevronRight,
  CircleHelp,
  Code2,
  Database,
  FileArchive,
  FileCode2,
  FolderGit2,
  Gauge,
  GitBranch,
  KeyRound,
  Layers3,
  LockKeyhole,
  Menu,
  Network,
  Play,
  RefreshCw,
  ScanSearch,
  Server,
  Shield,
  ShieldCheck,
  Sparkles,
  TerminalSquare,
  TestTube2,
  Upload,
  X,
  Zap,
} from './icons'
import './styles.css'

const API_BASE = import.meta.env.VITE_API_BASE || 'http://127.0.0.1:8000/api'

const severityMeta = {
  Critical: { color: 'critical', label: 'Critical', icon: AlertTriangle },
  High: { color: 'high', label: 'High', icon: AlertTriangle },
  Medium: { color: 'medium', label: 'Medium', icon: CircleHelp },
  Low: { color: 'low', label: 'Low', icon: CircleHelp },
}

async function api(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, options)
  const data = await response.json().catch(() => ({}))
  if (!response.ok) throw new Error(data.detail || 'The API request failed')
  return data
}

function App() {
  const [repo, setRepo] = useState(null)
  const [scan, setScan] = useState(null)
  const [verification, setVerification] = useState(null)
  const [selectedId, setSelectedId] = useState(null)
  const [structure, setStructure] = useState([])
  const [inventory, setInventory] = useState(null)
  const [graph, setGraph] = useState(null)
  const [securityDiff, setSecurityDiff] = useState(null)
  const [question, setQuestion] = useState('')
  const [questionBusy, setQuestionBusy] = useState(false)
  const [analystAnswer, setAnalystAnswer] = useState(null)
  const [findingAnalyses, setFindingAnalyses] = useState({})
  const [analysisBusy, setAnalysisBusy] = useState('')
  const [patch, setPatch] = useState(null)
  const [busy, setBusy] = useState('')
  const [toast, setToast] = useState(null)
  const [mobileNav, setMobileNav] = useState(false)

  const findings = scan?.findings || []
  const selected = findings.find((finding) => finding.id === selectedId) || findings[0]
  const score = scan?.score ?? 0
  const counts = scan?.counts || { Critical: 0, High: 0, Medium: 0, Low: 0 }

  const sortedFindings = useMemo(() => [...findings].sort((a, b) => {
    const order = { Critical: 0, High: 1, Medium: 2, Low: 3 }
    return order[a.severity] - order[b.severity] || b.confidence - a.confidence
  }), [findings])

  const notify = (kind, message) => {
    setToast({ kind, message })
    window.setTimeout(() => setToast(null), 4200)
  }

  const loadResult = async (data) => {
    setRepo(data.repository)
    setScan(data.scan)
    setVerification(null)
    setPatch(null)
    setSecurityDiff(null)
    setAnalystAnswer(null)
    setSelectedId(data.scan?.findings?.[0]?.id || null)
    setInventory(data.scan?.inventory || null)
    setGraph(data.scan?.graph || null)
    try {
      const tree = await api(`/repositories/${data.repository.id}/structure`)
      setStructure(tree.files || [])
    } catch {
      setStructure([])
    }
  }

  const runDemo = async () => {
    setBusy('demo')
    try {
      await loadResult(await api('/repositories/demo', { method: 'POST' }))
      notify('success', 'Demo repository loaded — the scanner found the seeded fixtures.')
    } catch (error) { notify('error', error.message) } finally { setBusy('') }
  }

  const uploadRepository = async (event) => {
    const file = event.target.files?.[0]
    if (!file) return
    setBusy('upload')
    const form = new FormData()
    form.append('file', file)
    try {
      await loadResult(await api('/repositories/upload', { method: 'POST', body: form }))
      notify('success', 'Repository uploaded and scanned successfully.')
    } catch (error) { notify('error', error.message) } finally {
      setBusy('')
      event.target.value = ''
    }
  }

  const rescan = async () => {
    if (!repo) return
    setBusy('scan')
    try {
      const data = await api(`/repositories/${repo.id}/scan`, { method: 'POST' })
      setScan(data.scan)
      setInventory(data.scan?.inventory || null)
      setGraph(data.scan?.graph || null)
      setVerification(null)
      setSecurityDiff(null)
      notify('success', `Rescan complete in ${data.scan.duration_ms} ms.`)
    } catch (error) { notify('error', error.message) } finally { setBusy('') }
  }

  const generateFix = async () => {
    if (!repo || !selected) return
    setBusy('fix')
    try {
      const data = await api(`/repositories/${repo.id}/findings/${selected.id}/fix`, { method: 'POST' })
      setPatch(data.patch)
      notify('success', 'A minimal patch is ready for review.')
    } catch (error) { notify('error', error.message) } finally { setBusy('') }
  }

  const applyFix = async () => {
    if (!repo || !patch) return
    setBusy('apply')
    try {
      await api(`/repositories/${repo.id}/patches/apply`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ patch_id: patch.id }),
      })
      setPatch({ ...patch, status: 'applied' })
      notify('success', 'Patch applied. Verify it against a fresh scan.')
    } catch (error) { notify('error', error.message) } finally { setBusy('') }
  }

  const verifyFix = async () => {
    if (!repo) return
    setBusy('verify')
    try {
      const data = await api(`/repositories/${repo.id}/verify`, { method: 'POST' })
      setVerification(data.verification)
      setScan(data.scan)
      setInventory(data.scan?.inventory || null)
      setGraph(data.scan?.graph || null)
      setSecurityDiff(data.scan?.security_diff || null)
      notify('success', `Verification complete — ${data.verification.fixed_count} finding(s) cleared.`)
    } catch (error) { notify('error', error.message) } finally { setBusy('') }
  }

  const askQuestion = async (prompt = question) => {
    if (!repo || !prompt.trim()) return
    setQuestionBusy(true)
    try {
      const data = await api(`/repositories/${repo.id}/questions`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ question: prompt.trim() }) })
      setAnalystAnswer(data)
      setQuestion('')
    } catch (error) { notify('error', error.message) } finally { setQuestionBusy(false) }
  }

  const analyzeFinding = async () => {
    if (!repo || !selected) return
    setAnalysisBusy(selected.id)
    try {
      const data = await api(`/repositories/${repo.id}/findings/${selected.id}/analyze`, { method: 'POST' })
      setFindingAnalyses((current) => ({ ...current, [selected.id]: data.analysis }))
      notify(data.analysis.status === 'completed' ? 'success' : 'error', data.analysis.message)
    } catch (error) { notify('error', error.message) } finally { setAnalysisBusy('') }
  }

  if (!repo) {
    return <Landing busy={busy} runDemo={runDemo} uploadRepository={uploadRepository} toast={toast} />
  }

  return (
    <div className="app-shell">
      <aside className={`sidebar ${mobileNav ? 'mobile-open' : ''}`}>
        <Brand onClose={() => setMobileNav(false)} />
        <div className="workspace-label">WORKSPACE</div>
        <div className="workspace-card">
          <div className="workspace-icon"><FolderGit2 size={16} /></div>
          <div className="workspace-copy"><strong>{repo.name}</strong><span>{repo.source === 'demo' ? 'Built-in demo' : 'ZIP upload'}</span></div>
          <span className="live-dot" />
        </div>
        <nav className="nav-list">
          <div className="nav-section">SECURITY CENTER</div>
          <button className="nav-item active"><Gauge size={17} /> Overview <span className="nav-count">{findings.length}</span></button>
          <button className="nav-item" onClick={() => document.getElementById('findings')?.scrollIntoView({ behavior: 'smooth' })}><ScanSearch size={17} /> Findings <span className="nav-count">{findings.length}</span></button>
          <button className="nav-item" onClick={() => document.getElementById('attack-map')?.scrollIntoView({ behavior: 'smooth' })}><Network size={17} /> Attack paths</button>
          <button className="nav-item" onClick={() => document.getElementById('verification')?.scrollIntoView({ behavior: 'smooth' })}><ShieldCheck size={17} /> Verification</button>
          <div className="nav-section">PROJECT</div>
          <button className="nav-item" onClick={() => document.getElementById('structure')?.scrollIntoView({ behavior: 'smooth' })}><Layers3 size={17} /> File structure</button>
          <button className="nav-item" onClick={rescan}><RefreshCw size={17} /> Re-run scan</button>
        </nav>
        <div className="sidebar-bottom">
          <div className="agent-card"><div className="agent-orb"><Bot size={17} /></div><div><strong>Security agent</strong><span>Pattern scanner online</span></div><span className="online-pill">ONLINE</span></div>
          <div className="team-lockup"><span>CLANKER CODE</span><small>Code fast. Ship safe.</small></div>
        </div>
      </aside>

      <main className="main-shell">
        <header className="topbar reference-topbar"><button className="mobile-menu" onClick={() => setMobileNav(true)}><Menu size={19} /></button><div className="topbar-brand"><Brand /></div><nav className="top-nav" aria-label="Primary navigation"><button className="active" onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}>Overview</button><button onClick={() => document.getElementById('threats')?.scrollIntoView({ behavior: 'smooth' })}>Threats <span>{findings.length}</span></button><button onClick={() => document.getElementById('attack-map')?.scrollIntoView({ behavior: 'smooth' })}>Network</button><button onClick={() => document.getElementById('findings')?.scrollIntoView({ behavior: 'smooth' })}>Vulnerabilities</button><button onClick={() => document.getElementById('ai-analysis')?.scrollIntoView({ behavior: 'smooth' })}>AI Analysis</button><button onClick={() => document.querySelector('.security-diff-panel')?.scrollIntoView({ behavior: 'smooth' })}>Reports</button></nav><div className="topbar-actions"><div className="system-status"><span className="status-dot green" /> Systems protected</div><button className="icon-button" title="Rescan" onClick={rescan}><RefreshCw size={17} className={busy === 'scan' ? 'spin' : ''} /></button><div className="avatar">CC</div></div></header>

        <div className="content-wrap">
          <section className="hero-row"><div><div className="eyebrow"><span className="eyebrow-line" /> THREAT INTELLIGENCE CONSOLE</div><h1>Security overview<span className="accent-dot">.</span></h1><p className="hero-sub">Your evidence-backed security analyst mapped {inventory?.files_analyzed || scan?.files_analyzed || 0} files{inventory?.frameworks?.length ? ` across ${inventory.frameworks.join(', ')}` : ''}, traced the highest-risk paths, and prioritized the fixes that matter.</p></div><div className="hero-actions"><label className="button secondary upload-button"><Upload size={16} /> Upload ZIP<input type="file" accept=".zip" onChange={uploadRepository} hidden /></label><button className="button primary" onClick={runDemo} disabled={busy === 'demo'}><Sparkles size={16} /> New demo scan</button></div></section>

          <ReferenceMetrics findings={findings} counts={counts} score={score} verification={verification} />
          <section className="reference-feature-grid"><FeaturedAI findings={findings} answer={analystAnswer} onAsk={askQuestion} /><FloatingThreatCard counts={counts} /></section>
          <ThreatActivity findings={sortedFindings} onSelectFinding={(id) => { setSelectedId(id); setPatch(null); document.getElementById('findings')?.scrollIntoView({ behavior: 'smooth' }) }} />
          <section className="reference-analysis-grid"><AIAnalysisPanel finding={selected} analysis={selected ? findingAnalyses[selected.id] : null} onInvestigate={() => document.getElementById('findings')?.scrollIntoView({ behavior: 'smooth' })} /><ScanProgress stages={scan?.stages || []} sources={scan?.scanner_sources || []} /></section>
          <NetworkTelemetry stages={scan?.stages || []} findings={findings} sources={scan?.scanner_sources || []} />

          <section className="content-grid">
            <div className="primary-column">
              <div className="section-heading" id="findings"><div><div className="eyebrow small"><span className="eyebrow-line" /> PRIORITIZED QUEUE</div><h2>Findings to review</h2></div><span className="result-count">{findings.length} detected <span>·</span> {scan?.duration_ms ?? 0}ms scan</span></div>
              <div className="finding-list">{sortedFindings.length ? sortedFindings.map((finding) => <FindingRow key={finding.id} finding={finding} selected={selected?.id === finding.id} onClick={() => { setSelectedId(finding.id); setPatch(null) }} />) : <EmptyState />}</div>
              <div className="signal-note"><Shield size={17} /><div><strong>Scanner evidence stays separate from agent reasoning.</strong><span>Findings above come from deterministic local rules. The agent layer explains evidence and proposes a minimal patch only when the code shape is understood.</span></div></div>
            </div>
            <aside className="detail-column">{selected ? <FindingDetail finding={selected} patch={patch} busy={busy} generateFix={generateFix} applyFix={applyFix} verifyFix={verifyFix} verification={verification} analysis={findingAnalyses[selected.id]} analyze={analyzeFinding} analysisBusy={analysisBusy === selected.id} /> : <EmptyDetail />}</aside>
          </section>

          <section className="lower-grid" id="attack-map"><AttackPath finding={selected} /><VerificationPanel verification={verification} onVerify={verifyFix} busy={busy} /></section>
          <section className="insight-grid"><RepositoryInventory inventory={inventory} /><SecurityGraph graph={graph} onSelectFinding={(id) => { setSelectedId(id); setPatch(null); document.getElementById('findings')?.scrollIntoView({ behavior: 'smooth' }) }} /></section>
          <SecurityDiffPanel diff={securityDiff} />
          <CommandBar question={question} setQuestion={setQuestion} onAsk={askQuestion} busy={questionBusy} answer={analystAnswer} />
          <section className="structure-panel" id="structure"><div className="section-heading"><div><div className="eyebrow small"><span className="eyebrow-line" /> PROJECT SURFACE</div><h2>Detected project structure</h2></div><span className="result-count">{scan?.files_analyzed || 0} files analyzed</span></div><div className="structure-content"><div className="language-strip">{Object.entries(scan?.languages || {}).map(([language, amount]) => <div className="language-item" key={language}><span className="language-dot" />{language}<strong>{amount}</strong></div>)}</div><div className="file-chips">{structure.slice(0, 8).map((file) => <span className="file-chip" key={file.path} title={`${file.language} · ${file.bytes} bytes`}><FileCode2 size={14} />{file.path}</span>)}</div></div></section>
          <footer className="footer"><span>CLANKERSHIELD <i>0.2 ANALYST</i></span><span>Evidence stays local and secrets are redacted <LockKeyhole size={13} /></span></footer>
        </div>
      </main>
      {toast && <div className={`toast ${toast.kind}`}><span>{toast.kind === 'success' ? <Check size={16} /> : <AlertTriangle size={16} />}</span>{toast.message}<button onClick={() => setToast(null)}><X size={14} /></button></div>}
    </div>
  )
}

function Brand({ onClose }) {
  return <div className="brand-row"><div className="brand-mark"><Shield size={19} strokeWidth={2.5} /></div><div className="brand-name">CLANKER<span>SHIELD</span></div><button className="close-mobile" onClick={onClose}><X size={17} /></button></div>
}

function Landing({ busy, runDemo, uploadRepository, toast }) {
  return <div className="landing"><div className="landing-grid" /><div className="landing-top"><Brand /><div className="landing-team">CLANKER CODE <span>AI SECURITY ENGINEERING</span></div></div><div className="landing-content"><div className="landing-badge"><span className="pulse" /> AI-POWERED THREAT INTELLIGENCE</div><h1>AI that sees threats.<br /><span>Before breaches.</span></h1><p>ClankerShield inventories your repository, detects risky code and secrets, traces the attack paths hiding inside it, and verifies every fix before you ship.</p><div className="landing-actions"><button className="button primary large" onClick={runDemo} disabled={!!busy}><Sparkles size={17} /> {busy === 'demo' ? 'Preparing demo…' : 'Start security scan'} <ArrowUpRight size={16} /></button><label className="button ghost large"><FileArchive size={17} /> Upload a repository ZIP<input type="file" accept=".zip" onChange={uploadRepository} hidden /></label></div><div className="landing-proof"><div><Check size={14} /> Deterministic scanner evidence</div><div><Check size={14} /> Human-readable attack paths</div><div><Check size={14} /> Fix, apply, rescan, verify</div></div></div><div className="landing-footer"><span>CLANKERSHIELD <i>by CLANKER CODE</i></span><span>Restricted to your uploaded repository <LockKeyhole size={13} /></span></div>{toast && <div className={`toast ${toast.kind}`}><span><AlertTriangle size={16} /></span>{toast.message}</div>}</div>
}

function ReferenceMetrics({ findings, counts, score, verification }) {
  const neutralized = verification?.fixed_count || 0
  const active = findings.length
  return <section className="reference-metrics"><ReferenceMetric label="THREATS DETECTED" value={findings.length} meta={`${counts.Critical + counts.High} high-priority signals`} tone="red" visual={<MiniBars tone="red" values={[22, 30, 26, 39, 34, 48, 42, 60, 52, 66, 58, 75]} />} /><ReferenceMetric label="THREATS NEUTRALIZED" value={neutralized} meta={verification ? 'Verified after rescan' : 'Apply a fix to begin'} tone="green" visual={<MiniDots tone="green" active={Math.max(3, neutralized)} />} /><ReferenceMetric label="ACTIVE VULNERABILITIES" value={active} meta={`${counts.Medium + counts.Low} lower-risk signals`} tone="yellow" visual={<MiniBars tone="yellow" values={[48, 38, 52, 42, 61, 45, 54, 68, 49, 58, 64, 53]} />} /><ReferenceMetric label="AI SECURITY SCORE" value={`${score}%`} meta="Evidence-backed posture score" tone="blue" visual={<MiniWave />} /></section>
}

function ReferenceMetric({ label, value, meta, tone, visual }) {
  return <article className={`reference-metric ${tone}`}><div className="reference-metric-head"><span>{label}</span><span className="metric-signal" /></div><strong>{value}</strong><div className="reference-metric-meta"><span>{meta}</span>{visual}</div></article>
}

function MiniBars({ values, tone }) {
  return <div className={`mini-bars ${tone}`}>{values.map((height, index) => <i key={index} style={{ height: `${height}%` }} />)}</div>
}

function MiniDots({ active, tone }) {
  return <div className={`mini-dots ${tone}`}>{Array.from({ length: 36 }, (_, index) => <i key={index} className={index >= 36 - Math.min(active, 18) ? 'active' : ''} />)}</div>
}

function MiniWave() {
  return <svg className="mini-wave" viewBox="0 0 180 42" preserveAspectRatio="none" aria-hidden="true"><path d="M0 31 C12 30 15 24 24 27 S36 37 47 29 S59 14 70 22 S83 35 94 28 S108 10 119 17 S132 33 143 23 S158 8 180 12" /></svg>
}

function FeaturedAI({ findings, answer, onAsk }) {
  const urgent = findings.filter((finding) => finding.severity === 'Critical' || finding.severity === 'High').length
  const message = answer?.answer || (urgent ? `${urgent} suspicious signal${urgent === 1 ? '' : 's'} require attention in this repository.` : 'Your repository is currently being monitored by ClankerShield AI.')
  return <article className="featured-ai"><div className="featured-ai-glow" /><div className="featured-ai-content"><div className="featured-kicker"><span className="ai-orb"><Sparkles size={15} /></span><span>AI SECURITY ANALYSIS</span><span className="featured-live"><span className="status-dot green" /> MONITORING</span></div><h2>Intelligence that turns signals into action.</h2><p>{message}</p><div className="featured-foot"><strong>{urgent}</strong><span>high-priority signals require attention</span><button className="featured-button" onClick={() => onAsk('What should I fix first?')}>View analysis <ArrowUpRight size={15} /></button></div></div></article>
}

function FloatingThreatCard({ counts }) {
  const critical = counts.Critical || 0
  const high = counts.High || 0
  return <article className="floating-threat-card"><div className="floating-threat-kicker">CRITICAL THREATS <span className="status-dot red" /></div><div className="floating-threat-value"><strong>{critical}</strong><div><span>{high} high-priority</span><small>in current scan</small></div></div><ThreatGrid count={critical} /></article>
}

function ThreatGrid({ count }) {
  const active = Math.min(12, Math.max(0, count * 2))
  return <div className="threat-grid">{Array.from({ length: 42 }, (_, index) => <i key={index} className={index >= 42 - active ? 'active' : ''} />)}</div>
}

function ThreatActivity({ findings, onSelectFinding }) {
  return <section className="threat-activity" id="threats"><div className="reference-section-head"><div><span className="reference-label">LIVE THREAT ACTIVITY</span><h2>Signals worth your attention</h2></div><span className="reference-count">{findings.length} evidence-backed events</span></div><div className="threat-card-grid">{findings.length ? findings.slice(0, 3).map((finding) => <ThreatEventCard key={finding.id} finding={finding} onClick={() => onSelectFinding(finding.id)} />) : <div className="reference-empty"><ShieldCheck size={19} /><span>No active findings in this scan.</span></div>}</div></section>
}

function ThreatEventCard({ finding, onClick }) {
  const meta = severityMeta[finding.severity] || severityMeta.Low
  const confidence = finding.analyst_confidence ? `${Math.round(finding.analyst_confidence * 100)}%` : `${Math.round((finding.confidence || 0) * 100)}%`
  const status = finding.severity === 'Critical' ? 'CRITICAL' : finding.severity === 'High' ? 'HIGH RISK' : finding.severity === 'Medium' ? 'SUSPICIOUS' : 'OBSERVE'
  return <button className={`threat-event-card ${meta.color}`} onClick={onClick}><div className="threat-event-top"><span className="threat-event-icon"><AlertTriangle size={15} /></span><span className={`threat-status ${meta.color}`}>{status}</span></div><h3>{finding.title}</h3><div className="threat-event-facts"><span><FileCode2 size={12} /> {finding.file}:{finding.line}</span><span><Activity size={12} /> {finding.sources?.[0] || finding.source}</span></div><div className="threat-event-bottom"><span>ANALYST CONFIDENCE <strong>{confidence}</strong></span><MiniBars tone={meta.color} values={[26, 34, 28, 48, 37, 55, 43, 61]} /></div></button>
}

function AIAnalysisPanel({ finding, analysis, onInvestigate }) {
  const risk = finding?.risk || {}
  const confidence = finding?.analyst_confidence ? `${Math.round(finding.analyst_confidence * 100)}%` : '—'
  const explanation = analysis?.analysis?.explanation || finding?.explanation || 'Select a finding to see evidence-backed analyst context.'
  return <article className="ai-analysis-panel" id="ai-analysis"><div className="ai-panel-head"><div><span className="reference-label">CLANKERSHIELD AI ANALYSIS</span><h2>{finding?.title || 'No finding selected'}</h2></div><span className="ai-panel-mark"><Sparkles size={16} /></span></div><p className="ai-analysis-copy">{explanation}</p><div className="ai-analysis-facts"><div><span>RISK</span><strong className={finding?.severity === 'Critical' || finding?.severity === 'High' ? 'risk-red' : 'risk-yellow'}>{risk.band || finding?.severity || '—'}</strong></div><div><span>CONFIDENCE</span><strong>{confidence}</strong></div><div><span>PATH NODES</span><strong>{finding?.attack_path_nodes?.length || 0}</strong></div></div><div className="ai-recommendation"><span>RECOMMENDED ACTION</span><p>{finding?.remediation || 'Run a scan to generate a precise remediation recommendation.'}</p></div><button className="button dark-action" onClick={onInvestigate}>Investigate finding <ArrowUpRight size={15} /></button></article>
}

function ScoreCard({ score, verification }) {
  const circumference = 2 * Math.PI * 45
  const offset = circumference - (score / 100) * circumference
  return <div className="score-card metric-card"><div className="metric-top"><span className="metric-label">OVERALL SECURITY SCORE</span><Gauge size={17} /></div><div className="score-body"><div className="score-ring"><svg viewBox="0 0 110 110"><circle className="ring-track" cx="55" cy="55" r="45" /><circle className="ring-value" cx="55" cy="55" r="45" strokeDasharray={circumference} strokeDashoffset={offset} /></svg><div className="score-number"><strong>{score}</strong><span>/ 100</span></div></div><div className="score-copy"><span className={score >= 75 ? 'score-good' : 'score-risk'}>{score >= 75 ? 'Good posture' : 'Needs attention'}</span><p>{verification ? `${verification.fixed_count} finding${verification.fixed_count === 1 ? '' : 's'} verified fixed.` : 'Resolve high-confidence findings to raise your score.'}</p></div></div></div>
}

function MetricCard({ icon: Icon, label, value, hint, tone }) {
  return <div className={`metric-card compact ${tone}`}><div className="metric-top"><span className="metric-label">{label.toUpperCase()}</span><div className="metric-icon"><Icon size={16} /></div></div><div className="metric-value">{value}</div><div className="metric-hint">{tone === 'success' && <Check size={13} />}{hint}</div></div>
}

function FindingRow({ finding, selected, onClick }) {
  const meta = severityMeta[finding.severity] || severityMeta.Low
  const Icon = meta.icon
  return <button className={`finding-row ${selected ? 'selected' : ''}`} onClick={onClick}><div className={`finding-severity ${meta.color}`}><Icon size={16} /></div><div className="finding-main"><div className="finding-title-line"><strong>{finding.title}</strong><span className={`severity-pill ${meta.color}`}>{meta.label}</span><span className="risk-chip">RISK {finding.risk_score ?? '—'}</span></div><div className="finding-meta"><span><FileCode2 size={13} />{finding.file}:{finding.line}</span><span><Activity size={13} />Scanner {Math.round((finding.confidence || 0) * 100)}%</span><span><Bot size={13} />Agent {Math.round((finding.analyst_confidence || 0) * 100)}%</span><span className="source-label">{(finding.sources || [finding.source]).join(' · ')}</span></div></div><ChevronRight size={17} className="finding-chevron" /></button>
}

function FindingDetail({ finding, patch, busy, generateFix, applyFix, verifyFix, verification, analysis, analyze, analysisBusy }) {
  const meta = severityMeta[finding.severity] || severityMeta.Low
  return <div className="detail-card"><div className="detail-kicker"><span className={`severity-pill ${meta.color}`}>{finding.severity}</span><span className="detail-source"><span className="tiny-dot" /> {finding.sources?.join(' · ') || finding.source}</span></div><h2>{finding.title}</h2><p className="detail-lede">{finding.explanation}</p><div className="detail-facts"><div><span>FILE</span><strong>{finding.file}</strong></div><div><span>LINE</span><strong>{finding.line}</strong></div><div><span>CWE</span><strong>{finding.cwe || '—'}</strong></div></div><RiskAssessment finding={finding} /><div className="code-block"><div className="code-head"><span><TerminalSquare size={14} /> REDACTED EVIDENCE</span><span className="code-lang">{finding.file.split('.').pop()?.toUpperCase()}</span></div><pre>{finding.snippet}</pre></div><div className="evidence-note"><ShieldCheck size={14} /><span>Evidence-backed conclusion: <strong>{finding.file}:{finding.line}</strong> is the source of this analysis. Secret-shaped values are redacted before display or AI handoff.</span></div><div className="ai-analysis-block"><div><span className="ai-analysis-label"><Sparkles size={13} /> CONTEXTUAL ANALYST</span>{analysis && <span className={`analysis-status ${analysis.status}`}>{analysis.status === 'completed' ? 'VALIDATED' : analysis.status.replace('_', ' ').toUpperCase()}</span>}</div>{analysis?.analysis ? <p>{analysis.analysis.explanation}</p> : <p className="analysis-muted">Ask the configured analyst to explain this finding using only the evidence above.</p>}<button className="button secondary" onClick={analyze} disabled={analysisBusy}>{analysisBusy ? <><RefreshCw size={14} className="spin" /> Analyzing evidence…</> : <><Sparkles size={14} /> Explain with analyst</>}</button></div><div className="detail-section"><div className="detail-section-title"><span className="section-icon"><Zap size={14} /></span><strong>Why it matters</strong></div><p>{finding.impact}</p></div><div className="detail-section"><div className="detail-section-title"><span className="section-icon"><ShieldCheck size={14} /></span><strong>Recommended remediation</strong></div><p>{finding.remediation}</p></div>{patch ? <PatchReview patch={patch} /> : <div className="detail-actions"><button className="button primary full" onClick={generateFix} disabled={busy === 'fix' || !finding.patch_available}>{busy === 'fix' ? <><RefreshCw size={15} className="spin" /> Generating patch…</> : <><Sparkles size={15} /> Generate safe fix</>}{!finding.patch_available && <span className="button-note">Guidance only</span>}</button></div>}{patch && <div className="detail-actions patch-actions"><button className="button secondary full" onClick={applyFix} disabled={busy === 'apply' || patch.status === 'applied'}>{patch.status === 'applied' ? <><Check size={15} /> Patch applied</> : busy === 'apply' ? 'Applying…' : <><Check size={15} /> Apply approved patch</>}</button><button className="button primary full" onClick={verifyFix} disabled={busy === 'verify' || patch.status !== 'applied'}>{busy === 'verify' ? <><RefreshCw size={15} className="spin" /> Rescanning…</> : <><ScanSearch size={15} /> Verify with rescan</>}</button></div>}{verification && <div className="mini-verification"><Check size={15} /><span><strong>{verification.fixed_count} fixed after rescan</strong><small>Security state compared before and after the approved patch.</small></span></div>}</div>
}

function RiskAssessment({ finding }) {
  const risk = finding.risk || {}
  return <div className="risk-assessment"><div className="risk-score"><span>DETERMINISTIC RISK</span><strong>{finding.risk_score ?? '—'}</strong><small>{risk.band || finding.severity}</small></div><div className="risk-factors"><div><span>EXPLOITABILITY</span><strong>{risk.exploitability || '—'}</strong></div><div><span>EXPOSURE</span><strong>{risk.external_exposure || '—'}</strong></div><div><span>EVIDENCE</span><strong>{risk.evidence_strength || '—'}</strong></div><div><span>AGENT CONFIDENCE</span><strong>{Math.round((finding.analyst_confidence || 0) * 100)}%</strong></div></div></div>
}

function CommandBar({ question, setQuestion, onAsk, busy, answer }) {
  const prompts = ['What should I fix first?', 'Why is the top finding risky?', 'Show me the most dangerous path']
  return <section className="command-bar"><div className="command-icon"><Sparkles size={17} /></div><div className="command-body"><div className="command-label">CONTEXTUAL SECURITY ANALYST</div><form onSubmit={(event) => { event.preventDefault(); onAsk() }}><input value={question} onChange={(event) => setQuestion(event.target.value)} placeholder="What would you like to investigate?" aria-label="Ask the contextual security analyst" /><button className="command-submit" disabled={busy || !question.trim()}>{busy ? <RefreshCw size={15} className="spin" /> : <ArrowUpRight size={16} />}</button></form><div className="prompt-row">{prompts.map((prompt) => <button key={prompt} onClick={() => { setQuestion(prompt); onAsk(prompt) }}>{prompt}</button>)}</div>{answer && <div className="command-answer"><div><span className={`answer-status ${answer.status}`}>{answer.status === 'completed' ? 'MODEL ANALYSIS' : 'LOCAL EVIDENCE'}</span><span>{answer.provider?.message}</span></div><p>{answer.answer}</p>{answer.evidence_refs?.length ? <small>Evidence: {answer.evidence_refs.map((reference) => `${reference.file}:${reference.line}`).join(' · ')}</small> : null}</div>}</div></section>
}

function PatchReview({ patch }) {
  return <div className="patch-review"><div className="patch-head"><span><GitBranch size={14} /> GENERATED PATCH</span><span className="draft-pill">{patch.status === 'applied' ? 'APPLIED' : 'DRAFT'}</span></div><p>{patch.explanation}</p><pre className="diff-block">{patch.diff}</pre></div>
}

function AttackPath({ finding }) {
  const path = finding?.attack_path_nodes || []
  return <div className="panel attack-panel"><div className="panel-heading"><div><div className="eyebrow small"><span className="eyebrow-line" /> DATA FLOW</div><h2>Attack path</h2></div><Network size={18} /></div>{path.length ? <div className="path-flow">{path.map((node, index) => <React.Fragment key={node.id}><div className={`path-node ${node.kind === 'sink' ? 'danger' : ''}`}><span className="path-node-icon">{index === 0 ? <Server size={15} /> : node.kind === 'sink' ? <Database size={15} /> : <Code2 size={15} />}</span><span>{node.label}</span>{node.location && <small>{node.location.file}:{node.location.line}</small>}{node.kind === 'sink' && <em>risk</em>}</div>{index < path.length - 1 && <ArrowDown size={15} className="path-arrow" />}</React.Fragment>)}</div> : <div className="unknown-path"><CircleHelp size={18} /><p>The scanner does not have enough evidence to reliably infer a data flow for this finding.</p></div>}</div>
}

function VerificationPanel({ verification, onVerify, busy }) {
  return <div className="panel verification-panel" id="verification"><div className="panel-heading"><div><div className="eyebrow small"><span className="eyebrow-line" /> CONTROLLED VERIFICATION</div><h2>Before / after</h2></div><TestTube2 size={18} /></div>{verification ? <><div className="compare-row"><div><span>BEFORE</span><strong>{verification.before_count}</strong><small>findings</small></div><ArrowUpRight size={19} className="compare-arrow" /><div className="after-value"><span>AFTER</span><strong>{verification.after_count}</strong><small>findings</small></div><div className="fixed-value"><span>FIXED</span><strong>{verification.fixed_count}</strong><small>verified</small></div></div><div className="verification-lines"><div><span><span className="status-dot green" /> Security rescan</span><strong className="text-green">{verification.security_rescan}</strong></div><div><span><span className={`status-dot ${verification.syntax_status === 'PASS' ? 'green' : 'red'}`} /> Static checks</span><strong className={verification.syntax_status === 'PASS' ? 'text-green' : 'text-red'}>{verification.syntax_status}</strong></div><div><span><span className="status-dot yellow" /> Runtime tests</span><strong className="text-yellow">{verification.test_status}</strong></div></div><p className="verification-note">Runtime tests stay disabled for uploaded repositories. Static syntax checks and the security rescan are real results from this workspace.</p></> : <div className="verify-empty"><div className="verify-icon"><ShieldCheck size={22} /></div><strong>Verify an approved fix</strong><p>Apply a generated patch, then rescan the repository to prove whether the finding disappeared.</p><button className="button secondary" onClick={onVerify} disabled={!!busy}><ScanSearch size={15} /> Run verification</button></div>}</div>
}

function ScanProgress({ stages, sources }) {
  const hasWarning = stages.some((stage) => stage.status === 'warning' || stage.status === 'not_configured')
  return <section className="scan-progress"><div className="scan-progress-heading"><div><div className="eyebrow small"><span className="eyebrow-line" /> ANALYSIS PIPELINE</div><h2>Scan stages</h2></div><span className={`pipeline-state ${hasWarning ? 'warning-state' : ''}`}><span className={`status-dot ${hasWarning ? 'yellow' : 'green'}`} /> {hasWarning ? 'Optional tools need attention' : 'All local stages complete'}</span></div><div className="stage-list">{stages.map((stage) => <div className={`stage-item ${stage.status === 'warning' || stage.status === 'not_configured' ? 'stage-warning' : ''}`} key={stage.id}><span className="stage-check">{stage.status === 'warning' || stage.status === 'not_configured' ? <CircleHelp size={12} /> : <Check size={12} />}</span><div><strong>{stage.label}</strong><small>{stage.detail} · {stage.duration_ms}ms</small></div></div>)}</div><div className="scanner-sources"><span>TRUTH SOURCES</span>{sources.map((source) => <span className="source-chip" key={source}>{source}</span>)}</div></section>
}

function NetworkTelemetry({ stages, findings, sources }) {
  const signalStages = stages.length ? stages.slice(0, 8) : [{ id: 'local', label: 'Local scan', detail: 'Awaiting scan', duration_ms: 0 }]
  const maxDuration = Math.max(...signalStages.map((stage) => stage.duration_ms || 0), 1)
  return <section className="telemetry-panel"><div className="telemetry-heading"><div><div className="eyebrow small"><span className="eyebrow-line" /> LOCAL SCAN TELEMETRY</div><h2>Threat signal activity</h2></div><span className="telemetry-live"><span className="live-dot" /> STREAMING RESULTS</span></div><div className="telemetry-layout"><div className="telemetry-summary"><div><strong>{findings.length}</strong><span>signals surfaced</span></div><div><strong>{stages.length}</strong><span>analysis stages</span></div><div><strong>{sources.length || 1}</strong><span>truth sources</span></div><p>Scan-local activity derived from this repository run. No live network traffic is simulated.</p></div><div className="telemetry-bars">{signalStages.map((stage, index) => <div className="telemetry-row" key={stage.id || index}><span>{stage.label}</span><div className="telemetry-track"><i style={{ width: `${Math.max(12, ((stage.duration_ms || 0) / maxDuration) * 100)}%` }} /></div><small>{stage.duration_ms || 0}ms</small></div>)}</div></div></section>
}

function RepositoryInventory({ inventory }) {
  const list = (values, empty = 'None detected') => values?.length ? values.slice(0, 5).map((value) => <span key={typeof value === 'string' ? value : value.name} className="inventory-tag">{typeof value === 'string' ? value : `${value.name} ${value.version}`}</span>) : <span className="inventory-empty">{empty}</span>
  return <div className="panel inventory-panel"><div className="panel-heading"><div><div className="eyebrow small"><span className="eyebrow-line" /> REPOSITORY INVENTORY</div><h2>What was mapped</h2></div><Layers3 size={18} /></div><div className="inventory-stats"><div><strong>{inventory?.files_analyzed || 0}</strong><span>files</span></div><div><strong>{inventory?.api_routes?.length || 0}</strong><span>routes</span></div><div><strong>{inventory?.dependencies?.length || 0}</strong><span>dependencies</span></div><div><strong>{inventory?.sensitive_files?.length || 0}</strong><span>sensitive</span></div></div><div className="inventory-groups"><div><span>FRAMEWORKS</span><div>{list(inventory?.frameworks)}</div></div><div><span>PACKAGE MANAGERS</span><div>{list(inventory?.package_managers)}</div></div><div><span>ENTRY POINTS</span><div>{list(inventory?.entry_points)}</div></div><div><span>AUTH / DATA FILES</span><div>{list([...(inventory?.authentication_files || []), ...(inventory?.database_files || [])])}</div></div></div></div>
}

function SecurityGraph({ graph, onSelectFinding }) {
  const nodes = graph?.nodes || []
  return <div className="panel graph-panel"><div className="panel-heading"><div><div className="eyebrow small"><span className="eyebrow-line" /> REPOSITORY SECURITY GRAPH</div><h2>Control and data map</h2></div><Network size={18} /></div>{nodes.length ? <><div className="graph-canvas">{nodes.slice(0, 9).map((node) => <button className={`graph-node ${node.kind} ${node.finding_ids?.length ? 'clickable' : ''}`} key={node.id} onClick={() => node.finding_ids?.[0] && onSelectFinding(node.finding_ids[0])}><span className="graph-node-dot" /><strong>{node.label}</strong><small>{node.detail || node.kind}</small></button>)}</div><div className="graph-legend"><span><i className="route" /> route</span><span><i className="finding" /> finding</span><span><i className="database" /> system</span><span>{graph.edges?.length || 0} relationships</span></div></> : <div className="unknown-path"><CircleHelp size={18} /><p>No graph edges were inferred from the current inventory.</p></div>}</div>
}

function SecurityDiffPanel({ diff }) {
  const resolved = diff?.resolved || []
  const remaining = diff?.remaining || []
  return <section className="security-diff-panel"><div className="section-heading"><div><div className="eyebrow small"><span className="eyebrow-line" /> REMEDIATION OUTCOME</div><h2>Security diff</h2></div>{diff ? <span className="result-count">Compared after a real rescan</span> : <span className="result-count">Apply a patch to generate this view</span>}</div>{diff ? <><div className="diff-summary"><div><span>BEFORE</span><strong>{diff.before.total}</strong><small>{diff.before.score}/100 score</small></div><ArrowUpRight size={19} className="compare-arrow" /><div className="after-value"><span>AFTER</span><strong>{diff.after.total}</strong><small>{diff.after.score}/100 score</small></div><div className="fixed-value"><span>RESOLVED</span><strong>{resolved.length}</strong><small>verified findings</small></div></div><div className="diff-columns"><div><h3><Check size={14} /> Resolved</h3>{resolved.length ? resolved.slice(0, 6).map((finding) => <div className="diff-finding resolved" key={finding.id}><span>{finding.title}</span><small>{finding.file}:{finding.line}</small></div>) : <p className="inventory-empty">No findings were cleared.</p>}</div><div><h3><AlertTriangle size={14} /> Remaining</h3>{remaining.length ? remaining.slice(0, 6).map((finding) => <div className="diff-finding remaining" key={finding.id}><span>{finding.title}</span><small>{finding.file}:{finding.line}</small></div>) : <p className="inventory-empty">No findings remain.</p>}</div></div></> : <div className="diff-empty"><GitBranch size={21} /><strong>Make verification visible</strong><p>Once a user-approved patch is rescanned, ClankerShield will show exactly what disappeared and what remains.</p></div>}</section>
}

function EmptyState() { return <div className="empty-state"><ShieldCheck size={22} /><strong>Surface is clear</strong><span>No findings were returned by the current scan.</span></div> }
function EmptyDetail() { return <div className="detail-card empty-detail"><Bot size={24} /><h2>Select a finding</h2><p>Choose a finding to inspect evidence, understand the risk, and review a minimal remediation patch.</p></div> }

createRoot(document.getElementById('root')).render(<App />)
