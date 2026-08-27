import { useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  Check,
  ChevronRight,
  Clipboard,
  FileSearch,
  Inbox,
  LockKeyhole,
  Mail,
  Network,
  Paperclip,
  Radar,
  Search,
  ShieldCheck,
  Upload,
  XCircle,
} from "lucide-react";

type AnyRecord = Record<string, any>;
type Analysis = AnyRecord;

const cx = (...names: Array<string | false | undefined>) =>
  names.filter(Boolean).join(" ");
const levelClass = (value = "") =>
  value.toLowerCase() === "high" || value.toLowerCase() === "critical"
    ? "high"
    : value.toLowerCase() === "medium"
      ? "medium"
      : value.toLowerCase() === "pass"
        ? "pass"
        : "low";

function Badge({
  children,
  tone = "muted",
}: {
  children: React.ReactNode;
  tone?: string;
}) {
  return <span className={cx("badge", tone)}>{children}</span>;
}
function Glass({
  children,
  className = "",
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return <section className={cx("glass", className)}>{children}</section>;
}
function SectionTitle({
  eyebrow,
  title,
  count,
}: {
  eyebrow?: string;
  title: string;
  count?: string;
}) {
  return (
    <div className="section-title">
      <div>
        <span className="micro">{eyebrow}</span>
        <h2>{title}</h2>
      </div>
      {count && <Badge>{count}</Badge>}
    </div>
  );
}

function Header({ onReset }: { onReset?: () => void }) {
  return (
    <header className="app-header">
      <button
        className="wordmark"
        onClick={onReset}
        aria-label="MailForensics home"
      >
        <img className="brand-mark" src="/mailforensics-mark.svg" alt="" />
        <span>
          Mail<span>Forensics</span>
        </span>
      </button>
      <nav>
        <a className="selected">Investigation</a>
        <a>Methodology</a>
        <a>Privacy</a>
      </nav>
      <div className="header-status">
        <i /> system operational
      </div>
    </header>
  );
}

function Uploader({
  onAnalyze,
  loading,
}: {
  onAnalyze: (file: File) => void;
  loading: boolean;
}) {
  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  const choose = (candidate?: File) => {
    if (candidate?.name.toLowerCase().endsWith(".eml")) setFile(candidate);
  };
  return (
    <div className="uploader-wrap">
      <Glass className={cx("upload-panel", dragging && "is-dragging")}>
        <div className="upload-grid" />
        <div
          className="upload-content"
          onDragEnter={() => setDragging(true)}
          onDragLeave={() => setDragging(false)}
          onDragOver={(e) => e.preventDefault()}
          onDrop={(e) => {
            e.preventDefault();
            setDragging(false);
            choose(e.dataTransfer.files[0]);
          }}
          onClick={() => input.current?.click()}
        >
          <input
            ref={input}
            hidden
            type="file"
            accept=".eml"
            onChange={(e) => choose(e.target.files?.[0])}
          />
          <span className="upload-symbol">
            <Mail size={23} />
          </span>
          <span className="micro">EVIDENCE INTAKE</span>
          <h2>{file ? file.name : "Drop your .eml file here"}</h2>
          <p>
            {file
              ? `${(file.size / 1024).toFixed(1)} KB · Ready to trace`
              : "or choose a message from your device"}
          </p>
          <button
            className="outline-button"
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              input.current?.click();
            }}
          >
            <Upload size={15} /> Choose file
          </button>
        </div>
        <div className="upload-foot">
          <span>
            <LockKeyhole size={13} /> Secure analysis
          </span>
          <span>Nothing retained after session</span>
        </div>
      </Glass>
      {file && (
        <button
          className="primary-button analyze-button"
          disabled={loading}
          onClick={() => onAnalyze(file)}
        >
          {loading ? "Tracing message" : "Analyze Email"}
          <ArrowUpRight size={17} />
        </button>
      )}
    </div>
  );
}

const investigationSteps = [
  "Parsing email",
  "Extracting headers",
  "Reconstructing mail flow",
  "Verifying authentication",
  "Inspecting URLs",
  "Calculating risk",
];
function Investigation({ fileName }: { fileName?: string }) {
  const [step] = useState(() => Math.floor(Math.random() * 2) + 2);
  return (
    <main className="investigation-screen">
      <div className="investigation-heading">
        <span className="micro">
          <Activity size={14} /> LIVE FORENSIC TRACE
        </span>
        <h1>
          Mail flow
          <br />
          <em>investigation</em>
        </h1>
        <p>
          {fileName || "Evidence sample"} is moving through the analysis engine.
        </p>
      </div>
      <div className="trace-layout">
        <div className="trace-map">
          <div className="trace-orbit orbit-one" />
          <div className="trace-orbit orbit-two" />
          <div className="trace-beam" />
          {["Sender", "Mail server", "Auth", "Recipient"].map((label, i) => (
            <div
              className={cx("trace-node", i <= step ? "active" : "")}
              style={{ "--i": i } as React.CSSProperties}
              key={label}
            >
              <span>
                {i === 0 ? (
                  <Mail size={16} />
                ) : i === 3 ? (
                  <Inbox size={16} />
                ) : (
                  <Network size={16} />
                )}
              </span>
              <small>{label}</small>
            </div>
          ))}
        </div>
        <Glass className="step-panel">
          <div className="step-top">
            <span className="micro">ANALYSIS PIPELINE</span>
            <span className="trace-live">
              <i /> live
            </span>
          </div>
          {investigationSteps.map((item, i) => (
            <div
              className={cx(
                "trace-step",
                i < step ? "done" : i === step ? "current" : "",
              )}
              key={item}
            >
              <span>
                {i < step ? (
                  <Check size={13} />
                ) : i === step ? (
                  <i />
                ) : (
                  <b>0{i + 1}</b>
                )}
              </span>
              <label>{item}</label>
              {i === step && <small>in progress</small>}
            </div>
          ))}
        </Glass>
      </div>
    </main>
  );
}

function Score({ value }: { value: number }) {
  return (
    <div className="score">
      <div
        className="score-ring"
        style={
          {
            "--score": `${Math.min(value, 100) * 3.6}deg`,
          } as React.CSSProperties
        }
      >
        <div>
          <strong>{value}</strong>
          <span>/100</span>
        </div>
      </div>
      <Badge tone={value > 70 ? "high" : "medium"}>
        {value > 70 ? "HIGH RISK" : "REVIEW"}
      </Badge>
    </div>
  );
}
function Finding({ finding }: { finding: AnyRecord }) {
  const [open, setOpen] = useState(false);
  return (
    <button
      className={cx("finding-row", open && "open")}
      onClick={() => setOpen(!open)}
    >
      <span className={cx("finding-level", levelClass(finding.severity))}>
        {finding.severity}
      </span>
      <span className="finding-icon">
        <AlertTriangle size={15} />
      </span>
      <span className="finding-copy">
        <b>{finding.title}</b>
        <small>{finding.description}</small>
        {open && (
          <span className="finding-detail">
            <em>
              <strong>Evidence</strong>
              {finding.evidence || "No direct evidence recorded."}
            </em>
            <em>
              <strong>Why it matters</strong>
              {finding.why_it_matters || finding.description}
            </em>
            <em>
              <strong>Recommended action</strong>
              {finding.recommendation ||
                "Validate this signal against the original message."}
            </em>
          </span>
        )}
      </span>
      <ChevronRight size={16} className="chevron" />
    </button>
  );
}
function MailFlow({ analysis }: { analysis: Analysis }) {
  const hops = analysis.received_chain || [];
  const observed = hops.map((hop: AnyRecord) => ({
    host: hop.to_host || hop.from_host || "Observed relay",
    detail:
      [hop.ip, hop.protocol, hop.tls ? "TLS" : ""]
        .filter(Boolean)
        .join(" · ") || "SMTP hop",
  }));
  const stages = [
    {
      label: "Sender",
      role: "Origin",
      detail: analysis.email_metadata?.sender_domain || "Visible From domain",
      icon: <Mail size={15} />,
    },
    {
      label: "MTA",
      role: "Mail Transfer Agent",
      detail: observed[0]?.host || "Inferred from transport",
      icon: <Network size={15} />,
    },
    {
      label: "SMTP relay",
      role: "Message transport",
      detail: observed[1]?.host || "Observed Received hop",
      icon: <Network size={15} />,
    },
    {
      label: "Authentication",
      role: "SPF · DKIM · DMARC",
      detail:
        Object.entries(analysis.authentication || {})
          .map(
            ([key, value]: [string, any]) =>
              `${key.toUpperCase()}: ${value.status}`,
          )
          .join(" · ") || "No results parsed",
      icon: <ShieldCheck size={15} />,
    },
    {
      label: "MRA",
      role: "Mail Receiving Agent",
      detail: observed[observed.length - 1]?.host || "Recipient-side handoff",
      icon: <Inbox size={15} />,
    },
    {
      label: "Recipient",
      role: "Destination",
      detail: analysis.email_metadata?.recipient || "Mailbox destination",
      icon: <Inbox size={15} />,
    },
  ];
  return (
    <Glass className="flow-panel">
      <SectionTitle
        eyebrow="SMTP PATH RECONSTRUCTION"
        title="Mail transfer flow"
        count={`${hops.length} parsed hops · ${stages.length} system stages`}
      />
      <div className="flow-track">
        {stages.map((stage: AnyRecord, i: number) => (
          <div
            className={cx(
              "flow-stop",
              i === 0 && "origin-stop",
              i === stages.length - 1 && "destination-stop",
            )}
            key={stage.label}
          >
            <span
              className={cx(
                i === 0 && "origin",
                i === stages.length - 1 && "destination",
              )}
            >
              {stage.icon}
            </span>
            <small>{stage.role}</small>
            <b title={stage.detail}>{stage.label}</b>
            <p title={stage.detail}>{stage.detail}</p>
            {i < stages.length - 1 && <i />}
          </div>
        ))}
      </div>
      <div className="flow-legend">
        <span>
          <i className="legend-parsed" /> Parsed from headers
        </span>
        <span>
          <i className="legend-inferred" /> System role inferred from message
          path
        </span>
      </div>
      <p className="muted-note">
        {hops.length
          ? "SMTP transport reconstructed chronologically from Received headers. MTA and MRA roles are mapped to the nearest observed handoff."
          : "No Received headers were available for independent path reconstruction; system roles are inferred only."}
      </p>
    </Glass>
  );
}
function Overview({
  analysis,
  onTab,
}: {
  analysis: Analysis;
  onTab: (tab: string) => void;
}) {
  const findings = analysis.findings || [];
  const senderDomain =
    analysis.domains?.find(
      (domain: AnyRecord) =>
        domain.domain === analysis.email_metadata?.sender_domain,
    ) || {};
  const senderDomainName = analysis.email_metadata?.sender_domain || "";
  const hasSenderDomain = /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(senderDomainName);
  const whoisUrl = hasSenderDomain
    ? `https://www.whois.com/whois/${encodeURIComponent(senderDomainName)}`
    : "#";
  const authenticationCheckUrl = hasSenderDomain
    ? `https://dmarcian.com/domain-checker/?domain=${encodeURIComponent(senderDomainName)}`
    : "#";
  const whois = senderDomain.whois?.response?.data || {};
  return (
    <>
      <div className="result-hero">
        <div className="result-intro">
          <span className="micro">
            INVESTIGATION COMPLETE ·{" "}
            {analysis.email_metadata?.filename || "EMAIL SAMPLE"}
          </span>
          <h1>{analysis.classification || "UNKNOWN"}</h1>
          <div className="message-type"><span>MESSAGE TYPE</span><b>{analysis.message_category?.label || "Uncategorized email"}</b><small>{analysis.message_category?.confidence || "low"} confidence · {analysis.message_category?.evidence || "No category evidence"}</small></div>
          <p>
            {analysis.verdict_explanation ||
              "Analysis completed with no additional explanation."}
          </p>
          <div className="subject-line">
            <Mail size={15} />
            <span>
              {analysis.email_metadata?.subject || "Untitled message"}
            </span>
          </div>
          <div className="meta-line">
            <span>{analysis.email_metadata?.sender}</span>
            <ArrowUpRight size={12} />
            <span>{analysis.email_metadata?.recipient}</span>
          </div>
        </div>
        <Glass className="verdict-panel">
          <span className="micro">COMPOSITE RISK</span>
          <Score value={analysis.risk_score || 0} />
          <p>
            Calculated across authentication, infrastructure, URLs, content, and
            observed indicators.
          </p>
        </Glass>
      </div>
      <div className="finding-section">
        <SectionTitle
          eyebrow="SIGNAL REVIEW"
          title="Key findings"
          count={`${findings.length} signals`}
        />
        <div className="finding-list">
          {findings.slice(0, 5).map((finding: AnyRecord, i: number) => (
            <Finding finding={finding} key={i} />
          ))}
        </div>
        {!findings.length && (
          <Glass className="empty-state">
            <Check size={17} /> No suspicious signals detected in local
            analysis.
          </Glass>
        )}
      </div>
      <MailFlow analysis={analysis} />
      <div className="overview-grid">
        <Glass>
          <SectionTitle eyebrow="AUTHENTICATION" title="Trust signals" />
          <div className="auth-list">
            {Object.entries(analysis.authentication || {}).map(
              ([key, value]: [string, any]) => (
                <div className="auth-row" key={key}>
                  <span>{key.toUpperCase()}</span>
                  <Badge tone={levelClass(value.status)}>{value.status}</Badge>
                  <small>
                    {value.signing_domain ||
                      value.record ||
                      value.policy ||
                      "No chain found"}
                  </small>
                </div>
              ),
            )}
          </div>
          <div className="auth-check-links">
            {hasSenderDomain ? (
              <>
                <a
                  className="link-button external-check-link"
                  href={authenticationCheckUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  title={`Check SPF, DKIM, and DMARC for ${senderDomainName} with dmarcian`}
                >
                  <img className="provider-logo" src="https://www.google.com/s2/favicons?domain=dmarcian.com&sz=32" alt="dmarcian logo" />
                  dmarcian <ArrowUpRight size={14} />
                </a>
              </>
            ) : (
              <span className="link-button link-disabled">Authentication lookup unavailable</span>
            )}
          </div>
        </Glass>
        <Glass className="sender-domain-card">
          <SectionTitle eyebrow="SENDER INTELLIGENCE" title="Sender domain" />
          <div className="domain-hero">
            <b>{analysis.email_metadata?.sender_domain || "Unknown domain"}</b>
            <Badge
              tone={
                senderDomain.reputation?.toLowerCase().includes("unknown")
                  ? "medium"
                  : "pass"
              }
            >
              {senderDomain.reputation || "No reputation data"}
            </Badge>
          </div>
          <div className="domain-facts">
            <div>
              <span>Role</span>
              <b>{senderDomain.role || "Sender"}</b>
            </div>
            <div>
              <span>Created date</span>
              <b>{whois.creation_date || senderDomain.age || "Unknown"}</b>
            </div>
            <div>
              <span>Registrar</span>
              <b>{whois.registrar || "Unknown"}</b>
            </div>
            <div>
              <span>Expiry date</span>
              <b>{whois.expiration_date || "Unknown"}</b>
            </div>
            <div>
              <span>Registrant</span>
              <b>{whois.registrant || "Redacted / unavailable"}</b>
            </div>
            <div>
              <span>Nameservers</span>
              <b>{whois.name_servers?.join(" · ") || "Unknown"}</b>
            </div>
            <div>
              <span>Domain status</span>
              <b>
                {Array.isArray(whois.status)
                  ? whois.status[0]
                  : whois.status || "Unknown"}
              </b>
            </div>
            <div>
              <span>Last updated</span>
              <b>{whois.updated_date || "Unknown"}</b>
            </div>
          </div>
          <div className="relationship-verdict">
            <span>Reply-To relationship</span>
            <b>{analysis.domain_relationship?.verdict?.replaceAll("_", " ") || "NOT ASSESSED"}</b>
            <small>{analysis.domain_relationship?.explanation || "No relationship explanation available."}</small>
          </div>
          {hasSenderDomain ? (
            <a
              className="link-button domain-whois-link"
              href={whoisUrl}
              target="_blank"
              rel="noopener noreferrer"
              title={`Open WHOIS lookup for ${senderDomainName}`}
            >
              Open WHOIS lookup <ArrowUpRight size={14} />
            </a>
          ) : (
            <span className="link-button link-disabled">
              WHOIS unavailable <ArrowUpRight size={14} />
            </span>
          )}
        </Glass>
      </div>
    </>
  );
}

function DataView({ analysis, tab }: { analysis: Analysis; tab: string }) {
  const [search, setSearch] = useState("");
  const data =
    tab === "URLs"
      ? analysis.urls
      : tab === "Domains"
        ? analysis.domains
        : tab === "IPs"
          ? analysis.ips
          : tab === "Attachments"
            ? analysis.attachments
            : analysis.findings;
  const filtered = (data || []).filter((item: any) =>
    JSON.stringify(item).toLowerCase().includes(search.toLowerCase()),
  );
  return (
    <Glass className="data-panel">
      <SectionTitle
        eyebrow="EVIDENCE INDEX"
        title={tab}
        count={`${filtered.length} observed`}
      />
      <div className="data-toolbar">
        <div className="search">
          <Search size={15} />
          <input
            placeholder={`Search ${tab.toLowerCase()}`}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <button className="outline-button">
          <Clipboard size={14} /> Copy all
        </button>
      </div>
      {filtered.length ? (
        <div className="evidence-list">
          {filtered.map((item: any, i: number) => (
            <div className="evidence-row" key={i}>
              <span className="evidence-type">
                {tab === "Findings" ? item.severity : tab.slice(0, -1)}
              </span>
              <div>
                <b>
                  {item.title ||
                    item.host ||
                    item.domain ||
                    item.ip ||
                    item.name ||
                    item.original}
                </b>
                <small>
                  {item.description ||
                    item.reputation ||
                    item.mime_type ||
                    item.sha256 ||
                    "Observed during analysis"}
                </small>
              </div>
              <ArrowUpRight size={15} />
            </div>
          ))}
        </div>
      ) : (
        <div className="empty-state">
          <FileSearch size={17} /> No {tab.toLowerCase()} detected.
        </div>
      )}
    </Glass>
  );
}
function RawView({ analysis }: { analysis: Analysis }) {
  return (
    <Glass className="raw-panel">
      <SectionTitle
        eyebrow="SOURCE EVIDENCE"
        title="Raw email"
        count="read-only"
      />
      <div className="raw-toolbar">
        <Search size={15} />
        <span>Search raw message</span>
        <Clipboard size={15} />
        <ArrowUpRight size={15} />
      </div>
      <pre>{analysis.raw_headers || "No raw headers available."}</pre>
    </Glass>
  );
}

function HeaderForensics({ analysis }: { analysis: Analysis }) {
  const metadata = analysis.email_metadata || {};
  const headers = analysis.headers || [];
  const important = [
    "From",
    "To",
    "Reply-To",
    "Return-Path",
    "Date",
    "Message-ID",
    "Authentication-Results",
    "Received-SPF",
    "DKIM-Signature",
  ];
  const selected = important
    .map((name) =>
      headers.find(
        (header: AnyRecord) => header.name.toLowerCase() === name.toLowerCase(),
      ),
    )
    .filter(Boolean);
  return (
    <>
      <Glass className="header-forensics">
        <SectionTitle
          eyebrow="HEADER FORENSICS"
          title="Identity & transport evidence"
          count={`${headers.length} headers parsed`}
        />
        <div className="header-facts">
          {[
            ["Message-ID", metadata.message_id],
            ["Return-Path", metadata.return_path],
            ["MIME type", metadata.mime_type],
            ["Sample size", `${metadata.size || 0} bytes`],
            ["Declared date", metadata.date],
            ["Sender domain", metadata.sender_domain],
          ].map(([label, value]) => (
            <div key={label}>
              <span>{label}</span>
              <b
                className={
                  label === "Message-ID" || label === "Return-Path"
                    ? "mono"
                    : ""
                }
              >
                {value || "Not set"}
              </b>
            </div>
          ))}
        </div>
        <div className="parsed-headers">
          {selected.map((header: AnyRecord) => (
            <div key={header.name}>
              <b>{header.name}</b>
              <span>{header.value}</span>
            </div>
          ))}
        </div>
        <details className="all-headers">
          <summary>
            View all parsed headers <ChevronRight size={14} />
          </summary>
          {headers.map((header: AnyRecord, i: number) => (
            <div key={`${header.name}-${i}`}>
              <b>{header.name}</b>
              <span>{header.value}</span>
            </div>
          ))}
        </details>
      </Glass>
      <Glass className="timeline-panel">
        <SectionTitle eyebrow="CHRONOLOGY" title="Investigation timeline" />{" "}
        <div className="timeline-list">
          {(analysis.timeline || []).map((event: AnyRecord, i: number) => (
            <div key={i}>
              <span>{event.time}</span>
              <i />
              <p>{event.event}</p>
            </div>
          ))}
        </div>
      </Glass>
    </>
  );
}
function SignalDetails({ analysis }: { analysis: Analysis }) {
  const content = analysis.content_analysis || {};
  const indicators = analysis.indicators || {};
  return (
    <div className="signal-grid">
      <Glass>
        <SectionTitle eyebrow="MESSAGE CONTENT" title="Content signals" />
        <div className="content-facts">
          <div>
            <span>HTML detected</span>
            <Badge tone={content.html_detected ? "medium" : "pass"}>
              {content.html_detected ? "YES" : "NO"}
            </Badge>
          </div>
          <div>
            <span>Active script</span>
            <Badge tone={content.javascript_detected ? "high" : "pass"}>
              {content.javascript_detected ? "DETECTED" : "NOT DETECTED"}
            </Badge>
          </div>
          <div>
            <span>Tracking pixels</span>
            <b>{content.tracking_pixels || 0}</b>
          </div>
          <div>
            <span>Phone numbers</span>
            <Badge tone={content.vishing_numbers?.length ? "high" : "pass"}>
              {content.vishing_numbers?.length || 0}
            </Badge>
          </div>
        </div>
        {content.vishing_numbers?.length ? (
          <div className="phone-alert">
            <span className="micro">CALL TARGETS DETECTED</span>
            <div>
              {content.vishing_numbers.map((number: string) => (
                <mark key={number}>{number}</mark>
              ))}
            </div>
          </div>
        ) : null}
        <p className="content-preview">
          {content.preview_text || "No readable plain-text preview available."}
        </p>
      </Glass>
      <Glass>
        <SectionTitle
          eyebrow="INDICATORS"
          title="Observed IOCs"
          count={`${Object.values(indicators).flat().length} total`}
        />
        <div className="ioc-list">
          {Object.entries(indicators).map(([type, values]: [string, any]) =>
            values.length ? (
              <div key={type}>
                <span>{type}</span>
                <b>{values.slice(0, 3).join(" · ")}</b>
              </div>
            ) : null,
          )}
        </div>
        {!Object.values(indicators).some((values: any) => values.length) && (
          <p className="muted-note">
            No indicators were extracted from this sample.
          </p>
        )}
      </Glass>
    </div>
  );
}

function EmailPreview({ analysis }: { analysis: Analysis }) {
  const preview = analysis.html_preview;
  const metadata = analysis.email_metadata || {};
  return (
    <Glass className="email-preview-panel">
      <SectionTitle
        eyebrow="MESSAGE VIEW"
        title="Inbox view"
        count={preview ? "RENDERED" : "EMPTY"}
      />
      <div className="email-preview-meta">
        <div><span>From</span><b>{metadata.sender || "Unknown sender"}</b></div>
        <div><span>To</span><b>{metadata.recipient || "Unknown recipient"}</b></div>
        <div><span>Subject</span><b>{metadata.subject || "(No subject)"}</b></div>
      </div>
      {preview ? (
        <iframe
          className="email-preview-frame"
          title="Sanitized rendered email preview"
          sandbox=""
          srcDoc={preview}
        />
      ) : (
        <div className="email-preview-fallback">No readable email body available.</div>
      )}
    </Glass>
  );
}

const priorityTabs = [
  "Verdict",
  "Findings",
  "Authentication",
  "Mail Flow",
  "Headers",
  "Content",
  "Email Preview",
  "Infrastructure",
  "Raw Email",
];
function Report({
  analysis,
  onReset,
}: {
  analysis: Analysis;
  onReset: () => void;
}) {
  const metadata = analysis.email_metadata || {};
  const jumpTo = (label: string) => {
    const selectors: Record<string, string> = {
      Verdict: ".result-hero",
      Findings: ".finding-section",
      Authentication: ".overview-grid",
      "Mail Flow": ".flow-panel",
      Headers: ".header-forensics",
      Content: ".signal-grid",
      "Email Preview": ".email-preview-panel",
      Infrastructure: ".report-grid",
      "Raw Email": ".raw-panel",
    };
    document
      .querySelector(selectors[label])
      ?.scrollIntoView({ behavior: "smooth", block: "start" });
  };
  return (
    <>
      <Header onReset={onReset} />
      <main className="workspace">
        <div className="workspace-top">
          <button className="back-button" onClick={onReset}>
            ← New investigation
          </button>
          <div>
            <Badge>
              <Radar size={13} /> ephemeral session
            </Badge>
            <Badge>{String(analysis.id || "trace").slice(0, 8)}</Badge>
          </div>
        </div>
        <div className="case-title">
          <div>
            <span className="micro">
              CASE FILE · {metadata.filename || "UNNAMED SAMPLE"}
            </span>
            <h2>{metadata.subject || "Email investigation"}</h2>
            <p>
              {metadata.sender || "Unknown sender"} <ArrowUpRight size={12} />{" "}
              {metadata.recipient || "Unknown recipient"}
            </p>
          </div>
          <span className="case-date">
            {metadata.date || "Date unavailable"}
          </span>
        </div>
        <div className="report-label">
          <span className="micro">
            <FileSearch size={14} /> COMPLETE FORENSIC REPORT
          </span>
          <span>Evidence priority</span>
        </div>
        <nav className="priority-nav" aria-label="Report evidence priority">
          {priorityTabs.map((label, index) => (
            <button key={label} onClick={() => jumpTo(label)}>
              <b>0{index + 1}</b>
              {label}
            </button>
          ))}
        </nav>
        <div className="tab-content full-report">
          <Overview analysis={analysis} onTab={() => undefined} />
          <HeaderForensics analysis={analysis} />
          <SignalDetails analysis={analysis} />
          <EmailPreview analysis={analysis} />
          <div className="report-divider">
            <span>DEEP FORENSICS</span>
          </div>
          <div className="report-grid">
            <DataView analysis={analysis} tab="Domains" />
            <DataView analysis={analysis} tab="IPs" />
          </div>
          <DataView analysis={analysis} tab="URLs" />
          <DataView analysis={analysis} tab="Attachments" />
          <DataView analysis={analysis} tab="Findings" />
          <RawView analysis={analysis} />
        </div>
      </main>
    </>
  );
}

export default function AppShell() {
  const [analysis, setAnalysis] = useState<Analysis>();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [fileName, setFileName] = useState("");
  async function run(file: File) {
    setLoading(true);
    setError("");
    setFileName(file.name);
    try {
      const form = new FormData();
      form.append("file", file);
      let response: Response;
      try {
        response = await fetch("/api/analyze", { method: "POST", body: form });
      } catch {
        throw new Error(
          "The analysis service is unreachable. Start FastAPI from the backend folder with: uvicorn app.main:app --reload --port 8000",
        );
      }
      const contentType = response.headers.get("content-type") || "";
      const data = contentType.includes("application/json")
        ? await response.json()
        : null;
      if (!response.ok)
        throw new Error(
          data?.detail || `Analysis service returned ${response.status}.`,
        );
      if (!data)
        throw new Error(
          "The analysis service returned an unexpected response.",
        );
      setAnalysis(data);
    } catch (e: any) {
      setError(e.message || "Analysis failed.");
    } finally {
      setLoading(false);
    }
  }
  if (loading)
    return (
      <>
        <Header />
        <Investigation fileName={fileName} />
      </>
    );
  if (analysis)
    return (
      <Report analysis={analysis} onReset={() => setAnalysis(undefined)} />
    );
  return (
    <>
      <Header />
      <main className="landing">
        <div className="landing-copy">
          <img
            className="landing-mark"
            src="/mailforensics-mark.svg"
            alt="MailForensics"
          />
          <span className="micro">
            <Radar size={14} /> EMAIL THREAT INVESTIGATION
          </span>
          <h1>
            Analyze every signal.
            <br />
            <em>Understand every email.</em>
          </h1>
          <p>
            Deep email forensics, authentication analysis, threat intelligence,
            and phishing detection from a single .eml file.
          </p>
        </div>
        <Uploader onAnalyze={run} loading={loading} />
        {error && (
          <div className="error-state">
            <XCircle size={17} /> {error}
          </div>
        )}
        <div className="landing-note">
          <span>
            <FileSearch size={14} /> Full MIME analysis
          </span>
          <span>
            <ShieldCheck size={14} /> Explainable scoring
          </span>
          <span>
            <LockKeyhole size={14} /> Privacy-first processing
          </span>
        </div>
      </main>
      <footer>
        MAILFORENSICS <span>·</span> Built for security investigation
      </footer>
    </>
  );
}
