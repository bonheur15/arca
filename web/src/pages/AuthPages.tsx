import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { ArrowLeft, ArrowRight, Check, Clock3, KeyRound, LockKeyhole, Mail, ShieldCheck, Sparkles } from "lucide-react";
import { motion } from "motion/react";
import { useEffect, useMemo, useRef, useState, type FormEvent, type ReactNode } from "react";
import { api, describeError } from "../api/client";
import { ArcaMark } from "../components/ArcaMark";
import { Button, EmptyState, ErrorState, Field, LoadingState, StatusPill } from "../components/Primitives";
import { PublicFiles } from "../features/files/FileViews";

function AuthLayout({ eyebrow, title, description, children, footer }: { eyebrow?: string; title: string; description: string; children: ReactNode; footer?: ReactNode }) {
  return (
    <div className="auth-page">
      <div className="auth-atmosphere" aria-hidden="true"><span /><span /><span /></div>
      <header className="auth-brand"><Link to="/sign-in"><ArcaMark size={34} /><span>arca</span></Link></header>
      <main className="auth-main">
        <motion.section className="auth-card" initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.35 }}>
          <div className="auth-card__head">
            {eyebrow ? <span className="eyebrow">{eyebrow}</span> : null}
            <h1>{title}</h1>
            <p>{description}</p>
          </div>
          {children}
        </motion.section>
        {footer ? <div className="auth-footer">{footer}</div> : null}
      </main>
      <p className="auth-security"><ShieldCheck size={15} />Authentication is secured by WorkOS</p>
    </div>
  );
}

export function SignInPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [stage, setStage] = useState<"email" | "code">("email");
  const start = useMutation({
    mutationFn: () => api.startMagicAuth(email.trim()),
    onSuccess: () => setStage("code"),
  });
  const verify = useMutation({
    mutationFn: () => api.verifyMagicAuth(code),
    onSuccess: async (session) => {
      queryClient.setQueryData(["session"], session);
      await navigate({ to: "/files" });
    },
  });
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (stage === "email") start.mutate(); else verify.mutate();
  };
  const error = start.error ?? verify.error;
  return (
    <AuthLayout
      eyebrow="Private workspace"
      title={stage === "email" ? "Welcome back" : "Check your inbox"}
      description={stage === "email" ? "Enter your account email. We’ll send a one-time sign-in code—no password needed." : `Enter the six-digit Magic Auth code sent to ${email}. It expires in 10 minutes.`}
      footer={<p>Need an account? <Link to="/request-access">Request access</Link></p>}
    >
      <form className="auth-form" onSubmit={submit}>
        {stage === "email" ? (
          <Field label="Email address">
            <div className="input-with-icon"><Mail size={18} /><input autoComplete="email" autoFocus name="email" onChange={(event) => setEmail(event.target.value)} placeholder="you@company.com" required type="email" value={email} /></div>
          </Field>
        ) : (
          <>
            <Field hint="This is different from Arca’s five-digit public share code." label="Magic Auth code">
              <input autoComplete="one-time-code" autoFocus className="code-input code-input--six" inputMode="numeric" maxLength={6} onChange={(event) => setCode(event.target.value.replace(/\D/g, ""))} pattern="[0-9]{6}" placeholder="000000" required value={code} />
            </Field>
            <button className="text-button" onClick={() => { setStage("email"); setCode(""); verify.reset(); }} type="button"><ArrowLeft size={15} />Use another email</button>
          </>
        )}
        {error ? <p className="form-error" role="alert">{describeError(error)}</p> : null}
        <Button className="button--full" disabled={start.isPending || verify.isPending || (stage === "code" && code.length !== 6)}>
          {start.isPending || verify.isPending ? "Please wait…" : stage === "email" ? <>Send sign-in code <ArrowRight size={17} /></> : <>Open my vault <ArrowRight size={17} /></>}
        </Button>
      </form>
    </AuthLayout>
  );
}

export function RequestAccessPage() {
  const startedAt = useRef(Date.now());
  const [receipt, setReceipt] = useState<{ token: string; state: "pending" | "approved" | "rejected" } | null>(() => {
    const token = sessionStorage.getItem("arca.access-request");
    return token ? { token, state: "pending" } : null;
  });
  const [form, setForm] = useState({ username: "", email: "", displayName: "", reason: "", website: "" });
  const request = useMutation({
    mutationFn: () => api.requestAccess({ ...form, startedAt: startedAt.current }),
    onSuccess: (value) => {
      sessionStorage.setItem("arca.access-request", value.statusToken);
      setReceipt({ token: value.statusToken, state: value.state });
    },
  });
  const status = useQuery({
    queryKey: ["access-request", receipt?.token],
    queryFn: () => api.accessRequestStatus(receipt?.token ?? ""),
    enabled: Boolean(receipt?.token),
    refetchInterval: 30_000,
  });
  const currentState = status.data?.state ?? receipt?.state;
  if (receipt) {
    return (
      <AuthLayout
        eyebrow="Access request"
        title={currentState === "approved" ? "Your vault is ready" : currentState === "rejected" ? "Request closed" : "Request received"}
        description={currentState === "approved" ? "Your account has been approved. Sign in and we’ll send your one-time Magic Auth code." : currentState === "rejected" ? "This request wasn’t approved. Contact the Arca administrator if you think this was a mistake." : "An Arca administrator will review your request. This page checks for updates automatically."}
        footer={<p><Link to="/sign-in">Back to sign in</Link></p>}
      >
        <EmptyState
          icon={currentState === "approved" ? "success" : "empty"}
          title={currentState === "approved" ? "Approved" : currentState === "rejected" ? "Not approved" : "Pending review"}
          description={currentState === "approved" ? "No approval email is sent—continue to sign in when you’re ready." : currentState === "rejected" ? "The request status is final." : "You can safely close this tab and return using this browser session."}
          action={currentState === "approved" ? <Button onClick={() => void location.assign("/sign-in")}>Continue to sign in</Button> : undefined}
        />
      </AuthLayout>
    );
  }
  return (
    <AuthLayout eyebrow="Join this Arca" title="Request a place in the vault" description="Tell the administrator who you are. Approval is quiet—you can check its status here later." footer={<p>Already have access? <Link to="/sign-in">Sign in</Link></p>}>
      <form className="auth-form auth-form--wide" onSubmit={(event) => { event.preventDefault(); request.mutate(); }}>
        <div className="form-grid">
          <Field label="Username" hint="Used by teammates when sharing with you."><input autoComplete="username" minLength={3} onChange={(event) => setForm({ ...form, username: event.target.value })} placeholder="marie" required value={form.username} /></Field>
          <Field label="Email address"><input autoComplete="email" onChange={(event) => setForm({ ...form, email: event.target.value })} placeholder="marie@company.com" required type="email" value={form.email} /></Field>
        </div>
        <Field label="Display name" hint="Optional"><input autoComplete="name" onChange={(event) => setForm({ ...form, displayName: event.target.value })} placeholder="Marie Curie" value={form.displayName} /></Field>
        <Field label="A short note" hint="Optional — up to 300 characters"><textarea maxLength={300} onChange={(event) => setForm({ ...form, reason: event.target.value })} placeholder="What will you use Arca for?" rows={3} value={form.reason} /></Field>
        <label className="honeypot" aria-hidden="true">Website<input autoComplete="off" onChange={(event) => setForm({ ...form, website: event.target.value })} tabIndex={-1} value={form.website} /></label>
        {request.error ? <p className="form-error" role="alert">{describeError(request.error)}</p> : null}
        <Button className="button--full" disabled={request.isPending}>{request.isPending ? "Sending…" : <>Request access <ArrowRight size={17} /></>}</Button>
      </form>
    </AuthLayout>
  );
}

const setupSteps = ["Unlock", "Instance", "Verify"];

export function SetupPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [step, setStep] = useState(0);
  const [setupCode, setSetupCode] = useState("");
  const [magicCode, setMagicCode] = useState("");
  const [form, setForm] = useState({
    instanceName: "Arca",
    publicUrl: window.location.origin,
    workosClientId: "",
    workosApiKey: "",
    username: "",
    email: "",
    displayName: "",
    quotaGb: 50,
  });
  const validate = useMutation({ mutationFn: () => api.validateSetupCode(setupCode), onSuccess: () => setStep(1) });
  const configure = useMutation({
    mutationFn: () => api.setupStart({
      setupCode,
      instanceName: form.instanceName,
      publicUrl: form.publicUrl,
      workosClientId: form.workosClientId,
      workosApiKey: form.workosApiKey,
      superadmin: { username: form.username, email: form.email, displayName: form.displayName || null, quotaBytes: form.quotaGb * 1024 ** 3 },
    }),
    onSuccess: () => setStep(2),
  });
  const verify = useMutation({
    mutationFn: () => api.setupVerify({ setupCode, code: magicCode }),
    onSuccess: async (session) => {
      queryClient.setQueryData(["session"], session);
      await queryClient.invalidateQueries();
      await navigate({ to: "/files" });
    },
  });
  const error = validate.error ?? configure.error ?? verify.error;
  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (step === 0) validate.mutate();
    if (step === 1) configure.mutate();
    if (step === 2) verify.mutate();
  };
  return (
    <AuthLayout eyebrow="First-run setup" title={step === 0 ? "Open your new vault" : step === 1 ? "Make Arca yours" : "Verify the first admin"} description={step === 0 ? "Use the 20-character setup code printed in the Arca server console. It expires after 30 minutes." : step === 1 ? "Connect authentication and create the initial superadmin. Secrets are sent directly to this instance." : `WorkOS sent a six-digit Magic Auth code to ${form.email}.`}>
      <ol className="setup-steps">
        {setupSteps.map((label, index) => <li className={index < step ? "complete" : index === step ? "active" : ""} key={label}><span>{index < step ? <Check size={13} /> : index + 1}</span>{label}</li>)}
      </ol>
      <form className="auth-form setup-form" onSubmit={submit}>
        {step === 0 ? (
          <Field label="Setup code"><div className="input-with-icon"><LockKeyhole size={18} /><input autoCapitalize="characters" autoComplete="off" autoFocus className="setup-code" maxLength={20} onChange={(event) => setSetupCode(event.target.value.replace(/[^A-Za-z0-9]/g, "").toUpperCase())} placeholder="XXXXXXXXXXXXXXXXXXXX" required value={setupCode} /></div></Field>
        ) : null}
        {step === 1 ? (
          <div className="setup-fields">
            <div className="form-section"><h2>Instance</h2><p>How this vault identifies itself.</p></div>
            <div className="form-grid"><Field label="Instance name"><input maxLength={80} onChange={(event) => setForm({ ...form, instanceName: event.target.value })} required value={form.instanceName} /></Field><Field label="Public URL"><input onChange={(event) => setForm({ ...form, publicUrl: event.target.value })} required type="url" value={form.publicUrl} /></Field></div>
            <div className="form-section"><h2>WorkOS Magic Auth</h2><p>Use unique credentials for this installation.</p></div>
            <div className="form-grid"><Field label="Client ID"><input autoComplete="off" onChange={(event) => setForm({ ...form, workosClientId: event.target.value })} placeholder="client_…" required value={form.workosClientId} /></Field><Field label="API key"><input autoComplete="new-password" onChange={(event) => setForm({ ...form, workosApiKey: event.target.value })} placeholder="sk_…" required type="password" value={form.workosApiKey} /></Field></div>
            <div className="form-section"><h2>Superadmin</h2><p>The first person responsible for this vault.</p></div>
            <div className="form-grid"><Field label="Username"><input autoComplete="username" minLength={3} onChange={(event) => setForm({ ...form, username: event.target.value })} required value={form.username} /></Field><Field label="Email"><input autoComplete="email" onChange={(event) => setForm({ ...form, email: event.target.value })} required type="email" value={form.email} /></Field><Field label="Display name" hint="Optional"><input autoComplete="name" onChange={(event) => setForm({ ...form, displayName: event.target.value })} value={form.displayName} /></Field><Field label="Storage quota"><div className="input-suffix"><input min={1} onChange={(event) => setForm({ ...form, quotaGb: Number(event.target.value) })} required type="number" value={form.quotaGb} /><span>GB</span></div></Field></div>
          </div>
        ) : null}
        {step === 2 ? <Field hint="This six-digit authentication code is not a public-share code." label="Magic Auth code"><input autoComplete="one-time-code" autoFocus className="code-input code-input--six" inputMode="numeric" maxLength={6} onChange={(event) => setMagicCode(event.target.value.replace(/\D/g, ""))} pattern="[0-9]{6}" placeholder="000000" required value={magicCode} /></Field> : null}
        {error ? <p className="form-error" role="alert">{describeError(error)}</p> : null}
        <Button className="button--full" disabled={(step === 0 && setupCode.length !== 20) || (step === 2 && magicCode.length !== 6) || validate.isPending || configure.isPending || verify.isPending}>{validate.isPending || configure.isPending || verify.isPending ? "Securing your vault…" : step === 0 ? <>Unlock setup <ArrowRight size={17} /></> : step === 1 ? <>Send verification code <ArrowRight size={17} /></> : <>Finish setup <Sparkles size={17} /></>}</Button>
      </form>
    </AuthLayout>
  );
}

function FiveDigitInput({ value, onChange, disabled = false }: { value: string; onChange: (value: string) => void; disabled?: boolean }) {
  const inputs = useRef<Array<HTMLInputElement | null>>([]);
  const digits = Array.from({ length: 5 }, (_, index) => value[index] ?? "");
  const update = (index: number, digit: string) => {
    const next = [...digits];
    next[index] = digit.replace(/\D/g, "").slice(-1);
    onChange(next.join(""));
    if (next[index] && index < 4) inputs.current[index + 1]?.focus();
  };
  return (
    <div className="public-code-input" onPaste={(event) => { const pasted = event.clipboardData.getData("text").replace(/\D/g, "").slice(0, 5); if (pasted) { event.preventDefault(); onChange(pasted); inputs.current[Math.min(pasted.length, 4)]?.focus(); } }}>
      {digits.map((digit, index) => <input aria-label={`Digit ${index + 1}`} autoComplete={index === 0 ? "one-time-code" : "off"} disabled={disabled} inputMode="numeric" key={index} maxLength={1} onChange={(event) => update(index, event.target.value)} onKeyDown={(event) => { if (event.key === "Backspace" && !digit && index > 0) inputs.current[index - 1]?.focus(); if (event.key === "ArrowLeft" && index > 0) inputs.current[index - 1]?.focus(); if (event.key === "ArrowRight" && index < 4) inputs.current[index + 1]?.focus(); }} ref={(element) => { inputs.current[index] = element; }} value={digit} />)}
    </div>
  );
}

export function RedeemPage() {
  const navigate = useNavigate();
  const [code, setCode] = useState("");
  const exchange = useMutation({ mutationFn: () => api.publicExchange(code), onSuccess: () => void navigate({ to: "/public" }) });
  return (
    <AuthLayout eyebrow="Public exchange" title="Receive a shared bundle" description="Enter the five-digit code from the sender. Public codes are short-lived and may have limited uses." footer={<p><Clock3 size={14} /> Codes expire in 30 minutes or less</p>}>
      <form className="auth-form" onSubmit={(event) => { event.preventDefault(); exchange.mutate(); }}>
        <FiveDigitInput disabled={exchange.isPending} onChange={setCode} value={code} />
        {exchange.error ? <p className="form-error" role="alert">That code is invalid or no longer available. Check the digits and try again.</p> : null}
        <Button className="button--full" disabled={code.length !== 5 || exchange.isPending}>{exchange.isPending ? "Opening bundle…" : <><KeyRound size={17} />Open shared files</>}</Button>
      </form>
    </AuthLayout>
  );
}

export function PublicPage() {
  const bundle = useQuery({ queryKey: ["public-bundle"], queryFn: api.publicBundle, retry: false });
  if (bundle.isPending) return <div className="public-page"><LoadingState label="Opening shared bundle…" /></div>;
  if (bundle.isError) return <div className="public-page public-page--center"><ErrorState error={bundle.error} onRetry={() => void bundle.refetch()} title="This bundle is unavailable" /><Link className="text-link" to="/redeem">Enter another code</Link></div>;
  return (
    <div className="public-page">
      <header className="public-header"><Link className="brand" to="/redeem"><ArcaMark size={30} /><span>arca</span></Link><StatusPill tone="accent"><Clock3 size={13} />Expires {new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit" }).format(new Date(bundle.data.expiresAt))}</StatusPill></header>
      <main className="public-main"><div className="page-heading"><span className="eyebrow">Shared with a secure code</span><h1>{bundle.data.name}</h1><p>Read-only access. Download the items you need before this exchange expires.</p></div><PublicFiles bundle={bundle.data} /></main>
      <footer className="public-footer"><ShieldCheck size={15} />Delivered privately through Arca</footer>
    </div>
  );
}
