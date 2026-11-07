# runner API: the layer the CLI and the GUI share

`src/bacnet_health/runner.py` wraps interface selection, socket binding, budget preview, confirmations and execution
for `scan`, `listen` and `audit`. Neither the GUI nor the CLI contains any BACnet logic; both call this module.

```python
class RunnerError(Exception): ...          # plain-English, user-facing message (port in use, no interface, ...)

@dataclass
class RunnerOptions:
    kind: str = "audit"                    # "scan" | "listen" | "audit"
    interface: str | None = None           # None = auto-pick (a person must confirm)
    bind: str | None = None                # "192.0.2.10/24" alternative to interface
    port: int = 47808
    targets: list[str] = []
    whois_gap_s: float = 1.0
    max_req_per_s: float = 5.0
    apdu_timeout_s: float = 3.0
    apdu_retries: int = 1
    read_properties: bool = True
    bbmd_audit: bool = True
    read_remote: bool = False              # cross-subnet: needs confirm()
    follow_bdt: bool = False               # cross-subnet: needs confirm()
    fdr_bbmd: str | None = None            # cross-subnet: needs confirm()
    listen_s: float = 600.0
    known_writers: list[str] = []
    site, client, prepared_by, org, authorised_by, scope_note: str = ""
    @classmethod from_args(cls, args) -> RunnerOptions
    @classmethod from_profile(cls, profile: Profile, kind: str = "audit") -> RunnerOptions

def interface_choices() -> tuple[Iface | None, list[Iface], list[str]]   # (auto-pick, ranked list, reasons)

def prepare(kind: str, opts: RunnerOptions) -> Session                     # binds the port; raises RunnerError

class Session:
    kind: str
    iface: Iface
    budget: Budget                         # preview (model.Budget)
    def describe(self) -> str              # "Will broadcast on 192.0.2.255 via en5 ..." + budget, plain English
    def dry_run_text(self) -> str          # every frame that would be sent first (hex), plus the plan
    def required_confirmations(self) -> list[tuple[str, str, str]]  # (action_id, target, risk_text)
    def cross_subnet_actions(self, args) -> list[tuple[str, str, str | None]]  # CLI helper
    def confirm(self, action_id: str, target: str, user: str) -> None  # records into RunInfo.confirmations
    def run(self, progress: Callable[[dict], None] | None = None) -> Result  # blocking; GUI calls it in a thread
    def cancel(self) -> None               # thread-safe; transmission stops within 100 ms
    def result(self) -> Result             # partial result after cancel
    def close(self) -> None                # releases the socket

def progress_line(p: dict) -> str          # one-line text for CLI progress
```

Progress events (dicts):

- `{"type": "phase", "phase": "listen"|"discover"|"read"|"bbmd"|"report"|"done", "message": str}`
- `{"type": "progress", "fraction": float 0..1, "message": str}` (fraction of the current phase)
- `{"type": "device", "instance": int, "address": str}`
- `{"type": "log", "level": "info"|"warning", "message": str}`
- `{"type": "budget-exceeded", "message": str}`

The pre-flight checks the GUI shows:

- `runner.preflight(opts) -> list[dict(name, status: "ok"|"warning"|"error"|"unknown", message)]`: port free, firewall
  (Windows), clock/NTP, interface up.
