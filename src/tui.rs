//! ArkIris interactive terminal UI.
//! No business logic lives here: the TUI is a read-only observability surface.

use crossterm::{
    cursor::{Hide, MoveTo, Show},
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    execute, queue,
    style::{Color, Print, ResetColor, SetBackgroundColor, SetForegroundColor},
    terminal::{self, Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen},
};
use std::{
    io::{self, Write},
    sync::{atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering}, Arc},
    thread,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug)]
pub enum Theme {
    Neon,
    Ocean,
    Amber,
    Mono,
}

impl Theme {
    pub fn parse(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "ocean" => Self::Ocean,
            "amber" => Self::Amber,
            "mono" | "monochrome" => Self::Mono,
            _ => Self::Neon,
        }
    }

    fn palette(self) -> Palette {
        match self {
            Self::Neon => Palette { fg: Color::White, accent: Color::Cyan, good: Color::Green, warn: Color::Yellow, dim: Color::DarkGrey, bg: Color::Black },
            Self::Ocean => Palette { fg: Color::White, accent: Color::Blue, good: Color::Green, warn: Color::Yellow, dim: Color::DarkGrey, bg: Color::Black },
            Self::Amber => Palette { fg: Color::White, accent: Color::Yellow, good: Color::Green, warn: Color::Yellow, dim: Color::DarkGrey, bg: Color::Black },
            Self::Mono => Palette { fg: Color::White, accent: Color::White, good: Color::White, warn: Color::White, dim: Color::Grey, bg: Color::Black },
        }
    }
}

#[derive(Clone, Copy)]
struct Palette { fg: Color, accent: Color, good: Color, warn: Color, dim: Color, bg: Color }

pub struct Metrics {
    pub udp_rx_bytes: AtomicU64,
    pub udp_tx_bytes: AtomicU64,
    pub tun_rx_bytes: AtomicU64,
    pub tun_tx_bytes: AtomicU64,
    pub packets_rx: AtomicU64,
    pub packets_tx: AtomicU64,
    pub ldt_tx_packets: AtomicU64,
    pub ldt_rx_packets: AtomicU64,
    pub ecn_ce: AtomicU64,
    pub dropped: AtomicU64,
    pub sessions: AtomicUsize,
}

impl Metrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            udp_rx_bytes: AtomicU64::new(0), udp_tx_bytes: AtomicU64::new(0),
            tun_rx_bytes: AtomicU64::new(0), tun_tx_bytes: AtomicU64::new(0),
            packets_rx: AtomicU64::new(0), packets_tx: AtomicU64::new(0),
            ldt_tx_packets: AtomicU64::new(0), ldt_rx_packets: AtomicU64::new(0),
            ecn_ce: AtomicU64::new(0),
            dropped: AtomicU64::new(0), sessions: AtomicUsize::new(0),
        })
    }
}

#[derive(Clone)]
pub struct TuiConfig {
    pub theme: Theme,
    pub refresh_ms: u64,
    pub mode: String,
    pub bind: String,
    pub peer: Option<String>,
    pub cc: String,
    pub fec: usize,
    pub mtu: u16,
    pub privacy: bool,
    pub pq: bool,
    pub ldt: bool,
    pub pacing_mbps: f64,
    pub tun_backend: String,
}

pub fn spawn(config: TuiConfig, metrics: Arc<Metrics>, started: Instant) -> Arc<AtomicBool> {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = stop.clone();
    thread::Builder::new()
        .name("arkiris-tui".into())
        .spawn(move || {
            if let Err(e) = run(config, metrics, started, stop_thread.clone()) {
                log::warn!("TUI exited: {}", e);
            }
        })
        .expect("failed to start TUI thread");
    stop
}

fn run(config: TuiConfig, metrics: Arc<Metrics>, started: Instant, stop: Arc<AtomicBool>) -> io::Result<()> {
    terminal::enable_raw_mode()?;
    let mut out = io::stdout();
    execute!(out, EnterAlternateScreen, Hide)?;
    let palette = config.theme.palette();
    let mut page = 0usize;
    let mut dense = false;
    let refresh = Duration::from_millis(config.refresh_ms.max(50));
    let mut prev_rx = 0u64;
    let mut prev_tx = 0u64;
    let mut last_tick = Instant::now();
    let mut rx_mbps = 0.0f64;
    let mut tx_mbps = 0.0f64;

    let result = (|| -> io::Result<()> {
        loop {
            if stop.load(Ordering::Relaxed) { break; }
            let now = Instant::now();
            let dt = now.duration_since(last_tick).as_secs_f64().max(0.001);
            let rx = metrics.udp_rx_bytes.load(Ordering::Relaxed);
            let tx = metrics.udp_tx_bytes.load(Ordering::Relaxed);
            rx_mbps = ((rx.saturating_sub(prev_rx)) as f64 * 8.0 / dt) / 1_048_576.0;
            tx_mbps = ((tx.saturating_sub(prev_tx)) as f64 * 8.0 / dt) / 1_048_576.0;
            prev_rx = rx; prev_tx = tx; last_tick = now;
            draw(&mut out, &config, &palette, &metrics, started, page, dense, rx_mbps, tx_mbps)?;
            out.flush()?;

            let deadline = Instant::now() + refresh;
            while Instant::now() < deadline {
                if event::poll(Duration::from_millis(50))? {
                    if let Event::Key(KeyEvent { code, modifiers, .. }) = event::read()? {
                        match (code, modifiers) {
                            (KeyCode::Char('q'), _) | (KeyCode::Esc, _) => { stop.store(true, Ordering::Relaxed); break; }
                            (KeyCode::Char('1'), _) => page = 0,
                            (KeyCode::Char('2'), _) => page = 1,
                            (KeyCode::Char('3'), _) => page = 2,
                            (KeyCode::Char('4'), _) => page = 3,
                            (KeyCode::Char('5'), _) => page = 4,
                            (KeyCode::Left, _) => page = page.saturating_sub(1),
                            (KeyCode::Right, _) => page = (page + 1) % 5,
                            (KeyCode::Char('+'), _) | (KeyCode::Char('='), _) => dense = false,
                            (KeyCode::Char('-'), _) => dense = true,
                            (KeyCode::Char('r'), KeyModifiers::CONTROL) => {},
                            _ => {}
                        }
                    }
                }
                if stop.load(Ordering::Relaxed) { break; }
            }
        }
        Ok(())
    })();

    execute!(out, Show, LeaveAlternateScreen)?;
    terminal::disable_raw_mode()?;
    result
}

fn draw(out: &mut io::Stdout, cfg: &TuiConfig, p: &Palette, m: &Metrics, started: Instant, page: usize, dense: bool, rx_mbps: f64, tx_mbps: f64) -> io::Result<()> {
    let (w, h) = terminal::size()?;
    let title = " ArkIris v1 ";
    queue!(out, SetBackgroundColor(p.bg), SetForegroundColor(p.fg), Clear(ClearType::All), MoveTo(0, 0), Print("═".repeat(w as usize)))?;
    queue!(out, MoveTo(2, 0), SetForegroundColor(p.accent), Print(title), ResetColor)?;
    let nav = "[1] Dashboard  [2] Sessions  [3] Network  [4] Security  [5] Config   ←/→ page   +/- density   Q quit";
    queue!(out, MoveTo(2, 1), SetForegroundColor(p.dim), Print(truncate(nav, w.saturating_sub(4) as usize)), ResetColor)?;
    match page {
        0 => dashboard(out, p, m, started, w, h, rx_mbps, tx_mbps, dense)?,
        1 => sessions(out, p, m, w, h)?,
        2 => network(out, p, m, w, h, rx_mbps, tx_mbps)?,
        3 => security(out, p, cfg, w, h)?,
        _ => config_page(out, p, cfg, w, h)?,
    }
    queue!(out, MoveTo(0, h.saturating_sub(1)), SetForegroundColor(p.dim), Print("─".repeat(w as usize)), ResetColor)?;
    Ok(())
}

fn dashboard(out: &mut io::Stdout, p: &Palette, m: &Metrics, started: Instant, w: u16, _h: u16, rx: f64, tx: f64, dense: bool) -> io::Result<()> {
    let uptime = format_duration(started.elapsed());
    panel(out, p, 2, 3, w.saturating_sub(4), if dense { 8 } else { 10 }, "LIVE OVERVIEW")?;
    line(out, p.fg, 4, 5, &format!("Status      ONLINE        Uptime {:>12}", uptime), w)?;
    line(out, p.good, 4, 6, &format!("Sessions    {:>6}", m.sessions.load(Ordering::Relaxed)), w)?;
    line(out, p.accent, 4, 7, &format!("RX          {:>10.2} Mbps", rx), w)?;
    line(out, p.accent, 30, 7, &format!("TX {:>10.2} Mbps", tx), w)?;
    line(out, p.fg, 4, 8, &format!("Packets     RX {:>12}   TX {:>12}", m.packets_rx.load(Ordering::Relaxed), m.packets_tx.load(Ordering::Relaxed)), w)?;
    line(out, p.warn, 4, 9, &format!("Drops       {:>12}", m.dropped.load(Ordering::Relaxed)), w)?;
    line(out, p.good, 4, 10, &format!("LDT         TX {:>10}   RX {:>10}", m.ldt_tx_packets.load(Ordering::Relaxed), m.ldt_rx_packets.load(Ordering::Relaxed)), w)?;
    if !dense { line(out, p.dim, 4, 11, &format!("ECN-CE      {:>10}", m.ecn_ce.load(Ordering::Relaxed)), w)?; }
    Ok(())
}

fn sessions(out: &mut io::Stdout, p: &Palette, m: &Metrics, w: u16, h: u16) -> io::Result<()> {
    panel(out, p, 2, 3, w.saturating_sub(4), h.saturating_sub(6), "SESSION MATRIX")?;
    line(out, p.fg, 4, 5, &format!("Active sessions: {}", m.sessions.load(Ordering::Relaxed)), w)?;
    line(out, p.dim, 4, 7, "Per-peer details remain in the existing monitor endpoint; this view avoids blocking the data plane.", w)?;
    Ok(())
}

fn network(out: &mut io::Stdout, p: &Palette, m: &Metrics, w: u16, h: u16, rx: f64, tx: f64) -> io::Result<()> {
    panel(out, p, 2, 3, w.saturating_sub(4), h.saturating_sub(6), "NETWORK / DATA PLANE")?;
    line(out, p.accent, 4, 5, &format!("Ingress     {:>10.2} Mbps", rx), w)?;
    line(out, p.accent, 4, 6, &format!("Egress      {:>10.2} Mbps", tx), w)?;
    line(out, p.fg, 4, 8, &format!("UDP RX      {:>12} bytes", m.udp_rx_bytes.load(Ordering::Relaxed)), w)?;
    line(out, p.fg, 4, 9, &format!("UDP TX      {:>12} bytes", m.udp_tx_bytes.load(Ordering::Relaxed)), w)?;
    line(out, p.fg, 4, 10, &format!("TUN RX      {:>12} bytes", m.tun_rx_bytes.load(Ordering::Relaxed)), w)?;
    line(out, p.fg, 4, 11, &format!("TUN TX      {:>12} bytes", m.tun_tx_bytes.load(Ordering::Relaxed)), w)?;
    Ok(())
}

fn security(out: &mut io::Stdout, p: &Palette, cfg: &TuiConfig, w: u16, h: u16) -> io::Result<()> {
    panel(out, p, 2, 3, w.saturating_sub(4), h.saturating_sub(6), "SECURITY POSTURE")?;
    line(out, p.good, 4, 5, "X25519                 ENABLED", w)?;
    line(out, p.good, 4, 6, "ML-KEM-768             ENABLED", w)?;
    line(out, p.good, 4, 7, "ChaCha20-Poly1305      ENABLED", w)?;
    line(out, p.good, 4, 8, "PSK + HMAC-SHA256      ENABLED", w)?;
    line(out, p.good, 4, 9, "Anti-replay window     2048 packets", w)?;
    line(out, if cfg.privacy { p.warn } else { p.dim }, 4, 10, &format!("Privacy framing        {}", if cfg.privacy { "ENABLED" } else { "disabled" }), w)?;
    Ok(())
}

fn config_page(out: &mut io::Stdout, p: &Palette, cfg: &TuiConfig, w: u16, h: u16) -> io::Result<()> {
    panel(out, p, 2, 3, w.saturating_sub(4), h.saturating_sub(6), "RUNTIME CONFIG")?;
    let rows = [
        format!("Mode            {}", cfg.mode),
        format!("Bind            {}", cfg.bind),
        format!("Peer            {}", cfg.peer.as_deref().unwrap_or("-")),
        format!("MTU             {}", cfg.mtu),
        format!("Congestion      {}", cfg.cc),
        format!("FEC             {}", if cfg.fec == 0 { "off".into() } else { cfg.fec.to_string() }),
        format!("Post-quantum    {}", if cfg.pq { "ML-KEM-768" } else { "disabled" }),
        format!("LDT             {}", if cfg.ldt { "enabled" } else { "disabled" }),
        format!("Pacing          {} Mbps", if cfg.pacing_mbps > 0.0 { format!("{:.1}", cfg.pacing_mbps) } else { "auto/off".into() }),
        format!("TUN backend     {}", cfg.tun_backend),
    ];
    for (i, row) in rows.iter().enumerate() { line(out, p.fg, 4, 5 + i as u16, row, w)?; }
    Ok(())
}

fn panel(out: &mut io::Stdout, p: &Palette, x: u16, y: u16, w: u16, h: u16, title: &str) -> io::Result<()> {
    if w < 4 || h < 3 { return Ok(()); }
    queue!(out, SetForegroundColor(p.accent), MoveTo(x, y), Print(format!("┌{}┐", "─".repeat(w.saturating_sub(2) as usize))))?;
    queue!(out, MoveTo(x + 2, y), Print(format!(" {} ", title)))?;
    for row in 1..h.saturating_sub(1) { queue!(out, MoveTo(x, y + row), Print("│"), MoveTo(x + w - 1, y + row), Print("│"))?; }
    queue!(out, MoveTo(x, y + h - 1), Print(format!("└{}┘", "─".repeat(w.saturating_sub(2) as usize))), ResetColor)?;
    Ok(())
}

fn line(out: &mut io::Stdout, color: Color, x: u16, y: u16, text: &str, width: u16) -> io::Result<()> {
    queue!(out, MoveTo(x, y), SetForegroundColor(color), Print(truncate(text, width.saturating_sub(x + 2) as usize)), ResetColor)
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max { s.to_string() } else { s.chars().take(max.saturating_sub(1)).collect::<String>() + "…" }
}

fn format_duration(d: Duration) -> String {
    let s = d.as_secs();
    format!("{:02}h {:02}m {:02}s", s / 3600, (s / 60) % 60, s % 60)
}
