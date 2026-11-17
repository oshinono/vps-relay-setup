//! relay-tui — TUI для настройки relay-сервера (способ A):
//! клиент → relay (этот сервер) → основной VPS. Трафик не расшифровывается,
//! просто пробрасывается через iptables DNAT. Запускать от root.

use std::{
    fs,
    net::{Ipv4Addr, SocketAddr, TcpStream},
    process::Command,
    time::Duration,
};

use ratatui::{
    crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    layout::{Alignment, Constraint, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Paragraph, Wrap},
    DefaultTerminal, Frame,
};

/// Метка в комментариях правил: по ней находим и удаляем только свои правила.
const TAG: &str = "relay-tui";

// ───────────────────────── модель ─────────────────────────

#[derive(Clone, Copy, PartialEq)]
enum Proto {
    Tcp,
    Udp,
    Both,
}

impl Proto {
    const ALL: [Proto; 3] = [Proto::Tcp, Proto::Udp, Proto::Both];

    fn label(self) -> &'static str {
        match self {
            Proto::Tcp => "TCP",
            Proto::Udp => "UDP",
            Proto::Both => "TCP+UDP",
        }
    }

    fn names(self) -> Vec<&'static str> {
        match self {
            Proto::Tcp => vec!["tcp"],
            Proto::Udp => vec!["udp"],
            Proto::Both => vec!["tcp", "udp"],
        }
    }

    fn idx(self) -> usize {
        Proto::ALL.iter().position(|p| *p == self).unwrap_or(0)
    }

    fn cycle(self, delta: i32) -> Proto {
        let i = (self.idx() as i32 + delta).rem_euclid(3) as usize;
        Proto::ALL[i]
    }
}

struct Config {
    ip: Ipv4Addr,
    main_port: u16,
    listen_port: u16,
    proto: Proto,
}

#[derive(Clone, Copy, PartialEq)]
enum Lvl {
    Info,
    Ok,
    Warn,
    Err,
    Out,
}

#[derive(Clone, Copy)]
enum Action {
    Apply,
    Remove,
    Status,
    Test,
    Persist,
}

const BUTTONS: [(&str, &str, Action); 5] = [
    ("F5", "Применить правила", Action::Apply),
    ("F6", "Удалить правила", Action::Remove),
    ("F7", "Показать статус", Action::Status),
    ("F8", "Проверить основной VPS", Action::Test),
    ("F9", "Сохранить после перезагрузки", Action::Persist),
];

const F_IP: usize = 0;
const F_MAIN_PORT: usize = 1;
const F_LISTEN_PORT: usize = 2;
const F_PROTO: usize = 3;
const F_BTN0: usize = 4;
const TOTAL: usize = F_BTN0 + BUTTONS.len();

struct App {
    main_ip: String,
    main_port: String,
    listen_port: String,
    proto: Proto,
    focus: usize,
    log: Vec<(Lvl, String)>,
    log_offset: usize,
    is_root: bool,
    busy: bool,
    quit: bool,
}

// ───────────────────────── системные команды ─────────────────────────

fn run<S: AsRef<str>>(args: &[S]) -> (bool, String) {
    let name: &str = args[0].as_ref();
    let rest: Vec<&str> = args[1..].iter().map(|a| a.as_ref()).collect();
    match Command::new(name).args(rest).output() {
        Ok(o) => {
            let mut s = String::from_utf8_lossy(&o.stdout).to_string();
            s.push_str(&String::from_utf8_lossy(&o.stderr));
            (o.status.success(), s.trim().to_string())
        }
        Err(e) => (false, format!("{name}: {e}")),
    }
}

fn tail(text: &str, n: usize) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(n);
    lines[start..].join("\n")
}

struct Rule {
    table: &'static str,
    chain: &'static str,
    insert: bool,
    spec: Vec<String>,
}

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

fn rules_for(cfg: &Config, p: &str) -> Vec<Rule> {
    let ip = cfg.ip.to_string();
    let mp = cfg.main_port.to_string();
    let lp = cfg.listen_port.to_string();
    let cm = format!("{TAG}:{p}:{lp}->{ip}:{mp}");
    let to = format!("{ip}:{mp}");
    vec![
        Rule {
            table: "nat",
            chain: "PREROUTING",
            insert: false,
            spec: s(&[
                "-p", p, "--dport", &lp, "-m", "comment", "--comment", &cm, "-j", "DNAT",
                "--to-destination", &to,
            ]),
        },
        Rule {
            table: "nat",
            chain: "POSTROUTING",
            insert: false,
            spec: s(&[
                "-p", p, "-d", &ip, "--dport", &mp, "-m", "comment", "--comment", &cm, "-j",
                "MASQUERADE",
            ]),
        },
        Rule {
            table: "filter",
            chain: "FORWARD",
            insert: true,
            spec: s(&[
                "-p", p, "-d", &ip, "--dport", &mp, "-m", "comment", "--comment", &cm, "-j",
                "ACCEPT",
            ]),
        },
    ]
}

fn conntrack_rule() -> Rule {
    let cm = format!("{TAG}:conntrack");
    Rule {
        table: "filter",
        chain: "FORWARD",
        insert: true,
        spec: s(&[
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-m",
            "comment",
            "--comment",
            &cm,
            "-j",
            "ACCEPT",
        ]),
    }
}

fn ipt(r: &Rule, op: &str) -> Vec<String> {
    let mut v = vec![
        "iptables".to_string(),
        "-w".to_string(),
        "-t".to_string(),
        r.table.to_string(),
        op.to_string(),
        r.chain.to_string(),
    ];
    v.extend(r.spec.iter().cloned());
    v
}

// ───────────────────────── логика приложения ─────────────────────────

impl App {
    fn new() -> Self {
        let is_root = run(&["id", "-u"]).1 == "0";
        let mut app = App {
            main_ip: String::new(),
            main_port: "443".into(),
            listen_port: "443".into(),
            proto: Proto::Tcp,
            focus: 0,
            log: vec![],
            log_offset: 0,
            is_root,
            busy: false,
            quit: false,
        };
        app.push(Lvl::Info, "Relay-проброс: клиент → этот сервер → основной VPS.");
        app.push(Lvl::Out, "Заполни параметры слева и нажми F5.");
        app.push(Lvl::Out, "VLESS/Xray → TCP, AmneziaWG/WireGuard → UDP.");
        if !is_root {
            app.push(Lvl::Err, "Нет прав root. Запусти: sudo ./relay-tui");
        }
        app
    }

    fn push(&mut self, lvl: Lvl, text: impl AsRef<str>) {
        for line in text.as_ref().lines() {
            self.log.push((lvl, line.to_string()));
        }
        if self.log.len() > 1000 {
            self.log.drain(..200);
        }
        self.log_offset = 0;
    }

    fn field_mut(&mut self) -> Option<(&mut String, bool)> {
        match self.focus {
            F_IP => Some((&mut self.main_ip, true)),
            F_MAIN_PORT => Some((&mut self.main_port, false)),
            F_LISTEN_PORT => Some((&mut self.listen_port, false)),
            _ => None,
        }
    }

    fn on_key(&mut self, key: KeyEvent) -> Option<Action> {
        if key.kind != KeyEventKind::Press {
            return None;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.quit = true;
            return None;
        }
        match key.code {
            KeyCode::Esc => self.quit = true,
            KeyCode::Tab | KeyCode::Down => self.focus = (self.focus + 1) % TOTAL,
            KeyCode::BackTab | KeyCode::Up => self.focus = (self.focus + TOTAL - 1) % TOTAL,
            KeyCode::F(5) => return Some(Action::Apply),
            KeyCode::F(6) => return Some(Action::Remove),
            KeyCode::F(7) => return Some(Action::Status),
            KeyCode::F(8) => return Some(Action::Test),
            KeyCode::F(9) => return Some(Action::Persist),
            KeyCode::PageUp => self.log_offset += 5,
            KeyCode::PageDown => self.log_offset = self.log_offset.saturating_sub(5),
            KeyCode::Enter => {
                if self.focus >= F_BTN0 {
                    return Some(BUTTONS[self.focus - F_BTN0].2);
                }
                self.focus = (self.focus + 1) % TOTAL;
            }
            KeyCode::Left if self.focus == F_PROTO => self.proto = self.proto.cycle(-1),
            KeyCode::Right | KeyCode::Char(' ') if self.focus == F_PROTO => {
                self.proto = self.proto.cycle(1)
            }
            KeyCode::Backspace => {
                if let Some((text, _)) = self.field_mut() {
                    text.pop();
                }
            }
            KeyCode::Char(c) => {
                if let Some((text, is_ip)) = self.field_mut() {
                    let allowed = if is_ip {
                        c.is_ascii_digit() || c == '.'
                    } else {
                        c.is_ascii_digit()
                    };
                    let max = if is_ip { 15 } else { 5 };
                    if allowed && text.len() < max {
                        text.push(c);
                    }
                }
            }
            _ => {}
        }
        None
    }

    fn config(&self) -> Result<Config, String> {
        let ip: Ipv4Addr = self
            .main_ip
            .parse()
            .map_err(|_| "Некорректный IPv4 основного VPS".to_string())?;
        let main_port: u16 = self
            .main_port
            .parse()
            .ok()
            .filter(|p| *p > 0)
            .ok_or("Некорректный порт основного VPS")?;
        let listen_port: u16 = self
            .listen_port
            .parse()
            .ok()
            .filter(|p| *p > 0)
            .ok_or("Некорректный порт на relay")?;
        Ok(Config {
            ip,
            main_port,
            listen_port,
            proto: self.proto,
        })
    }

    fn need_root(&mut self) -> bool {
        if !self.is_root {
            self.push(Lvl::Err, "Нужны права root: запусти `sudo ./relay-tui`");
        }
        self.is_root
    }

    fn exec(&mut self, action: Action) {
        self.push(Lvl::Info, "────────────────────────────");
        match action {
            Action::Apply => self.apply(),
            Action::Remove => self.remove(),
            Action::Status => self.status(),
            Action::Test => self.test(),
            Action::Persist => self.persist(),
        }
    }

    fn ensure(&mut self, r: &Rule) {
        let name = format!("{}/{}", r.table, r.chain);
        if run(&ipt(r, "-C")).0 {
            self.push(Lvl::Info, format!("{name}: правило уже есть"));
            return;
        }
        let op = if r.insert { "-I" } else { "-A" };
        let (ok, out) = run(&ipt(r, op));
        if ok {
            self.push(Lvl::Ok, format!("{name}: добавлено"));
        } else {
            self.push(Lvl::Err, format!("{name}: {out}"));
        }
    }

    fn apply(&mut self) {
        if !self.need_root() {
            return;
        }
        let cfg = match self.config() {
            Ok(c) => c,
            Err(e) => {
                self.push(Lvl::Err, e);
                return;
            }
        };
        if cfg.listen_port == 22 {
            self.push(
                Lvl::Err,
                "Порт 22 на relay — это твой SSH, пробросом его не перехватываем. Выбери другой.",
            );
            return;
        }

        let (ok, out) = run(&["sysctl", "-w", "net.ipv4.ip_forward=1"]);
        if ok {
            self.push(Lvl::Ok, "ip_forward включён");
        } else {
            self.push(Lvl::Err, format!("sysctl: {out}"));
            return;
        }
        match fs::write("/etc/sysctl.d/99-relay.conf", "net.ipv4.ip_forward=1\n") {
            Ok(_) => self.push(Lvl::Ok, "ip_forward сохранён в /etc/sysctl.d/99-relay.conf"),
            Err(e) => self.push(Lvl::Warn, format!("Не записал sysctl.d: {e}")),
        }

        for p in cfg.proto.names() {
            self.push(
                Lvl::Info,
                format!(
                    "{}: :{} → {}:{}",
                    p.to_uppercase(),
                    cfg.listen_port,
                    cfg.ip,
                    cfg.main_port
                ),
            );
            for r in rules_for(&cfg, p) {
                self.ensure(&r);
            }
        }
        self.ensure(&conntrack_rule());

        let (ok, out) = run(&["ufw", "status"]);
        if ok && out.contains("Status: active") {
            self.push(
                Lvl::Warn,
                "ufw активен: разреши порт (ufw allow) и поставь DEFAULT_FORWARD_POLICY=\"ACCEPT\" в /etc/default/ufw.",
            );
        }

        self.push(Lvl::Ok, "Готово.");
        self.push(
            Lvl::Info,
            format!(
                "В Happ замени адрес сервера на IP этого relay, порт — {}. Остальное не трогай.",
                cfg.listen_port
            ),
        );
        self.push(Lvl::Warn, "Чтобы правила пережили перезагрузку — нажми F9.");
    }

    fn remove(&mut self) {
        if !self.need_root() {
            return;
        }
        let cfg = match self.config() {
            Ok(c) => c,
            Err(e) => {
                self.push(Lvl::Err, e);
                return;
            }
        };
        let mut removed = 0;
        for p in cfg.proto.names() {
            for r in rules_for(&cfg, p) {
                for _ in 0..10 {
                    if !run(&ipt(&r, "-C")).0 {
                        break;
                    }
                    if run(&ipt(&r, "-D")).0 {
                        removed += 1;
                    } else {
                        break;
                    }
                }
            }
        }
        if removed > 0 {
            self.push(Lvl::Ok, format!("Удалено правил: {removed}"));
            self.push(
                Lvl::Out,
                "Общее правило conntrack (FORWARD) и ip_forward не трогаю — они безвредны.",
            );
            self.push(Lvl::Warn, "Нажми F9, чтобы сохранить новое состояние.");
        } else {
            self.push(Lvl::Warn, "Правил с такими параметрами не найдено.");
        }
    }

    fn status(&mut self) {
        if !self.need_root() {
            return;
        }
        let (_, fwd) = run(&["sysctl", "-n", "net.ipv4.ip_forward"]);
        if fwd.trim() == "1" {
            self.push(Lvl::Ok, "ip_forward = 1");
        } else {
            self.push(Lvl::Err, "ip_forward = 0 (проброс не работает)");
        }

        let mut found = false;
        for (title, args) in [
            ("nat", vec!["iptables", "-w", "-t", "nat", "-S"]),
            ("filter", vec!["iptables", "-w", "-S", "FORWARD"]),
        ] {
            let (_, out) = run(&args);
            let mine: Vec<&str> = out.lines().filter(|l| l.contains(TAG)).collect();
            if !mine.is_empty() {
                found = true;
                self.push(Lvl::Info, format!("таблица {title}:"));
                for l in mine {
                    self.push(Lvl::Out, l);
                }
            }
        }
        if !found {
            self.push(Lvl::Warn, "Правил relay-tui не найдено.");
        }
    }

    fn test(&mut self) {
        let cfg = match self.config() {
            Ok(c) => c,
            Err(e) => {
                self.push(Lvl::Err, e);
                return;
            }
        };
        let ip = cfg.ip.to_string();
        let (ok, out) = run(&["ping", "-c", "2", "-W", "2", &ip]);
        if ok {
            self.push(Lvl::Ok, format!("ping {ip}: отвечает"));
            self.push(Lvl::Out, tail(&out, 2));
        } else {
            self.push(
                Lvl::Warn,
                format!("ping {ip}: нет ответа (ICMP мог быть закрыт, смотри TCP ниже)"),
            );
        }

        if cfg.proto != Proto::Udp {
            let addr: Result<SocketAddr, _> = format!("{ip}:{}", cfg.main_port).parse();
            match addr {
                Ok(a) => match TcpStream::connect_timeout(&a, Duration::from_secs(3)) {
                    Ok(_) => self.push(Lvl::Ok, format!("TCP {ip}:{} доступен", cfg.main_port)),
                    Err(e) => self.push(
                        Lvl::Err,
                        format!("TCP {ip}:{} недоступен: {e}", cfg.main_port),
                    ),
                },
                Err(e) => self.push(Lvl::Err, format!("адрес: {e}")),
            }
        }
        if cfg.proto != Proto::Tcp {
            self.push(
                Lvl::Out,
                "UDP простым подключением не проверить: смотри `awg show` (handshake) на основном VPS.",
            );
        }
    }

    fn persist(&mut self) {
        if !self.need_root() {
            return;
        }
        if !run(&["sh", "-c", "command -v netfilter-persistent"]).0 {
            self.push(Lvl::Info, "Ставлю iptables-persistent…");
            let (ok, out) = run(&[
                "env",
                "DEBIAN_FRONTEND=noninteractive",
                "apt-get",
                "install",
                "-y",
                "iptables-persistent",
            ]);
            if !ok {
                self.push(Lvl::Err, tail(&out, 5));
                return;
            }
            self.push(Lvl::Ok, "iptables-persistent установлен");
        }
        let (ok, out) = run(&["netfilter-persistent", "save"]);
        if ok {
            self.push(Lvl::Ok, "Правила сохранены, переживут перезагрузку");
        } else {
            self.push(Lvl::Err, tail(&out, 5));
        }
    }
}

// ───────────────────────── отрисовка ─────────────────────────

fn valid_ip(v: &str) -> bool {
    v.parse::<Ipv4Addr>().is_ok()
}

fn valid_port(v: &str) -> bool {
    v.parse::<u16>().map(|p| p > 0).unwrap_or(false)
}

fn field_line(app: &App, idx: usize, label: &str, value: &str, valid: bool) -> Line<'static> {
    let focused = app.focus == idx;
    let mark = if focused { "▸ " } else { "  " };
    let label_style = if focused {
        Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD)
    } else {
        Style::new().fg(Color::Gray)
    };
    let value_style = if !valid {
        Style::new().fg(Color::Red)
    } else if focused {
        Style::new().fg(Color::White).add_modifier(Modifier::BOLD)
    } else {
        Style::new().fg(Color::White)
    };
    let mut shown = value.to_string();
    if focused {
        shown.push('█');
    }
    Line::from(vec![
        Span::styled(format!("{mark}{label:<18}"), label_style),
        Span::styled(shown, value_style),
    ])
}

fn ui(f: &mut Frame, app: &App) {
    let [head, body, foot] = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(12),
        Constraint::Length(4),
    ])
    .areas(f.area());
    let [left, right] =
        Layout::horizontal([Constraint::Percentage(44), Constraint::Percentage(56)]).areas(body);
    let [fields_a, btn_a, hint_a] = Layout::vertical([
        Constraint::Length(6),
        Constraint::Length(7),
        Constraint::Min(3),
    ])
    .areas(left);

    // шапка
    let status = if app.busy {
        Span::styled(" ⏳ выполняется… ", Style::new().fg(Color::Yellow))
    } else if app.is_root {
        Span::styled(" root ✔ ", Style::new().fg(Color::Green))
    } else {
        Span::styled(" нет root — запусти через sudo ", Style::new().fg(Color::Red))
    };
    let title = Line::from(vec![
        Span::styled(
            " Relay Setup ",
            Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ),
        Span::raw("· способ A: проброс через iptables DNAT "),
        status,
    ]);
    f.render_widget(
        Paragraph::new(title)
            .alignment(Alignment::Center)
            .block(Block::bordered().border_type(BorderType::Rounded)),
        head,
    );

    // поля
    let mut proto_spans = vec![Span::styled(
        format!(
            "{}{:<18}",
            if app.focus == F_PROTO { "▸ " } else { "  " },
            "Протокол"
        ),
        if app.focus == F_PROTO {
            Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD)
        } else {
            Style::new().fg(Color::Gray)
        },
    )];
    for p in Proto::ALL {
        let style = if p == app.proto {
            Style::new()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::new().fg(Color::DarkGray)
        };
        proto_spans.push(Span::styled(format!(" {} ", p.label()), style));
        proto_spans.push(Span::raw(" "));
    }
    let fields = vec![
        field_line(app, F_IP, "IP основного VPS", &app.main_ip, valid_ip(&app.main_ip)),
        field_line(
            app,
            F_MAIN_PORT,
            "Порт основного",
            &app.main_port,
            valid_port(&app.main_port),
        ),
        field_line(
            app,
            F_LISTEN_PORT,
            "Порт на relay",
            &app.listen_port,
            valid_port(&app.listen_port),
        ),
        Line::from(proto_spans),
    ];
    f.render_widget(
        Paragraph::new(fields).block(
            Block::bordered()
                .border_type(BorderType::Rounded)
                .title(" Параметры "),
        ),
        fields_a,
    );

    // кнопки
    let buttons: Vec<Line> = BUTTONS
        .iter()
        .enumerate()
        .map(|(i, (key, label, _))| {
            let focused = app.focus == F_BTN0 + i;
            let style = if focused {
                Style::new()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::new().fg(Color::White)
            };
            Line::from(Span::styled(format!(" [{key}] {label} "), style))
        })
        .collect();
    f.render_widget(
        Paragraph::new(buttons).block(
            Block::bordered()
                .border_type(BorderType::Rounded)
                .title(" Действия "),
        ),
        btn_a,
    );

    // подсказка
    let lp = if valid_port(&app.listen_port) {
        app.listen_port.as_str()
    } else {
        "…"
    };
    let hint = format!(
        "Happ: адрес = IP этого сервера, порт = {lp}. UUID, flow, SNI, public key и shortId — как у основного VPS."
    );
    f.render_widget(
        Paragraph::new(hint)
            .style(Style::new().fg(Color::Gray))
            .wrap(Wrap { trim: true })
            .block(
                Block::bordered()
                    .border_type(BorderType::Rounded)
                    .title(" Подсказка "),
            ),
        hint_a,
    );

    // журнал
    let h = right.height.saturating_sub(2) as usize;
    let total = app.log.len();
    let off = app.log_offset.min(total.saturating_sub(h));
    let end = total - off;
    let start = end.saturating_sub(h);
    let lines: Vec<Line> = app.log[start..end]
        .iter()
        .map(|(lvl, text)| {
            let (prefix, color) = match lvl {
                Lvl::Info => ("▶ ", Color::Cyan),
                Lvl::Ok => ("✔ ", Color::Green),
                Lvl::Warn => ("! ", Color::Yellow),
                Lvl::Err => ("✘ ", Color::Red),
                Lvl::Out => ("  ", Color::DarkGray),
            };
            Line::from(Span::styled(
                format!("{prefix}{text}"),
                Style::new().fg(color),
            ))
        })
        .collect();
    let log_title = if off > 0 {
        format!(" Журнал (↑{off}) ")
    } else {
        " Журнал ".to_string()
    };
    f.render_widget(
        Paragraph::new(lines).block(
            Block::bordered()
                .border_type(BorderType::Rounded)
                .title(log_title),
        ),
        right,
    );

    // подвал
    f.render_widget(
        Paragraph::new(
            "Tab/↑↓ поле · ←→/Пробел протокол · Enter действие · F5 применить · F6 удалить · \
             F7 статус · F8 проверить · F9 сохранить · PgUp/PgDn журнал · Esc выход",
        )
        .style(Style::new().fg(Color::DarkGray))
        .wrap(Wrap { trim: true })
        .block(Block::bordered().border_type(BorderType::Rounded)),
        foot,
    );
}

// ───────────────────────── main ─────────────────────────

fn run_app(terminal: &mut DefaultTerminal) -> std::io::Result<()> {
    let mut app = App::new();
    while !app.quit {
        terminal.draw(|f| ui(f, &app))?;
        if let Event::Key(key) = event::read()? {
            if let Some(action) = app.on_key(key) {
                app.busy = true;
                terminal.draw(|f| ui(f, &app))?;
                app.exec(action);
                app.busy = false;
            }
        }
    }
    Ok(())
}

fn main() -> std::io::Result<()> {
    let mut terminal = ratatui::init();
    let result = run_app(&mut terminal);
    ratatui::restore();
    result
}
