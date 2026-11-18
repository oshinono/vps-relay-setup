//! relay-tui — IPv4 TCP/UDP relay через iptables DNAT.

use std::{
    fs,
    io::{self, Write},
    net::Ipv4Addr,
    path::Path,
    process::Command,
    sync::mpsc::{self, Receiver, TryRecvError},
    thread,
    time::Duration,
};

use ratatui::{
    crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    layout::{Constraint, Layout},
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, BorderType, List, ListItem, ListState, Paragraph, Wrap},
    DefaultTerminal, Frame,
};

const TAG: &str = "relay-tui";
const CONFIG: &str = "/etc/relay-tui/routes";
const RELEASE_SUMS: &str =
    "https://github.com/oshinono/vps-relay-setup/releases/latest/download/SHA256SUMS";

fn release_hash(sums: &str, asset: &str) -> Option<String> {
    let mut matches = sums.lines().filter_map(|line| {
        let mut parts = line.split_whitespace();
        let hash = parts.next()?;
        (parts.next()? == asset).then_some(hash)
    });
    let hash = matches.next()?;
    (matches.next().is_none() && hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| hash.to_ascii_lowercase())
}

fn check_update() -> Result<bool, String> {
    let target = match std::env::consts::ARCH {
        "x86_64" => "x86_64-unknown-linux-musl",
        "aarch64" => "aarch64-unknown-linux-musl",
        "arm" => "armv7-unknown-linux-musleabihf",
        "x86" => "i686-unknown-linux-musl",
        _ => return Err("архитектура не поддерживается".into()),
    };
    let sums = command(
        "curl",
        &[
            "-q",
            "-fsSL",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--connect-timeout",
            "5",
            "--max-time",
            "15",
            RELEASE_SUMS,
        ],
    )?;
    let latest = release_hash(&sums, &format!("relay-tui-{target}"))
        .ok_or("в релизе нет корректной контрольной суммы")?;
    let running = fs::File::open("/proc/self/exe").map_err(|e| e.to_string())?;
    let local = Command::new("sha256sum")
        .stdin(running)
        .output()
        .map_err(|e| format!("sha256sum: {e}"))?;
    if !local.status.success() {
        return Err("не удалось вычислить SHA-256".into());
    }
    let local = String::from_utf8_lossy(&local.stdout);
    Ok(local.split_whitespace().next() != Some(latest.as_str()))
}

#[derive(Clone, Copy, PartialEq, Eq)]
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

#[derive(Clone, Copy, PartialEq, Eq)]
struct Config {
    ip: Ipv4Addr,
    main_port: u16,
    listen_port: u16,
    proto: Proto,
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
                "-p",
                p,
                "--dport",
                &lp,
                "-m",
                "comment",
                "--comment",
                &cm,
                "-j",
                "DNAT",
                "--to-destination",
                &to,
            ]),
        },
        Rule {
            table: "nat",
            chain: "POSTROUTING",
            insert: false,
            spec: s(&[
                "-p",
                p,
                "-d",
                &ip,
                "--dport",
                &mp,
                "-m",
                "comment",
                "--comment",
                &cm,
                "-j",
                "MASQUERADE",
            ]),
        },
        Rule {
            table: "filter",
            chain: "FORWARD",
            insert: true,
            spec: s(&[
                "-p",
                p,
                "-d",
                &ip,
                "--dport",
                &mp,
                "-m",
                "comment",
                "--comment",
                &cm,
                "-j",
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

fn command<S: AsRef<std::ffi::OsStr>>(name: &str, args: &[S]) -> Result<String, String> {
    let out = Command::new(name)
        .args(args)
        .env("LC_ALL", "C")
        .output()
        .map_err(|e| format!("{name}: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr);
        Err(format!(
            "{name}: {}",
            stderr
                .trim()
                .lines()
                .next()
                .unwrap_or("команда завершилась с ошибкой")
        ))
    }
}

impl Config {
    fn parse(proto: Proto, route: &str) -> Option<Self> {
        let (listen, dest) = route.split_once("->")?;
        let (ip, port) = dest.split_once(':')?;
        let (listen_port, main_port) = (listen.parse().ok()?, port.parse().ok()?);
        (listen_port != 0 && main_port != 0).then_some(Self {
            ip: ip.parse().ok()?,
            listen_port,
            main_port,
            proto,
        })
    }

    fn route(self) -> String {
        format!("{}->{}:{}", self.listen_port, self.ip, self.main_port)
    }

    fn overlaps(self, other: Self) -> bool {
        self.listen_port == other.listen_port
            && (self.proto == other.proto
                || self.proto == Proto::Both
                || other.proto == Proto::Both)
    }

    fn rules(self) -> impl Iterator<Item = Rule> {
        self.proto
            .names()
            .into_iter()
            .flat_map(move |p| rules_for(&self, p))
    }
}

fn load_routes(path: &Path) -> Result<Vec<Config>, String> {
    let data = match fs::read_to_string(path) {
        Ok(data) => data,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.to_string()),
    };
    data.lines()
        .enumerate()
        .map(|(i, line)| {
            let (proto, route) = line.split_once(' ').unwrap_or_default();
            Proto::ALL
                .into_iter()
                .find(|p| p.label() == proto)
                .and_then(|p| Config::parse(p, route))
                .ok_or_else(|| format!("Некорректная строка {} в {}", i + 1, path.display()))
        })
        .collect()
}

fn save_routes(routes: &[Config]) -> io::Result<()> {
    let path = Path::new(CONFIG);
    let dir = path.parent().unwrap();
    fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(".routes.{}", std::process::id()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)?;
    let result = (|| {
        for cfg in routes {
            writeln!(file, "{} {}", cfg.proto.label(), cfg.route())?;
        }
        file.sync_all()?;
        fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(tmp);
    }
    result
}

fn discover(rules: &str) -> Vec<Config> {
    let mut routes: Vec<Config> = Vec::new();
    for line in rules.lines() {
        let Some((_, comment)) = line.split_once(" --comment ") else {
            continue;
        };
        let Some((proto, route)) = comment
            .split_whitespace()
            .next()
            .and_then(|s| s.trim_matches('"').strip_prefix("relay-tui:"))
            .and_then(|s| s.split_once(':'))
        else {
            continue;
        };
        let proto = match proto {
            "tcp" => Proto::Tcp,
            "udp" => Proto::Udp,
            _ => continue,
        };
        let Some(cfg) = Config::parse(proto, route) else {
            continue;
        };
        if let Some(existing) = routes.iter_mut().find(|r| {
            r.ip == cfg.ip && r.listen_port == cfg.listen_port && r.main_port == cfg.main_port
        }) {
            if existing.proto != proto {
                existing.proto = Proto::Both;
            }
        } else {
            routes.push(cfg);
        }
    }
    routes
}

fn rule_command(rule: &Rule, op: &str) -> Result<String, String> {
    command("iptables", &ipt(rule, op)[1..])
}

fn present(rule: &Rule) -> Result<bool, String> {
    match rule_command(rule, "-C") {
        Ok(_) => Ok(true),
        Err(e) if e.contains("Bad rule (does a matching rule exist in that chain?)") => Ok(false),
        Err(e) => Err(e),
    }
}

#[derive(Clone, Copy)]
enum Status {
    Off,
    On,
    Partial,
    Unknown,
}

struct Firewall {
    forwarding: bool,
    return_rule: bool,
}

impl Firewall {
    fn status(&self, cfg: Config) -> Result<Status, String> {
        let checks = cfg
            .rules()
            .map(|r| present(&r))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(if !checks.contains(&true) {
            Status::Off
        } else if !checks.contains(&false) && self.forwarding && self.return_rule {
            Status::On
        } else {
            Status::Partial
        })
    }
}

struct Editor {
    fields: [String; 3],
    proto: Proto,
    focus: usize,
    cursor: usize,
    original: Option<usize>,
}

impl Editor {
    fn new(original: Option<usize>, cfg: Option<Config>) -> Self {
        let fields = cfg
            .map(|c| {
                [
                    c.ip.to_string(),
                    c.main_port.to_string(),
                    c.listen_port.to_string(),
                ]
            })
            .unwrap_or_else(|| [String::new(), "443".into(), "443".into()]);
        let cursor = fields[0].len();
        Self {
            fields,
            proto: cfg.map_or(Proto::Tcp, |c| c.proto),
            focus: 0,
            cursor,
            original,
        }
    }

    fn next(&mut self, delta: usize) {
        self.focus = (self.focus + delta) % 4;
        self.cursor = self.fields.get(self.focus).map_or(0, String::len);
    }

    fn input(&mut self, code: KeyCode) {
        if let Some(value) = self.fields.get_mut(self.focus) {
            let max = if self.focus == 0 { 15 } else { 5 };
            match code {
                KeyCode::Left => self.cursor = self.cursor.saturating_sub(1),
                KeyCode::Right => self.cursor = (self.cursor + 1).min(value.len()),
                KeyCode::Home => self.cursor = 0,
                KeyCode::End => self.cursor = value.len(),
                KeyCode::Backspace if self.cursor > 0 => {
                    self.cursor -= 1;
                    value.remove(self.cursor);
                }
                KeyCode::Delete if self.cursor < value.len() => {
                    value.remove(self.cursor);
                }
                KeyCode::Char(c)
                    if value.len() < max
                        && (c.is_ascii_digit() || (self.focus == 0 && c == '.')) =>
                {
                    value.insert(self.cursor, c);
                    self.cursor += 1;
                }
                _ => {}
            }
        } else {
            match code {
                KeyCode::Left => self.proto = self.proto.cycle(-1),
                KeyCode::Right | KeyCode::Char(' ') => self.proto = self.proto.cycle(1),
                _ => {}
            }
        }
    }

    fn config(&self) -> Result<Config, String> {
        let [ip, target, listen] = &self.fields;
        let cfg = Config::parse(self.proto, &format!("{listen}->{ip}:{target}"))
            .ok_or("Нужны IPv4-адрес и порты от 1 до 65535.")?;
        if cfg.listen_port == 22 {
            return Err("Порт 22 зарезервирован для SSH.".into());
        }
        Ok(cfg)
    }
}

struct App {
    routes: Vec<Config>,
    statuses: Vec<Status>,
    list: ListState,
    editor: Option<Editor>,
    access: Option<String>,
    config_error: Option<String>,
    firewall_error: Option<String>,
    message: String,
    confirm_delete: bool,
    update: String,
    update_check: Option<Receiver<Result<bool, String>>>,
}

impl App {
    fn new() -> Self {
        let access = if !cfg!(target_os = "linux") {
            Some("Для управления правилами нужен Linux.".into())
        } else if !matches!(command("id", &["-u"]), Ok(uid) if uid.trim() == "0") {
            Some(
                "Только просмотр. Для управления установи от root: /usr/local/bin/relay-tui".into(),
            )
        } else {
            None
        };
        let (routes, config_error) = match load_routes(Path::new(CONFIG)) {
            Ok(routes) => (routes, None),
            Err(e) => (Vec::new(), Some(e)),
        };
        let mut app = Self {
            routes,
            statuses: Vec::new(),
            list: ListState::default(),
            editor: None,
            access,
            config_error,
            firewall_error: None,
            message: String::new(),
            confirm_delete: false,
            update: String::new(),
            update_check: None,
        };
        app.refresh();
        app.start_update_check();
        app
    }

    fn start_update_check(&mut self) {
        if !cfg!(target_os = "linux") || self.update_check.is_some() {
            return;
        }
        let (send, receive) = mpsc::channel();
        self.update = "Проверка обновлений…".into();
        self.update_check = Some(receive);
        thread::spawn(move || {
            let _ = send.send(check_update());
        });
    }

    fn poll_update(&mut self) {
        let Some(check) = &self.update_check else {
            return;
        };
        self.update = match check.try_recv() {
            Ok(Ok(false)) => "Установлен актуальный билд".into(),
            Ok(Ok(true)) => "Доступен другой билд из последнего релиза. Запусти install.sh.".into(),
            Ok(Err(e)) => format!("Не удалось проверить обновления: {e}"),
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => "Проверка обновлений прервана".into(),
        };
        self.update_check = None;
    }

    fn refresh(&mut self) {
        self.firewall_error = None;
        self.statuses = vec![Status::Unknown; self.routes.len()];
        if self.access.is_none() {
            if let Err(e) = self.read_firewall() {
                self.firewall_error = Some(e);
            }
        }
        let selected = self
            .list
            .selected()
            .unwrap_or(0)
            .min(self.routes.len().saturating_sub(1));
        self.list
            .select((!self.routes.is_empty()).then_some(selected));
    }

    fn read_firewall(&mut self) -> Result<(), String> {
        let nat = command("iptables", &["-w", "-t", "nat", "-S"])?;
        let filter = command("iptables", &["-w", "-S", "FORWARD"])?;
        for mut cfg in discover(&format!("{nat}\n{filter}")) {
            let mut missing = [Proto::Tcp, Proto::Udp].into_iter().filter(|&proto| {
                let single = Config { proto, ..cfg };
                single.overlaps(cfg)
                    && !self.routes.iter().any(|r| {
                        r.ip == cfg.ip && r.main_port == cfg.main_port && r.overlaps(single)
                    })
            });
            if let Some(proto) = missing.next() {
                cfg.proto = if missing.next().is_some() {
                    Proto::Both
                } else {
                    proto
                };
                self.routes.push(cfg);
            }
        }
        self.statuses.resize(self.routes.len(), Status::Unknown);
        let firewall = Firewall {
            forwarding: command("sysctl", &["-n", "net.ipv4.ip_forward"])?.trim() == "1",
            return_rule: present(&conntrack_rule())?,
        };
        for (status, cfg) in self.statuses.iter_mut().zip(&self.routes) {
            *status = firewall.status(*cfg)?;
        }
        Ok(())
    }

    fn writable(&self) -> Result<(), String> {
        if let Some(e) = self
            .access
            .as_ref()
            .or(self.config_error.as_ref())
            .or(self.firewall_error.as_ref())
        {
            Err(e.clone())
        } else {
            Ok(())
        }
    }

    fn store(&mut self, routes: Vec<Config>) -> Result<(), String> {
        save_routes(&routes).map_err(|e| format!("Не сохранил {CONFIG}: {e}"))?;
        self.routes = routes;
        Ok(())
    }

    fn save_editor(&mut self) -> Result<&'static str, String> {
        self.writable()?;
        let edit = self.editor.as_ref().unwrap();
        let cfg = edit.config()?;
        let mut routes = self.routes.clone();
        if routes
            .iter()
            .enumerate()
            .any(|(i, c)| Some(i) != edit.original && c.overlaps(cfg))
        {
            return Err("Этот входной порт уже занят релеем с тем же протоколом.".into());
        }
        let index = edit.original.unwrap_or(routes.len());
        if let Some(old) = routes.get_mut(index) {
            if *old != cfg && !matches!(self.statuses[index], Status::Off) {
                return Err("Сначала отключи релей в списке, затем измени его.".into());
            }
            *old = cfg;
        } else {
            routes.push(cfg);
        }
        self.store(routes)?;
        self.editor = None;
        self.list.select(Some(index));
        self.refresh();
        Ok("Маршрут сохранён. A — применить.")
    }

    fn toggle(&mut self, enable: bool) -> Result<&'static str, String> {
        self.refresh();
        self.writable()?;
        let i = self.list.selected().ok_or("Нет выбранного релея.")?;
        let cfg = self.routes[i];
        save_routes(&self.routes).map_err(|e| format!("Не сохранил {CONFIG}: {e}"))?;
        if enable {
            if cfg.listen_port == 22 {
                return Err("Порт 22 зарезервирован для SSH.".into());
            }
            if self
                .routes
                .iter()
                .zip(&self.statuses)
                .enumerate()
                .any(|(j, (other, status))| {
                    i != j && other.overlaps(cfg) && !matches!(status, Status::Off)
                })
            {
                return Err("Входной порт уже занят активным релеем с тем же протоколом.".into());
            }
            command("sysctl", &["-w", "net.ipv4.ip_forward=1"])?;
            fs::write(
                "/etc/sysctl.d/99-relay.conf",
                "net.ipv4.ip_forward=1
",
            )
            .map_err(|e| format!("Не сохранил ip_forward: {e}"))?;
            for r in cfg.rules().chain(std::iter::once(conntrack_rule())) {
                if !present(&r)? {
                    rule_command(&r, if r.insert { "-I" } else { "-A" })?;
                }
            }
            Ok("Правила применены. P — сохранить после перезагрузки.")
        } else {
            for r in cfg.rules() {
                for _ in 0..10 {
                    if !present(&r)? {
                        break;
                    }
                    rule_command(&r, "-D")?;
                }
                if present(&r)? {
                    return Err("Остались дубликаты правил. Повтори отключение.".into());
                }
            }
            Ok("Правила отключены. P — сохранить после перезагрузки.")
        }
    }

    fn delete(&mut self) -> Result<&'static str, String> {
        self.refresh();
        self.writable()?;
        let i = self.list.selected().ok_or("Нет выбранного релея.")?;
        if !matches!(self.statuses[i], Status::Off) {
            return Err("Сначала отключи правила клавишей X.".into());
        }
        let mut routes = self.routes.clone();
        routes.remove(i);
        self.store(routes)?;
        self.refresh();
        Ok("Маршрут удалён.")
    }

    fn key(&mut self, key: KeyEvent) -> bool {
        if !matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
            return false;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return true;
        }
        if let Some(editor) = &mut self.editor {
            match key.code {
                KeyCode::Esc => {
                    self.editor = None;
                    self.message.clear();
                }
                KeyCode::Enter if key.kind == KeyEventKind::Press => {
                    self.refresh();
                    self.message = self.save_editor().unwrap_or_else_message();
                }
                KeyCode::Tab | KeyCode::Down => editor.next(1),
                KeyCode::BackTab | KeyCode::Up => editor.next(3),
                code => editor.input(code),
            }
            return false;
        }
        if self.confirm_delete {
            self.confirm_delete = false;
            self.message = if key.code == KeyCode::Char('y') && key.kind == KeyEventKind::Press {
                self.delete().unwrap_or_else_message()
            } else {
                String::new()
            };
            return false;
        }
        let i = self.list.selected().unwrap_or(0);
        if key.kind == KeyEventKind::Repeat && !matches!(key.code, KeyCode::Up | KeyCode::Down) {
            return false;
        }
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => return true,
            KeyCode::Up if i > 0 => self.list.select(Some(i - 1)),
            KeyCode::Down if i + 1 < self.routes.len() => self.list.select(Some(i + 1)),
            KeyCode::Char('n') => {
                self.editor = Some(Editor::new(None, None));
                self.message.clear();
            }
            KeyCode::Enter | KeyCode::Char('e') if i < self.routes.len() => {
                self.editor = Some(Editor::new(Some(i), Some(self.routes[i])));
                self.message = if matches!(self.statuses[i], Status::On | Status::Partial) {
                    "Чтобы изменить активный релей, сначала отключи его (X).".into()
                } else {
                    String::new()
                };
            }
            KeyCode::Char('u') => self.start_update_check(),
            KeyCode::Char('r') => {
                self.refresh();
                self.message.clear();
            }
            KeyCode::Char('a' | 'x') => {
                self.message = self
                    .toggle(key.code == KeyCode::Char('a'))
                    .unwrap_or_else_message();
                self.refresh();
            }
            KeyCode::Delete if i < self.routes.len() => {
                self.confirm_delete = true;
                self.message = "Удалить выбранный маршрут? Y — да · Esc — отмена".into();
            }
            KeyCode::Char('p') => {
                self.message = self
                    .writable()
                    .and_then(|()| {
                        command("netfilter-persistent", &["save"])
                            .map(|_| "Правила сохранены после перезагрузки.")
                            .map_err(|e| {
                                format!("{e}. На Debian/Ubuntu нужен пакет iptables-persistent.")
                            })
                    })
                    .unwrap_or_else_message();
            }
            _ => {}
        }
        false
    }
}

trait Message {
    fn unwrap_or_else_message(self) -> String;
}

impl Message for Result<&str, String> {
    fn unwrap_or_else_message(self) -> String {
        self.map(str::to_owned).unwrap_or_else(|e| e)
    }
}

fn shortcuts(items: &[(&str, &str, Color)]) -> Line<'static> {
    Line::from(
        items
            .iter()
            .flat_map(|&(key, label, color)| {
                [
                    Span::styled(
                        format!(" {key} "),
                        Style::default().fg(Color::Black).bg(color).bold(),
                    ),
                    Span::raw(format!(" {label}  ")),
                ]
            })
            .collect::<Vec<_>>(),
    )
}

fn ui(frame: &mut Frame, app: &mut App) {
    let area = frame.area();
    let show_update = app.editor.is_none() && !app.update.is_empty();
    let [title, notice, update, body, message, keys] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(2),
        Constraint::Length(if show_update { 1 } else { 0 }),
        Constraint::Min(1),
        Constraint::Length(2),
        Constraint::Length(if app.editor.is_none() && area.width < 60 {
            5
        } else {
            3
        }),
    ])
    .areas(area);
    let warning = app
        .access
        .as_deref()
        .or(app.config_error.as_deref())
        .or(app.firewall_error.as_deref())
        .unwrap_or("");
    frame.render_widget(
        Paragraph::new(warning).yellow().wrap(Wrap { trim: true }),
        notice,
    );
    frame.render_widget(
        Paragraph::new(app.message.as_str()).wrap(Wrap { trim: true }),
        message,
    );
    if let Some(edit) = &app.editor {
        frame.render_widget(
            Paragraph::new(if edit.original.is_some() {
                " ◇  Редактор релея "
            } else {
                " +  Новый релей "
            })
            .fg(Color::Black)
            .bg(Color::Cyan)
            .bold(),
            title,
        );
        let labels = [
            "IPv4 конечного VPS",
            "Порт конечного VPS",
            "Входной порт релея",
            "Протокол",
        ];
        let rows = Layout::vertical([Constraint::Length(1); 4]).split(body);
        for (i, label) in labels.iter().enumerate() {
            let value = edit
                .fields
                .get(i)
                .map_or(edit.proto.label(), String::as_str);
            let prefix = format!("{} {label}: ", if i == edit.focus { '›' } else { ' ' });
            let x = rows[i]
                .x
                .saturating_add((prefix.chars().count() + edit.cursor) as u16);
            let style = if i == edit.focus {
                Style::default().fg(Color::Cyan).bold()
            } else {
                Style::default()
            };
            frame.render_widget(
                Paragraph::new(format!("{prefix}{value}")).style(style),
                rows[i],
            );
            if i == edit.focus && i < 3 && rows[i].height > 0 && x < rows[i].right() {
                frame.set_cursor_position((x, rows[i].y));
            }
        }
        frame.render_widget(
            Paragraph::new(vec![
                shortcuts(&[
                    ("Tab/↑↓", "поле", Color::Cyan),
                    ("←→", "курсор / протокол", Color::Cyan),
                ]),
                shortcuts(&[
                    ("Enter", "сохранить", Color::Green),
                    ("Esc", "отмена", Color::Gray),
                ]),
            ])
            .wrap(Wrap { trim: true }),
            keys,
        );
    } else {
        frame.render_widget(
            Paragraph::new(format!(" ◈  Релеи  /  {} ", app.routes.len()))
                .fg(Color::Black)
                .bg(Color::Cyan)
                .bold(),
            title,
        );
        let card = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::DarkGray))
            .title(" Маршруты ");
        if show_update {
            frame.render_widget(Paragraph::new(app.update.as_str()), update);
        }
        if app.routes.is_empty() {
            frame.render_widget(
                Paragraph::new("Список пуст. N — добавить релей.").block(card),
                body,
            );
        } else {
            let items = app.routes.iter().zip(&app.statuses).map(|(cfg, status)| {
                let (label, color) = match status {
                    Status::Off => ("○ Не применён", Color::Gray),
                    Status::On => ("● Применён", Color::Green),
                    Status::Partial => ("◐ Частично", Color::Yellow),
                    Status::Unknown => ("? Нет статуса", Color::Yellow),
                };
                ListItem::new(Line::from(vec![
                    Span::styled(format!("{label:15}"), Style::default().fg(color).bold()),
                    Span::raw(format!(
                        " {} :{} → {}:{}",
                        cfg.proto.label(),
                        cfg.listen_port,
                        cfg.ip,
                        cfg.main_port
                    )),
                ]))
            });
            frame.render_stateful_widget(
                List::new(items)
                    .block(card)
                    .highlight_symbol("› ")
                    .highlight_style(Style::default().reversed()),
                body,
                &mut app.list,
            );
        }
        frame.render_widget(
            Paragraph::new(vec![
                shortcuts(&[
                    ("↑↓", "выбор", Color::Gray),
                    ("N", "добавить", Color::Cyan),
                    ("Enter/E", "править", Color::Cyan),
                ]),
                shortcuts(&[
                    ("A", "применить", Color::Green),
                    ("X", "отключить", Color::Yellow),
                    ("Del", "удалить", Color::Red),
                    ("P", "сохранить", Color::Green),
                ]),
                shortcuts(&[
                    ("R", "обновить список", Color::Gray),
                    ("U", "проверить обновления", Color::Cyan),
                    ("Q/Esc", "выход", Color::Gray),
                ]),
            ])
            .wrap(Wrap { trim: true }),
            keys,
        );
    }
}

fn main() -> io::Result<()> {
    let mut app = App::new();
    let mut terminal: DefaultTerminal = ratatui::init();
    let result = (|| loop {
        app.poll_update();
        terminal.draw(|frame| ui(frame, &mut app))?;
        if app.update_check.is_some() && !event::poll(Duration::from_millis(150))? {
            continue;
        }
        if let Event::Key(key) = event::read()? {
            if app.key(key) {
                return Ok(());
            }
        }
    })();
    ratatui::restore();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_checksum_requires_one_valid_matching_line() {
        let hash = "a".repeat(64);
        let entry = format!("{hash}  relay-tui-arm");
        assert_eq!(release_hash(&entry, "relay-tui-arm"), Some(hash));
        assert!(release_hash(&entry, "relay-tui-other").is_none());
        assert!(release_hash(&format!("{entry}\n{entry}"), "relay-tui-arm").is_none());
        assert!(release_hash("invalid  relay-tui-arm", "relay-tui-arm").is_none());
    }

    #[test]
    fn imports_both_protocols_and_rejects_invalid_input() {
        let routes = discover(
            "-A PREROUTING -m comment --comment \"relay-tui:tcp:443->192.0.2.1:8443\" -j DNAT
-A FORWARD -m comment --comment relay-tui:udp:443->192.0.2.1:8443 -j ACCEPT
-A FORWARD -m comment --comment relay-tui:conntrack",
        );
        assert_eq!(routes.len(), 1);
        assert!(routes[0].proto == Proto::Both);
        assert_eq!(routes[0].route(), "443->192.0.2.1:8443");
        assert!(Config::parse(Proto::Tcp, "0->192.0.2.1:8443").is_none());
    }
}
