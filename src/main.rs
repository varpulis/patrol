//! patrol — temporal grep for log files and event streams
//!
//! Usage:
//!   patrol 'Login -> Transfer -> Logout .within(5m)' auth.jsonl
//!   cat events.jsonl | patrol 'Reading.increasing(temperature) .partition_by(sensor_id)'
//!   patrol 'Login[status=="failed"] -> Login[status=="success"] .within(30m)' auth.log

mod engine;
mod event;
mod format;
mod nfa;
mod pattern;

use std::io::{self, BufRead, Write};
use std::process;

// ANSI colors
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const CYAN: &str = "\x1b[36m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RESET: &str = "\x1b[0m";

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 || args[1] == "-h" || args[1] == "--help" {
        print_usage();
        process::exit(0);
    }

    if args[1] == "--version" || args[1] == "-V" {
        println!("patrol {}", env!("CARGO_PKG_VERSION"));
        process::exit(0);
    }

    let pattern_str = &args[1];
    let file_path = args.get(2);

    // Parse pattern
    let pat = match pattern::parse(pattern_str) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{RED}{BOLD}error{RESET}: failed to parse pattern: {e}");
            eprintln!("{DIM}pattern: {pattern_str}{RESET}");
            process::exit(1);
        }
    };

    // Compile NFA
    let nfa = nfa::compile(&pat.steps, pat.within, pat.partition_by.as_deref());
    let mut eng = engine::Engine::new(nfa);

    // Print header
    let is_tty = atty_stdout();
    if is_tty {
        eprint!("{DIM}patrol{RESET} ");
        eprint!("{CYAN}{pattern_str}{RESET}");
        if let Some(ref path) = file_path {
            eprint!(" {DIM}{path}{RESET}");
        }
        eprintln!();
    }

    // Process input
    let stdin = io::stdin();
    let reader: Box<dyn BufRead> = if let Some(path) = file_path {
        match std::fs::File::open(path) {
            Ok(f) => Box::new(io::BufReader::new(f)),
            Err(e) => {
                eprintln!("{RED}{BOLD}error{RESET}: cannot open {path}: {e}");
                process::exit(1);
            }
        }
    } else {
        Box::new(stdin.lock())
    };

    let mut stdout = io::stdout().lock();
    let mut _line_num: u64 = 0;
    let mut total_matches: u64 = 0;
    let mut total_events: u64 = 0;

    // Auto-detect format from first non-empty line
    let mut detected_format: Option<format::Format> = None;

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };
        _line_num += 1;

        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }

        // Detect format on first line
        let fmt = *detected_format.get_or_insert_with(|| {
            let f = format::detect(trimmed);
            if is_tty {
                let fmt_name = match f {
                    format::Format::JsonLines => "JSON Lines",
                    format::Format::Syslog => "syslog",
                    format::Format::Logfmt => "logfmt",
                    format::Format::ApacheClf => "Apache/Nginx CLF",
                    format::Format::PlainText => "plain text",
                };
                eprintln!("{DIM}format: {fmt_name}{RESET}");
            }
            f
        });

        // Parse event using detected format
        let event = match format::parse_line(trimmed, fmt) {
            Some(e) => e,
            None => continue,
        };

        total_events += 1;

        // Process through engine
        let matches = eng.process(&event);

        for m in &matches {
            total_matches += 1;

            if is_tty {
                // Pretty print
                writeln!(
                    stdout,
                    "{RED}{BOLD}MATCH #{}{RESET} ({} events)",
                    total_matches,
                    m.events.len()
                )
                .ok();

                for (alias, captured) in &m.captured {
                    let fields: Vec<String> = captured
                        .data
                        .iter()
                        .map(|(k, v)| format!("{k}={v}"))
                        .collect();
                    writeln!(
                        stdout,
                        "  {GREEN}{alias}{RESET}: {YELLOW}{}{RESET} {{ {} }}",
                        captured.event_type,
                        fields.join(", ")
                    )
                    .ok();
                }
                writeln!(stdout).ok();
            } else {
                // JSON output for piping
                let mut obj = serde_json::Map::new();
                obj.insert(
                    "match".into(),
                    serde_json::Value::Number(total_matches.into()),
                );
                obj.insert(
                    "events".into(),
                    serde_json::Value::Number(m.events.len().into()),
                );
                let mut captured_obj = serde_json::Map::new();
                for (alias, ev) in &m.captured {
                    let mut ev_obj = serde_json::Map::new();
                    ev_obj.insert(
                        "event_type".into(),
                        serde_json::Value::String(ev.event_type.clone()),
                    );
                    for (k, v) in &ev.data {
                        ev_obj.insert(k.clone(), v.clone());
                    }
                    captured_obj.insert(alias.clone(), serde_json::Value::Object(ev_obj));
                }
                obj.insert("captured".into(), serde_json::Value::Object(captured_obj));
                writeln!(stdout, "{}", serde_json::Value::Object(obj)).ok();
            }
        }
    }

    // Summary
    if is_tty && total_events > 0 {
        eprintln!(
            "{DIM}{total_events} events processed, {}{total_matches} matches{RESET}",
            if total_matches > 0 { GREEN } else { "" }
        );
    }
}

fn atty_stdout() -> bool {
    #[cfg(unix)]
    {
        extern "C" {
            fn isatty(fd: i32) -> i32;
        }
        unsafe { isatty(1) != 0 }
    }
    #[cfg(windows)]
    {
        extern "system" {
            fn GetStdHandle(nStdHandle: u32) -> *mut std::ffi::c_void;
            fn GetConsoleMode(hConsoleHandle: *mut std::ffi::c_void, lpMode: *mut u32) -> i32;
        }
        unsafe {
            let handle = GetStdHandle(0xFFFF_FFF5); // STD_OUTPUT_HANDLE
            let mut mode = 0u32;
            GetConsoleMode(handle, &mut mode) != 0
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

fn print_usage() {
    println!(
        "{BOLD}patrol{RESET} — temporal grep for log files and event streams
{DIM}https://github.com/varpulis/patrol{RESET}

{BOLD}USAGE{RESET}
    patrol '<pattern>' [file]
    cat events.jsonl | patrol '<pattern>'

{BOLD}PATTERN SYNTAX{RESET}
    {GREEN}A -> B -> C{RESET}                      Sequence (A followed by B followed by C)
    {GREEN}A[field==\"value\"]{RESET}                 Field comparison
    {GREEN}A -> all B as bs -> C{RESET}             Kleene+ (one or more Bs)
    {GREEN}A -> NOT B -> C{RESET}                   Negation (B must not occur)
    {GREEN}R.increasing(temperature){RESET}          Rising values (monotonic)
    {GREEN}R.decreasing(pressure){RESET}             Falling values
    {GREEN}... .within(5m){RESET}                    Time window (s/m/h)
    {GREEN}... .partition_by(user_id){RESET}          Partition by field

{BOLD}EXAMPLES{RESET}
    # Brute force detection
    patrol 'Login[status==\"failed\"] -> Login[status==\"failed\"] -> Login[status==\"success\"] .within(30m)' auth.jsonl

    # Rising temperature
    cat sensors.jsonl | patrol 'Reading.increasing(temperature) .partition_by(sensor_id)'

    # API timeout
    patrol 'Request -> NOT Response .within(30s)' api.jsonl

{BOLD}INPUT FORMAT{RESET}
    JSON lines with an \"event_type\" field:
      {{\"event_type\": \"Login\", \"user\": \"alice\", \"status\": \"failed\"}}

    Plain text lines are matched as event_type \"_\" with data.line = <the line>.

{BOLD}OUTPUT{RESET}
    TTY: colored match summaries
    Pipe: JSON lines (one per match)
"
    );
}
