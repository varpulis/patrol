//! patrol — temporal grep for log files and event streams
//!
//! Usage:
//!   patrol 'Login -> Transfer -> Logout .within(5m)' auth.jsonl
//!   cat events.jsonl | patrol 'Reading.increasing(temperature) .partition_by(sensor_id)'
//!   patrol 'Login[status=="failed"] -> Login[status=="success"] .within(30m)' auth.log

use patrol::{engine, format, nfa, pattern};

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

// Exit codes follow grep: 0 match found, 1 no match, 2 error.
const EXIT_MATCH: i32 = 0;
const EXIT_NO_MATCH: i32 = 1;
const EXIT_ERROR: i32 = 2;

struct Args {
    pattern: Option<String>,
    file: Option<String>,
    multiline: bool,
    context_before: u64,
    context_after: u64,
}

fn parse_args() -> Result<Args, String> {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let mut args = Args {
        pattern: None,
        file: None,
        multiline: false,
        context_before: 0,
        context_after: 0,
    };

    let parse_num = |s: &str| -> Result<u64, String> {
        s.parse::<u64>()
            .map_err(|_| format!("expected a non-negative integer, got '{s}'"))
    };

    let mut i = 0;
    while i < raw.len() {
        let a = &raw[i];
        match a.as_str() {
            "-h" | "--help" => {
                print_usage();
                process::exit(EXIT_MATCH);
            }
            "-V" | "--version" => {
                println!("patrol {}", env!("CARGO_PKG_VERSION"));
                process::exit(EXIT_MATCH);
            }
            "-m" | "--multiline" => {
                args.multiline = true;
                i += 1;
            }
            "-p" | "--pattern-file" => {
                i += 1;
                let path = raw.get(i).ok_or("--pattern-file requires a path")?;
                let contents = std::fs::read_to_string(path)
                    .map_err(|e| format!("cannot read pattern file {path}: {e}"))?;
                args.pattern = Some(contents.trim().to_string());
                i += 1;
            }
            "-C" | "--context" => {
                i += 1;
                let n = parse_num(raw.get(i).ok_or("--context requires a count")?)?;
                args.context_before = n;
                args.context_after = n;
                i += 1;
            }
            "-A" | "--after-context" => {
                i += 1;
                let n = parse_num(raw.get(i).ok_or("--after-context requires a count")?)?;
                args.context_after = n;
                i += 1;
            }
            "-B" | "--before-context" => {
                i += 1;
                let n = parse_num(raw.get(i).ok_or("--before-context requires a count")?)?;
                args.context_before = n;
                i += 1;
            }
            s if s.starts_with('-') && s != "-" => {
                return Err(format!("unknown flag: {s}"));
            }
            _ => {
                if args.pattern.is_none() {
                    args.pattern = Some(a.clone());
                } else if args.file.is_none() {
                    args.file = Some(a.clone());
                } else {
                    return Err(format!("unexpected argument: {a}"));
                }
                i += 1;
            }
        }
    }

    if args.pattern.is_none() {
        return Err("missing pattern (use -h for help)".into());
    }
    Ok(args)
}

struct PendingMatch {
    num: u64,
    m: engine::Match,
    first_line: u64,
    last_line: u64,
}

fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{RED}{BOLD}error{RESET}: {e}");
            process::exit(EXIT_ERROR);
        }
    };

    let pattern_str = args.pattern.as_ref().unwrap().clone();

    let pat = match pattern::parse(&pattern_str) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{RED}{BOLD}error{RESET}: failed to parse pattern: {e}");
            eprintln!("{DIM}pattern: {pattern_str}{RESET}");
            process::exit(EXIT_ERROR);
        }
    };

    let nfa = match nfa::compile(&pat.steps, pat.within, pat.partition_by.as_deref()) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("{RED}{BOLD}error{RESET}: failed to compile pattern: {e}");
            process::exit(EXIT_ERROR);
        }
    };
    let mut eng = engine::Engine::new(nfa);

    let is_tty = atty_stdout();
    if is_tty {
        eprint!("{DIM}patrol{RESET} ");
        eprint!("{CYAN}{pattern_str}{RESET}");
        if let Some(ref path) = args.file {
            eprint!(" {DIM}{path}{RESET}");
        }
        eprintln!();
    }

    let stdin = io::stdin();
    let reader: Box<dyn BufRead> = if let Some(ref path) = args.file {
        match std::fs::File::open(path) {
            Ok(f) => Box::new(io::BufReader::new(f)),
            Err(e) => {
                eprintln!("{RED}{BOLD}error{RESET}: cannot open {path}: {e}");
                process::exit(EXIT_ERROR);
            }
        }
    } else {
        Box::new(stdin.lock())
    };

    let mut stdout = io::stdout().lock();
    let mut total_matches: u64 = 0;
    let mut total_events: u64 = 0;

    let ctx_enabled = args.context_before > 0 || args.context_after > 0;
    // Raw physical lines (1-based line numbers), only populated when ctx is enabled.
    let mut raw_lines: Vec<String> = Vec::new();
    // Pending matches awaiting trailing context before they can be emitted.
    let mut pending: Vec<PendingMatch> = Vec::new();

    let mut detected_format: Option<format::Format> = None;

    // Multiline state: a logical "record" can span multiple physical lines.
    let mut buffered_text: Option<String> = None;
    let mut buffered_start: u64 = 0;
    let mut physical_line: u64 = 0;

    // Helper: process a logical record (text spanning [start..physical_line])
    // through the engine and queue resulting matches.
    let process_record = |raw: &str,
                          start_line: u64,
                          end_line: u64,
                          detected_format: &mut Option<format::Format>,
                          eng: &mut engine::Engine,
                          total_events: &mut u64,
                          total_matches: &mut u64,
                          pending: &mut Vec<PendingMatch>,
                          stdout: &mut io::StdoutLock|
     -> io::Result<()> {
        let trimmed = raw.trim_end();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            return Ok(());
        }

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

        let mut event = match format::parse_line(trimmed, fmt) {
            Some(e) => e,
            None => return Ok(()),
        };
        event.line_num = start_line;
        let _ = end_line;

        *total_events += 1;

        let matches = eng.process(&event);
        for m in matches {
            *total_matches += 1;
            let first = m
                .events
                .iter()
                .map(|e| e.line_num)
                .filter(|&l| l > 0)
                .min()
                .unwrap_or(start_line);
            let last = m
                .events
                .iter()
                .map(|e| e.line_num)
                .max()
                .unwrap_or(start_line);
            if ctx_enabled {
                pending.push(PendingMatch {
                    num: *total_matches,
                    m,
                    first_line: first,
                    last_line: last,
                });
            } else {
                emit_match(stdout, *total_matches, &m, is_tty)?;
            }
        }
        Ok(())
    };

    for line_res in reader.lines() {
        let line = match line_res {
            Ok(l) => l,
            Err(_) => continue,
        };
        physical_line += 1;

        if ctx_enabled {
            raw_lines.push(line.clone());
        }

        // Multiline continuation: fold into the current record without
        // starting a new one.
        if args.multiline {
            if let Some(buf) = buffered_text.as_mut() {
                if is_continuation(&line) {
                    buf.push('\n');
                    buf.push_str(&line);
                    continue;
                }
            }
        }

        // New record starts here — flush the previous one first.
        if let Some(prev) = buffered_text.take() {
            let prev_end = physical_line - 1;
            if let Err(e) = process_record(
                &prev,
                buffered_start,
                prev_end,
                &mut detected_format,
                &mut eng,
                &mut total_events,
                &mut total_matches,
                &mut pending,
                &mut stdout,
            ) {
                eprintln!("{RED}{BOLD}error{RESET}: write: {e}");
                process::exit(EXIT_ERROR);
            }
        }
        buffered_text = Some(line);
        buffered_start = physical_line;

        // Flush any pending matches whose trailing-context window is satisfied.
        if ctx_enabled {
            flush_ready(
                &mut pending,
                physical_line,
                args.context_before,
                args.context_after,
                &raw_lines,
                &mut stdout,
                is_tty,
            );
        }
    }

    if let Some(prev) = buffered_text.take() {
        if let Err(e) = process_record(
            &prev,
            buffered_start,
            physical_line,
            &mut detected_format,
            &mut eng,
            &mut total_events,
            &mut total_matches,
            &mut pending,
            &mut stdout,
        ) {
            eprintln!("{RED}{BOLD}error{RESET}: write: {e}");
            process::exit(EXIT_ERROR);
        }
    }

    // Flush any runs waiting on trailing negation — their absence window has
    // ended now that input is exhausted.
    let tail = eng.flush();
    for m in tail {
        total_matches += 1;
        let first = m
            .events
            .iter()
            .map(|e| e.line_num)
            .filter(|&l| l > 0)
            .min()
            .unwrap_or(physical_line);
        let last = m
            .events
            .iter()
            .map(|e| e.line_num)
            .max()
            .unwrap_or(physical_line);
        if ctx_enabled {
            pending.push(PendingMatch {
                num: total_matches,
                m,
                first_line: first,
                last_line: last,
            });
        } else if let Err(e) = emit_match(&mut stdout, total_matches, &m, is_tty) {
            eprintln!("{RED}{BOLD}error{RESET}: write: {e}");
            process::exit(EXIT_ERROR);
        }
    }

    // At EOF, emit every remaining pending match with whatever trailing
    // context is available.
    if ctx_enabled {
        for p in pending.drain(..) {
            if let Err(e) = emit_with_context(
                &mut stdout,
                &p,
                args.context_before,
                args.context_after,
                &raw_lines,
                is_tty,
            ) {
                eprintln!("{RED}{BOLD}error{RESET}: write: {e}");
                process::exit(EXIT_ERROR);
            }
        }
    }

    if is_tty && total_events > 0 {
        eprintln!(
            "{DIM}{total_events} events processed, {}{total_matches} matches{RESET}",
            if total_matches > 0 { GREEN } else { "" }
        );
    }

    if total_matches > 0 {
        process::exit(EXIT_MATCH);
    } else {
        process::exit(EXIT_NO_MATCH);
    }
}

fn flush_ready(
    pending: &mut Vec<PendingMatch>,
    current_line: u64,
    ctx_before: u64,
    ctx_after: u64,
    raw_lines: &[String],
    stdout: &mut io::StdoutLock,
    is_tty: bool,
) {
    let mut i = 0;
    while i < pending.len() {
        if pending[i].last_line + ctx_after < current_line {
            let p = pending.swap_remove(i);
            if let Err(e) = emit_with_context(stdout, &p, ctx_before, ctx_after, raw_lines, is_tty)
            {
                eprintln!("{RED}{BOLD}error{RESET}: write: {e}");
                process::exit(EXIT_ERROR);
            }
        } else {
            i += 1;
        }
    }
}

fn emit_with_context(
    stdout: &mut io::StdoutLock,
    p: &PendingMatch,
    ctx_before: u64,
    ctx_after: u64,
    raw_lines: &[String],
    is_tty: bool,
) -> io::Result<()> {
    if !is_tty {
        // For piped output, emit the normal JSONL record plus a "context" array.
        let mut obj = serde_json::Map::new();
        obj.insert("match".into(), serde_json::Value::Number(p.num.into()));
        obj.insert(
            "events".into(),
            serde_json::Value::Number(p.m.events.len().into()),
        );
        obj.insert(
            "first_line".into(),
            serde_json::Value::Number(p.first_line.into()),
        );
        obj.insert(
            "last_line".into(),
            serde_json::Value::Number(p.last_line.into()),
        );

        let mut captured_obj = serde_json::Map::new();
        for (alias, ev) in &p.m.captured {
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

        let start = p.first_line.saturating_sub(ctx_before).max(1);
        let end = (p.last_line + ctx_after).min(raw_lines.len() as u64);
        let mut ctx_arr = Vec::new();
        let match_lines: std::collections::HashSet<u64> =
            p.m.events.iter().map(|e| e.line_num).collect();
        for ln in start..=end {
            let idx = (ln - 1) as usize;
            if idx >= raw_lines.len() {
                break;
            }
            let mut entry = serde_json::Map::new();
            entry.insert("line".into(), serde_json::Value::Number(ln.into()));
            entry.insert(
                "text".into(),
                serde_json::Value::String(raw_lines[idx].clone()),
            );
            entry.insert(
                "matched".into(),
                serde_json::Value::Bool(match_lines.contains(&ln)),
            );
            ctx_arr.push(serde_json::Value::Object(entry));
        }
        obj.insert("context".into(), serde_json::Value::Array(ctx_arr));

        writeln!(stdout, "{}", serde_json::Value::Object(obj))?;
        return Ok(());
    }

    // TTY mode: grep-style framed context.
    writeln!(
        stdout,
        "{RED}{BOLD}== MATCH #{num} ({n} events, lines {first}–{last}) =={RESET}",
        num = p.num,
        n = p.m.events.len(),
        first = p.first_line,
        last = p.last_line,
    )?;

    let start = p.first_line.saturating_sub(ctx_before).max(1);
    let end = (p.last_line + ctx_after).min(raw_lines.len() as u64);
    let match_lines: std::collections::HashSet<u64> =
        p.m.events.iter().map(|e| e.line_num).collect();
    let width = digit_count(end);

    for ln in start..=end {
        let idx = (ln - 1) as usize;
        if idx >= raw_lines.len() {
            break;
        }
        let text = &raw_lines[idx];
        if match_lines.contains(&ln) {
            writeln!(
                stdout,
                "{YELLOW}{BOLD}>>{RESET} {CYAN}{ln:>w$}{RESET} | {text}",
                w = width
            )?;
        } else {
            writeln!(stdout, "   {DIM}{ln:>w$} | {text}{RESET}", w = width)?;
        }
    }
    writeln!(stdout)?;
    Ok(())
}

fn digit_count(mut n: u64) -> usize {
    if n == 0 {
        return 1;
    }
    let mut c = 0;
    while n > 0 {
        c += 1;
        n /= 10;
    }
    c
}

fn is_continuation(line: &str) -> bool {
    // Classic stack-trace / wrapped-field convention: continuation lines begin
    // with whitespace. Covers Java/Python stack traces, wrapped syslog messages,
    // and indented nested logs.
    line.starts_with([' ', '\t'])
}

fn emit_match(
    stdout: &mut io::StdoutLock,
    num: u64,
    m: &engine::Match,
    is_tty: bool,
) -> io::Result<()> {
    if is_tty {
        writeln!(
            stdout,
            "{RED}{BOLD}MATCH #{}{RESET} ({} events)",
            num,
            m.events.len()
        )?;

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
            )?;
        }
        writeln!(stdout)?;
    } else {
        let mut obj = serde_json::Map::new();
        obj.insert("match".into(), serde_json::Value::Number(num.into()));
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
        writeln!(stdout, "{}", serde_json::Value::Object(obj))?;
    }
    Ok(())
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
    patrol '<pattern>' [file] [flags]
    cat events.jsonl | patrol '<pattern>' [flags]

{BOLD}FLAGS{RESET}
    -p, --pattern-file <path>   Read the pattern from a file
    -m, --multiline             Treat indented lines as continuations (stack traces)
    -C, --context <n>           Show N lines of surrounding context
    -A, --after-context <n>     Show N lines after each match
    -B, --before-context <n>    Show N lines before each match
    -h, --help                  Show this help
    -V, --version               Show version

{BOLD}PATTERN SYNTAX{RESET}
    {GREEN}A -> B -> C{RESET}                      Sequence (A followed by B followed by C)
    {GREEN}A[field==\"value\"]{RESET}                 Field comparison
    {GREEN}A[field=~\"regex\"]{RESET}                 Regex match (!=~ for negation)
    {GREEN}A -> all B as bs -> C{RESET}             Kleene+ (one or more Bs)
    {GREEN}A -> NOT B -> C{RESET}                   Negation: B must not occur between A and C
    {GREEN}A -> NOT B .within(5m){RESET}            Trailing negation: no B for 5m after A
    {GREEN}R.increasing(temperature){RESET}          Rising values (monotonic)
    {GREEN}R.decreasing(pressure){RESET}             Falling values
    {GREEN}... .within(5m){RESET}                    Time window (s/m/h) — event time
    {GREEN}... .partition_by(user_id){RESET}          Partition by field

{BOLD}EXAMPLES{RESET}
    # Brute force detection
    patrol 'Login[status==\"failed\"] -> Login[status==\"failed\"] -> Login[status==\"success\"] .within(30m)' auth.jsonl

    # Rising temperature
    cat sensors.jsonl | patrol 'Reading.increasing(temperature) .partition_by(sensor_id)'

    # Missing API response (absence detection)
    patrol 'Request -> NOT Response .within(30s) .partition_by(request_id)' api.jsonl

    # Stack traces from Java exceptions
    patrol '_[message=~\"NullPointerException\"]' -m app.log

{BOLD}EXIT CODES{RESET}
    0  at least one match found
    1  no matches
    2  error (bad pattern, unreadable file, etc.)

{BOLD}OUTPUT{RESET}
    TTY: colored match summaries (with -C, grep-style framed context)
    Pipe: JSON lines (one per match; context included when -C is set)
"
    );
}
