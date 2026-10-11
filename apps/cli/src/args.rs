//! The command line, parsed by hand (ADR 0040).
//!
//! `wetechinetmonctl [GLOBAL FLAGS] incidents <verb> [INCIDENT] [FLAGS]`.
//! Flags may sit anywhere after the program name. An unknown flag, a
//! missing value, a flag the verb does not take, or a stray argument is a
//! usage error, never ignored: a misspelled flag must fail loudly, not run
//! a different command than the operator believes.

/// How results are printed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Output {
    /// Aligned columns for people.
    Table,
    /// `Table` with more columns.
    Wide,
    /// The API's response body, verbatim.
    Json,
}

/// Flags that apply to every command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Global {
    pub output: Output,
    pub profile: Option<String>,
}

/// An incident as the operator named it: its UUID or its number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncidentRef(pub String);

/// `incidents list` filters, passed to the API as query parameters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListArgs {
    /// `(name, value)` query pairs, in the order given.
    pub query: Vec<(String, String)>,
}

/// The paged histories of one incident.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum History {
    Timeline,
    Detections,
    Audit,
}

impl History {
    pub fn path(self) -> &'static str {
        match self {
            History::Timeline => "timeline",
            History::Detections => "detections",
            History::Audit => "audit",
        }
    }
}

/// When a suppression ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Until {
    /// RFC 3339 UTC, as given.
    At(String),
    /// From now.
    For(std::time::Duration),
}

/// A change to one incident, mapped one-to-one to an API action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Acknowledge,
    Investigate,
    Monitor,
    Unassign,
    Unsuppress,
    Resolve {
        note: Option<String>,
    },
    Close {
        reason: String,
        detail: Option<String>,
    },
    Reopen {
        reason: String,
    },
    Suppress {
        until: Until,
        reason: String,
    },
    AssignUser(String),
    AssignTeam(String),
    /// Assign to the caller, as `GET /whoami` names them.
    Claim,
    Severity {
        level: String,
        reason: Option<String>,
    },
    Priority {
        level: String,
    },
    Note {
        body: String,
    },
    /// Replace your own note; the original stays, marked superseded.
    NoteEdit {
        index: u32,
        body: String,
    },
    NoteRedact {
        index: u32,
        reason: String,
    },
}

impl Action {
    /// The API action path below `/incidents/{id}/`.
    pub fn path(&self) -> String {
        match self {
            Action::NoteEdit { index, .. } => format!("notes/{index}/edit"),
            Action::NoteRedact { index, .. } => format!("notes/{index}/redact"),
            other => other.verb().to_string(),
        }
    }

    /// What the action is called in messages.
    pub fn verb(&self) -> &'static str {
        match self {
            Action::NoteEdit { .. } => "note edit",
            Action::NoteRedact { .. } => "note redact",
            Action::Acknowledge => "acknowledge",
            Action::Investigate => "investigate",
            Action::Monitor => "monitor",
            Action::Unassign => "unassign",
            Action::Unsuppress => "unsuppress",
            Action::Resolve { .. } => "resolve",
            Action::Close { .. } => "close",
            Action::Reopen { .. } => "reopen",
            Action::Suppress { .. } => "suppress",
            Action::AssignUser(_) | Action::AssignTeam(_) | Action::Claim => "assign",
            Action::Severity { .. } => "severity",
            Action::Priority { .. } => "priority",
            Action::Note { .. } => "notes",
        }
    }

    /// Whether the API needs `expected_version`. A note change does not.
    pub fn is_versioned(&self) -> bool {
        !matches!(
            self,
            Action::Note { .. } | Action::NoteEdit { .. } | Action::NoteRedact { .. }
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Help,
    Version,
    List(ListArgs),
    Show(IncidentRef),
    /// A paged history, with `--limit` and `--cursor` passed through.
    History {
        kind: History,
        incident: IncidentRef,
        query: Vec<(String, String)>,
    },
    NoteList(IncidentRef),
    /// Opens an incident by hand (ADR 0039).
    Open(OpenArgs),
    /// Writes the export document to a new file, or to stdout.
    Export {
        incident: IncidentRef,
        file: Option<String>,
    },
    /// Sets (`Some`) or removes (`None`) one tag.
    Tag {
        incident: IncidentRef,
        key: String,
        value: Option<String>,
    },
    Change {
        incident: IncidentRef,
        action: Action,
        /// Pins the version instead of reading it first.
        expected_version: Option<u64>,
        /// Answers the confirmation prompt in advance.
        yes: bool,
    },
}

/// `incidents open`, field for field the API request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenArgs {
    pub title: String,
    pub description: Option<String>,
    pub severity: String,
    pub priority: Option<String>,
    pub target_scope: String,
    pub target: String,
    pub direction: String,
    pub address_family: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    pub global: Global,
    pub command: Command,
}

/// Why the command line was refused. The text is for the operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageError(pub String);

fn usage(text: impl Into<String>) -> UsageError {
    UsageError(text.into())
}

pub const USAGE: &str = "\
Usage: wetechinetmonctl [--output table|wide|json] [--profile NAME] incidents <verb> ...

Reading:
  incidents list [--state S] [--severity S] [--priority P] [--direction D]
                 [--target-type T] [--sort opened_at|last_detected_at]
                 [--order desc|asc] [--limit N] [--cursor C]
                 [--opened-from TIME --opened-to TIME]
  incidents show INCIDENT
  incidents timeline INCIDENT [--limit N] [--cursor C]
  incidents detections INCIDENT [--limit N] [--cursor C]
  incidents audit INCIDENT [--limit N] [--cursor C]
  incidents note list INCIDENT

Changing (each reads the current version first unless --expected-version):
  incidents acknowledge INCIDENT
  incidents investigate INCIDENT
  incidents monitor INCIDENT
  incidents assign INCIDENT --user U | --team T
  incidents unassign INCIDENT          (also: release)
  incidents resolve INCIDENT [--note TEXT]
  incidents close INCIDENT --reason R [--detail TEXT]          (confirms)
  incidents reopen INCIDENT --reason TEXT                      (confirms)
  incidents suppress INCIDENT (--until TIME | --for 2h) --reason TEXT  (confirms)
  incidents unsuppress INCIDENT
  incidents severity set INCIDENT LEVEL [--reason TEXT]   (confirms when lowering)
  incidents priority set INCIDENT LEVEL
  incidents note add INCIDENT --message TEXT
  incidents note edit INCIDENT INDEX --message TEXT   (your own note)
  incidents note redact INCIDENT INDEX --reason TEXT   (confirms)
  incidents claim INCIDENT                 (assign to yourself)
  incidents tag set INCIDENT KEY VALUE
  incidents tag remove INCIDENT KEY
  incidents export INCIDENT [--file PATH]  (a new file, never overwritten)
  incidents open --title T --severity S --target-scope host|prefix|slash24|hostgroup_total
                 --target X --direction incoming|outgoing|internal
                 [--priority P] [--description TEXT] [--address-family 4|6]

  --yes answers a confirmation in advance; without a terminal it is required.
  --expected-version N pins the version instead of reading it.

INCIDENT is an incident id or number, such as WNM-2026-000123.
--state, --severity and --priority repeat, or take a comma-separated list.

Credentials are never flags. Set WETECHINETMON_API_TOKEN, or a profile in
the config file (WETECHINETMON_CONFIG). See apps/cli/README.md.
";

/// Every flag that takes a value, as `(flag, name)`. Which verb accepts
/// which is decided after parsing.
const VALUE_FLAGS: &[(&str, &str)] = &[
    ("--state", "state"),
    ("--severity", "severity"),
    ("--priority", "priority"),
    ("--direction", "direction"),
    ("--target-type", "target_type"),
    ("--sort", "sort"),
    ("--order", "order"),
    ("--limit", "limit"),
    ("--cursor", "cursor"),
    ("--opened-from", "opened_from"),
    ("--opened-to", "opened_to"),
    ("--expected-version", "expected_version"),
    ("--note", "note"),
    ("--reason", "reason"),
    ("--detail", "detail"),
    ("--until", "until"),
    ("--for", "for"),
    ("--user", "user"),
    ("--team", "team"),
    ("--message", "message"),
    ("--file", "file"),
    ("--title", "title"),
    ("--description", "description"),
    ("--target-scope", "target_scope"),
    ("--target", "target"),
    ("--address-family", "address_family"),
];

/// `list` flags that may repeat or take a comma-separated list.
const LIST_REPEATING: &[&str] = &["state", "severity", "priority"];
const LIST_FLAGS: &[&str] = &[
    "state",
    "severity",
    "priority",
    "direction",
    "target_type",
    "sort",
    "order",
    "limit",
    "cursor",
    "opened_from",
    "opened_to",
];

/// Names that look like credentials. Refused with a pointer to the
/// environment, because flags land in shell history.
const CREDENTIAL_FLAGS: &[&str] = &["--token", "--api-token", "--password", "--secret"];

/// Flags the verb has not consumed yet.
struct Flags {
    values: Vec<(String, String)>,
    yes: bool,
}

impl Flags {
    /// The one value of `name`, if given; twice is an error.
    fn take(&mut self, name: &str) -> Result<Option<String>, UsageError> {
        let mut found = None;
        let mut index = 0;
        while index < self.values.len() {
            if self.values[index].0 == name {
                let (_, value) = self.values.remove(index);
                if found.replace(value).is_some() {
                    return Err(usage(format!("--{} may be given once", flag(name))));
                }
            } else {
                index += 1;
            }
        }
        Ok(found)
    }

    fn require(&mut self, name: &str, verb: &str) -> Result<String, UsageError> {
        self.take(name)?
            .ok_or_else(|| usage(format!("incidents {verb} needs --{}", flag(name))))
    }

    /// Refuses whatever the verb did not consume.
    fn finish(self, verb: &str, allows_yes: bool) -> Result<bool, UsageError> {
        if let Some((name, _)) = self.values.first() {
            return Err(usage(format!(
                "--{} does not apply to incidents {verb}",
                flag(name)
            )));
        }
        if self.yes && !allows_yes {
            return Err(usage(format!("--yes does not apply to incidents {verb}")));
        }
        Ok(self.yes)
    }
}

fn flag(name: &str) -> String {
    name.replace('_', "-")
}

/// `2h`, `30m`, `1d`, `90s`: a whole number and a unit.
fn duration(text: &str) -> Result<std::time::Duration, UsageError> {
    let invalid = || {
        usage(format!(
            "--for {text:?}: use a number and s, m, h or d, such as 2h"
        ))
    };
    let unit = text.chars().last().ok_or_else(invalid)?;
    let number: u64 = text[..text.len() - unit.len_utf8()]
        .parse()
        .map_err(|_| invalid())?;
    let seconds = match unit {
        's' => number,
        'm' => number.checked_mul(60).ok_or_else(invalid)?,
        'h' => number.checked_mul(3_600).ok_or_else(invalid)?,
        'd' => number.checked_mul(86_400).ok_or_else(invalid)?,
        _ => return Err(invalid()),
    };
    if seconds == 0 {
        return Err(invalid());
    }
    Ok(std::time::Duration::from_secs(seconds))
}

pub fn parse(args: &[String]) -> Result<Invocation, UsageError> {
    let mut global = Global {
        output: Output::Table,
        profile: None,
    };
    let mut words: Vec<String> = Vec::new();
    let mut flags = Flags {
        values: Vec::new(),
        yes: false,
    };
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        let (name, inline) = match arg.split_once('=') {
            Some((name, value)) if name.starts_with("--") => (name, Some(value.to_string())),
            _ => (arg.as_str(), None),
        };
        if CREDENTIAL_FLAGS.contains(&name) {
            return Err(usage(format!(
                "{name} is not accepted: credentials on the command line land in shell \
                 history. Set WETECHINETMON_API_TOKEN or use a profile."
            )));
        }
        let mut value = |name: &str| -> Result<String, UsageError> {
            match &inline {
                Some(value) => Ok(value.clone()),
                None => rest
                    .next()
                    .cloned()
                    .ok_or_else(|| usage(format!("{name} needs a value"))),
            }
        };
        match name {
            "-h" | "--help" => {
                return Ok(Invocation {
                    global,
                    command: Command::Help,
                })
            }
            "--version" => {
                return Ok(Invocation {
                    global,
                    command: Command::Version,
                })
            }
            "-y" | "--yes" => {
                if inline.is_some() {
                    return Err(usage("--yes takes no value"));
                }
                flags.yes = true;
            }
            "-o" | "--output" => {
                global.output = match value(name)?.as_str() {
                    "table" => Output::Table,
                    "wide" => Output::Wide,
                    "json" => Output::Json,
                    other => {
                        return Err(usage(format!(
                            "--output is table, wide or json, not {other:?}"
                        )))
                    }
                }
            }
            "--profile" => global.profile = Some(value(name)?),
            flag if flag.starts_with('-') && flag != "-" => {
                let Some((_, key)) = VALUE_FLAGS.iter().find(|(f, _)| *f == flag) else {
                    return Err(usage(format!("unknown flag {flag}")));
                };
                flags.values.push(((*key).to_string(), value(name)?));
            }
            word => {
                if inline.is_some() {
                    return Err(usage(format!("unexpected argument {arg}")));
                }
                words.push(word.to_string());
            }
        }
    }

    let words: Vec<&str> = words.iter().map(String::as_str).collect();
    let reference = |id: &&str| IncidentRef((*id).to_string());
    let command = match words.as_slice() {
        [] => {
            flags.finish("", false)?;
            Command::Help
        }
        ["incidents", "list"] => {
            let mut query = Vec::new();
            for (name, value) in std::mem::take(&mut flags.values) {
                if !LIST_FLAGS.contains(&name.as_str()) {
                    flags.values.push((name, value));
                    continue;
                }
                if LIST_REPEATING.contains(&name.as_str()) {
                    for one in value.split(',').filter(|v| !v.is_empty()) {
                        query.push((name.clone(), one.to_string()));
                    }
                } else {
                    query.push((name, value));
                }
            }
            flags.finish("list", false)?;
            Command::List(ListArgs { query })
        }
        ["incidents", "show", id] => {
            flags.finish("show", false)?;
            Command::Show(reference(id))
        }
        ["incidents", verb @ ("timeline" | "detections" | "audit"), id] => {
            let kind = match *verb {
                "timeline" => History::Timeline,
                "detections" => History::Detections,
                _ => History::Audit,
            };
            let mut query = Vec::new();
            for name in ["limit", "cursor"] {
                if let Some(value) = flags.take(name)? {
                    query.push((name.to_string(), value));
                }
            }
            flags.finish(verb, false)?;
            Command::History {
                kind,
                incident: reference(id),
                query,
            }
        }
        ["incidents", "note", "list", id] => {
            flags.finish("note list", false)?;
            Command::NoteList(reference(id))
        }
        ["incidents", "note", "add", id] => {
            let body = flags.require("message", "note add")?;
            change(flags, "note add", reference(id), Action::Note { body })?
        }
        ["incidents", "note", "edit", id, index] => {
            let index = note_index(index)?;
            let body = flags.require("message", "note edit")?;
            change(
                flags,
                "note edit",
                reference(id),
                Action::NoteEdit { index, body },
            )?
        }
        ["incidents", "note", "redact", id, index] => {
            let index = note_index(index)?;
            let reason = flags.require("reason", "note redact")?;
            change(
                flags,
                "note redact",
                reference(id),
                Action::NoteRedact { index, reason },
            )?
        }
        ["incidents", "open"] => {
            let address_family = match flags.take("address_family")? {
                Some(text) => Some(
                    text.parse()
                        .map_err(|_| usage("--address-family is 4 or 6"))?,
                ),
                None => None,
            };
            let open = OpenArgs {
                title: flags.require("title", "open")?,
                description: flags.take("description")?,
                severity: flags.require("severity", "open")?,
                priority: flags.take("priority")?,
                target_scope: flags.require("target_scope", "open")?,
                target: flags.require("target", "open")?,
                direction: flags.require("direction", "open")?,
                address_family,
            };
            flags.finish("open", false)?;
            Command::Open(open)
        }
        ["incidents", "export", id] => {
            let file = flags.take("file")?;
            flags.finish("export", false)?;
            Command::Export {
                incident: reference(id),
                file,
            }
        }
        ["incidents", "tag", "set", id, key, value] => {
            flags.finish("tag set", false)?;
            Command::Tag {
                incident: reference(id),
                key: (*key).to_string(),
                value: Some((*value).to_string()),
            }
        }
        ["incidents", "tag", "remove", id, key] => {
            flags.finish("tag remove", false)?;
            Command::Tag {
                incident: reference(id),
                key: (*key).to_string(),
                value: None,
            }
        }
        ["incidents", "severity", "set", id, level] => {
            let reason = flags.take("reason")?;
            let action = Action::Severity {
                level: (*level).to_string(),
                reason,
            };
            change(flags, "severity set", reference(id), action)?
        }
        ["incidents", "priority", "set", id, level] => {
            let action = Action::Priority {
                level: (*level).to_string(),
            };
            change(flags, "priority set", reference(id), action)?
        }
        ["incidents", verb, id] if is_change_verb(verb) => {
            let action = match *verb {
                "acknowledge" => Action::Acknowledge,
                "investigate" => Action::Investigate,
                "monitor" => Action::Monitor,
                "unassign" | "release" => Action::Unassign,
                "unsuppress" => Action::Unsuppress,
                "claim" => Action::Claim,
                "resolve" => Action::Resolve {
                    note: flags.take("note")?,
                },
                "close" => Action::Close {
                    reason: flags.require("reason", verb)?,
                    detail: flags.take("detail")?,
                },
                "reopen" => Action::Reopen {
                    reason: flags.require("reason", verb)?,
                },
                "suppress" => {
                    let until = match (flags.take("until")?, flags.take("for")?) {
                        (Some(at), None) => Until::At(at),
                        (None, Some(text)) => Until::For(duration(&text)?),
                        _ => {
                            return Err(usage(
                                "incidents suppress needs exactly one of --until and --for",
                            ))
                        }
                    };
                    Action::Suppress {
                        until,
                        reason: flags.require("reason", verb)?,
                    }
                }
                _ => match (flags.take("user")?, flags.take("team")?) {
                    (Some(user), None) => Action::AssignUser(user),
                    (None, Some(team)) => Action::AssignTeam(team),
                    _ => {
                        return Err(usage(
                            "incidents assign needs exactly one of --user and --team",
                        ))
                    }
                },
            };
            change(flags, verb, reference(id), action)?
        }
        ["incidents"] => return Err(usage("incidents needs a verb; see --help")),
        ["incidents", verb, ..] => {
            return Err(usage(format!(
                "incidents {verb}: unknown verb, or the wrong number of arguments; see --help"
            )))
        }
        [other, ..] => return Err(usage(format!("unknown command {other}; see --help"))),
    };
    Ok(Invocation { global, command })
}

fn is_change_verb(verb: &str) -> bool {
    matches!(
        verb,
        "acknowledge"
            | "investigate"
            | "monitor"
            | "unassign"
            | "release"
            | "unsuppress"
            | "resolve"
            | "close"
            | "reopen"
            | "suppress"
            | "assign"
            | "claim"
    )
}

/// A change command: takes `--expected-version` (not for a note) and
/// `--yes`, and refuses any other leftover flag.
/// A note's position, as `incidents note list` shows it after `#`.
fn note_index(text: &str) -> Result<u32, UsageError> {
    text.trim_start_matches('#')
        .parse()
        .map_err(|_| usage("INDEX is a note's number, such as 3 or #3"))
}

fn change(
    mut flags: Flags,
    verb: &str,
    incident: IncidentRef,
    action: Action,
) -> Result<Command, UsageError> {
    let expected_version = match flags.take("expected_version")? {
        Some(_) if !action.is_versioned() => {
            return Err(usage(format!(
                "--expected-version does not apply to incidents {verb}"
            )))
        }
        Some(text) => Some(
            text.parse()
                .map_err(|_| usage("--expected-version is a whole number"))?,
        ),
        None => None,
    };
    let yes = flags.finish(verb, true)?;
    Ok(Command::Change {
        incident,
        action,
        expected_version,
        yes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(line: &str) -> Result<Invocation, UsageError> {
        let args: Vec<String> = line.split_whitespace().map(String::from).collect();
        parse(&args)
    }

    fn reference(id: &str) -> IncidentRef {
        IncidentRef(id.to_string())
    }

    fn action(line: &str) -> Action {
        match run(line).unwrap().command {
            Command::Change { action, .. } => action,
            other => panic!("{line}: not a change: {other:?}"),
        }
    }

    #[test]
    fn every_read_verb_parses() {
        let cases = [
            (
                "incidents show WNM-2026-000123",
                Command::Show(reference("WNM-2026-000123")),
            ),
            (
                "incidents timeline X --limit 5",
                Command::History {
                    kind: History::Timeline,
                    incident: reference("X"),
                    query: vec![("limit".into(), "5".into())],
                },
            ),
            (
                "incidents detections X",
                Command::History {
                    kind: History::Detections,
                    incident: reference("X"),
                    query: vec![],
                },
            ),
            (
                "incidents audit X --cursor c1",
                Command::History {
                    kind: History::Audit,
                    incident: reference("X"),
                    query: vec![("cursor".into(), "c1".into())],
                },
            ),
            ("incidents note list X", Command::NoteList(reference("X"))),
            ("", Command::Help),
            ("--help", Command::Help),
            ("--version", Command::Version),
        ];
        for (line, command) in cases {
            assert_eq!(run(line).unwrap().command, command, "{line}");
        }
    }

    #[test]
    fn every_change_verb_parses() {
        assert_eq!(action("incidents acknowledge X"), Action::Acknowledge);
        assert_eq!(action("incidents investigate X"), Action::Investigate);
        assert_eq!(action("incidents monitor X"), Action::Monitor);
        assert_eq!(action("incidents release X"), Action::Unassign);
        assert_eq!(action("incidents unassign X"), Action::Unassign);
        assert_eq!(action("incidents unsuppress X"), Action::Unsuppress);
        assert_eq!(
            action("incidents resolve X --note done"),
            Action::Resolve {
                note: Some("done".into())
            }
        );
        assert_eq!(
            action("incidents close X --reason false_positive --yes"),
            Action::Close {
                reason: "false_positive".into(),
                detail: None
            }
        );
        assert_eq!(
            action("incidents reopen X --reason recurred"),
            Action::Reopen {
                reason: "recurred".into()
            }
        );
        assert_eq!(
            action("incidents suppress X --for 2h --reason backup"),
            Action::Suppress {
                until: Until::For(std::time::Duration::from_secs(7_200)),
                reason: "backup".into()
            }
        );
        assert_eq!(
            action("incidents suppress X --until 2026-10-06T00:00:00Z --reason backup"),
            Action::Suppress {
                until: Until::At("2026-10-06T00:00:00Z".into()),
                reason: "backup".into()
            }
        );
        assert_eq!(
            action("incidents assign X --user u_1"),
            Action::AssignUser("u_1".into())
        );
        assert_eq!(
            action("incidents assign X --team noc"),
            Action::AssignTeam("noc".into())
        );
        assert_eq!(
            action("incidents severity set X minor --reason=subsided"),
            Action::Severity {
                level: "minor".into(),
                reason: Some("subsided".into())
            }
        );
        assert_eq!(action("incidents claim X"), Action::Claim);
        assert_eq!(
            action("incidents priority set X P3"),
            Action::Priority { level: "P3".into() }
        );
        assert_eq!(
            action("incidents note add X --message hello"),
            Action::Note {
                body: "hello".into()
            }
        );
        assert_eq!(
            action("incidents note edit X 3 --message better"),
            Action::NoteEdit {
                index: 3,
                body: "better".into()
            }
        );
        assert_eq!(
            action("incidents note redact X #2 --reason pasted-a-key"),
            Action::NoteRedact {
                index: 2,
                reason: "pasted-a-key".into()
            }
        );
        assert_eq!(
            Action::NoteRedact {
                index: 2,
                reason: String::new()
            }
            .path(),
            "notes/2/redact"
        );
    }

    #[test]
    fn open_export_and_tags_parse() {
        let Command::Open(open) = run(
            "incidents open --title Spoofing --severity major --target-scope host              --target 203.0.113.5 --direction incoming --address-family 4",
        )
        .unwrap()
        .command
        else {
            panic!("not open")
        };
        assert_eq!(
            (
                open.title.as_str(),
                open.target.as_str(),
                open.address_family
            ),
            ("Spoofing", "203.0.113.5", Some(4))
        );
        assert_eq!(
            run("incidents export X --file out.json").unwrap().command,
            Command::Export {
                incident: reference("X"),
                file: Some("out.json".into())
            }
        );
        assert_eq!(
            run("incidents tag set X env prod").unwrap().command,
            Command::Tag {
                incident: reference("X"),
                key: "env".into(),
                value: Some("prod".into())
            }
        );
        assert_eq!(
            run("incidents tag remove X env").unwrap().command,
            Command::Tag {
                incident: reference("X"),
                key: "env".into(),
                value: None
            }
        );
    }

    #[test]
    fn version_and_confirmation_flags_reach_the_command() {
        let Command::Change {
            expected_version,
            yes,
            ..
        } = run("incidents close X --reason resolved --expected-version 8 -y")
            .unwrap()
            .command
        else {
            panic!("not a change")
        };
        assert_eq!((expected_version, yes), (Some(8), true));
    }

    #[test]
    fn list_flags_become_query_pairs_and_lists_split() {
        let parsed = run(
            "incidents list --state open,acknowledged --state resolved --severity=critical --limit 5",
        )
        .unwrap();
        let Command::List(list) = parsed.command else {
            panic!("not a list")
        };
        let pairs: Vec<(&str, &str)> = list
            .query
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        assert_eq!(
            pairs,
            [
                ("state", "open"),
                ("state", "acknowledged"),
                ("state", "resolved"),
                ("severity", "critical"),
                ("limit", "5")
            ]
        );
    }

    #[test]
    fn global_flags_may_sit_anywhere() {
        let parsed = run("incidents show X -o json --profile prod").unwrap();
        assert_eq!(parsed.global.output, Output::Json);
        assert_eq!(parsed.global.profile.as_deref(), Some("prod"));
        assert_eq!(
            run("--output=wide incidents list").unwrap().global.output,
            Output::Wide
        );
    }

    #[test]
    fn mistakes_are_refused_not_ignored() {
        for line in [
            "incidents list --stat open",
            "incidents show",
            "incidents show A B",
            "incidents frobnicate X",
            "incidents",
            "alerts list",
            "incidents show X --state open",
            "incidents timeline X --state open",
            "incidents list --limit",
            "-o yaml incidents list",
            "incidents list --yes",
            "incidents close X",
            "incidents close X --reason a --reason b",
            "incidents acknowledge X --reason why",
            "incidents assign X",
            "incidents assign X --user a --team b",
            "incidents suppress X --reason r",
            "incidents suppress X --for 2h --until 2026-10-06T00:00:00Z --reason r",
            "incidents suppress X --for 2w --reason r",
            "incidents suppress X --for 0h --reason r",
            "incidents acknowledge X --expected-version six",
            "incidents note add X --message m --expected-version 3",
            "incidents note add X",
            "incidents note edit X 1",
            "incidents note edit X one --message m",
            "incidents note edit X 1 --message m --expected-version 3",
            "incidents note redact X 1",
            "incidents severity set X",
            "incidents --yes=true acknowledge X",
            "incidents open --title t --severity major",
            "incidents open --title t --severity major --target-scope host --target x --direction incoming --address-family six",
            "incidents export X --yes",
            "incidents tag set X env",
            "incidents tag remove X env --reason r",
            "incidents claim X --user u",
        ] {
            assert!(run(line).is_err(), "{line} should be refused");
        }
    }

    #[test]
    fn credentials_are_never_flags() {
        for line in [
            "incidents list --token wnm_x",
            "--api-token=wnm_x incidents list",
        ] {
            let error = run(line).unwrap_err();
            assert!(error.0.contains("WETECHINETMON_API_TOKEN"), "{}", error.0);
            assert!(!error.0.contains("wnm_x"), "the secret is never echoed");
        }
    }
}
