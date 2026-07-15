function __sendbox_should_offer_completions_for_flags_or_options -a expected_commands
    set -l non_repeating_flags_or_options $argv[2..]

    set -l non_repeating_flags_or_options_absent 0
    set -l positional_index 0
    set -l commands
    __sendbox_parse_tokens
    test "$commands" = "$expected_commands"; and return $non_repeating_flags_or_options_absent
end

function __sendbox_should_offer_completions_for_positional -a expected_commands expected_positional_index positional_index_comparison
    if test -z $positional_index_comparison
        set positional_index_comparison -eq
    end

    set -l non_repeating_flags_or_options
    set -l non_repeating_flags_or_options_absent 0
    set -l positional_index 0
    set -l commands
    __sendbox_parse_tokens
    test "$commands" = "$expected_commands" -a \( "$positional_index" "$positional_index_comparison" "$expected_positional_index" \)
end

function __sendbox_parse_tokens -S
    set -l unparsed_tokens (__sendbox_tokens -pc)
    set -l present_flags_and_options

    switch $unparsed_tokens[1]
    case 'sendbox'
        __sendbox_parse_subcommand 0 'version' 'h/help'
        switch $unparsed_tokens[1]
        case 'run'
            __sendbox_parse_subcommand 0 'config=' 'project=' 'policy=' 'runtime=' 'version' 'h/help'
        case 'init'
            __sendbox_parse_subcommand 0 'project=' 'policy=' 'runtime=' 'version' 'h/help'
        case 'analyze'
            __sendbox_parse_subcommand 0 'project=' 'output=' 'version' 'h/help'
        case 'secrets'
            __sendbox_parse_subcommand 0 'version' 'h/help'
            switch $unparsed_tokens[1]
            case 'add'
                __sendbox_parse_subcommand 1 'version' 'h/help'
            case 'remove'
                __sendbox_parse_subcommand 1 'version' 'h/help'
            case 'list'
                __sendbox_parse_subcommand 0 'version' 'h/help'
            end
        case 'policy'
            __sendbox_parse_subcommand 0 'version' 'h/help'
            switch $unparsed_tokens[1]
            case 'show'
                __sendbox_parse_subcommand 0 'config=' 'version' 'h/help'
            case 'validate'
                __sendbox_parse_subcommand 0 'config=' 'version' 'h/help'
            end
        case 'mcp'
            __sendbox_parse_subcommand 0 'version' 'h/help'
            switch $unparsed_tokens[1]
            case 'script'
                __sendbox_parse_subcommand 0 'config=' 'startup' 'no-stdio' 'no-http' 'version' 'h/help'
            case 'parse'
                __sendbox_parse_subcommand 1 'json' 'redact' 'version' 'h/help'
            case 'report'
                __sendbox_parse_subcommand 1 'version' 'h/help'
            end
        case 'boundary'
            __sendbox_parse_subcommand 0 'version' 'h/help'
            switch $unparsed_tokens[1]
            case 'script'
                __sendbox_parse_subcommand 0 'config=' 'component=' 'version' 'h/help'
            end
        case 'completions'
            __sendbox_parse_subcommand 0 'version' 'h/help'
            switch $unparsed_tokens[1]
            case 'install'
                __sendbox_parse_subcommand 0 'shell=' 'version' 'h/help'
            case 'print'
                __sendbox_parse_subcommand 0 'shell=' 'version' 'h/help'
            end
        case 'help'
            __sendbox_parse_subcommand -r 1 'version'
        end
    end
end

function __sendbox_tokens
    if test (string split -m 1 -f 1 -- . "$FISH_VERSION") -gt 3
        commandline --tokens-raw $argv
    else
        commandline -o $argv
    end
end

function __sendbox_parse_subcommand -S -a positional_count
    argparse -s r -- $argv
    set -l option_specs $argv[2..]

    set -a commands $unparsed_tokens[1]
    set -e unparsed_tokens[1]

    set positional_index 0

    while true
        argparse -sn "$commands" $option_specs -- $unparsed_tokens 2> /dev/null
        set unparsed_tokens $argv
        set positional_index (math $positional_index + 1)

        for non_repeating_flag_or_option in $non_repeating_flags_or_options
            if set -ql _flag_$non_repeating_flag_or_option
                set non_repeating_flags_or_options_absent 1
                break
            end
        end

        if test (count $unparsed_tokens) -eq 0 -o \( -z "$_flag_r" -a "$positional_index" -gt "$positional_count" \)
            break
        end
        set -e unparsed_tokens[1]
    end
end

function __sendbox_complete_directories
    set -l token (commandline -t)
    string match -- '*/' $token
    set -l subdirs $token*/
    printf '%s\n' $subdirs
end

function __sendbox_custom_completion
    set -x SAP_SHELL fish
    set -x SAP_SHELL_VERSION $FISH_VERSION

    set -l tokens (__sendbox_tokens -p)
    if test -z (__sendbox_tokens -t)
        set -l index (count (__sendbox_tokens -pc))
        set tokens $tokens[..$index] \'\' $tokens[(math $index + 1)..]
    end
    command $tokens[1] $argv $tokens
end

complete -c 'sendbox' -f
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox" version' -l 'version' -d 'Show the version.'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox" h help' -s 'h' -l 'help' -d 'Show help information.'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_positional "sendbox" 1' -fa 'run' -d 'Run an agent in a sandboxed container'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_positional "sendbox" 1' -fa 'init' -d 'Initialize a sendbox configuration for a project'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_positional "sendbox" 1' -fa 'analyze' -d 'Analyze a project and suggest sandbox configuration'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_positional "sendbox" 1' -fa 'secrets' -d 'Manage secrets for sandbox injection'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_positional "sendbox" 1' -fa 'policy' -d 'View and validate security policies'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_positional "sendbox" 1' -fa 'mcp' -d 'Inspect Model Context Protocol (MCP) calls via eBPF'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_positional "sendbox" 1' -fa 'boundary' -d 'Inspect fail-closed syscall and MCP boundary artifacts'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_positional "sendbox" 1' -fa 'completions' -d 'Install shell completions for sendbox'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_positional "sendbox" 1' -fa 'help' -d 'Show subcommand help information.'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox run" config' -l 'config' -d 'Path to sendbox config file' -rfka ''
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox run" project' -l 'project' -d 'Path to the project directory' -rfka ''
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox run" policy' -l 'policy' -d 'Security policy preset (default, permissive, strict)' -rfka 'default permissive strict'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox run" runtime' -l 'runtime' -d 'Runtime provider (auto, apple, kata)' -rfka 'auto apple kata'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox run" version' -l 'version' -d 'Show the version.'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox run" h help' -s 'h' -l 'help' -d 'Show help information.'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox init" project' -l 'project' -d 'Path to the project directory' -rfka ''
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox init" policy' -l 'policy' -d 'Security policy preset (default, permissive, strict)' -rfka 'default permissive strict'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox init" runtime' -l 'runtime' -d 'Runtime provider (auto, apple, kata)' -rfka 'auto apple kata'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox init" version' -l 'version' -d 'Show the version.'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox init" h help' -s 'h' -l 'help' -d 'Show help information.'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox analyze" project' -l 'project' -d 'Path to the project directory' -rfka ''
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox analyze" output' -l 'output' -d 'Output directory for generated devcontainer.json' -rfka ''
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox analyze" version' -l 'version' -d 'Show the version.'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox analyze" h help' -s 'h' -l 'help' -d 'Show help information.'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox secrets" version' -l 'version' -d 'Show the version.'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox secrets" h help' -s 'h' -l 'help' -d 'Show help information.'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_positional "sendbox secrets" 1' -fa 'add' -d 'Add a secret to the vault'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_positional "sendbox secrets" 1' -fa 'remove' -d 'Remove a secret from the vault'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_positional "sendbox secrets" 1' -fa 'list' -d 'List all secret keys in the vault'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox secrets add" version' -l 'version' -d 'Show the version.'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox secrets add" h help' -s 'h' -l 'help' -d 'Show help information.'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox secrets remove" version' -l 'version' -d 'Show the version.'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox secrets remove" h help' -s 'h' -l 'help' -d 'Show help information.'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox secrets list" version' -l 'version' -d 'Show the version.'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox secrets list" h help' -s 'h' -l 'help' -d 'Show help information.'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox policy" version' -l 'version' -d 'Show the version.'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox policy" h help' -s 'h' -l 'help' -d 'Show help information.'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_positional "sendbox policy" 1' -fa 'show' -d 'Display the effective security policy'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_positional "sendbox policy" 1' -fa 'validate' -d 'Validate a configuration file\'s policy section'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox policy show" config' -l 'config' -d 'Path to sendbox config file' -rfka ''
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox policy show" version' -l 'version' -d 'Show the version.'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox policy show" h help' -s 'h' -l 'help' -d 'Show help information.'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox policy validate" config' -l 'config' -d 'Path to sendbox config file' -rfka ''
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox policy validate" version' -l 'version' -d 'Show the version.'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox policy validate" h help' -s 'h' -l 'help' -d 'Show help information.'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox mcp" version' -l 'version' -d 'Show the version.'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox mcp" h help' -s 'h' -l 'help' -d 'Show help information.'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_positional "sendbox mcp" 1' -fa 'script' -d 'Print the bpftrace program (or guest startup script) for MCP inspection'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_positional "sendbox mcp" 1' -fa 'parse' -d 'Parse a captured MCP trace log into structured calls'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_positional "sendbox mcp" 1' -fa 'report' -d 'Summarise MCP activity from a captured trace log'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox mcp script" config' -l 'config' -d 'Path to sendbox config file' -rfka ''
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox mcp script" startup' -l 'startup' -d 'Print the guest startup bash script instead of the raw bpftrace program'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox mcp script" no-stdio' -l 'no-stdio' -d 'Disable stdio (pipe) transport tracing'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox mcp script" no-http' -l 'no-http' -d 'Disable HTTP/SSE (TLS) transport tracing'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox mcp script" version' -l 'version' -d 'Show the version.'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox mcp script" h help' -s 'h' -l 'help' -d 'Show help information.'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox mcp parse" json' -l 'json' -d 'Emit parsed calls as JSON'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox mcp parse" redact' -l 'redact' -d 'Redact payloads, keeping only method/id/tool metadata'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox mcp parse" version' -l 'version' -d 'Show the version.'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox mcp parse" h help' -s 'h' -l 'help' -d 'Show help information.'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox mcp report" version' -l 'version' -d 'Show the version.'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox mcp report" h help' -s 'h' -l 'help' -d 'Show help information.'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox boundary" version' -l 'version' -d 'Show the version.'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox boundary" h help' -s 'h' -l 'help' -d 'Show help information.'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_positional "sendbox boundary" 1' -fa 'script' -d 'Print a generated boundary component'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox boundary script" config' -l 'config' -d 'Path to sendbox config file' -rfka ''
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox boundary script" component' -l 'component' -d 'Component: bootstrap, bpftrace, proxy, proxy-client, or seccomp' -rfka 'bootstrap bpftrace proxy proxy-client seccomp'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox boundary script" version' -l 'version' -d 'Show the version.'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox boundary script" h help' -s 'h' -l 'help' -d 'Show help information.'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox completions" version' -l 'version' -d 'Show the version.'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox completions" h help' -s 'h' -l 'help' -d 'Show help information.'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_positional "sendbox completions" 1' -fa 'install' -d 'Install completions for your current shell'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_positional "sendbox completions" 1' -fa 'print' -d 'Print completions to stdout (for manual setup)'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox completions install" shell' -l 'shell' -d 'Shell to install for (bash, zsh, fish). Auto-detected if omitted.' -rfka ''
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox completions install" version' -l 'version' -d 'Show the version.'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox completions install" h help' -s 'h' -l 'help' -d 'Show help information.'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox completions print" shell' -l 'shell' -d 'Shell (bash, zsh, fish)' -rfka ''
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox completions print" version' -l 'version' -d 'Show the version.'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox completions print" h help' -s 'h' -l 'help' -d 'Show help information.'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox help" version' -l 'version' -d 'Show the version.'
