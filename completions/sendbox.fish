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
            __sendbox_parse_subcommand 0 'config=' 'project=' 'policy=' 'version' 'h/help'
        case 'init'
            __sendbox_parse_subcommand 0 'project=' 'policy=' 'version' 'h/help'
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
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_positional "sendbox" 1' -fa 'help' -d 'Show subcommand help information.'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox run" config' -l 'config' -d 'Path to sendbox config file' -rfka ''
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox run" project' -l 'project' -d 'Path to the project directory' -rfka ''
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox run" policy' -l 'policy' -d 'Security policy preset (default, permissive, strict)' -rfka 'default permissive strict'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox run" version' -l 'version' -d 'Show the version.'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox run" h help' -s 'h' -l 'help' -d 'Show help information.'
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox init" project' -l 'project' -d 'Path to the project directory' -rfka ''
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox init" policy' -l 'policy' -d 'Security policy preset (default, permissive, strict)' -rfka 'default permissive strict'
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
complete -c 'sendbox' -n '__sendbox_should_offer_completions_for_flags_or_options "sendbox help" version' -l 'version' -d 'Show the version.'
