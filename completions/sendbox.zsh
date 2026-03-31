#compdef sendbox

__sendbox_complete() {
    local -ar non_empty_completions=("${@:#(|:*)}")
    local -ar empty_completions=("${(M)@:#(|:*)}")
    _describe -V '' non_empty_completions -- empty_completions -P $'\'\''
}

__sendbox_custom_complete() {
    local -a completions
    completions=("${(@f)"$("${command_name}" "${@}" "${command_line[@]}")"}")
    if [[ "${#completions[@]}" -gt 1 ]]; then
        __sendbox_complete "${completions[@]:0:-1}"
    fi
}

__sendbox_cursor_index_in_current_word() {
    if [[ -z "${QIPREFIX}${IPREFIX}${PREFIX}" ]]; then
        printf 0
    else
        printf %s "${#${(z)LBUFFER}[-1]}"
    fi
}

_sendbox() {
    emulate -RL zsh -G
    setopt extendedglob nullglob numericglobsort
    unsetopt aliases banghist

    local -xr SAP_SHELL=zsh
    local -x SAP_SHELL_VERSION
    SAP_SHELL_VERSION="$(builtin emulate zsh -c 'printf %s "${ZSH_VERSION}"')"
    local -r SAP_SHELL_VERSION

    local context state state_descr line
    local -A opt_args

    local -r command_name="${words[1]}"
    local -ar command_line=("${words[@]}")
    local -ir current_word_index="$((CURRENT - 1))"

    local -i ret=1
    local -ar arg_specs=(
        '--version[Show the version.]'
        '(-h --help)'{-h,--help}'[Show help information.]'
        '(-): :->command'
        '(-)*:: :->arg'
    )
    _arguments -w -s -S : "${arg_specs[@]}" && ret=0
    case "${state}" in
    command)
        local -ar subcommands=(
            'run:Run an agent in a sandboxed container'
            'init:Initialize a sendbox configuration for a project'
            'analyze:Analyze a project and suggest sandbox configuration'
            'secrets:Manage secrets for sandbox injection'
            'policy:View and validate security policies'
            'help:Show subcommand help information.'
        )
        _describe -V subcommand subcommands && ret=0
        ;;
    arg)
        case "${words[1]}" in
        run|init|analyze|secrets|policy|help)
            "_sendbox_${words[1]}" && ret=0
            ;;
        esac
        ;;
    esac

    return "${ret}"
}

_sendbox_run() {
    local -i ret=1
    local -ar ___policy=('default' 'permissive' 'strict')
    local -ar arg_specs=(
        '--config[Path to sendbox config file]:config:'
        '--project[Path to the project directory]:project:'
        '--policy[Security policy preset (default, permissive, strict)]:policy:{__sendbox_complete "${___policy[@]}"}'
        '--version[Show the version.]'
        '(-h --help)'{-h,--help}'[Show help information.]'
    )
    _arguments -w -s -S : "${arg_specs[@]}" && ret=0

    return "${ret}"
}

_sendbox_init() {
    local -i ret=1
    local -ar ___policy=('default' 'permissive' 'strict')
    local -ar arg_specs=(
        '--project[Path to the project directory]:project:'
        '--policy[Security policy preset (default, permissive, strict)]:policy:{__sendbox_complete "${___policy[@]}"}'
        '--version[Show the version.]'
        '(-h --help)'{-h,--help}'[Show help information.]'
    )
    _arguments -w -s -S : "${arg_specs[@]}" && ret=0

    return "${ret}"
}

_sendbox_analyze() {
    local -i ret=1
    local -ar arg_specs=(
        '--project[Path to the project directory]:project:'
        '--output[Output directory for generated devcontainer.json]:output:'
        '--version[Show the version.]'
        '(-h --help)'{-h,--help}'[Show help information.]'
    )
    _arguments -w -s -S : "${arg_specs[@]}" && ret=0

    return "${ret}"
}

_sendbox_secrets() {
    local -i ret=1
    local -ar arg_specs=(
        '--version[Show the version.]'
        '(-h --help)'{-h,--help}'[Show help information.]'
        '(-): :->command'
        '(-)*:: :->arg'
    )
    _arguments -w -s -S : "${arg_specs[@]}" && ret=0
    case "${state}" in
    command)
        local -ar subcommands=(
            'add:Add a secret to the vault'
            'remove:Remove a secret from the vault'
            'list:List all secret keys in the vault'
        )
        _describe -V subcommand subcommands && ret=0
        ;;
    arg)
        case "${words[1]}" in
        add|remove|list)
            "_sendbox_secrets_${words[1]}" && ret=0
            ;;
        esac
        ;;
    esac

    return "${ret}"
}

_sendbox_secrets_add() {
    local -i ret=1
    local -ar arg_specs=(
        ':key:'
        '--version[Show the version.]'
        '(-h --help)'{-h,--help}'[Show help information.]'
    )
    _arguments -w -s -S : "${arg_specs[@]}" && ret=0

    return "${ret}"
}

_sendbox_secrets_remove() {
    local -i ret=1
    local -ar arg_specs=(
        ':key:'
        '--version[Show the version.]'
        '(-h --help)'{-h,--help}'[Show help information.]'
    )
    _arguments -w -s -S : "${arg_specs[@]}" && ret=0

    return "${ret}"
}

_sendbox_secrets_list() {
    local -i ret=1
    local -ar arg_specs=(
        '--version[Show the version.]'
        '(-h --help)'{-h,--help}'[Show help information.]'
    )
    _arguments -w -s -S : "${arg_specs[@]}" && ret=0

    return "${ret}"
}

_sendbox_policy() {
    local -i ret=1
    local -ar arg_specs=(
        '--version[Show the version.]'
        '(-h --help)'{-h,--help}'[Show help information.]'
        '(-): :->command'
        '(-)*:: :->arg'
    )
    _arguments -w -s -S : "${arg_specs[@]}" && ret=0
    case "${state}" in
    command)
        local -ar subcommands=(
            'show:Display the effective security policy'
            'validate:Validate a configuration file'\''s policy section'
        )
        _describe -V subcommand subcommands && ret=0
        ;;
    arg)
        case "${words[1]}" in
        show|validate)
            "_sendbox_policy_${words[1]}" && ret=0
            ;;
        esac
        ;;
    esac

    return "${ret}"
}

_sendbox_policy_show() {
    local -i ret=1
    local -ar arg_specs=(
        '--config[Path to sendbox config file]:config:'
        '--version[Show the version.]'
        '(-h --help)'{-h,--help}'[Show help information.]'
    )
    _arguments -w -s -S : "${arg_specs[@]}" && ret=0

    return "${ret}"
}

_sendbox_policy_validate() {
    local -i ret=1
    local -ar arg_specs=(
        '--config[Path to sendbox config file]:config:'
        '--version[Show the version.]'
        '(-h --help)'{-h,--help}'[Show help information.]'
    )
    _arguments -w -s -S : "${arg_specs[@]}" && ret=0

    return "${ret}"
}

_sendbox_help() {
    local -i ret=1
    local -ar arg_specs=(
        '*:subcommands:'
        '--version[Show the version.]'
    )
    _arguments -w -s -S : "${arg_specs[@]}" && ret=0

    return "${ret}"
}

if [[ "${funcstack[1]}" = _sendbox ]]; then
    _sendbox "${@}"
else
    compdef _sendbox sendbox
fi
