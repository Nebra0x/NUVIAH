#!/usr/bin/env bash
#
# NUVIAH - OSINT Username Trace Intelligence
# Version: 1.0.5
#
# Copyright © 2026 Nebra0x
# All rights reserved except as expressly granted under the LICENSE file.
#
# Licensed under the PolyForm Strict License 1.0.0.
# Noncommercial use of the unmodified official software is permitted only
# under the terms of the LICENSE file.
#
# Modification, redistribution, resale, sublicensing, and commercial use
# are prohibited without prior written authorization from the copyright holder.
# This notice is a summary; the LICENSE file governs.
#
# Passive username discovery across public endpoints.
# Exact by default. Exploratory by choice.
#
# Responsible use: use only with public data and in authorized contexts.
# A username match does NOT prove that two accounts belong to the same person.
#

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

readonly NUVIAH_VERSION="1.0.5"
readonly PROGRAM_NAME="${0##*/}"
readonly DEFAULT_USER_AGENT="Nuviah/${NUVIAH_VERSION} (passive public-profile checker)"
readonly MAX_RESPONSE_BYTES=8388608  # 8 MiB per response

if (( BASH_VERSINFO[0] < 4 )); then
    printf 'Error: NUVIAH requires Bash 4 or later.\n' >&2
    exit 2
fi

# -----------------------------------------------------------------------------
# Default configuration
# -----------------------------------------------------------------------------

ACTION="scan"
USERNAME=""
PLATFORMS_RAW="all"
OUTPUT_DIR="./nuviah-reports"
TIMEOUT=12
CONNECT_TIMEOUT=5
DELAY_MS=350
MAX_HTTP_REQUESTS=150
SIMILAR_ENABLED=0
SIMILARITY_THRESHOLD=88
MAX_VARIANTS=6
HISTORY_ENABLED=0
WANT_TXT=1
WANT_CSV=0
WANT_JSON=0
WANT_PDF=0
NO_COLOR_ENV="${NO_COLOR-}"
NO_COLOR=0
NO_BANNER=0
QUIET=0
DEBUG=0
DISCORD_ID=""
USER_AGENT="$DEFAULT_USER_AGENT"

# Keep an optional GitHub token available to Bash without exporting it to
# curl, Python or other child processes. The token is supplied to curl through
# a private temporary header file only for the relevant request.
GITHUB_TOKEN_VALUE="${GITHUB_TOKEN-}"
unset GITHUB_TOKEN
export -n GITHUB_TOKEN_VALUE 2>/dev/null || true

TMP_DIR=""
RESULTS_TSV=""
BASE_PATH=""
CURRENT_TASK=0
TOTAL_TASKS=0
HTTP_REQUEST_COUNT=0
REQUEST_SEQ=0

# Colors are initialized after CLI parsing.
C_RESET=""
C_DIM=""
C_BOLD=""
C_VIOLET=""
C_GREEN=""
C_YELLOW=""
C_RED=""
C_CYAN=""
C_GRAY=""

cleanup() {
    if [[ -n "${TMP_DIR:-}" && -d "$TMP_DIR" ]]; then
        rm -rf -- "$TMP_DIR"
    fi
}

handle_interrupt() {
    exit 130
}

handle_termination() {
    exit 143
}

trap cleanup EXIT
trap handle_interrupt INT
trap handle_termination TERM

# -----------------------------------------------------------------------------
# Output and utilities
# -----------------------------------------------------------------------------

configure_colors() {
    if (( NO_COLOR == 0 )) && [[ -t 1 ]] && [[ -z "$NO_COLOR_ENV" ]]; then
        C_RESET=$'\033[0m'
        C_DIM=$'\033[2m'
        C_BOLD=$'\033[1m'
        C_VIOLET=$'\033[38;5;141m'
        C_GREEN=$'\033[38;5;78m'
        C_YELLOW=$'\033[38;5;220m'
        C_RED=$'\033[38;5;203m'
        C_CYAN=$'\033[38;5;81m'
        C_GRAY=$'\033[38;5;245m'
    fi
}

info() {
    (( QUIET == 1 )) && return 0
    printf '%b%s%b\n' "$C_CYAN" "$*" "$C_RESET"
}

warn() {
    printf '%b[WARN]%b %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2
}

die() {
    printf '%b[ERROR]%b %s\n' "$C_RED" "$C_RESET" "$*" >&2
    exit 2
}

debug_log() {
    (( DEBUG == 1 )) || return 0
    printf '%b[DEBUG]%b %s\n' "$C_GRAY" "$C_RESET" "$*" >&2
}

require_arg() {
    local option="$1"
    local value="${2-}"
    [[ -n "$value" ]] || die "Option $option requires a value."
}

is_uint() {
    [[ "${1-}" =~ ^[0-9]+$ ]]
}

python_version_supported() {
    python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)' \
        >/dev/null 2>&1
}

normalize_decimal() {
    local value="$1"
    is_uint "$value" || return 1
    # All numeric CLI limits are small. Reject pathological values before
    # Bash arithmetic can overflow, and force base-10 parsing for values like 08.
    (( ${#value} <= 10 )) || return 1
    printf '%d' "$((10#$value))"
}

validate_range() {
    local name="$1"
    local value="$2"
    local min="$3"
    local max="$4"
    local decimal

    decimal="$(normalize_decimal "$value")" || die "$name must be an integer."
    (( decimal >= min && decimal <= max )) || die "$name must be between $min and $max."
}

sleep_ms() {
    local milliseconds="$1"
    (( milliseconds > 0 )) || return 0
    local seconds=$(( milliseconds / 1000 ))
    local remainder=$(( milliseconds % 1000 ))
    sleep "${seconds}.$(printf '%03d' "$remainder")"
}

utc_now() {
    date -u '+%Y-%m-%dT%H:%M:%SZ'
}

safe_filename() {
    local value="$1"
    value="${value//[^A-Za-z0-9._-]/_}"
    printf '%s' "$value"
}

sanitize_field() {
    local value="${1-}"
    value="${value//$'\t'/ }"
    value="${value//$'\r'/ }"
    value="${value//$'\n'/ }"
    printf '%s' "$value"
}

terminal_columns() {
    local cols="${COLUMNS:-}"
    local normalized=""

    normalized="$(normalize_decimal "$cols" 2>/dev/null || true)"
    if [[ -z "$normalized" ]] || (( normalized < 20 )); then
        cols="$(tput cols 2>/dev/null || true)"
        normalized="$(normalize_decimal "$cols" 2>/dev/null || true)"
    fi
    if [[ -z "$normalized" ]] || (( normalized < 20 )); then
        normalized=80
    fi
    # Avoid excessive padding if an untrusted environment supplies a huge value.
    if (( normalized > 240 )); then
        normalized=240
    fi
    printf '%s' "$normalized"
}

center_line() {
    local text="${1-}"
    local cols
    cols="$(terminal_columns)"
    local width=${#text}
    local padding=0
    if (( cols > width )); then
        padding=$(( (cols - width) / 2 ))
    fi
    printf '%*s%s\n' "$padding" '' "$text"
}

banner() {
    (( NO_BANNER == 1 || QUIET == 1 )) && return 0

    printf '\n%b' "$C_VIOLET"
    center_line '•   •'
    printf '\n'
    center_line '•      ◉      •'
    printf '\n'
    center_line '•   •'
    printf '%b\n\n' "$C_RESET"

    printf '%b' "$C_BOLD"
    center_line 'N U V I A H'
    printf '%b\n' "$C_RESET"
    printf '%b' "$C_DIM"
    center_line 'DIGITAL PRESENCE'
    printf '%b\n' "$C_RESET"
}

print_legend() {
    cat <<'EOF'
RESULT LEGEND

  ◉  CONFIRMED
     Strong technical evidence confirms the public endpoint.

  ◌  PROBABLE
     Evidence suggests a match, but verification remains heuristic.

  ○  NOT FOUND
     No current public endpoint was verified.
     This does not mean the username never existed.

  ◈  BLOCKED
     Verification was prevented by authentication, rate limiting,
     access controls or anti-bot protections.

  ◇  INCONCLUSIVE
     Available evidence is insufficient for a reliable classification.

  ×  ERROR
     Network, DNS, timeout or processing error.

  ·  MANUAL CHECK
     Reliable automated username-only verification is not available.
EOF
}

usage() {
    banner
    cat <<EOF
NUVIAH ${NUVIAH_VERSION} - passive analysis of public username traces

USAGE

  ${PROGRAM_NAME} scan <username> [OPTIONS]
  ${PROGRAM_NAME} <username> [OPTIONS]
  ${PROGRAM_NAME} help [scan]
  ${PROGRAM_NAME} [COMMAND]

COMMANDS

  scan <username>             Search for an exact username across public sources
  help                        Show this help screen
  help scan                   Show scan-specific help
  --legend                    Show the result legend only
  --list-platforms            List supported platforms and verification methods
  --check-deps                Check required and optional dependencies
  --self-test                 Run built-in offline diagnostic tests
  -h, --help                  Show this help screen
  -V, --version               Show the NUVIAH version

SCAN OPTIONS

  -p, --platforms <list>      Scan selected platforms only
                              Example: --platforms "github,instagram,telegram"

      --all                   Scan all supported platforms

      --similar               Search conservative username variants

      --similarity-threshold <N>
                              Minimum textual similarity: 70-100
                              Default: ${SIMILARITY_THRESHOLD}

      --max-variants <N>      Maximum generated variants: 1-25
                              Default: ${MAX_VARIANTS}

      --history               Search for a public Wayback snapshot

      --discord-id <ID>       Add a manual Discord profile link for a known ID

REPORT OPTIONS

      --csv                   Also generate a CSV report
      --json                  Also generate a JSON report
      --pdf                   Also generate a PDF report
                              Requires python3-reportlab

      --all-formats           Generate TXT, CSV, JSON and PDF reports
      --no-txt                Do not generate the TXT report

  -o, --output-dir <dir>      Report directory
                              Default: ${OUTPUT_DIR}

NETWORK AND LIMITS

      --timeout <sec>         Total request timeout: 2-120
                              Default: ${TIMEOUT}

      --connect-timeout <sec> Connection timeout: 1-60
                              Default: ${CONNECT_TIMEOUT}

      --delay <ms>            Delay between requests: 0-10000
                              Default: ${DELAY_MS}

      --max-requests <N>      Maximum HTTP request budget
                              Default: ${MAX_HTTP_REQUESTS}

      --user-agent <string>   Use a custom User-Agent

INTERFACE

      --no-color              Disable ANSI colors
      --no-banner             Hide the NUVIAH banner
  -q, --quiet                 Show only the summary and report paths
      --debug                 Show diagnostic information

EXAMPLES

  Exact scan:
      ${PROGRAM_NAME} scan octocat

  Selected platforms:
      ${PROGRAM_NAME} scan octocat --platforms "github,reddit,telegram"

  All supported platforms:
      ${PROGRAM_NAME} scan octocat --all

  Similar username candidates:
      ${PROGRAM_NAME} scan octocat --similar --similarity-threshold 88 --max-variants 5

  Historical trace search:
      ${PROGRAM_NAME} scan octocat --history

  Complete analysis:
      ${PROGRAM_NAME} scan octocat --all --similar --history --all-formats --output-dir reports

  Username beginning with a hyphen (place options before --):
      ${PROGRAM_NAME} scan --platforms discord -- -example

EOF
    print_legend
    cat <<'EOF'

IMPORTANT

  Username similarity does not imply identity correlation.

  NUVIAH analyzes publicly accessible traces. A matching or similar username
  does not prove that accounts on different platforms belong to the same person.

  Historical evidence does not independently prove deletion, renaming,
  suspension or ownership.
EOF
}

scan_usage() {
    banner
    cat <<EOF
NUVIAH ${NUVIAH_VERSION} - scan command

USAGE

  ${PROGRAM_NAME} scan <username> [OPTIONS]

CORE OPTIONS

  -p, --platforms <list>      Selected platforms, comma-separated
      --all                   All supported platforms
      --similar               Search conservative username variants
      --similarity-threshold <N>
                              Minimum textual similarity: 70-100
                              Default: ${SIMILARITY_THRESHOLD}
      --max-variants <N>      Maximum generated variants: 1-25
                              Default: ${MAX_VARIANTS}
      --history               Search public historical snapshots
      --discord-id <ID>       Add a manual Discord profile link for a known ID

REPORT OPTIONS

      --csv                   Generate CSV in addition to TXT
      --json                  Generate JSON in addition to TXT
      --pdf                   Generate PDF in addition to TXT
      --all-formats           Generate TXT, CSV, JSON and PDF
      --no-txt                Disable TXT output
  -o, --output-dir <dir>      Select the report directory

NETWORK OPTIONS

      --timeout <sec>         Total request timeout
      --connect-timeout <sec> Connection timeout
      --delay <ms>            Delay between requests
      --max-requests <N>      HTTP request budget
      --user-agent <string>   Custom User-Agent

INTERFACE

      --no-color              Disable ANSI colors
      --no-banner             Hide the banner
  -q, --quiet                 Minimal terminal output
      --debug                 Diagnostic output
  -h, --help                  Show this scan help

EXAMPLES

  ${PROGRAM_NAME} scan octocat --platforms "github,telegram"
  ${PROGRAM_NAME} scan octocat --similar --max-variants 5
  ${PROGRAM_NAME} scan octocat --history --pdf
  ${PROGRAM_NAME} scan octocat --all --similar --history --all-formats -o reports
  ${PROGRAM_NAME} scan --platforms discord -- -example

EOF
    print_legend
}

# -----------------------------------------------------------------------------
# Platform database
# -----------------------------------------------------------------------------

declare -a PLATFORM_ORDER=()
declare -A P_LABEL=()
declare -A P_URL=()
declare -A P_MODE=()
declare -A P_SIMILAR=()
declare -A P_HISTORY=()
declare -A P_CONFIDENCE=()
declare -A P_NEGATIVE=()
declare -A P_NOTE=()

init_platforms() {
    PLATFORM_ORDER=(
        instagram
        tiktok
        github
        youtube
        x
        snapchat
        discord
        reddit
        linkedin
        pinterest
        telegram
        bereal
    )

    P_LABEL[instagram]="Instagram"
    P_URL[instagram]="https://www.instagram.com/{username}/"
    P_MODE[instagram]="html"
    P_SIMILAR[instagram]=1
    P_HISTORY[instagram]=1
    P_CONFIDENCE[instagram]=78
    P_NEGATIVE[instagram]=$'Sorry, this page isn\'t available\nThe link you followed may be broken\nPage Not Found'
    P_NOTE[instagram]="Public page; login walls and anti-bot protections may interfere."

    P_LABEL[tiktok]="TikTok"
    P_URL[tiktok]="https://www.tiktok.com/@{username}"
    P_MODE[tiktok]="html"
    P_SIMILAR[tiktok]=1
    P_HISTORY[tiktok]=1
    P_CONFIDENCE[tiktok]=78
    P_NEGATIVE[tiktok]=$'Couldn\'t find this account\nCouldn\'t find this page\nThis account doesn\'t exist\nPage not available'
    P_NOTE[tiktok]="Public page; content is often dynamic."

    P_LABEL[github]="GitHub"
    P_URL[github]="https://github.com/{username}"
    P_MODE[github]="github_api"
    P_SIMILAR[github]=1
    P_HISTORY[github]=1
    P_CONFIDENCE[github]=100
    P_NEGATIVE[github]=""
    P_NOTE[github]="Strong verification through the public REST API."

    P_LABEL[youtube]="YouTube"
    P_URL[youtube]="https://www.youtube.com/@{username}"
    P_MODE[youtube]="html"
    P_SIMILAR[youtube]=1
    P_HISTORY[youtube]=1
    P_CONFIDENCE[youtube]=88
    P_NEGATIVE[youtube]=$'This page isn\'t available\nThe page you requested cannot be found\n404 Not Found'
    P_NOTE[youtube]="Public handle check; remains heuristic without an API key."

    P_LABEL[x]="X / Twitter"
    P_URL[x]="https://x.com/{username}"
    P_MODE[x]="html"
    P_SIMILAR[x]=1
    P_HISTORY[x]=1
    P_CONFIDENCE[x]=72
    P_NEGATIVE[x]=$'This account doesn’t exist\nThis account doesn\'t exist\nHmm...this page doesn’t exist\nHmm...this page doesn\'t exist'
    P_NOTE[x]="Frequent login redirects and JavaScript-rendered content."

    P_LABEL[snapchat]="Snapchat"
    P_URL[snapchat]="https://www.snapchat.com/add/{username}"
    P_MODE[snapchat]="html"
    P_SIMILAR[snapchat]=1
    P_HISTORY[snapchat]=1
    P_CONFIDENCE[snapchat]=78
    P_NEGATIVE[snapchat]=$'Sorry, we couldn\'t find\nThis content is not available\nPage not found'
    P_NOTE[snapchat]="Public Profile is optional; a negative result does not rule out an account."

    P_LABEL[discord]="Discord"
    P_URL[discord]=""
    P_MODE[discord]="manual"
    P_SIMILAR[discord]=0
    P_HISTORY[discord]=0
    P_CONFIDENCE[discord]=0
    P_NEGATIVE[discord]=""
    P_NOTE[discord]="No reliable public username-only enumeration."

    P_LABEL[reddit]="Reddit"
    P_URL[reddit]="https://www.reddit.com/user/{username}/"
    P_MODE[reddit]="reddit_api"
    P_SIMILAR[reddit]=1
    P_HISTORY[reddit]=1
    P_CONFIDENCE[reddit]=96
    P_NEGATIVE[reddit]=""
    P_NOTE[reddit]="Verification through a public JSON endpoint; authentication may be required."

    P_LABEL[linkedin]="LinkedIn"
    P_URL[linkedin]="https://www.linkedin.com/in/{username}/"
    P_MODE[linkedin]="html"
    P_SIMILAR[linkedin]=0
    P_HISTORY[linkedin]=1
    P_CONFIDENCE[linkedin]=68
    P_NEGATIVE[linkedin]=$'Page not found\nprofile you requested was not found\nThis page doesn’t exist\nThis page doesn\'t exist'
    P_NOTE[linkedin]="The public slug does not necessarily match the username used elsewhere."

    P_LABEL[pinterest]="Pinterest"
    P_URL[pinterest]="https://www.pinterest.com/{username}/"
    P_MODE[pinterest]="html"
    P_SIMILAR[pinterest]=1
    P_HISTORY[pinterest]=1
    P_CONFIDENCE[pinterest]=82
    P_NEGATIVE[pinterest]=$'Sorry! We couldn\'t find that page\nPage not found\nThis page isn\'t available'
    P_NOTE[pinterest]="Private profiles may not be publicly verifiable."

    P_LABEL[telegram]="Telegram"
    P_URL[telegram]="https://t.me/{username}"
    P_MODE[telegram]="html"
    P_SIMILAR[telegram]=1
    P_HISTORY[telegram]=1
    P_CONFIDENCE[telegram]=82
    P_NEGATIVE[telegram]=$'Username not found\nThis username is not available'
    P_NOTE[telegram]="A t.me URL may represent a user, group, channel or bot."

    P_LABEL[bereal]="BeReal"
    P_URL[bereal]=""
    P_MODE[bereal]="manual"
    P_SIMILAR[bereal]=0
    P_HISTORY[bereal]=0
    P_CONFIDENCE[bereal]=0
    P_NEGATIVE[bereal]=""
    P_NOTE[bereal]="Reliable username lookup is performed in the app."
}

normalize_platform() {
    local value="${1,,}"
    value="${value//[[:space:]]/}"
    case "$value" in
        twitter|x.com|twitter.com|x/twitter|twitter/x) printf 'x' ;;
        ithub) printf 'github' ;;
        instagram.com|ig) printf 'instagram' ;;
        tiktok.com|tt) printf 'tiktok' ;;
        github.com|gh) printf 'github' ;;
        youtube.com|yt) printf 'youtube' ;;
        snapchat.com|snap) printf 'snapchat' ;;
        reddit.com) printf 'reddit' ;;
        linkedin.com) printf 'linkedin' ;;
        pinterest.com) printf 'pinterest' ;;
        telegram.org|t.me) printf 'telegram' ;;
        bere.al) printf 'bereal' ;;
        *) printf '%s' "$value" ;;
    esac
}

list_platforms() {
    printf '%-13s %-16s %-12s %-9s %s\n' "KEY" "PLATFORM" "VERIFICATION" "SIMILAR" "NOTES"
    printf '%s\n' "----------------------------------------------------------------------------------------------------"
    local key mode verification
    for key in "${PLATFORM_ORDER[@]}"; do
        mode="${P_MODE[$key]}"
        case "$mode" in
            github_api) verification="Strong API" ;;
            reddit_api) verification="API/JSON" ;;
            html) verification="Heuristic" ;;
            manual) verification="Manual" ;;
            *) verification="$mode" ;;
        esac
        printf '%-13s %-16s %-12s %-9s %s\n' \
            "$key" "${P_LABEL[$key]}" "$verification" \
            "$([[ "${P_SIMILAR[$key]}" == 1 ]] && printf 'yes' || printf 'no')" \
            "${P_NOTE[$key]}"
    done
}

# -----------------------------------------------------------------------------
# Username validation
# -----------------------------------------------------------------------------

valid_global_username() {
    local value="$1"
    [[ "$value" =~ ^[A-Za-z0-9._-]{1,64}$ ]]
}

platform_accepts_username() {
    local platform="$1"
    local value="$2"
    local length=${#value}

    case "$platform" in
        github)
            (( length >= 1 && length <= 39 )) || return 1
            [[ "$value" =~ ^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$ ]] || return 1
            [[ "$value" != *--* ]]
            ;;
        instagram)
            (( length >= 1 && length <= 30 )) || return 1
            [[ "$value" =~ ^[A-Za-z0-9._]+$ ]]
            ;;
        tiktok)
            (( length >= 2 && length <= 24 )) || return 1
            [[ "$value" =~ ^[A-Za-z0-9._]+$ ]] || return 1
            [[ "$value" != *. ]]
            ;;
        youtube)
            (( length >= 3 && length <= 30 )) || return 1
            [[ "$value" =~ ^[A-Za-z0-9._-]+$ ]]
            ;;
        x)
            (( length >= 1 && length <= 15 )) || return 1
            [[ "$value" =~ ^[A-Za-z0-9_]+$ ]]
            ;;
        snapchat)
            (( length >= 3 && length <= 15 )) || return 1
            [[ "$value" =~ ^[A-Za-z][A-Za-z0-9._-]*$ ]]
            ;;
        reddit)
            (( length >= 3 && length <= 20 )) || return 1
            [[ "$value" =~ ^[A-Za-z0-9_-]+$ ]]
            ;;
        linkedin)
            (( length >= 3 && length <= 100 )) || return 1
            [[ "$value" =~ ^[A-Za-z0-9-]+$ ]]
            ;;
        pinterest)
            (( length >= 3 && length <= 30 )) || return 1
            [[ "$value" =~ ^[A-Za-z0-9_]+$ ]] || return 1
            [[ ! "$value" =~ ^[0-9]+$ ]]
            ;;
        telegram)
            (( length >= 5 && length <= 32 )) || return 1
            [[ "$value" =~ ^[A-Za-z][A-Za-z0-9_]+$ ]]
            ;;
        discord|bereal)
            valid_global_username "$value"
            ;;
        *)
            return 1
            ;;
    esac
}

# -----------------------------------------------------------------------------
# CLI parsing
# -----------------------------------------------------------------------------

parse_cli() {
    local -a positionals=()
    local command_context="root"

    # Explicit help command supports: `help` and `help scan`.
    if (( $# > 0 )) && [[ "$1" == "help" ]]; then
        shift
        if (( $# == 0 )); then
            ACTION="help"
            return 0
        fi
        if [[ "$1" == "scan" ]]; then
            shift
            (( $# == 0 )) || die "Unexpected argument after 'help scan': $1"
            ACTION="scan_help"
            return 0
        fi
        die "Unknown help topic: $1"
    fi

    # `scan` is optional for backward compatibility, but establishes
    # scan-specific help when followed by -h/--help.
    if (( $# > 0 )) && [[ "$1" == "scan" ]]; then
        command_context="scan"
        shift
    fi

    while (( $# > 0 )); do
        case "$1" in
            scan)
                command_context="scan"
                shift
                ;;
            help)
                if [[ "${2-}" == "scan" ]]; then
                    ACTION="scan_help"
                    shift 2
                else
                    ACTION="help"
                    shift
                fi
                ;;
            -p|--platforms)
                require_arg "$1" "${2-}"
                PLATFORMS_RAW="$2"
                shift 2
                ;;
            --all)
                PLATFORMS_RAW="all"
                shift
                ;;
            --similar)
                SIMILAR_ENABLED=1
                shift
                ;;
            --similarity-threshold)
                require_arg "$1" "${2-}"
                SIMILARITY_THRESHOLD="$2"
                shift 2
                ;;
            --max-variants)
                require_arg "$1" "${2-}"
                MAX_VARIANTS="$2"
                shift 2
                ;;
            --history)
                HISTORY_ENABLED=1
                shift
                ;;
            --discord-id)
                require_arg "$1" "${2-}"
                DISCORD_ID="$2"
                shift 2
                ;;
            -o|--output-dir)
                require_arg "$1" "${2-}"
                OUTPUT_DIR="$2"
                shift 2
                ;;
            --csv)
                WANT_CSV=1
                shift
                ;;
            --json)
                WANT_JSON=1
                shift
                ;;
            --pdf)
                WANT_PDF=1
                shift
                ;;
            --all-formats)
                WANT_TXT=1
                WANT_CSV=1
                WANT_JSON=1
                WANT_PDF=1
                shift
                ;;
            --no-txt)
                WANT_TXT=0
                shift
                ;;
            --timeout)
                require_arg "$1" "${2-}"
                TIMEOUT="$2"
                shift 2
                ;;
            --connect-timeout)
                require_arg "$1" "${2-}"
                CONNECT_TIMEOUT="$2"
                shift 2
                ;;
            --delay)
                require_arg "$1" "${2-}"
                DELAY_MS="$2"
                shift 2
                ;;
            --max-requests)
                require_arg "$1" "${2-}"
                MAX_HTTP_REQUESTS="$2"
                shift 2
                ;;
            --user-agent)
                require_arg "$1" "${2-}"
                USER_AGENT="$2"
                shift 2
                ;;
            --no-color)
                NO_COLOR=1
                shift
                ;;
            --no-banner)
                NO_BANNER=1
                shift
                ;;
            -q|--quiet)
                QUIET=1
                NO_BANNER=1
                shift
                ;;
            --debug)
                DEBUG=1
                shift
                ;;
            --check-deps)
                ACTION="check_deps"
                shift
                ;;
            --self-test)
                ACTION="self_test"
                shift
                ;;
            --list-platforms)
                ACTION="list_platforms"
                shift
                ;;
            --legend)
                ACTION="legend"
                shift
                ;;
            -h|--help)
                if [[ "$command_context" == "scan" ]]; then
                    ACTION="scan_help"
                else
                    ACTION="help"
                fi
                shift
                ;;
            -V|--version)
                ACTION="version"
                shift
                ;;
            --)
                shift
                while (( $# > 0 )); do
                    positionals+=("$1")
                    shift
                done
                ;;
            -* )
                die "Unknown option: $1"
                ;;
            *)
                positionals+=("$1")
                shift
                ;;
        esac
    done

    if (( ${#positionals[@]} > 1 )); then
        die "Specify exactly one username."
    fi
    if (( ${#positionals[@]} == 1 )); then
        USERNAME="${positionals[0]}"
    fi

    if [[ "$ACTION" != "scan" && -n "$USERNAME" ]]; then
        die "Unexpected argument for this command: $USERNAME"
    fi
}

validate_options() {
    validate_range "--similarity-threshold" "$SIMILARITY_THRESHOLD" 70 100
    validate_range "--max-variants" "$MAX_VARIANTS" 1 25
    validate_range "--timeout" "$TIMEOUT" 2 120
    validate_range "--connect-timeout" "$CONNECT_TIMEOUT" 1 60
    validate_range "--delay" "$DELAY_MS" 0 10000
    validate_range "--max-requests" "$MAX_HTTP_REQUESTS" 1 1000

    # Store canonical decimal values after validation. This prevents later
    # arithmetic from interpreting leading-zero input as octal.
    SIMILARITY_THRESHOLD="$(normalize_decimal "$SIMILARITY_THRESHOLD")"
    MAX_VARIANTS="$(normalize_decimal "$MAX_VARIANTS")"
    TIMEOUT="$(normalize_decimal "$TIMEOUT")"
    CONNECT_TIMEOUT="$(normalize_decimal "$CONNECT_TIMEOUT")"
    DELAY_MS="$(normalize_decimal "$DELAY_MS")"
    MAX_HTTP_REQUESTS="$(normalize_decimal "$MAX_HTTP_REQUESTS")"

    if [[ -n "$DISCORD_ID" && ! "$DISCORD_ID" =~ ^[0-9]{15,22}$ ]]; then
        die "--discord-id must contain a valid numeric Discord ID (15-22 digits)."
    fi

    if [[ -n "$GITHUB_TOKEN_VALUE" ]] && \
       [[ "$GITHUB_TOKEN_VALUE" == *$'\n'* || "$GITHUB_TOKEN_VALUE" == *$'\r'* ]]; then
        die "GITHUB_TOKEN must not contain newline characters."
    fi

    if [[ "$USER_AGENT" == *$'\n'* || "$USER_AGENT" == *$'\r'* ]]; then
        die "--user-agent must not contain newline characters."
    fi

    if (( WANT_TXT == 0 && WANT_CSV == 0 && WANT_JSON == 0 && WANT_PDF == 0 )); then
        die "No report format selected."
    fi
}

check_core_dependencies() {
    command -v curl >/dev/null 2>&1 || die "curl is not installed. Run: sudo apt install curl"
    command -v python3 >/dev/null 2>&1 || die "python3 is not installed. Run: sudo apt install python3"
    python_version_supported || die "NUVIAH requires Python 3.9 or later."

    if (( WANT_PDF == 1 )); then
        if ! python3 -c 'import reportlab' >/dev/null 2>&1; then
            die "For --pdf install ReportLab: sudo apt install python3-reportlab"
        fi
    fi
}

check_dependencies_report() {
    local failed=0
    local reportlab_version=""

    printf 'Bash:       %s\n' "$(bash --version | head -n 1)"
    if command -v curl >/dev/null 2>&1; then
        printf 'curl:       OK - %s\n' "$(curl --version | head -n 1)"
    else
        printf 'curl:       MISSING\n'
        failed=1
    fi

    if command -v python3 >/dev/null 2>&1; then
        if python_version_supported; then
            printf 'python3:    OK - %s\n' "$(python3 --version 2>&1)"
        else
            printf 'python3:    UNSUPPORTED - %s (requires 3.9+)\n' "$(python3 --version 2>&1)"
            failed=1
        fi
        if reportlab_version="$(python3 -c 'import reportlab; print(reportlab.Version)' 2>/dev/null)"; then
            printf 'reportlab:  OK - %s\n' "$reportlab_version"
        else
            printf 'reportlab:  optional, not installed (required for --pdf)\n'
        fi
    else
        printf 'python3:    MISSING\n'
        printf 'reportlab:  unavailable because python3 is missing\n'
        failed=1
    fi

    return "$failed"
}

# -----------------------------------------------------------------------------
# Platform selection and variants
# -----------------------------------------------------------------------------

declare -a SELECTED_PLATFORMS=()

select_platforms() {
    local raw="$PLATFORMS_RAW"
    local -A seen=()
    local -a requested=()
    local item key

    if [[ "${raw,,}" == "all" ]]; then
        SELECTED_PLATFORMS=("${PLATFORM_ORDER[@]}")
        return 0
    fi

    local old_ifs="$IFS"
    IFS=',' read -r -a requested <<< "$raw"
    IFS="$old_ifs"

    for item in "${requested[@]}"; do
        key="$(normalize_platform "$item")"
        [[ -n "$key" ]] || continue
        [[ -n "${P_LABEL[$key]-}" ]] || die "Unsupported platform: $item"
        if [[ -z "${seen[$key]-}" ]]; then
            SELECTED_PLATFORMS+=("$key")
            seen[$key]=1
        fi
        if [[ "${item,,}" == "ithub" ]]; then
            warn "Interpreting 'ithub' as 'github'."
        fi
    done

    (( ${#SELECTED_PLATFORMS[@]} > 0 )) || die "The platform list is empty."
}

generate_variants() {
    local username="$1"
    local threshold="$2"
    local maximum="$3"
    local output_file="$4"

    python3 - "$username" "$threshold" "$maximum" > "$output_file" <<'PY_VARIANTS'
from __future__ import annotations

import re
import sys

original = sys.argv[1]
threshold = int(sys.argv[2])
maximum = int(sys.argv[3])


def levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(
                current[-1] + 1,
                previous[j] + 1,
                previous[j - 1] + (ca != cb),
            ))
        previous = current
    return previous[-1]


def similarity(a: str, b: str) -> int:
    denominator = max(len(a), len(b), 1)
    return round((1 - levenshtein(a.lower(), b.lower()) / denominator) * 100)

candidates: dict[str, tuple[str, int]] = {}


def add(value: str, kind: str, priority: int) -> None:
    if value == original or not value:
        return
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", value):
        return
    current = candidates.get(value)
    if current is None or priority < current[1]:
        candidates[value] = (kind, priority)

# Separator variants: the most conservative transformations.
if any(separator in original for separator in "._-"):
    compact = re.sub(r"[._-]+", "", original)
    add(compact, "separator_removed", 1)
    parts = [part for part in re.split(r"[._-]+", original) if part]
    if len(parts) >= 2:
        for separator in ("_", ".", "-"):
            add(separator.join(parts), "separator_variant", 1)

# Common suffixes, intentionally limited.
for suffix in ("1", "01", "_1"):
    add(original + suffix, "numeric_suffix", 3)

# If it ends in digits, try the form without the numeric suffix.
without_digits = re.sub(r"[_\-.]?\d{1,4}$", "", original)
if without_digits != original:
    add(without_digits, "numeric_suffix_removed", 2)

# Remove one character: possible typo or adaptation to a platform limit.
if len(original) >= 6:
    for index in range(len(original)):
        add(original[:index] + original[index + 1:], "single_deletion", 4)

# Swap two adjacent characters: a common typographical error.
if len(original) >= 6:
    for index in range(len(original) - 1):
        if original[index] != original[index + 1]:
            value = (
                original[:index]
                + original[index + 1]
                + original[index]
                + original[index + 2:]
            )
            add(value, "adjacent_transposition", 5)

rows = []
for value, (kind, priority) in candidates.items():
    score = similarity(original, value)
    if score >= threshold:
        rows.append((value, score, kind, priority))

rows.sort(key=lambda row: (-row[1], row[3], row[0].lower()))
for value, score, kind, _priority in rows[:maximum]:
    print(f"{value}\t{score}\t{kind}")
PY_VARIANTS
}

# -----------------------------------------------------------------------------
# Result storage and counters
# -----------------------------------------------------------------------------

declare -A STATUS_COUNTS=()
declare -A SECTION_STATUS_COUNTS=()
declare -A EXACT_STATUS=()
declare -A EXACT_URL=()

write_results_header() {
    local file="$1"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "section" "platform" "platform_label" "query_username" \
        "candidate_username" "variant_type" "status" "http_status" \
        "technical_confidence" "username_similarity" "url" "effective_url" \
        "reason" "observed_at" "evidence_url" "evidence_timestamp" > "$file"
}

append_result() {
    local section="$1"
    local platform="$2"
    local platform_label="$3"
    local query_username="$4"
    local candidate_username="$5"
    local variant_type="$6"
    local status="$7"
    local http_status="$8"
    local technical_confidence="$9"
    local username_similarity="${10}"
    local url="${11}"
    local effective_url="${12}"
    local reason="${13}"
    local observed_at="${14}"
    local evidence_url="${15-}"
    local evidence_timestamp="${16-}"

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$(sanitize_field "$section")" \
        "$(sanitize_field "$platform")" \
        "$(sanitize_field "$platform_label")" \
        "$(sanitize_field "$query_username")" \
        "$(sanitize_field "$candidate_username")" \
        "$(sanitize_field "$variant_type")" \
        "$(sanitize_field "$status")" \
        "$(sanitize_field "$http_status")" \
        "$(sanitize_field "$technical_confidence")" \
        "$(sanitize_field "$username_similarity")" \
        "$(sanitize_field "$url")" \
        "$(sanitize_field "$effective_url")" \
        "$(sanitize_field "$reason")" \
        "$(sanitize_field "$observed_at")" \
        "$(sanitize_field "$evidence_url")" \
        "$(sanitize_field "$evidence_timestamp")" >> "$RESULTS_TSV"

    local section_key="${section}|${status}"
    STATUS_COUNTS[$status]=$(( ${STATUS_COUNTS[$status]:-0} + 1 ))
    SECTION_STATUS_COUNTS[$section_key]=$(( ${SECTION_STATUS_COUNTS[$section_key]:-0} + 1 ))
}

status_color() {
    case "$1" in
        FOUND|CURRENT_AND_HISTORICAL) printf '%s' "$C_GREEN" ;;
        POSSIBLE_MATCH|ARCHIVED|HISTORICAL_TRACE) printf '%s' "$C_CYAN" ;;
        NOT_FOUND) printf '%s' "$C_DIM" ;;
        BLOCKED|INCONCLUSIVE|INVALID_FORMAT|NO_ARCHIVE_EVIDENCE|ARCHIVE_ERROR|MANUAL_CHECK) printf '%s' "$C_YELLOW" ;;
        ERROR) printf '%s' "$C_RED" ;;
        *) printf '%s' "$C_RESET" ;;
    esac
}


status_symbol() {
    case "$1" in
        FOUND|CURRENT_AND_HISTORICAL) printf '◉' ;;
        POSSIBLE_MATCH|ARCHIVED|HISTORICAL_TRACE) printf '◌' ;;
        NOT_FOUND) printf '○' ;;
        BLOCKED) printf '◈' ;;
        INCONCLUSIVE|INVALID_FORMAT|NO_ARCHIVE_EVIDENCE|ARCHIVE_ERROR) printf '◇' ;;
        ERROR) printf '×' ;;
        MANUAL_CHECK) printf '·' ;;
        *) printf '?' ;;
    esac
}

status_display() {
    case "$1" in
        FOUND|CURRENT_AND_HISTORICAL) printf 'CONFIRMED' ;;
        POSSIBLE_MATCH|ARCHIVED|HISTORICAL_TRACE) printf 'PROBABLE' ;;
        NOT_FOUND) printf 'NOT FOUND' ;;
        BLOCKED) printf 'BLOCKED' ;;
        INCONCLUSIVE|INVALID_FORMAT|NO_ARCHIVE_EVIDENCE|ARCHIVE_ERROR) printf 'INCONCLUSIVE' ;;
        ERROR) printf 'ERROR' ;;
        MANUAL_CHECK) printf 'MANUAL CHECK' ;;
        *) printf '%s' "$1" ;;
    esac
}

summary_symbol() {
    case "$1" in
        CONFIRMED) printf '◉' ;;
        PROBABLE) printf '◌' ;;
        'NOT FOUND') printf '○' ;;
        BLOCKED) printf '◈' ;;
        INCONCLUSIVE) printf '◇' ;;
        ERROR) printf '×' ;;
        'MANUAL CHECK') printf '·' ;;
        *) printf '?' ;;
    esac
}

print_section_summary() {
    local title="$1"
    local section="$2"
    local -A grouped=()
    local technical display count index total=0

    for technical in FOUND POSSIBLE_MATCH NOT_FOUND BLOCKED INCONCLUSIVE MANUAL_CHECK \
        INVALID_FORMAT ERROR CURRENT_AND_HISTORICAL HISTORICAL_TRACE ARCHIVED \
        NO_ARCHIVE_EVIDENCE ARCHIVE_ERROR; do
        index="${section}|${technical}"
        count="${SECTION_STATUS_COUNTS[$index]:-0}"
        (( count > 0 )) || continue
        display="$(status_display "$technical")"
        grouped[$display]=$(( ${grouped[$display]:-0} + count ))
        total=$(( total + count ))
    done

    (( total > 0 )) || return 0
    printf '\n%s\n' "$title"
    printf '%s\n' '---------------------'
    for display in CONFIRMED PROBABLE 'NOT FOUND' BLOCKED INCONCLUSIVE ERROR 'MANUAL CHECK'; do
        count="${grouped[$display]:-0}"
        (( count > 0 )) || continue
        printf '%s  %-18s %d\n' "$(summary_symbol "$display")" "$display" "$count"
    done
}

render_progress() {
    local label="$1"
    (( QUIET == 1 )) && return 0
    [[ -t 1 ]] || return 0

    local width=24
    local filled=0
    local empty=0
    local percent=0
    if (( TOTAL_TASKS > 0 )); then
        percent=$(( CURRENT_TASK * 100 / TOTAL_TASKS ))
        filled=$(( CURRENT_TASK * width / TOTAL_TASKS ))
    fi
    empty=$(( width - filled ))

    local bar_filled bar_empty
    printf -v bar_filled '%*s' "$filled" ''
    printf -v bar_empty '%*s' "$empty" ''
    bar_filled="${bar_filled// /#}"
    bar_empty="${bar_empty// /-}"

    printf '\r%b[%s%s]%b %3d%%  %-28.28s' \
        "$C_VIOLET" "$bar_filled" "$bar_empty" "$C_RESET" "$percent" "$label"
}

clear_progress() {
    (( QUIET == 1 )) && return 0
    [[ -t 1 ]] || return 0
    printf '\r\033[2K'
}

print_result_line() {
    local section="$1"
    local platform_label="$2"
    local candidate="$3"
    local status="$4"
    local confidence="$5"
    local similarity="$6"
    local url="$7"
    local color symbol display score extra

    (( QUIET == 1 )) && return 0
    color="$(status_color "$status")"
    symbol="$(status_symbol "$status")"
    display="$(status_display "$status")"

    if [[ "$confidence" =~ ^[0-9]+$ ]] && (( confidence > 0 )); then
        printf -v score '%3s%%' "$confidence"
    else
        score='  — '
    fi

    extra=""
    if [[ "$section" == "SIMILAR" ]]; then
        extra="  candidate=${candidate}  sim=${similarity}%"
    elif [[ "$section" == "HISTORY" ]]; then
        extra="  history=${candidate}"
    fi

    printf '%b[%02d/%02d]%b %-15s %b%s  %-14s%b %s%s' \
        "$C_GRAY" "$CURRENT_TASK" "$TOTAL_TASKS" "$C_RESET" \
        "$platform_label" "$color" "$symbol" "$display" "$C_RESET" "$score" "$extra"
    [[ -n "$url" ]] && printf '  %s' "$url"
    printf '\n'
}

# -----------------------------------------------------------------------------
# HTTP engine
# -----------------------------------------------------------------------------

HTTP_RC=0
HTTP_STATUS="000"
HTTP_EFFECTIVE_URL=""
HTTP_CONTENT_TYPE=""
HTTP_TIME=""
HTTP_ERROR=""
HTTP_BODY_FILE=""

discard_http_artifacts() {
    if [[ -n "${HTTP_BODY_FILE:-}" ]]; then
        rm -f -- "$HTTP_BODY_FILE"
    fi
    HTTP_BODY_FILE=""
}

http_request() {
    local url="$1"
    local accept_header="${2:-text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8}"
    local authorization_header="${3-}"

    discard_http_artifacts

    if (( HTTP_REQUEST_COUNT >= MAX_HTTP_REQUESTS )); then
        HTTP_RC=99
        HTTP_STATUS="000"
        HTTP_EFFECTIVE_URL="$url"
        HTTP_CONTENT_TYPE=""
        HTTP_TIME="0"
        HTTP_ERROR="Maximum HTTP request budget reached"
        return 0
    fi

    if (( HTTP_REQUEST_COUNT > 0 )); then
        sleep_ms "$DELAY_MS"
    fi
    HTTP_REQUEST_COUNT=$(( HTTP_REQUEST_COUNT + 1 ))
    REQUEST_SEQ=$(( REQUEST_SEQ + 1 ))

    HTTP_BODY_FILE="${TMP_DIR}/body_${REQUEST_SEQ}.dat"
    local error_file="${TMP_DIR}/curl_${REQUEST_SEQ}.err"
    local authorization_file=""
    local metadata=""
    local -a curl_args=(
        curl
        --silent
        --show-error
        --location
        --compressed
        --max-redirs 8
        --connect-timeout "$CONNECT_TIMEOUT"
        --max-time "$TIMEOUT"
        --max-filesize "$MAX_RESPONSE_BYTES"
        --proto '=https'
        --proto-redir '=https'
        --user-agent "$USER_AGENT"
        --header "Accept: $accept_header"
        --header 'Accept-Language: en-US,en;q=0.8'
        --header 'Cache-Control: no-cache'
        --output "$HTTP_BODY_FILE"
        --write-out '%{http_code}|%{url_effective}|%{content_type}|%{time_total}'
    )

    if [[ -n "$authorization_header" ]]; then
        authorization_file="${TMP_DIR}/authorization_${REQUEST_SEQ}.headers"
        printf '%s\n' "$authorization_header" > "$authorization_file"
        curl_args+=(--header "@${authorization_file}")
    fi

    HTTP_RC=0
    local file_limit_kib=$(( (MAX_RESPONSE_BYTES + 1023) / 1024 ))
    metadata="$(
        ulimit -f "$file_limit_kib" 2>/dev/null || true
        "${curl_args[@]}" "$url" 2>"$error_file"
    )" || HTTP_RC=$?
    HTTP_ERROR="$(cat "$error_file" 2>/dev/null || true)"
    rm -f -- "$error_file"
    [[ -z "$authorization_file" ]] || rm -f -- "$authorization_file"

    # `curl --max-filesize` cannot always know the final size in advance.
    # RLIMIT_FSIZE above enforces the cap even for streamed/chunked responses.
    if (( HTTP_RC == 23 || HTTP_RC >= 128 )) && [[ -f "$HTTP_BODY_FILE" ]]; then
        local body_bytes
        body_bytes="$(wc -c < "$HTTP_BODY_FILE" 2>/dev/null || printf '0')"
        if [[ "$body_bytes" =~ ^[0-9]+$ ]] && (( body_bytes >= MAX_RESPONSE_BYTES )); then
            HTTP_RC=63
            HTTP_ERROR="Response body reached the ${MAX_RESPONSE_BYTES}-byte safety limit"
        fi
    fi

    IFS='|' read -r HTTP_STATUS HTTP_EFFECTIVE_URL HTTP_CONTENT_TYPE HTTP_TIME <<< "$metadata"
    [[ "$HTTP_STATUS" =~ ^[0-9]{3}$ ]] || HTTP_STATUS="000"
    HTTP_EFFECTIVE_URL="${HTTP_EFFECTIVE_URL:-$url}"
    HTTP_CONTENT_TYPE="${HTTP_CONTENT_TYPE:-}"
    HTTP_TIME="${HTTP_TIME:-0}"

    debug_log "HTTP rc=$HTTP_RC status=$HTTP_STATUS time=$HTTP_TIME url=$url effective=$HTTP_EFFECTIVE_URL"
}

body_contains() {
    local file="$1"
    local needle="$2"
    [[ -s "$file" && -n "$needle" ]] || return 1
    LC_ALL=C grep -Fqi -- "$needle" "$file"
}

body_contains_any() {
    local file="$1"
    local markers="$2"
    local marker
    [[ -s "$file" && -n "$markers" ]] || return 1
    while IFS= read -r marker; do
        [[ -n "$marker" ]] || continue
        if body_contains "$file" "$marker"; then
            return 0
        fi
    done <<< "$markers"
    return 1
}

body_indicates_block() {
    local file="$1"
    local markers=$'cf-chl-\nchallenge-platform\nJust a moment...\nAccess Denied\nToo Many Requests\nVerify you are human\nAttention Required! | Cloudflare\nunusual traffic from your computer network'
    body_contains_any "$file" "$markers"
}

is_auth_wall() {
    local effective="${1,,}"
    case "$effective" in
        *'/login'*|*'/signin'*|*'/authwall'*|*'/checkpoint'*|*'/accounts/login'*|*'/i/flow/login'*|*'/consent'*)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

has_positive_marker() {
    local platform="$1"
    local username="$2"
    local file="$3"
    local effective_url="$4"
    local lower_effective="${effective_url,,}"
    local lower_username="${username,,}"

    case "$platform" in
        instagram)
            body_contains "$file" "instagram.com/${username}/" ||
            body_contains "$file" "\"username\":\"${username}\""
            ;;
        tiktok)
            body_contains "$file" "tiktok.com/@${username}" ||
            body_contains "$file" "\"uniqueId\":\"${username}\""
            ;;
        youtube)
            body_contains "$file" "youtube.com/@${username}" ||
            body_contains "$file" "\"canonicalBaseUrl\":\"/@${username}\""
            ;;
        x)
            body_contains "$file" "x.com/${username}" ||
            body_contains "$file" "twitter.com/${username}" ||
            body_contains "$file" "\"screen_name\":\"${username}\""
            ;;
        snapchat)
            body_contains "$file" "snapchat.com/add/${username}"
            ;;
        linkedin)
            body_contains "$file" "linkedin.com/in/${username}"
            ;;
        pinterest)
            body_contains "$file" "pinterest.com/${username}" ||
            body_contains "$file" "\"username\":\"${username}\""
            ;;
        telegram)
            if body_contains "$file" "tgme_page_title"; then
                body_contains "$file" "@${username}" ||
                body_contains "$file" "t.me/${username}" ||
                [[ "$lower_effective" == *"t.me/${lower_username}"* ]]
            else
                return 1
            fi
            ;;
        *)
            return 1
            ;;
    esac
}

# Current result for a single verification.
R_STATUS=""
R_HTTP="000"
R_CONFIDENCE=0
R_URL=""
R_EFFECTIVE_URL=""
R_REASON=""

reset_result() {
    R_STATUS="INCONCLUSIVE"
    R_HTTP="000"
    R_CONFIDENCE=0
    R_URL=""
    R_EFFECTIVE_URL=""
    R_REASON="No classification available"
}

classify_common_http_failure() {
    local status="$1"
    local rc="$2"

    if (( rc != 0 )); then
        R_CONFIDENCE=0
        case "$rc" in
            6)
                R_STATUS="ERROR"
                R_REASON="DNS resolution failed"
                ;;
            7)
                R_STATUS="ERROR"
                R_REASON="Server connection failed"
                ;;
            28)
                R_STATUS="ERROR"
                R_REASON="Network timeout"
                ;;
            47)
                R_STATUS="INCONCLUSIVE"
                R_REASON="Redirect limit exceeded"
                ;;
            63)
                R_STATUS="INCONCLUSIVE"
                R_REASON="Response exceeded the ${MAX_RESPONSE_BYTES}-byte safety limit"
                ;;
            99)
                R_STATUS="ERROR"
                R_REASON="Maximum HTTP request budget reached"
                ;;
            *)
                R_STATUS="ERROR"
                R_REASON="curl error $rc${HTTP_ERROR:+: $HTTP_ERROR}"
                ;;
        esac
        return 0
    fi

    case "$status" in
        401|403|407|429|451)
            R_STATUS="BLOCKED"
            R_CONFIDENCE=0
            R_REASON="Access restricted or rate-limited: HTTP $status"
            return 0
            ;;
        408|425|5??)
            R_STATUS="INCONCLUSIVE"
            R_CONFIDENCE=15
            R_REASON="Temporary service response HTTP $status"
            return 0
            ;;
    esac

    return 1
}

check_github() {
    local username="$1"
    local public_url="${P_URL[github]//\{username\}/$username}"
    local api_url="https://api.github.com/users/${username}"
    local auth=""

    if [[ -n "$GITHUB_TOKEN_VALUE" ]]; then
        auth="Authorization: Bearer ${GITHUB_TOKEN_VALUE}"
    fi

    reset_result
    R_URL="$public_url"
    http_request "$api_url" 'application/vnd.github+json' "$auth"
    R_HTTP="$HTTP_STATUS"
    R_EFFECTIVE_URL="$HTTP_EFFECTIVE_URL"

    if classify_common_http_failure "$HTTP_STATUS" "$HTTP_RC"; then
        return 0
    fi

    case "$HTTP_STATUS" in
        200)
            local login=""
            login="$(python3 - "$HTTP_BODY_FILE" <<'PY_GITHUB'
import json
import sys
try:
    with open(sys.argv[1], "r", encoding="utf-8", errors="replace") as handle:
        data = json.load(handle)
    value = data.get("login", "") if isinstance(data, dict) else ""
    if isinstance(value, str):
        print(value)
except Exception:
    pass
PY_GITHUB
)"
            if [[ -n "$login" && "${login,,}" == "${username,,}" ]]; then
                R_STATUS="FOUND"
                R_CONFIDENCE=100
                R_REASON="User verified through the GitHub REST API"
            else
                R_STATUS="INCONCLUSIVE"
                R_CONFIDENCE=30
                R_REASON="API returned HTTP 200, but the JSON response does not match the username"
            fi
            ;;
        404)
            R_STATUS="NOT_FOUND"
            R_CONFIDENCE=98
            R_REASON="GitHub API: user unavailable (HTTP 404); this does not prove the username never existed"
            ;;
        *)
            R_STATUS="INCONCLUSIVE"
            R_CONFIDENCE=20
            R_REASON="Unexpected GitHub API response: HTTP $HTTP_STATUS"
            ;;
    esac
}

check_reddit() {
    local username="$1"
    local public_url="${P_URL[reddit]//\{username\}/$username}"
    local api_url="https://www.reddit.com/user/${username}/about.json"

    reset_result
    R_URL="$public_url"
    http_request "$api_url" 'application/json,text/plain;q=0.9,*/*;q=0.8'
    R_HTTP="$HTTP_STATUS"
    R_EFFECTIVE_URL="$HTTP_EFFECTIVE_URL"

    if classify_common_http_failure "$HTTP_STATUS" "$HTTP_RC"; then
        return 0
    fi

    case "$HTTP_STATUS" in
        200)
            local parsed=""
            parsed="$(python3 - "$HTTP_BODY_FILE" <<'PY_REDDIT'
import json
import sys
try:
    with open(sys.argv[1], "r", encoding="utf-8", errors="replace") as handle:
        data = json.load(handle)
    if isinstance(data, dict) and data.get("kind") == "t2" and isinstance(data.get("data"), dict):
        user = data["data"]
        print("ok\t{}\t{}".format(user.get("name", ""), bool(user.get("is_suspended", False))))
    elif isinstance(data, dict) and data.get("error"):
        print("error\t{}\t{}".format(data.get("error", ""), data.get("message", "")))
    else:
        print("unknown\t\t")
except Exception:
    print("invalid\t\t")
PY_REDDIT
)"
            local parsed_state parsed_name parsed_extra
            IFS=$'\t' read -r parsed_state parsed_name parsed_extra <<< "$parsed"
            if [[ "$parsed_state" == "ok" && "${parsed_name,,}" == "${username,,}" ]]; then
                R_STATUS="FOUND"
                R_CONFIDENCE=96
                if [[ "$parsed_extra" == "True" ]]; then
                    R_REASON="Reddit profile verified; account reported as suspended"
                else
                    R_REASON="Profile verified through the Reddit JSON endpoint"
                fi
            elif [[ "$parsed_state" == "error" && "$parsed_name" == "404" ]]; then
                R_STATUS="NOT_FOUND"
                R_CONFIDENCE=94
                R_REASON="Reddit endpoint indicates the profile is unavailable"
            else
                R_STATUS="INCONCLUSIVE"
                R_CONFIDENCE=30
                R_REASON="Reddit endpoint returned HTTP 200, but the response could not be verified"
            fi
            ;;
        404)
            R_STATUS="NOT_FOUND"
            R_CONFIDENCE=94
            R_REASON="Reddit profile unavailable (HTTP 404); deletion cannot be inferred"
            ;;
        *)
            R_STATUS="INCONCLUSIVE"
            R_CONFIDENCE=20
            R_REASON="Unexpected Reddit response: HTTP $HTTP_STATUS"
            ;;
    esac
}

check_html_platform() {
    local platform="$1"
    local username="$2"
    local public_url="${P_URL[$platform]//\{username\}/$username}"

    reset_result
    R_URL="$public_url"
    http_request "$public_url"
    R_HTTP="$HTTP_STATUS"
    R_EFFECTIVE_URL="$HTTP_EFFECTIVE_URL"

    if classify_common_http_failure "$HTTP_STATUS" "$HTTP_RC"; then
        return 0
    fi

    if body_indicates_block "$HTTP_BODY_FILE"; then
        R_STATUS="BLOCKED"
        R_CONFIDENCE=0
        R_REASON="Challenge, anti-bot or access-denied page detected"
        return 0
    fi

    # Authentication redirects take precedence over HTTP and body-level
    # negative indicators because a login wall does not establish absence.
    if is_auth_wall "$HTTP_EFFECTIVE_URL"; then
        R_STATUS="INCONCLUSIVE"
        R_CONFIDENCE=20
        R_REASON="Redirect to login, consent or authentication wall; profile existence cannot be verified"
        return 0
    fi

    if [[ "$HTTP_STATUS" == "404" || "$HTTP_STATUS" == "410" ]]; then
        R_STATUS="NOT_FOUND"
        R_CONFIDENCE=85
        R_REASON="Public endpoint unavailable (HTTP $HTTP_STATUS); this does not prove historical absence"
        return 0
    fi

    if [[ "$HTTP_STATUS" =~ ^2[0-9][0-9]$ ]]; then
        local negative_match=0
        local positive_match=0

        if body_contains_any "$HTTP_BODY_FILE" "${P_NEGATIVE[$platform]}"; then
            negative_match=1
        fi
        if has_positive_marker "$platform" "$username" "$HTTP_BODY_FILE" "$HTTP_EFFECTIVE_URL"; then
            positive_match=1
        fi

        if (( negative_match == 1 && positive_match == 1 )); then
            R_STATUS="INCONCLUSIVE"
            R_CONFIDENCE=40
            R_REASON="The response contains conflicting positive and unavailable-profile markers"
        elif (( negative_match == 1 )); then
            R_STATUS="NOT_FOUND"
            R_CONFIDENCE=88
            R_REASON="The page contains an explicit unavailable-profile marker"
        elif (( positive_match == 1 )); then
            R_STATUS="POSSIBLE_MATCH"
            R_CONFIDENCE="${P_CONFIDENCE[$platform]}"
            R_REASON="Exact URL and matching content marker; heuristic verification, not API-backed"
        else
            R_STATUS="INCONCLUSIVE"
            R_CONFIDENCE=35
            R_REASON="HTTP $HTTP_STATUS without a reliable positive or negative marker"
        fi
        return 0
    fi

    R_STATUS="INCONCLUSIVE"
    R_CONFIDENCE=20
    R_REASON="Unexpected HTTP response: $HTTP_STATUS"
}

check_manual_platform() {
    local platform="$1"
    local username="$2"

    reset_result
    R_STATUS="MANUAL_CHECK"
    R_HTTP="---"
    R_CONFIDENCE=0
    R_EFFECTIVE_URL=""

    case "$platform" in
        discord)
            if [[ -n "$DISCORD_ID" ]]; then
                R_URL="https://discord.com/users/${DISCORD_ID}"
                R_REASON="Discord ID supplied: open the profile manually; username-only enumeration is not reliable"
            else
                R_URL=""
                R_REASON="Discord does not provide reliable public username lookup; verify in the app or provide --discord-id"
            fi
            ;;
        bereal)
            R_URL=""
            R_REASON="BeReal username lookup must be performed in the app"
            ;;
        *)
            R_URL=""
            R_REASON="Platform configured for manual verification"
            ;;
    esac
}

scan_one() {
    local section="$1"
    local platform="$2"
    local candidate="$3"
    local similarity="$4"
    local variant_type="$5"
    local label="${P_LABEL[$platform]}"

    CURRENT_TASK=$(( CURRENT_TASK + 1 ))
    render_progress "${section}: ${label}"

    local observed
    observed="$(utc_now)"

    if ! platform_accepts_username "$platform" "$candidate"; then
        reset_result
        R_STATUS="INVALID_FORMAT"
        R_HTTP="---"
        R_CONFIDENCE=0
        R_URL=""
        R_EFFECTIVE_URL=""
        R_REASON="Candidate does not match the platform's expected username format"
    else
        case "${P_MODE[$platform]}" in
            github_api) check_github "$candidate" ;;
            reddit_api) check_reddit "$candidate" ;;
            html) check_html_platform "$platform" "$candidate" ;;
            manual) check_manual_platform "$platform" "$candidate" ;;
            *)
                reset_result
                R_STATUS="ERROR"
                R_REASON="Unknown platform mode"
                ;;
        esac
    fi

    append_result \
        "$section" "$platform" "$label" "$USERNAME" "$candidate" "$variant_type" \
        "$R_STATUS" "$R_HTTP" "$R_CONFIDENCE" "$similarity" "$R_URL" \
        "$R_EFFECTIVE_URL" "$R_REASON" "$observed" "" ""

    if [[ "$section" == "EXACT" ]]; then
        EXACT_STATUS[$platform]="$R_STATUS"
        EXACT_URL[$platform]="$R_URL"
    fi

    clear_progress
    print_result_line "$section" "$label" "$candidate" "$R_STATUS" \
        "$R_CONFIDENCE" "$similarity" "$R_URL"
    discard_http_artifacts
}

# -----------------------------------------------------------------------------
# Historical traces - Wayback Availability API
# -----------------------------------------------------------------------------

history_check_one() {
    local platform="$1"
    local label="${P_LABEL[$platform]}"
    local original_url="${EXACT_URL[$platform]-}"

    CURRENT_TASK=$(( CURRENT_TASK + 1 ))
    render_progress "HISTORY: ${label}"

    local observed
    observed="$(utc_now)"

    if [[ -z "$original_url" ]]; then
        append_result \
            "HISTORY" "$platform" "$label" "$USERNAME" "$USERNAME" \
            "wayback_availability" "ARCHIVE_ERROR" "---" "0" "100" "" "" \
            "No public URL is available for historical lookup" "$observed" "" ""
        clear_progress
        print_result_line "HISTORY" "$label" "$USERNAME" "ARCHIVE_ERROR" "0" "100" ""
        discard_http_artifacts
        return 0
    fi

    local encoded_url
    encoded_url="$(python3 - "$original_url" <<'PY_URLENCODE'
import sys
from urllib.parse import quote
print(quote(sys.argv[1], safe=""))
PY_URLENCODE
)"
    local api_url="https://archive.org/wayback/available?url=${encoded_url}"

    http_request "$api_url" 'application/json,text/plain;q=0.9,*/*;q=0.8'

    local history_status=""
    local confidence=0
    local reason=""
    local evidence_url=""
    local evidence_timestamp=""

    if (( HTTP_RC != 0 )); then
        history_status="ARCHIVE_ERROR"
        case "$HTTP_RC" in
            6) reason="DNS resolution failed while querying Wayback" ;;
            7) reason="Connection failed while querying Wayback" ;;
            28) reason="Timeout while querying Wayback" ;;
            47) reason="Wayback redirect limit exceeded" ;;
            63) reason="Wayback response exceeded the ${MAX_RESPONSE_BYTES}-byte safety limit" ;;
            99) reason="Maximum HTTP request budget reached before the Wayback request" ;;
            *) reason="curl error $HTTP_RC while querying Wayback${HTTP_ERROR:+: $HTTP_ERROR}" ;;
        esac
    elif [[ "$HTTP_STATUS" == "401" || "$HTTP_STATUS" == "403" || "$HTTP_STATUS" == "407" || "$HTTP_STATUS" == "429" || "$HTTP_STATUS" == "451" ]]; then
        history_status="ARCHIVE_ERROR"
        reason="Wayback unavailable: HTTP $HTTP_STATUS"
    elif [[ "$HTTP_STATUS" =~ ^2[0-9][0-9]$ ]]; then
        local parsed=""
        parsed="$(python3 - "$HTTP_BODY_FILE" <<'PY_WAYBACK'
import json
import sys
try:
    with open(sys.argv[1], "r", encoding="utf-8", errors="replace") as handle:
        data = json.load(handle)
    closest = data.get("archived_snapshots", {}).get("closest", {})
    if closest.get("available") is True and closest.get("url"):
        print("yes\t{}\t{}\t{}".format(
            closest.get("url", ""),
            closest.get("timestamp", ""),
            closest.get("status", ""),
        ))
    else:
        print("no\t\t\t")
except Exception:
    print("invalid\t\t\t")
PY_WAYBACK
)"
        local available archived_url archived_timestamp archived_status
        IFS=$'\t' read -r available archived_url archived_timestamp archived_status <<< "$parsed"

        if [[ "$available" == "yes" ]]; then
            evidence_url="$archived_url"
            evidence_timestamp="$archived_timestamp"
            confidence=90

            if [[ ! "$archived_status" =~ ^2[0-9][0-9]$ ]]; then
                history_status="ARCHIVED"
                confidence=55
                reason="A snapshot URL is accessible, but its archived HTTP status (${archived_status:-unknown}) does not confirm profile content"
            else
                case "${EXACT_STATUS[$platform]-}" in
                    NOT_FOUND)
                        history_status="HISTORICAL_TRACE"
                        reason="A successful public snapshot exists while the current endpoint is unavailable; possible rename, deletion, suspension or privacy change"
                        ;;
                    FOUND)
                        history_status="CURRENT_AND_HISTORICAL"
                        reason="A strongly verified current endpoint and at least one successful public snapshot are accessible"
                        ;;
                    POSSIBLE_MATCH)
                        history_status="ARCHIVED"
                        confidence=85
                        reason="A successful public snapshot is accessible; the current endpoint is only heuristically probable"
                        ;;
                    *)
                        history_status="ARCHIVED"
                        reason="At least one successful public snapshot is accessible; current state is inconclusive"
                        ;;
                esac
            fi
        elif [[ "$available" == "no" ]]; then
            history_status="NO_ARCHIVE_EVIDENCE"
            confidence=0
            reason="No accessible snapshot was returned; this does not mean the profile never existed"
        else
            history_status="ARCHIVE_ERROR"
            confidence=0
            reason="Wayback response could not be interpreted"
        fi
    else
        history_status="ARCHIVE_ERROR"
        reason="Unexpected Wayback response: HTTP $HTTP_STATUS"
    fi

    append_result \
        "HISTORY" "$platform" "$label" "$USERNAME" "$USERNAME" \
        "wayback_availability" "$history_status" "$HTTP_STATUS" "$confidence" "100" \
        "$original_url" "$HTTP_EFFECTIVE_URL" "$reason" "$observed" \
        "$evidence_url" "$evidence_timestamp"

    clear_progress
    print_result_line "HISTORY" "$label" "$USERNAME" "$history_status" \
        "$confidence" "100" "$evidence_url"
    discard_http_artifacts
}

# -----------------------------------------------------------------------------
# Report generation
# -----------------------------------------------------------------------------

generate_reports() {
    local tsv_file="$1"
    local base_path="$2"
    local want_txt="$3"
    local want_csv="$4"
    local want_json="$5"
    local want_pdf="$6"
    local target_username="$7"
    local started_at="$8"
    local platforms_csv="$9"

    python3 - "$tsv_file" "$base_path" "$want_txt" "$want_csv" "$want_json" \
        "$want_pdf" "$target_username" "$NUVIAH_VERSION" "$started_at" "$platforms_csv" <<'PY_REPORT'
from __future__ import annotations

import csv
import html
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

(
    tsv_path,
    base_path,
    want_txt,
    want_csv,
    want_json,
    want_pdf,
    target,
    version,
    started_at,
    platforms_csv,
) = sys.argv[1:]

want_txt = want_txt == "1"
want_csv = want_csv == "1"
want_json = want_json == "1"
want_pdf = want_pdf == "1"

def output_path(extension: str) -> Path:
    return Path(f"{base_path}{extension}")

with open(tsv_path, "r", encoding="utf-8", newline="") as handle:
    rows = list(csv.DictReader(handle, delimiter="\t"))

numeric_fields = ("technical_confidence", "username_similarity")
for row in rows:
    for field in numeric_fields:
        try:
            row[field] = int(row[field]) if row.get(field, "") != "" else None
        except (TypeError, ValueError):
            row[field] = None

exact_rows = [row for row in rows if row["section"] == "EXACT"]
similar_rows = [row for row in rows if row["section"] == "SIMILAR"]
history_rows = [row for row in rows if row["section"] == "HISTORY"]

summary = {
    "exact": dict(Counter(row["status"] for row in exact_rows)),
    "similar": dict(Counter(row["status"] for row in similar_rows)),
    "history": dict(Counter(row["status"] for row in history_rows)),
}

DISPLAY_STATUS = {
    "FOUND": "CONFIRMED",
    "CURRENT_AND_HISTORICAL": "CONFIRMED",
    "POSSIBLE_MATCH": "PROBABLE",
    "ARCHIVED": "PROBABLE",
    "HISTORICAL_TRACE": "PROBABLE",
    "NOT_FOUND": "NOT FOUND",
    "NO_ARCHIVE_EVIDENCE": "INCONCLUSIVE",
    "INVALID_FORMAT": "INCONCLUSIVE",
    "BLOCKED": "BLOCKED",
    "INCONCLUSIVE": "INCONCLUSIVE",
    "ARCHIVE_ERROR": "INCONCLUSIVE",
    "ERROR": "ERROR",
    "MANUAL_CHECK": "MANUAL CHECK",
}

STATUS_SYMBOL = {
    "CONFIRMED": "◉",
    "PROBABLE": "◌",
    "NOT FOUND": "○",
    "BLOCKED": "◈",
    "INCONCLUSIVE": "◇",
    "ERROR": "×",
    "MANUAL CHECK": "·",
}

DISPLAY_ORDER = (
    "CONFIRMED",
    "PROBABLE",
    "NOT FOUND",
    "BLOCKED",
    "INCONCLUSIVE",
    "ERROR",
    "MANUAL CHECK",
)

def display_status(value: str) -> str:
    return DISPLAY_STATUS.get(value, value)

def group_display_summary(values: dict[str, int]) -> dict[str, int]:
    grouped: Counter[str] = Counter()
    for status, count in values.items():
        grouped[display_status(status)] += count
    return {label: grouped[label] for label in DISPLAY_ORDER if grouped[label]}

display_summary = {
    section: group_display_summary(values)
    for section, values in summary.items()
}

report = {
    "schema_version": "1.0",
    "tool": {
        "name": "NUVIAH",
        "version": version,
        "purpose": "Passive analysis of public traces associated with usernames",
    },
    "scan": {
        "query_username": target,
        "started_at": started_at,
        "report_generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "platforms": [item for item in platforms_csv.split(",") if item],
    },
    "summary": summary,
    "display_summary": display_summary,
    "methodology_notes": [
        "FOUND is reserved for strong verification through APIs or structured data.",
        "POSSIBLE_MATCH is heuristic and does not prove account ownership.",
        "Username similarity does not equal identity correlation.",
        "A Wayback snapshot only shows that a URL was archived and accessible.",
        "The absence of archive evidence does not prove that a profile never existed.",
    ],
    "results": rows,
}

if want_json:
    with open(output_path(".json"), "w", encoding="utf-8") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2)
        handle.write("\n")

if want_csv:
    with open(output_path(".csv"), "w", encoding="utf-8", newline="") as handle:
        fieldnames = list(rows[0].keys()) if rows else [
            "section", "platform", "platform_label", "query_username",
            "candidate_username", "variant_type", "status", "http_status",
            "technical_confidence", "username_similarity", "url",
            "effective_url", "reason", "observed_at", "evidence_url",
            "evidence_timestamp",
        ]
        writer = csv.DictWriter(handle, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
        writer.writeheader()

        def csv_safe(value: object) -> object:
            if isinstance(value, str) and value.startswith(("=", "+", "-", "@", "\t", "\r")):
                return "'" + value
            return value

        writer.writerows(
            {field: csv_safe(row.get(field, "")) for field in fieldnames}
            for row in rows
        )

if want_txt:
    with open(output_path(".txt"), "w", encoding="utf-8") as handle:
        handle.write("NUVIAH - DIGITAL PRESENCE DOSSIER\n")
        handle.write("=" * 72 + "\n")
        handle.write(f"Target username:      {target}\n")
        handle.write(f"Started at:           {started_at}\n")
        handle.write(f"Platforms:            {platforms_csv}\n")
        handle.write("\nIMPORTANT\n")
        handle.write("A username match does not prove that accounts belong to the same person.\n")
        handle.write("Historical evidence alone does not prove deletion or renaming.\n")

        def write_summary(title: str, values: dict[str, int]) -> None:
            handle.write(f"\n{title}\n")
            handle.write("-" * len(title) + "\n")
            if not values:
                handle.write("No results.\n")
            else:
                for key, value in values.items():
                    handle.write(f"{key:<28} {value}\n")

        write_summary("EXACT SEARCH SUMMARY", display_summary["exact"])
        write_summary("SIMILAR USERNAME SUMMARY", display_summary["similar"])
        write_summary("HISTORICAL TRACE SUMMARY", display_summary["history"])

        for section, section_rows in (
            ("EXACT USERNAME RESULTS", exact_rows),
            ("SIMILAR USERNAME CANDIDATES", similar_rows),
            ("HISTORICAL TRACES", history_rows),
        ):
            handle.write(f"\n{section}\n")
            handle.write("=" * len(section) + "\n")
            if not section_rows:
                handle.write("No results.\n")
                continue
            for row in section_rows:
                handle.write(f"\n[{row['platform_label']}] {display_status(row['status'])}\n")
                handle.write(f"Candidate:             {row['candidate_username']}\n")
                handle.write(f"Variant type:          {row['variant_type']}\n")
                handle.write(f"HTTP:                  {row['http_status']}\n")
                handle.write(f"Technical confidence: {row['technical_confidence']}\n")
                handle.write(f"Username similarity:  {row['username_similarity']}\n")
                handle.write(f"URL:                   {row['url']}\n")
                handle.write(f"Effective URL:         {row['effective_url']}\n")
                handle.write(f"Evidence URL:          {row['evidence_url']}\n")
                handle.write(f"Evidence timestamp:    {row['evidence_timestamp']}\n")
                handle.write(f"Reason:                {row['reason']}\n")
                handle.write(f"Observed at:           {row['observed_at']}\n")

if want_pdf:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.pdfgen import canvas
    from reportlab.platypus import Paragraph

    W, H = A4

    COVER_BG = colors.HexColor("#F6F3ED")
    PAGE_BG = colors.HexColor("#FBFAF7")
    GRAPHITE = colors.HexColor("#17161A")
    MUTED = colors.HexColor("#6E6974")
    ACCENT = colors.HexColor("#7D6A91")
    LINE = colors.HexColor("#D9D4CE")
    LAVENDER = colors.HexColor("#E9E3EF")
    LAVENDER_LINE = colors.HexColor("#D8CDE2")

    font_paths = {
        "NuviahLight": [
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-ExtraLight.ttf",
            "/usr/share/fonts/dejavu/DejaVuSans-ExtraLight.ttf",
        ],
        "NuviahBold": [
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
            "/usr/share/fonts/dejavu/DejaVuSans-Bold.ttf",
        ],
        "NuviahRegular": [
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/usr/share/fonts/dejavu/DejaVuSans.ttf",
        ],
        "NuviahMono": [
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
            "/usr/share/fonts/dejavu/DejaVuSansMono.ttf",
        ],
    }

    registered = True
    for name, candidates in font_paths.items():
        path = next((item for item in candidates if os.path.isfile(item)), None)
        if path is None:
            registered = False
            break
        pdfmetrics.registerFont(TTFont(name, path))

    if registered:
        FONT_LIGHT = "NuviahLight"
        FONT_BOLD = "NuviahBold"
        FONT_REG = "NuviahRegular"
        FONT_MONO = "NuviahMono"
    else:
        FONT_LIGHT = "Helvetica"
        FONT_BOLD = "Helvetica-Bold"
        FONT_REG = "Helvetica"
        FONT_MONO = "Courier"

    pdf_path = output_path(".pdf")
    c = canvas.Canvas(str(pdf_path), pagesize=A4)
    c.setTitle(f"NUVIAH - Digital Presence Dossier - {target}")
    c.setAuthor("NUVIAH")
    c.setSubject("Passive public username trace analysis")

    def y_from_top(origin_y: float) -> float:
        return H - origin_y

    def draw_text(x: float, origin_y: float, text: object, font: str, size: float,
                  color=GRAPHITE, align: str = "left") -> None:
        value = "" if text is None else str(text)
        c.setFillColor(color)
        c.setFont(font, size)
        y = y_from_top(origin_y)
        if align == "center":
            c.drawCentredString(x, y, value)
        elif align == "right":
            c.drawRightString(x, y, value)
        else:
            c.drawString(x, y, value)

    def fit_text(text: object, font: str, size: float, max_width: float) -> str:
        value = "" if text is None else str(text)
        if pdfmetrics.stringWidth(value, font, size) <= max_width:
            return value
        ellipsis = "..."
        while value and pdfmetrics.stringWidth(value + ellipsis, font, size) > max_width:
            value = value[:-1]
        return value + ellipsis if value else ellipsis

    def fill_page(color) -> None:
        c.setFillColor(color)
        c.rect(0, 0, W, H, stroke=0, fill=1)

    def draw_footer(page_number: int) -> None:
        c.setStrokeColor(LINE)
        c.setLineWidth(0.45)
        c.line(51.0236, y_from_top(802.2047), 544.2520, y_from_top(802.2047))
        draw_text(51.0236, 817.7953, "NUVIAH / DIGITAL PRESENCE", FONT_LIGHT, 7.2, MUTED)
        draw_text(544.2520, 817.7953, f"TRACE DOSSIER  /  {page_number:02d}", FONT_LIGHT, 7.2, MUTED, "right")

    def draw_header(section: str, title: str) -> None:
        draw_text(51.0236, 68.0315, section, FONT_BOLD, 7.8, ACCENT)
        draw_text(51.0236, 90.7087, title, FONT_BOLD, 19.0, GRAPHITE)
        c.setStrokeColor(LINE)
        c.setLineWidth(0.5)
        c.line(51.0236, y_from_top(102.0472), 544.2520, y_from_top(102.0472))

    def draw_rounded_box(x: float, top: float, width: float, height: float,
                         fill_color, stroke_color=LINE, radius: float = 8.0,
                         stroke_width: float = 0.5) -> None:
        c.setFillColor(fill_color)
        c.setStrokeColor(stroke_color)
        c.setLineWidth(stroke_width)
        c.roundRect(x, H - top - height, width, height, radius, stroke=1, fill=1)

    def status_label(row: dict) -> str:
        display = display_status(row.get("status", ""))
        return f"{STATUS_SYMBOL.get(display, '?')}  {display}"

    def technical_score(row: dict) -> str:
        value = row.get("technical_confidence")
        return f"{value}%" if isinstance(value, int) and value > 0 else "-"

    def endpoint(row: dict, historical: bool = False) -> str:
        value = row.get("evidence_url") if historical and row.get("evidence_url") else row.get("url", "")
        value = str(value or "")
        for prefix in ("https://www.", "http://www.", "https://", "http://"):
            if value.startswith(prefix):
                value = value[len(prefix):]
                break
        return value.rstrip("/") or "-"

    def mode_label() -> str:
        parts = ["EXACT"]
        if similar_rows:
            parts.append("SIMILAR")
        if history_rows:
            parts.append("HISTORY")
        return " / ".join(parts)

    def generated_date() -> str:
        value = (started_at or "")[:10]
        try:
            datetime.strptime(value, "%Y-%m-%d")
            return value
        except ValueError:
            return datetime.now(timezone.utc).strftime("%Y-%m-%d")

    def paragraph(x: float, top: float, width: float, text: str, font: str,
                  size: float, leading: float, color, max_height=None) -> float:
        style = ParagraphStyle(
            name=f"P-{x}-{top}-{size}",
            fontName=font,
            fontSize=size,
            leading=leading,
            textColor=color,
            spaceAfter=0,
            spaceBefore=0,
        )
        p = Paragraph(html.escape(text), style)
        _, height = p.wrap(width, max_height or H)
        p.drawOn(c, x, H - top - height)
        return height

    def draw_eye() -> None:
        # Coordinates match the Nuviah Eye used in the approved dossier.
        for x, top_y, radius in (
            (230.3149, 286.2425, 3.0118),
            (364.9606, 286.2425, 3.0118),
            (272.8347, 250.8095, 3.0118),
            (322.4409, 250.8095, 3.0118),
            (272.8347, 321.6756, 3.0118),
            (322.4409, 321.6756, 3.0118),
        ):
            c.setFillColor(GRAPHITE)
            c.circle(x, H - top_y, radius, stroke=0, fill=1)
        cx, cy = 297.6378, H - 286.2425
        c.setFillColor(ACCENT)
        c.circle(cx, cy, 8.1496, stroke=0, fill=1)
        c.setFillColor(PAGE_BG)
        c.circle(cx, cy, 3.7205, stroke=0, fill=1)
        c.setFillColor(GRAPHITE)
        c.circle(cx, cy, 1.9488, stroke=0, fill=1)

    # ------------------------------------------------------------------
    # Cover page
    # ------------------------------------------------------------------
    page_no = 1
    fill_page(COVER_BG)
    draw_text(W / 2, 62.3622, "PUBLIC-SOURCE REPORT / AUTOMATED DATA", FONT_LIGHT, 7.5, MUTED, "center")
    draw_eye()
    draw_text(W / 2, 370.4315, "N U V I A H", FONT_BOLD, 18.0, GRAPHITE, "center")
    draw_text(W / 2, 408.3166, "DIGITAL PRESENCE", FONT_LIGHT, 9.5, MUTED, "center")
    c.setStrokeColor(ACCENT)
    c.setLineWidth(0.6)
    c.line(235.2756, y_from_top(446.2016), 360.0, y_from_top(446.2016))
    draw_text(W / 2, 484.0867, "TRACE DOSSIER", FONT_BOLD, 10.5, GRAPHITE, "center")

    draw_rounded_box(138.8976, 519.6615, 317.4804, 90.7086, PAGE_BG, LINE, 10.0, 0.7)
    draw_text(161.5748, 550.8425, "TARGET", FONT_LIGHT, 7.5, MUTED)
    draw_text(161.5748, 579.1890, fit_text(target, FONT_BOLD, 15.0, 165.0), FONT_BOLD, 15.0, GRAPHITE)
    draw_text(433.6920, 550.8425, "MODE", FONT_LIGHT, 7.5, MUTED, "right")
    mode_value = mode_label()
    mode_size = 9.0
    while mode_size > 6.8 and pdfmetrics.stringWidth(mode_value, FONT_BOLD, mode_size) > 155.0:
        mode_size -= 0.3
    draw_text(433.6920, 579.1890, mode_value, FONT_BOLD, mode_size, GRAPHITE, "right")

    draw_text(W / 2, 765.3544, "This document contains public-source technical observations.", FONT_LIGHT, 7.6, MUTED, "center")
    draw_footer(page_no)
    c.showPage()

    # ------------------------------------------------------------------
    # Executive summary page
    # ------------------------------------------------------------------
    page_no += 1
    fill_page(PAGE_BG)
    draw_header("01 / OVERVIEW", "Executive Summary")

    unique_sources = len({row.get("platform") for row in exact_rows if row.get("platform")})
    unique_sources = unique_sources or len([item for item in platforms_csv.split(",") if item])
    meta = (
        (51.0236, "TARGET", target),
        (204.0945, "SOURCES", str(unique_sources)),
        (317.4803, "MODE", mode_label()),
        (430.8661, "GENERATED", generated_date()),
    )
    for x, label, value in meta:
        draw_text(x, 147.4016, label, FONT_LIGHT, 7.5, MUTED)
        draw_text(x, 161.5748, fit_text(value, FONT_BOLD, 9.0, 105.0), FONT_BOLD, 9.0, GRAPHITE)

    exact_counts = Counter(display_status(row.get("status", "")) for row in exact_rows)
    signal_count = exact_counts["CONFIRMED"] + exact_counts["PROBABLE"]
    not_found_count = exact_counts["NOT FOUND"]
    blocked_count = exact_counts["BLOCKED"]
    uncertain_count = exact_counts["INCONCLUSIVE"] + exact_counts["ERROR"] + exact_counts["MANUAL CHECK"]

    cards = (
        (51.0236, signal_count, "CONFIRMED / PROBABLE"),
        (177.1654, not_found_count, "NOT FOUND"),
        (303.3071, blocked_count, "BLOCKED"),
        (429.4488, uncertain_count, "UNCERTAIN"),
    )
    for x, count, label in cards:
        draw_rounded_box(x, 189.9213, 114.8032, 70.8661, COVER_BG, LINE, 8.0, 0.5)
        draw_text(x + 14.1732, 223.9370, str(count), FONT_BOLD, 16.0, GRAPHITE)
        draw_text(x + 14.1732, 242.3622, label, FONT_LIGHT, 6.9, MUTED)

    table_left = 51.0236
    table_right = 549.9213
    c.setFillColor(COVER_BG)
    c.rect(table_left, H - 340.1575, table_right - table_left, 25.5118, stroke=0, fill=1)
    c.setStrokeColor(LINE)
    c.setLineWidth(0.6)
    c.line(table_left, y_from_top(340.1576), table_right, y_from_top(340.1576))
    for x, text in ((56.0236, "SOURCE"), (152.4016, "STATUS"), (282.7953, "TECH"), (339.4882, "PUBLIC ENDPOINT")):
        draw_text(x, 328.6017, text, FONT_BOLD, 7.2, MUTED)

    overview_rows = exact_rows[:6]
    first_baseline = 356.5308
    row_step = 28.3465
    for index, row in enumerate(overview_rows):
        baseline = first_baseline + index * row_step
        line_top = 368.5040 + index * row_step
        draw_text(56.0236, baseline, fit_text(row.get("platform_label", ""), FONT_REG, 8.2, 88.0), FONT_REG, 8.2, GRAPHITE)
        draw_text(152.4016, baseline, fit_text(status_label(row), FONT_REG, 8.2, 120.0), FONT_REG, 8.2, GRAPHITE)
        draw_text(282.7953, baseline, technical_score(row), FONT_REG, 8.2, GRAPHITE)
        draw_text(339.4882, baseline, fit_text(endpoint(row), FONT_REG, 8.2, 204.0), FONT_REG, 8.2, GRAPHITE)
        c.setStrokeColor(LINE)
        c.setLineWidth(0.35)
        c.line(table_left, y_from_top(line_top), table_right, y_from_top(line_top))

    note = (
        "Username similarity and endpoint availability do not establish identity correlation. "
        "Probable findings require independent validation before attribution."
    )
    if len(exact_rows) > 6:
        note += f" The overview lists 6 of {len(exact_rows)} exact-source results; the full register follows."
    draw_rounded_box(51.0236, 564.0945, 493.2284, 79.3701, LAVENDER, LAVENDER_LINE, 8.0, 0.5)
    draw_text(65.1969, 583.9370, "ANALYST NOTE", FONT_BOLD, 8.2, GRAPHITE)
    paragraph(65.1969, 591.0, 464.0, note, FONT_REG, 8.2, 11.6, MUTED)
    draw_footer(page_no)
    c.showPage()

    # ------------------------------------------------------------------
    # Evidence register pages
    # ------------------------------------------------------------------
    evidence_items: list[dict] = []
    for row in exact_rows:
        evidence_items.append({"kind": "EXACT", "row": row})
    for row in similar_rows:
        evidence_items.append({"kind": "SIMILAR", "row": row})
    for row in history_rows:
        evidence_items.append({"kind": "HISTORY", "row": row})

    if not evidence_items:
        evidence_items.append({
            "kind": "EXACT",
            "row": {
                "platform_label": "No records",
                "status": "INCONCLUSIVE",
                "technical_confidence": None,
                "reason": "No evidence records were generated for this scan.",
                "url": "",
                "candidate_username": target,
                "username_similarity": None,
                "evidence_url": "",
                "evidence_timestamp": "",
            },
        })

    chunks = [evidence_items[i:i + 6] for i in range(0, len(evidence_items), 6)]
    evidence_number = 0
    for chunk_index, chunk in enumerate(chunks):
        page_no += 1
        fill_page(PAGE_BG)
        title = "Trace Register" if chunk_index == 0 else "Trace Register / Continued"
        draw_header("02 / EVIDENCE", title)

        for local_index, item in enumerate(chunk):
            evidence_number += 1
            row = item["row"]
            kind = item["kind"]
            base = 144.5670 + local_index * 68.0315
            platform = str(row.get("platform_label", ""))
            candidate = str(row.get("candidate_username", "") or "")
            if kind == "SIMILAR":
                heading = f"{evidence_number:02d}  {platform} / {candidate}"
            elif kind == "HISTORY":
                heading = f"{evidence_number:02d}  {platform} / ARCHIVE"
            else:
                heading = f"{evidence_number:02d}  {platform}"
            draw_text(51.0236, base, fit_text(heading, FONT_BOLD, 9.5, 330.0), FONT_BOLD, 9.5, GRAPHITE)

            display = display_status(row.get("status", ""))
            status_text = f"{STATUS_SYMBOL.get(display, '?')} {display}   {technical_score(row)}"
            draw_text(544.2520, base + 0.99, status_text, FONT_REG, 8.2, ACCENT, "right")

            reason = str(row.get("reason", "") or "")
            if kind == "SIMILAR":
                similarity = row.get("username_similarity")
                prefix = f"Similar username candidate ({similarity}% textual similarity). " if similarity is not None else "Similar username candidate. "
                reason = prefix + reason
            elif kind == "HISTORY":
                stamp = str(row.get("evidence_timestamp", "") or "")
                prefix = f"Historical snapshot {stamp}. " if stamp else "Historical trace. "
                reason = prefix + reason
            draw_text(51.0236, base + 17.01, fit_text(reason, FONT_REG, 8.2, 493.0), FONT_REG, 8.2, MUTED)

            url_value = row.get("evidence_url") if kind == "HISTORY" and row.get("evidence_url") else row.get("url", "")
            draw_text(51.0236, base + 29.75, fit_text(url_value or "-", FONT_MONO, 7.1, 493.0), FONT_MONO, 7.1, GRAPHITE)

            line_top = 195.5906 + local_index * 68.0315
            c.setStrokeColor(LINE)
            c.setLineWidth(0.35)
            c.line(51.0236, y_from_top(line_top), 544.2520, y_from_top(line_top))

        draw_footer(page_no)
        c.showPage()

    # ------------------------------------------------------------------
    # Methodology and legend page
    # ------------------------------------------------------------------
    page_no += 1
    fill_page(PAGE_BG)
    draw_header("03 / METHOD", "Methodology & Limits")

    method_items = (
        (150.2363, "EXACT BY DEFAULT", "NUVIAH evaluates the exact username first. Similar-username discovery is treated as a separate exploratory mode."),
        (193.0394, "CONSERVATIVE CLASSIFICATION", "HTTP 200 alone is not considered proof. Authentication walls, anti-bot responses and ambiguous pages are classified separately."),
        (247.4646, "NO IDENTITY ATTRIBUTION", "A matching username across multiple services does not prove that the accounts belong to the same person."),
        (290.2677, "HISTORICAL EVIDENCE", "Archived snapshots may support historical presence, but absence from an archive does not prove that a profile never existed."),
    )
    for baseline, heading, body in method_items:
        draw_text(51.0236, baseline, heading, FONT_BOLD, 8.5, GRAPHITE)
        paragraph(51.0236, baseline + 6.0, 493.0, body, FONT_REG, 8.2, 11.6, MUTED)

    draw_rounded_box(51.0236, 344.6929, 493.2284, 85.0394, LAVENDER, LAVENDER_LINE, 8.0, 0.5)
    draw_text(65.1969, 367.3701, "INTERPRETATION RULE", FONT_BOLD, 8.2, GRAPHITE)
    paragraph(
        65.1969,
        374.6,
        464.0,
        "Technical confidence describes the reliability of the detection method. It is not a probability that two accounts belong to the same person.",
        FONT_REG,
        8.2,
        11.6,
        MUTED,
    )

    draw_rounded_box(51.0236, 615.1180, 493.2284, 130.3938, COVER_BG, LINE, 8.0, 0.5)
    draw_text(65.1969, 643.4646, "RESULT LEGEND", FONT_BOLD, 7.8, GRAPHITE)
    legend_left = (
        ("◉  CONFIRMED", ACCENT),
        ("◌  PROBABLE", ACCENT),
        ("○  NOT FOUND", GRAPHITE),
        ("◈  BLOCKED", GRAPHITE),
    )
    legend_right = (
        ("◇  INCONCLUSIVE", GRAPHITE),
        ("×  ERROR", GRAPHITE),
        ("·  MANUAL CHECK", GRAPHITE),
    )
    for i, (label, color) in enumerate(legend_left):
        draw_text(65.1969, 674.4882 + i * 18.4252, label, FONT_REG, 8.0, color)
    for i, (label, color) in enumerate(legend_right):
        draw_text(306.1417, 674.4882 + i * 18.4252, label, FONT_REG, 8.0, color)

    draw_footer(page_no)
    c.save()
PY_REPORT
}

# -----------------------------------------------------------------------------
# Offline self-test
# -----------------------------------------------------------------------------

self_test() {
    local failures=0
    local test_dir
    test_dir="$(mktemp -d)"
    TMP_DIR="$test_dir"

    printf 'NUVIAH self-test offline\n'
    printf '%s\n' '------------------------'

    if bash -n "$0"; then
        printf '[PASS] Bash syntax\n'
    else
        printf '[FAIL] Bash syntax\n'
        failures=$(( failures + 1 ))
    fi

    if command -v curl >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1 && \
       python_version_supported; then
        printf '[PASS] Core dependencies\n'
    else
        printf '[FAIL] Core dependencies\n'
        failures=$(( failures + 1 ))
    fi

    local variants_file="${test_dir}/variants.tsv"
    if generate_variants "nebra_witch" 85 6 "$variants_file" && [[ -s "$variants_file" ]]; then
        printf '[PASS] Variant generator\n'
    else
        printf '[FAIL] Variant generator\n'
        failures=$(( failures + 1 ))
    fi

    if platform_accepts_username github "torvalds" && \
       ! platform_accepts_username x "username_troppo_lungo" && \
       ! platform_accepts_username telegram "abc"; then
        printf '[PASS] Platform validation\n'
    else
        printf '[FAIL] Platform validation\n'
        failures=$(( failures + 1 ))
    fi

    local marker_file="${test_dir}/marker.html"
    printf '%s' "Sorry, this page isn't available" > "$marker_file"
    if body_contains_any "$marker_file" "${P_NEGATIVE[instagram]}"; then
        printf '[PASS] Negative marker detection\n'
    else
        printf '[FAIL] Negative marker detection\n'
        failures=$(( failures + 1 ))
    fi

    if is_auth_wall "https://www.tiktok.com/login?redirect_url=https%3A%2F%2Fwww.tiktok.com%2F%40example"; then
        printf '[PASS] Authentication-wall detection\n'
    else
        printf '[FAIL] Authentication-wall detection\n'
        failures=$(( failures + 1 ))
    fi

    if [[ "$(status_display INVALID_FORMAT)" == "INCONCLUSIVE" ]] && \
       [[ "$(status_display NO_ARCHIVE_EVIDENCE)" == "INCONCLUSIVE" ]] && \
       [[ "$(status_symbol INVALID_FORMAT)" == "◇" ]]; then
        printf '[PASS] Conservative status presentation\n'
    else
        printf '[FAIL] Conservative status presentation\n'
        failures=$(( failures + 1 ))
    fi

    if bash "$0" --no-banner -h | grep -F 'RESULT LEGEND' >/dev/null && \
       bash "$0" --no-banner --legend | grep -F '◉  CONFIRMED' >/dev/null && \
       bash "$0" --no-banner help scan | grep -F 'scan command' >/dev/null && \
       bash "$0" --no-banner scan --help | grep -F 'CORE OPTIONS' >/dev/null; then
        printf '[PASS] Help and legend CLI\n'
    else
        printf '[FAIL] Help and legend CLI\n'
        failures=$(( failures + 1 ))
    fi

    local test_tsv="${test_dir}/results.tsv"
    write_results_header "$test_tsv"
    cat >> "$test_tsv" <<'EOF_TEST_ROWS'
EXACT	github	GitHub	example	example	exact	FOUND	200	100	100	https://github.com/example	https://api.github.com/users/example	Mock API confirmation	2026-01-01T00:00:00Z		
EXACT	discord	Discord	example	example	exact	MANUAL_CHECK	---	0	100			Manual validation required	2026-01-01T00:00:01Z		
SIMILAR	github	GitHub	example	example1	numeric_suffix	NOT_FOUND	404	98	89	https://github.com/example1	https://api.github.com/users/example1	Mock not found	2026-01-01T00:00:02Z		
HISTORY	github	GitHub	example	example	wayback_availability	CURRENT_AND_HISTORICAL	200	90	100	https://github.com/example	https://archive.org/wayback/available	Mock archive	2026-01-01T00:00:03Z	https://web.archive.org/web/20200101000000/https://github.com/example	20200101000000
EOF_TEST_ROWS

    local test_base="${test_dir}/nuviah_selftest.user"
    local pdf_flag=0
    if python3 -c 'import reportlab' >/dev/null 2>&1; then
        pdf_flag=1
    fi

    if generate_reports "$test_tsv" "$test_base" 1 1 1 "$pdf_flag" \
        "example" "2026-01-01T00:00:00Z" "github,discord"; then
        if [[ -s "${test_base}.txt" && -s "${test_base}.csv" && -s "${test_base}.json" ]] && \
           python3 -m json.tool "${test_base}.json" >/dev/null 2>&1; then
            printf '[PASS] TXT/CSV/JSON reports\n'
        else
            printf '[FAIL] TXT/CSV/JSON reports\n'
            failures=$(( failures + 1 ))
        fi
        if (( pdf_flag == 1 )); then
            if [[ -s "${test_base}.pdf" ]] && [[ "$(head -c 5 "${test_base}.pdf")" == "%PDF-" ]]; then
                printf '[PASS] PDF report\n'
            else
                printf '[FAIL] PDF report\n'
                failures=$(( failures + 1 ))
            fi
        else
            printf '[SKIP] PDF report - reportlab not installed\n'
        fi
    else
        printf '[FAIL] Report generation\n'
        failures=$(( failures + 1 ))
    fi

    rm -rf -- "$test_dir"
    TMP_DIR=""

    if (( failures == 0 )); then
        printf '\nAll offline tests passed.\n'
        return 0
    fi

    printf '\nSelf-test failed: %d check(s) did not pass.\n' "$failures" >&2
    return 1
}

# -----------------------------------------------------------------------------
# Scan execution
# -----------------------------------------------------------------------------

run_scan() {
    [[ -n "$USERNAME" ]] || die "A username is required. Use --help for examples."

    USERNAME="${USERNAME#@}"
    valid_global_username "$USERNAME" || die "Invalid username. Allowed characters: letters, numbers, dot, underscore and hyphen (1-64 characters)."

    validate_options
    check_core_dependencies
    select_platforms

    mkdir -p -- "$OUTPUT_DIR"
    TMP_DIR="$(mktemp -d)"
    RESULTS_TSV="${TMP_DIR}/results.tsv"
    write_results_header "$RESULTS_TSV"

    local started_at
    started_at="$(utc_now)"
    local timestamp
    timestamp="$(date -u '+%Y%m%d_%H%M%S_%N')_${BASHPID}"
    local safe_user
    safe_user="$(safe_filename "$USERNAME")"
    BASE_PATH="${OUTPUT_DIR%/}/nuviah_${safe_user}_${timestamp}"

    local variants_file="${TMP_DIR}/variants.tsv"
    : > "$variants_file"
    if (( SIMILAR_ENABLED == 1 )); then
        generate_variants "$USERNAME" "$SIMILARITY_THRESHOLD" "$MAX_VARIANTS" "$variants_file"
        if [[ ! -s "$variants_file" ]]; then
            warn "No generated variant meets the configured similarity threshold."
        fi
    fi

    local -a scan_tasks=()
    local platform candidate similarity variant_type

    for platform in "${SELECTED_PLATFORMS[@]}"; do
        scan_tasks+=("EXACT"$'\t'"$platform"$'\t'"$USERNAME"$'\t'"100"$'\t'"exact")
    done

    if (( SIMILAR_ENABLED == 1 )) && [[ -s "$variants_file" ]]; then
        while IFS=$'\t' read -r candidate similarity variant_type; do
            [[ -n "$candidate" ]] || continue
            for platform in "${SELECTED_PLATFORMS[@]}"; do
                if [[ "${P_SIMILAR[$platform]}" == "1" ]]; then
                    scan_tasks+=("SIMILAR"$'\t'"$platform"$'\t'"$candidate"$'\t'"$similarity"$'\t'"$variant_type")
                fi
            done
        done < "$variants_file"
    fi

    local history_tasks=0
    if (( HISTORY_ENABLED == 1 )); then
        for platform in "${SELECTED_PLATFORMS[@]}"; do
            if [[ "${P_HISTORY[$platform]}" == "1" ]]; then
                history_tasks=$(( history_tasks + 1 ))
            fi
        done
    fi

    TOTAL_TASKS=$(( ${#scan_tasks[@]} + history_tasks ))

    local planned_http=0
    local task section
    for task in "${scan_tasks[@]}"; do
        IFS=$'\t' read -r section platform candidate similarity variant_type <<< "$task"
        if [[ "${P_MODE[$platform]}" != "manual" ]] && \
           platform_accepts_username "$platform" "$candidate"; then
            planned_http=$(( planned_http + 1 ))
        fi
    done

    if (( HISTORY_ENABLED == 1 )); then
        for platform in "${SELECTED_PLATFORMS[@]}"; do
            if [[ "${P_HISTORY[$platform]}" == "1" ]] && \
               platform_accepts_username "$platform" "$USERNAME"; then
                planned_http=$(( planned_http + 1 ))
            fi
        done
    fi

    if (( planned_http > MAX_HTTP_REQUESTS )); then
        die "The planned scan requires up to $planned_http requests, above --max-requests=$MAX_HTTP_REQUESTS. Reduce platforms/variants or deliberately raise the limit."
    fi

    banner
    if (( QUIET == 0 )); then
        printf '%bTarget:%b      %s\n' "$C_BOLD" "$C_RESET" "$USERNAME"
        printf '%bSources:%b     %s\n' "$C_BOLD" "$C_RESET" "$(IFS=,; printf '%s' "${SELECTED_PLATFORMS[*]}")"
        printf '%bMode:%b        EXACT%s%s\n\n' "$C_BOLD" "$C_RESET" \
            "$([[ $SIMILAR_ENABLED == 1 ]] && printf ' + SIMILAR' || true)" \
            "$([[ $HISTORY_ENABLED == 1 ]] && printf ' + HISTORY' || true)"
    fi

    for task in "${scan_tasks[@]}"; do
        IFS=$'\t' read -r section platform candidate similarity variant_type <<< "$task"
        scan_one "$section" "$platform" "$candidate" "$similarity" "$variant_type"
    done

    if (( HISTORY_ENABLED == 1 )); then
        for platform in "${SELECTED_PLATFORMS[@]}"; do
            if [[ "${P_HISTORY[$platform]}" == "1" ]]; then
                history_check_one "$platform"
            fi
        done
    fi

    local platforms_csv
    platforms_csv="$(IFS=,; printf '%s' "${SELECTED_PLATFORMS[*]}")"
    generate_reports "$RESULTS_TSV" "$BASE_PATH" "$WANT_TXT" "$WANT_CSV" \
        "$WANT_JSON" "$WANT_PDF" "$USERNAME" "$started_at" "$platforms_csv"

    local -a expected_reports=()
    (( WANT_TXT == 1 )) && expected_reports+=("${BASE_PATH}.txt")
    (( WANT_CSV == 1 )) && expected_reports+=("${BASE_PATH}.csv")
    (( WANT_JSON == 1 )) && expected_reports+=("${BASE_PATH}.json")
    (( WANT_PDF == 1 )) && expected_reports+=("${BASE_PATH}.pdf")

    local report_file
    for report_file in "${expected_reports[@]}"; do
        [[ -s "$report_file" ]] || die "Report generation failed or produced an empty file: $report_file"
    done

    printf '\n%bSCAN COMPLETE%b\n' "$C_BOLD" "$C_RESET"
    printf '%s\n' '---------------------'
    printf 'HTTP requests: %d\n' "$HTTP_REQUEST_COUNT"

    print_section_summary "EXACT RESULTS" "EXACT"
    print_section_summary "SIMILAR CANDIDATES" "SIMILAR"
    print_section_summary "HISTORICAL TRACES" "HISTORY"

    printf '\nReports generated:\n'
    (( WANT_TXT == 1 )) && printf '  TXT  %s\n' "${BASE_PATH}.txt"
    (( WANT_CSV == 1 )) && printf '  CSV  %s\n' "${BASE_PATH}.csv"
    (( WANT_JSON == 1 )) && printf '  JSON %s\n' "${BASE_PATH}.json"
    (( WANT_PDF == 1 )) && printf '  PDF  %s\n' "${BASE_PATH}.pdf"

    printf '\n%s\n' "Note: username similarity != identity correlation."
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------

init_platforms
parse_cli "$@"
configure_colors

case "$ACTION" in
    help)
        usage
        ;;
    scan_help)
        scan_usage
        ;;
    legend)
        print_legend
        ;;
    version)
        printf 'NUVIAH %s\n' "$NUVIAH_VERSION"
        ;;
    list_platforms)
        list_platforms
        ;;
    check_deps)
        check_dependencies_report
        ;;
    self_test)
        check_core_dependencies
        self_test
        ;;
    scan)
        run_scan
        ;;
    *)
        die "Unknown internal action: $ACTION"
        ;;
esac
