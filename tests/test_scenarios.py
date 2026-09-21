# tests/test_scenarios.py
# Acceptance tests: simulate real attack, benign developer, and background service
# scenarios through the full Python detection pipeline (engine + alerts).

from lineage.alerts import format_alert
from lineage.engine import classify_event


def _simulate_event(parent: str, child: str, uid: int = 1000) -> str | None:
    """Run an event through the full pipeline: classify then format."""
    result = classify_event(parent=parent, child=child)
    if result["level"] == "NONE":
        return None
    alert_event = {
        "level": result["level"],
        "reason": result["reason"],
        "parent": parent.strip(),
        "child": child.strip(),
        "uid": uid,
    }
    return format_alert(alert_event)


# --- Scenario Group 1: High-Risk Web and Database Server Exploits (CRITICAL) ---


def test_scenario_web_shell_exploitation():
    """Scenario 1: nginx web server spawning /bin/sh triggers CRITICAL."""
    output = _simulate_event(parent="nginx", child="/bin/sh", uid=33)
    assert output is not None
    assert "CRITICAL" in output
    assert "nginx" in output
    assert "T1059" in output
    assert "uid=33" in output


def test_scenario_apache_cgi_rce():
    """Scenario 2: Apache web server spawning /bin/dash via CGI exploit."""
    output = _simulate_event(parent="apache2", child="/bin/dash", uid=33)
    assert output is not None
    assert "CRITICAL" in output
    assert "apache2" in output
    assert "T1059" in output
    assert "uid=33" in output


def test_scenario_postgres_copy_program_rce():
    """Scenario 3: PostgreSQL spawning /bin/sh via COPY PROGRAM abuse."""
    output = _simulate_event(parent="postgres", child="/bin/sh", uid=70)
    assert output is not None
    assert "CRITICAL" in output
    assert "postgres" in output
    assert "T1059" in output
    assert "uid=70" in output


def test_scenario_mysql_udf_command_execution():
    """Scenario 4: MySQL daemon spawning /bin/bash via UDF exploit."""
    output = _simulate_event(parent="mysqld", child="/bin/bash", uid=27)
    assert output is not None
    assert "CRITICAL" in output
    assert "mysqld" in output
    assert "T1059" in output
    assert "uid=27" in output


def test_scenario_sshd_compromised_child():
    """Scenario 5: sshd spawning an unexpected standalone shell."""
    output = _simulate_event(parent="sshd", child="/bin/sh", uid=0)
    assert output is not None
    assert "CRITICAL" in output
    assert "sshd" in output
    assert "T1059" in output


# --- Scenario Group 2: Desktop Application and Utility Abuse (WARNING) ---


def test_scenario_unknown_process_spawning_shell():
    """Scenario 6: Evince PDF reader spawning bash triggers WARNING."""
    output = _simulate_event(parent="evince", child="bash", uid=1000)
    assert output is not None
    assert "WARNING" in output
    assert "evince" in output


def test_scenario_office_document_macro_exploit():
    """Scenario 7: LibreOffice spawning /bin/bash via document macro."""
    output = _simulate_event(parent="libreoffice", child="/bin/bash", uid=1000)
    assert output is not None
    assert "WARNING" in output
    assert "libreoffice" in output
    assert "T1059" in output


def test_scenario_media_player_rce():
    """Scenario 8: VLC media player spawning /bin/sh via malformed subtitle."""
    output = _simulate_event(parent="vlc", child="/bin/sh", uid=1000)
    assert output is not None
    assert "WARNING" in output
    assert "vlc" in output


def test_scenario_web_downloader_script_injection():
    """Scenario 9: curl command execution spawning /bin/sh triggers WARNING."""
    output = _simulate_event(parent="curl", child="/bin/sh", uid=1000)
    assert output is not None
    assert "WARNING" in output
    assert "curl" in output


# --- Scenario Group 3: Benign Terminal and Developer Workflows (NONE) ---


def test_scenario_legitimate_terminal_use():
    """Scenario 10: GNOME Terminal spawning bash triggers no alert."""
    output = _simulate_event(parent="gnome-terminal", child="bash")
    assert output is None


def test_scenario_tmux_session_shell_spawn():
    """Scenario 11: tmux multiplexer spawning /usr/bin/zsh triggers no alert."""
    output = _simulate_event(parent="tmux", child="/usr/bin/zsh")
    assert output is None


def test_scenario_kitty_terminal_spawning_fish():
    """Scenario 12: Kitty terminal emulator spawning /usr/bin/fish."""
    output = _simulate_event(parent="kitty", child="/usr/bin/fish")
    assert output is None


def test_scenario_alacritty_spawning_bash():
    """Scenario 13: Alacritty terminal emulator spawning /bin/bash."""
    output = _simulate_event(parent="alacritty", child="/bin/bash")
    assert output is None


def test_scenario_konsole_spawning_zsh():
    """Scenario 14: Konsole terminal emulator spawning /bin/zsh."""
    output = _simulate_event(parent="konsole", child="/bin/zsh")
    assert output is None


def test_scenario_nested_subshell_execution():
    """Scenario 15: Interactive shell (bash) executing a subshell script (sh)."""
    output = _simulate_event(parent="bash", child="/bin/sh")
    assert output is None


# --- Scenario Group 4: Background Service Worker Processes (NONE) ---


def test_scenario_nginx_forking_worker_process():
    """Scenario 16: nginx spawning a non-shell worker process triggers no alert."""
    output = _simulate_event(parent="nginx", child="/usr/sbin/nginx", uid=33)
    assert output is None


def test_scenario_postgres_forking_walwriter():
    """Scenario 17: PostgreSQL spawning background worker triggers no alert."""
    output = _simulate_event(
        parent="postgres", child="/usr/lib/postgresql/postgres", uid=70
    )
    assert output is None


def test_scenario_apache_spawning_non_shell():
    """Scenario 18: Apache spawning internal worker binary triggers no alert."""
    output = _simulate_event(parent="apache2", child="/usr/sbin/apache2", uid=33)
    assert output is None


# --- Scenario Group 5: Path Normalization and Defensive Boundary Handling ---


def test_scenario_full_path_child_binary():
    """Scenario 19: Deep path resolution (/usr/local/bin/bash) is detected."""
    output = _simulate_event(parent="apache2", child="/usr/local/bin/bash", uid=33)
    assert output is not None
    assert "CRITICAL" in output
    assert "apache2" in output


def test_scenario_whitespace_padded_names():
    """Scenario 20: Command names with surrounding whitespace are handled."""
    output = _simulate_event(parent="  nginx  ", child="  /bin/bash  ", uid=33)
    assert output is not None
    assert "CRITICAL" in output
    assert "nginx" in output


def test_scenario_uncommon_shell_ksh():
    """Scenario 21: Korn shell (/bin/ksh) spawned by service process is detected."""
    output = _simulate_event(parent="mysqld", child="/bin/ksh", uid=27)
    assert output is not None
    assert "CRITICAL" in output
    assert "mysqld" in output
