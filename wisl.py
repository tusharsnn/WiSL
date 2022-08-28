import subprocess
import sys
from typing import Final, Literal
import base64


LISTEN_ADDR: Final[str] = "0.0.0.0"
RULE_PREFIX: Final[str] = "WiSL"
CRLF: Final[str] = "\r\n"


def main():
    port = 8000
    wait = False
    try:
        ip = get_wsl_ip()
    except Exception as e:
        print("could not find WSL IP-address", e)
        return -1
    # remove_all_firewall_rules()
    add_firewall_rule(port, wait=wait)
    add_port_forwarding(wsl_ip=ip, listen_ip=LISTEN_ADDR, port=port, wait=wait)
    # remove_firewall_rule(port, wait=False)


def get_wsl_ip() -> str:
    # output = run("ip a s eth0")
    output = run("wsl.exe hostname -I")
    # ip_regex = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    # res = re.search(ip_regex, output.stdout)
    if output.returncode:
        raise Exception()
    return output.stdout.rstrip(CRLF)


def remove_all_firewall_rules():
    cmd = r"netsh.exe advfirewall firewall delete rule name=" + RULE_PREFIX
    if not (returncode := run_with_elevation(cmd)):
        return returncode
    return -1


def remove_firewall_rule(port: int, wait: bool = False):
    cmd = (
        r"netsh advfirewall firewall delete rule name="
        + RULE_PREFIX
        + r" localport="
        + str(port)
        + r" protocol=tcp"
    )
    if not (returncode := run_with_elevation(cmd, wait)):
        return returncode
    return -1


def add_firewall_rule(port: int, wait: bool = False):
    if rule_exist(port):
        return 0

    def firewall_rule_with_dir(dir: Literal["in", "out"] = "in"):
        return (
            r"netsh advfirewall firewall add rule name="
            + RULE_PREFIX
            + rf" dir={dir} action=allow profile=private localport="
            + str(port)
            + r" protocol=tcp"
        )

    in_cmd = firewall_rule_with_dir("in")
    out_cmd = firewall_rule_with_dir("out")
    concat_cmd = in_cmd + ";" + out_cmd
    if run_with_elevation(concat_cmd, wait):
        # revert any changes made
        remove_firewall_rule(port, wait)
        return -1
    return 0


def add_port_forwarding(wsl_ip: str, listen_ip: str, port: int, *, wait: bool = False):
    cmd = (
        r"netsh.exe interface portproxy add v4tov4 listenport="
        + str(port)
        + r" listenaddress="
        + listen_ip
        + r" connectport="
        + str(port)
        + r" connectaddress="
        + wsl_ip
    )

    return run_with_elevation(cmd, wait=wait)


# TODO: check if port forwarding works with UAC
def run(cmd: str | list[str], **kwargs) -> subprocess.CompletedProcess[str]:
    if isinstance(cmd, str):
        return subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            **kwargs,
        )
    else:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            **kwargs,
        )


def run_with_elevation(cmd: str, wait: bool = False) -> Literal[0, -1]:
    if wait:
        # add pause at the end of the command
        cmd += r";pause"

    encoded_cmd = enc_cmd(cmd)
    elevated_process_cmd = (
        r"Start-Process pwsh '-e " + encoded_cmd + r"' -Verb RunAs -Wait"
    )

    elev_enc_cmd = enc_cmd(elevated_process_cmd)
    out = run("pwsh.exe -e " + elev_enc_cmd)

    if not out.returncode:
        if out.stdout:
            print(out.stdout.rstrip(CRLF))
        return 0
    else:
        err_msg = get_err_msg(out)
        print("could not run with elevation")
        if err_msg:
            print(err_msg)
        return -1


def get_err_msg(out: subprocess.CompletedProcess[str]):
    return out.stderr.rstrip(CRLF) or out.stdout.rstrip(CRLF)


def get_username():
    cmd_out = run("whoami.exe")
    if not cmd_out.returncode:
        return cmd_out.stdout.rstrip(CRLF)


# encode command for powershell
def enc_cmd(cmd: str) -> str:
    return base64.b64encode(cmd.encode("utf-16le")).decode()


# TODO: use parser to check rule existence
# checks if rule exists based on `port` and `RULE_PREFIX`
def rule_exist(port: int) -> bool:
    cmd = (
        r"netsh.exe advfirewall firewall show rule name="
        + RULE_PREFIX
        + r" | grep 'LocalPort'"
    )
    out = run(cmd)
    out_msg = out.stdout.rstrip(CRLF)
    return True if str(port) in out_msg else False


if __name__ == "__main__":
    sys.exit(main())
