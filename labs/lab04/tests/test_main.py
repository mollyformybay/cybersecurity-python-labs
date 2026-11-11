import json

import pytest

from labs.lab04 import main as cli


def test_local_cli_outputs_json(capsys):
    code = cli.main(
        ["--cve", "CVE-2099-10001", "--input", "labs/lab04/data/nvd_sample.json"]
    )
    output = json.loads(capsys.readouterr().out)
    assert code == 0
    assert output["decision"] == "other"


def test_invalid_cve_is_argument_error():
    with pytest.raises(SystemExit) as error:
        cli.main(["--cve", "cve-2099-10001"])
    assert error.value.code == 2


def test_invalid_input_reports_error(capsys):
    code = cli.main(["--cve", "CVE-2099-10001", "--input", "missing.json"])
    assert code == 1
    assert "Помилка читання даних" in capsys.readouterr().err
