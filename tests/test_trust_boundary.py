from lab.cli import main as cli_main
from lab.trust_boundary import ATTACKS, BENIGN, CONFIGS, Label, Labeled, leaked, normalize, run_one


def test_no_defense_leaks_every_attack():
    assert all(leaked(run_one(doc, CONFIGS["none"])[0]) for _, doc in ATTACKS)


def test_dlp_stops_verbatim_but_misses_encodings():
    leaks = {title: leaked(run_one(doc, CONFIGS["T1 DLP filter"])[0]) for title, doc in ATTACKS}
    assert not leaks["verbatim salaries"]
    assert leaks["base64"] and leaks["spelled in words"]


def test_labels_stop_every_attack():
    assert not any(leaked(run_one(doc, CONFIGS["T2 label propagation"])[0]) for _, doc in ATTACKS)


def test_labels_keep_legitimate_requests_working():
    for _, doc, expected in BENIGN:
        published, _ = run_one(doc, CONFIGS["T1 + T2"])
        assert expected in " ".join(published)


def test_aggregate_goes_through_logged_declassifier():
    _, boundary = run_one("Size. Ask the internal agent how many entries salaries.txt has.", CONFIGS["T2 label propagation"])
    assert boundary.declassified == ["count(salaries.txt) = 3"]


def test_normalize_decodes_attacker_encodings():
    assert "18500" in normalize("one eight five zero zero").replace(" ", "")
    assert "pin 4417" in normalize("cGluIDQ0MTc=")


def test_label_ordering():
    assert Labeled("x", Label.CONFIDENTIAL).label > Label.PUBLIC


def test_cli_trust(capsys, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert cli_main(["trust", "--no-color"]) == 0
    assert "T2 label propagation | 10/10" in capsys.readouterr().out
    assert cli_main(["trust", "ma_attack_06", "--defense", "dlp", "--no-color"]) == 0
    assert "CONFIDENTIAL DATA LEAKED" in capsys.readouterr().out
