"""Tests for software normalization."""

from __future__ import annotations

from attackchainbuilder.normalize import SYNONYMS, software_overlap, tokenize_software


def test_tokenize_software_basic():
    tokens = tokenize_software("Apache Log4j 2.14.1")
    assert "apache" in tokens
    assert "log4j" in tokens


def test_tokenize_software_synonyms():
    tokens = tokenize_software("httpd server")
    assert "apache" in tokens
    assert "server" in tokens


def test_tokenize_software_empty():
    assert tokenize_software("") == []
    assert tokenize_software(None) == []  # type: ignore[arg-type]


def test_tokenize_software_deduplicates():
    tokens = tokenize_software("apache apache httpd")
    assert tokens.count("apache") == 1


def test_tokenize_software_stops():
    tokens = tokenize_software("the apache and nginx of the server")
    assert "the" not in tokens
    assert "and" not in tokens
    assert "apache" in tokens
    assert "nginx" in tokens


def test_software_overlap_full():
    assert software_overlap(["apache", "log4j"], ["apache", "log4j"]) == 1.0


def test_software_overlap_partial():
    overlap = software_overlap(["apache", "log4j", "java"], ["apache", "nginx"])
    assert overlap == 0.5  # 1 / min(3, 2) = 1/2


def test_software_overlap_none():
    assert software_overlap(["apache"], ["nginx"]) == 0.0
    assert software_overlap([], ["apache"]) == 0.0
    assert software_overlap(["apache"], []) == 0.0


def test_synonyms_mapping():
    assert SYNONYMS["httpd"] == "apache"
    assert SYNONYMS["log4shell"] == "log4j"
    assert SYNONYMS["pkexec"] == "polkit"
    assert SYNONYMS["esxi"] == "vmware"
