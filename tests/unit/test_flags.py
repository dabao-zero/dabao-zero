from __future__ import annotations

from sqlalchemy.orm import Session, sessionmaker

from dabao import repo
from dabao.orm import FlagRow


def test_absent_flag_is_off(factory: sessionmaker[Session]) -> None:
    with factory() as s:
        assert repo.get_flag(s, "frozen") is False


def test_set_and_clear_flag_keeps_note_and_time(factory: sessionmaker[Session]) -> None:
    with factory() as s:
        repo.set_flag(s, "frozen", True, "incident 42", 10.0)
        assert repo.get_flag(s, "frozen") is True
        repo.set_flag(s, "frozen", False, "resolved", 20.0)
        assert repo.get_flag(s, "frozen") is False
        row = s.get(FlagRow, "frozen")
        assert row is not None and (row.note, row.updated_at) == ("resolved", 20.0)


def test_flags_are_independent(factory: sessionmaker[Session]) -> None:
    with factory() as s:
        repo.set_flag(s, "frozen", True, "", 1.0)
        assert repo.get_flag(s, "other") is False


def test_any_value_other_than_one_is_off(factory: sessionmaker[Session]) -> None:
    with factory() as s:
        s.add(FlagRow(name="frozen", value="true", note="", updated_at=1.0))
        s.commit()
        assert repo.get_flag(s, "frozen") is False  # fail safe: only an explicit "1" freezes
