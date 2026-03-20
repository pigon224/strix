from pathlib import Path

from strix.telemetry.tracer import Tracer, get_global_tracer, set_global_tracer
from strix.tools.notes import notes_actions


def _reset_notes_state() -> None:
    notes_actions._notes_storage.clear()
    notes_actions._loaded_notes_run_dir = None


def test_wiki_notes_are_persisted_and_removed(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    _reset_notes_state()

    previous_tracer = get_global_tracer()
    tracer = Tracer("wiki-test-run")
    set_global_tracer(tracer)

    try:
        created = notes_actions.create_note(
            title="Repo Map",
            content="## Architecture\n- monolith",
            category="wiki",
            tags=["source-map"],
        )
        assert created["success"] is True
        note_id = created["note_id"]
        assert isinstance(note_id, str)

        note = notes_actions._notes_storage[note_id]
        wiki_filename = note.get("wiki_filename")
        assert isinstance(wiki_filename, str)

        wiki_path = tmp_path / "strix_runs" / "wiki-test-run" / "wiki" / wiki_filename
        assert wiki_path.exists()
        assert "## Architecture" in wiki_path.read_text(encoding="utf-8")

        updated = notes_actions.update_note(
            note_id=note_id,
            content="## Architecture\n- service-oriented",
        )
        assert updated["success"] is True
        assert "service-oriented" in wiki_path.read_text(encoding="utf-8")

        deleted = notes_actions.delete_note(note_id=note_id)
        assert deleted["success"] is True
        assert wiki_path.exists() is False
    finally:
        _reset_notes_state()
        set_global_tracer(previous_tracer)  # type: ignore[arg-type]


def test_notes_jsonl_replay_survives_memory_reset(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    _reset_notes_state()

    previous_tracer = get_global_tracer()
    tracer = Tracer("notes-replay-run")
    set_global_tracer(tracer)

    try:
        created = notes_actions.create_note(
            title="Auth findings",
            content="initial finding",
            category="findings",
            tags=["auth"],
        )
        assert created["success"] is True
        note_id = created["note_id"]
        assert isinstance(note_id, str)

        notes_path = tmp_path / "strix_runs" / "notes-replay-run" / "notes" / "notes.jsonl"
        assert notes_path.exists() is True

        _reset_notes_state()
        listed = notes_actions.list_notes(category="findings")
        assert listed["success"] is True
        assert listed["total_count"] == 1
        assert listed["notes"][0]["note_id"] == note_id

        updated = notes_actions.update_note(note_id=note_id, content="updated finding")
        assert updated["success"] is True

        _reset_notes_state()
        listed_after_update = notes_actions.list_notes(search="updated finding")
        assert listed_after_update["success"] is True
        assert listed_after_update["total_count"] == 1
        assert listed_after_update["notes"][0]["note_id"] == note_id

        deleted = notes_actions.delete_note(note_id=note_id)
        assert deleted["success"] is True

        _reset_notes_state()
        listed_after_delete = notes_actions.list_notes(category="findings")
        assert listed_after_delete["success"] is True
        assert listed_after_delete["total_count"] == 0
    finally:
        _reset_notes_state()
        set_global_tracer(previous_tracer)  # type: ignore[arg-type]
