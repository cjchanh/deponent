#!/usr/bin/env python3
"""Tamper-evidence proof for the hash-chained ledger.
Run: python -m pytest -q tests/test_ledger.py"""
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from deponent import Gate, Ledger


class TestLedger(unittest.TestCase):
    def setUp(self):
        self.work = Path(tempfile.mkdtemp())
        self.log = self.work / "ledger.jsonl"
        self.gate = Gate(self.work)

    def test_chain_intact_and_verifies(self):
        led = Ledger(self.log)
        for cmd in ("ls", "python -m pytest -q", "rm -rf /"):
            d = self.gate.evaluate("run_cmd", {"cmd": cmd})
            led.record(agent="builder", tool="run_cmd", params={"cmd": cmd}, decision=d, outcome="done")
        ok, msg = led.verify()
        self.assertTrue(ok, msg)
        self.assertEqual(len(led.entries), 3)

    def test_tamper_is_detected(self):
        led = Ledger(self.log)
        d = self.gate.evaluate("run_cmd", {"cmd": "ls"})
        led.record(agent="builder", tool="run_cmd", params={"cmd": "ls"}, decision=d)
        # forge a BLOCK into an ALLOW after the fact
        led.entries[0]["verdict"] = "ALLOW_FORGED"
        ok, msg = led.verify()
        self.assertFalse(ok)
        self.assertIn("hash mismatch", msg)

    def test_reordering_is_detected(self):
        led = Ledger(self.log)
        for cmd in ("ls", "wc -l", "echo hi"):
            d = self.gate.evaluate("run_cmd", {"cmd": cmd})
            led.record(agent="b", tool="run_cmd", params={"cmd": cmd}, decision=d)
        led.entries[0], led.entries[1] = led.entries[1], led.entries[0]
        ok, _ = led.verify()
        self.assertFalse(ok)

    def test_persist_and_reload_roundtrip(self):
        led = Ledger(self.log)
        for cmd in ("ls", "echo hi"):
            d = self.gate.evaluate("run_cmd", {"cmd": cmd})
            led.record(agent="b", tool="run_cmd", params={"cmd": cmd}, decision=d, outcome="x")
        reloaded = Ledger.load(self.log)
        ok, _ = reloaded.verify()
        self.assertTrue(ok)
        self.assertEqual(len(reloaded.entries), 2)

    # --- truncation: the disclosed limit + its anchor (2026-07-03 audit) ---
    # A hash chain has no built-in length commitment: drop the tail and the shorter
    # chain still re-links from genesis. This test LOCKS that disclosed limit so it
    # can never silently become a false "any tamper is caught" claim.
    def test_truncation_passes_verify_alone(self):
        led = Ledger(self.log)
        for cmd in ("ls", "echo a", "echo b"):
            d = self.gate.evaluate("run_cmd", {"cmd": cmd})
            led.record(agent="b", tool="run_cmd", params={"cmd": cmd}, decision=d, outcome="x")
        truncated = led.entries[:1]                       # drop the last two decisions
        ok, _ = Ledger.verify_entries(truncated)          # verify() alone: still "intact"
        self.assertTrue(ok, "documents the disclosed limit — chain-only verify misses truncation")

    # ...and the anchor that DOES catch it: a known expected length (from a receipt).
    def test_expected_len_catches_truncation(self):
        led = Ledger(self.log)
        for cmd in ("ls", "echo a", "echo b"):
            d = self.gate.evaluate("run_cmd", {"cmd": cmd})
            led.record(agent="b", tool="run_cmd", params={"cmd": cmd}, decision=d, outcome="x")
        truncated = led.entries[:1]
        ok, msg = Ledger.verify_entries(truncated, expected_len=3)
        self.assertFalse(ok, "expected_len must fail-closed on a short chain")
        self.assertIn("length mismatch", msg)

    def test_verify_entries_third_positional_is_expected_len(self):
        led = Ledger(self.log)
        for cmd in ("ls", "echo a", "echo b"):
            d = self.gate.evaluate("run_cmd", {"cmd": cmd})
            led.record(agent="b", tool="run_cmd", params={"cmd": cmd}, decision=d, outcome="x")
        ok, msg = Ledger.verify_entries(led.entries, Ledger.GENESIS, 3)
        self.assertTrue(ok, msg)
        ok_short, msg_short = Ledger.verify_entries(led.entries[:1], Ledger.GENESIS, 3)
        self.assertFalse(ok_short)
        self.assertIn("length mismatch", msg_short)

    def test_head_returns_last_hash_and_count(self):
        led = Ledger(self.log)
        self.assertEqual(led.head(), (Ledger.GENESIS, 0))
        for cmd in ("ls", "echo a", "echo b"):
            d = self.gate.evaluate("run_cmd", {"cmd": cmd})
            led.record(agent="b", tool="run_cmd", params={"cmd": cmd}, decision=d, outcome="x")
        h, n = led.head()
        self.assertEqual(n, 3)
        self.assertEqual(h, led.entries[-1]["entry_hash"])

    def test_empty_head_is_genesis_and_anchors_against_rechain(self):
        led = Ledger(self.log)
        self.assertEqual(led.head(), (Ledger.GENESIS, 0))
        ok, msg = led.verify(expected_head=Ledger.GENESIS)
        self.assertTrue(ok, msg)
        ok_skip, _ = led.verify()
        self.assertTrue(ok_skip)
        d = self.gate.evaluate("run_cmd", {"cmd": "ls"})
        led.record(agent="b", tool="run_cmd", params={"cmd": "ls"}, decision=d, outcome="x")
        ok_after, msg_after = led.verify(expected_head=Ledger.GENESIS)
        self.assertFalse(ok_after)
        self.assertIn("head mismatch", msg_after)

    def test_module_docstring_anchor_line_is_not_over_indented(self):
        from deponent import ledger as ledger_mod
        doc = ledger_mod.__doc__ or ""
        self.assertIn(
            "and\n`verify_entries(..., expected_length=N, expected_head=h)`",
            doc,
        )
        self.assertNotIn("and\n    `verify_entries(", doc)

    def test_truncation_fails_expected_length_and_head(self):
        led = Ledger(self.log)
        for cmd in ("ls", "echo a", "echo b"):
            d = self.gate.evaluate("run_cmd", {"cmd": cmd})
            led.record(agent="b", tool="run_cmd", params={"cmd": cmd}, decision=d, outcome="x")
        original_head, original_n = led.head()
        self.assertEqual(original_n, 3)
        led.entries = led.entries[:1]
        ok, _ = led.verify()
        self.assertTrue(ok, "chain-only verify still misses tail truncation")
        ok_len, msg_len = led.verify(expected_length=original_n)
        self.assertFalse(ok_len)
        self.assertIn("length mismatch", msg_len)
        ok_head, msg_head = led.verify(expected_head=original_head)
        self.assertFalse(ok_head)
        self.assertIn("head mismatch", msg_head)

    def test_rechain_after_edit_fails_expected_head(self):
        led = Ledger(self.log)
        for cmd in ("ls", "echo a", "echo b"):
            d = self.gate.evaluate("run_cmd", {"cmd": cmd})
            led.record(agent="b", tool="run_cmd", params={"cmd": cmd}, decision=d, outcome="x")
        original_head, _ = led.head()
        led.entries[1]["verdict"] = "ALLOW_FORGED"
        prev = Ledger.GENESIS
        for e in led.entries:
            payload = {k: e[k] for k in e if k not in ("prev_hash", "entry_hash")}
            e["prev_hash"] = prev
            e["entry_hash"] = Ledger._hash(prev, payload)
            prev = e["entry_hash"]
        led.prev = prev
        ok, _ = led.verify()
        self.assertTrue(ok, "a full re-chain looks intact to verify() alone")
        ok_head, msg = led.verify(expected_head=original_head)
        self.assertFalse(ok_head)
        self.assertIn("head mismatch", msg)

    def test_middle_deletion_is_detected(self):
        led = Ledger(self.log)
        for cmd in ("ls", "echo a", "echo b"):
            d = self.gate.evaluate("run_cmd", {"cmd": cmd})
            led.record(agent="b", tool="run_cmd", params={"cmd": cmd}, decision=d, outcome="x")
        del led.entries[1]
        ok, _ = led.verify()
        self.assertFalse(ok)

    # --- absent testimony: a missing or empty ledger FILE is never "intact" ---
    # Zero entries rehydrated from disk is exactly what deleting or emptying the file
    # produces, so load() + verify() must not call it intact without an external anchor.
    def _record_two(self) -> Ledger:
        led = Ledger(self.log)
        for cmd in ("ls", "echo a"):
            d = self.gate.evaluate("run_cmd", {"cmd": cmd})
            led.record(agent="b", tool="run_cmd", params={"cmd": cmd}, decision=d, outcome="x")
        return led

    def test_load_of_missing_path_is_not_intact(self):
        gone = self.work / "gone.jsonl"
        self.assertFalse(gone.exists())
        ok, msg = Ledger.load(gone).verify()
        self.assertFalse(ok, msg)
        self.assertIn("no testimony", msg)
        self.assertIn("not found", msg)

    def test_deleted_ledger_file_is_not_intact_on_reload(self):
        self._record_two()
        self.log.unlink()
        ok, msg = Ledger.load(self.log).verify()
        self.assertFalse(ok, msg)
        self.assertIn("not found", msg)

    def test_emptied_ledger_file_is_not_intact_on_reload(self):
        self._record_two()
        for emptied in ("", "\n   \n\n"):                     # 0 bytes; blank lines only
            self.log.write_text(emptied, encoding="utf-8")
            ok, msg = Ledger.load(self.log).verify()
            self.assertFalse(ok, f"{emptied!r}: {msg}")
            self.assertIn("no testimony", msg)

    def test_empty_loaded_chain_verifies_only_against_an_external_anchor(self):
        # A zero-action run never creates its file (record() writes lazily); its
        # published empty head (GENESIS / length 0) must still verify it.
        led = Ledger.load(self.work / "zero-action-run.jsonl")
        for anchor in ({"expected_head": Ledger.GENESIS}, {"expected_length": 0}):
            ok, msg = led.verify(**anchor)
            self.assertTrue(ok, f"{anchor}: {msg}")
        for anchor in ({"expected_head": "0" * 64}, {"expected_length": 2}):
            ok, msg = led.verify(**anchor)
            self.assertFalse(ok, f"{anchor}: {msg}")

    def test_provenance_default_lives_on_the_instance(self):
        # Class-level state must never decide a live ledger's verdict (attack round 1).
        with mock.patch.object(Ledger, "_loaded_file_found", False, create=True):
            ok, msg = Ledger(self.log).verify()
        self.assertTrue(ok, msg)

    def test_load_of_missing_path_still_starts_a_verifiable_chain(self):
        led = Ledger.load(self.log)                       # first run: no file yet
        d = self.gate.evaluate("run_cmd", {"cmd": "ls"})
        led.record(agent="b", tool="run_cmd", params={"cmd": "ls"}, decision=d, outcome="x")
        ok, msg = led.verify()
        self.assertTrue(ok, msg)
        ok_reloaded, msg_reloaded = Ledger.load(self.log).verify()
        self.assertTrue(ok_reloaded, msg_reloaded)

    # --- a fresh chain never forks an existing ledger file ---
    # Ledger(path) starts at GENESIS; appending that onto a file that already holds a
    # chain forks it (the file then fails load().verify() at the seam). Resuming an
    # existing chain is explicit: Ledger.load(path).
    def test_constructor_refuses_a_file_that_already_holds_a_chain(self):
        self._record_two()
        before = self.log.read_bytes()
        with self.assertRaises(FileExistsError):
            Ledger(self.log)
        self.assertEqual(self.log.read_bytes(), before)

    def test_fresh_chain_refuses_to_append_onto_a_file_that_gained_entries(self):
        late = Ledger(self.log)                           # bound while the file is absent
        self._record_two()                                # another writer fills it first
        before = self.log.read_bytes()
        d = self.gate.evaluate("run_cmd", {"cmd": "ls"})
        with self.assertRaises(FileExistsError):
            late.record(agent="b", tool="run_cmd", params={"cmd": "ls"}, decision=d)
        self.assertEqual(self.log.read_bytes(), before)
        self.assertEqual((late.entries, late.prev), ([], Ledger.GENESIS))

    def test_resume_with_load_continues_one_verifiable_chain(self):
        self._record_two()
        resumed = Ledger.load(self.log)
        d = self.gate.evaluate("run_cmd", {"cmd": "ls"})
        resumed.record(agent="b", tool="run_cmd", params={"cmd": "ls"}, decision=d, outcome="x")
        reloaded = Ledger.load(self.log)
        ok, msg = reloaded.verify()
        self.assertTrue(ok, msg)
        self.assertEqual(len(reloaded.entries), 3)

    # --- a stale writer never forks the file (R2-1): every append checks the tail ---
    # The file must still end where this ledger left it (same byte length, same last
    # entry hash); otherwise another writer moved or cut it and appending from a stale
    # head would fork it. The refusal writes nothing.
    def _append(self, led: Ledger, cmd: str = "ls") -> dict:
        d = self.gate.evaluate("run_cmd", {"cmd": cmd})
        return led.record(agent="b", tool="run_cmd", params={"cmd": cmd}, decision=d, outcome="x")

    def test_stale_instance_refuses_to_fork_after_another_writer_appends(self):
        self._record_two()
        first, second = Ledger.load(self.log), Ledger.load(self.log)
        self._append(first, "echo first")
        before = self.log.read_bytes()
        stale = (list(second.entries), second.prev)
        with self.assertRaises(FileExistsError) as caught:
            self._append(second, "echo second")
        self.assertIn("changed since", str(caught.exception))
        self.assertEqual(self.log.read_bytes(), before)
        self.assertEqual((second.entries, second.prev), stale)
        ok, msg = Ledger.load(self.log).verify()
        self.assertTrue(ok, msg)

    def test_append_refuses_a_file_cut_under_it(self):
        self._record_two()
        led = Ledger.load(self.log)
        self.log.write_bytes(self.log.read_bytes().splitlines(keepends=True)[0])
        before = self.log.read_bytes()
        with self.assertRaises(FileExistsError):
            self._append(led)
        self.assertEqual(self.log.read_bytes(), before)

    def test_append_refuses_a_same_length_rechained_tail(self):
        # Same byte length, different last entry: only the head check can see it.
        self._record_two()
        led = Ledger.load(self.log)
        first, last = [json.loads(x) for x in self.log.read_text(encoding="utf-8").split("\n")[:2]]
        last["agent"] = "c"                                   # same length as "b"
        payload = {k: v for k, v in last.items() if k not in ("prev_hash", "entry_hash")}
        last["entry_hash"] = Ledger._hash(last["prev_hash"], payload)
        forged = "".join(json.dumps(e, ensure_ascii=False) + "\n" for e in (first, last)).encode()
        self.assertEqual(len(forged), self.log.stat().st_size)
        self.log.write_bytes(forged)
        with self.assertRaises(FileExistsError):
            self._append(led)
        self.assertEqual(self.log.read_bytes(), forged)

    def test_append_refuses_bytes_added_after_its_last_entry(self):
        # Same last entry, longer file: only the length check can see it.
        self._record_two()
        led = Ledger.load(self.log)
        with self.log.open("ab") as f:
            f.write(b"\n")
        before = self.log.read_bytes()
        with self.assertRaises(FileExistsError):
            self._append(led)
        self.assertEqual(self.log.read_bytes(), before)

    def test_append_refuses_when_its_file_vanished(self):
        self._record_two()
        led = Ledger.load(self.log)
        self.log.unlink()
        with self.assertRaises(FileExistsError):
            self._append(led)
        self.assertFalse(self.log.exists())

    def test_write_slipped_into_the_check_window_is_refused_at_the_next_append(self):
        # Residual H8: with no OS lock, a foreign write can land between this ledger's
        # check and its own write. That one is not prevented (the fork reaches the file,
        # and verify() reports it), but the very next append must refuse, because the
        # file is longer than this ledger's own writes explain.
        self._record_two()
        mine, other = Ledger.load(self.log), Ledger.load(self.log)
        fired = []

        def hash_then_race(prev, payload):
            if not fired:
                fired.append(True)
                self._append(other, "echo other")         # lands inside mine's window
            return Ledger._hash(prev, payload)

        mine._hash = hash_then_race
        self._append(mine, "echo mine")
        del mine._hash
        self.assertFalse(Ledger.load(self.log).verify()[0])  # the fork is on disk, evident
        before = self.log.read_bytes()
        with self.assertRaises(FileExistsError):
            self._append(mine, "echo mine again")
        self.assertEqual(self.log.read_bytes(), before)

    # --- the reader matches the writer (R3): records are split on "\n" only ---
    # json.dumps(ensure_ascii=False) leaves U+2028, U+2029 and U+0085 raw inside strings;
    # str.splitlines() cut a record there, so an agent could make its own testimony
    # unloadable through any tool parameter.
    def _round_trip_with(self, sep: str) -> None:
        led = Ledger(self.log)
        self._append(led, "ls")
        self._append(led, f"ls a{sep}b")
        reloaded = Ledger.load(self.log)
        ok, msg = reloaded.verify()
        self.assertTrue(ok, f"{sep!r}: {msg}")
        self.assertEqual(reloaded.head(), led.head())
        self.assertEqual(reloaded.entries[-1]["params"]["cmd"], f"ls a{sep}b")

    def test_u2028_in_a_param_round_trips(self):
        self._round_trip_with(" ")

    def test_u2029_in_a_param_round_trips(self):
        self._round_trip_with(" ")

    def test_u0085_in_a_param_round_trips(self):
        self._round_trip_with("\u0085")

    def test_a_stray_line_separator_between_records_fails_closed(self):
        led = Ledger(self.log)
        self._append(led, "ls")
        self._append(led, "echo a")
        first, second = self.log.read_text(encoding="utf-8").split("\n")[:2]
        self.log.write_text(first + "\n \n" + second + "\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            Ledger.load(self.log)

    def test_constructor_counts_non_json_whitespace_as_content(self):
        self.log.write_bytes(b"\x0b\n")                 # blank to str.strip(), not to JSON
        with self.assertRaises(FileExistsError):
            Ledger(self.log)

    def test_a_record_cut_mid_way_fails_closed(self):
        led = Ledger(self.log)
        self._append(led, "ls")
        self._append(led, "echo a")
        first, second = self.log.read_text(encoding="utf-8").split("\n")[:2]
        self.log.write_text(first + "\n" + second[:-5] + "\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            Ledger.load(self.log)

    def test_append_refuses_a_tail_the_loader_cannot_parse(self):
        # Same size, but the final "\n" became "\v": appending would glue two records
        # into one unloadable line, so the tail check must read "\v" as content too.
        self._record_two()
        led = Ledger.load(self.log)
        self.log.write_bytes(self.log.read_bytes()[:-1] + b"\x0b")
        before = self.log.read_bytes()
        with self.assertRaises(FileExistsError):
            self._append(led)
        self.assertEqual(self.log.read_bytes(), before)

    def test_crlf_records_from_a_text_mode_writer_still_load_and_resume(self):
        # Released writers used text mode, which wrote "\r\n" on Windows; keep those working.
        led = Ledger(self.log)
        self._append(led, "ls")
        self._append(led, "echo a")
        self.log.write_bytes(self.log.read_bytes().replace(b"\n", b"\r\n"))
        resumed = Ledger.load(self.log)
        ok, msg = resumed.verify()
        self.assertTrue(ok, msg)
        self.assertEqual(resumed.head(), led.head())
        self._append(resumed, "echo b")
        reloaded = Ledger.load(self.log)
        ok, msg = reloaded.verify()
        self.assertTrue(ok, msg)
        self.assertEqual(reloaded.head()[1], 3)

    def test_constructor_over_an_empty_file_starts_a_fresh_chain(self):
        for blank in ("", "\n  \n"):                      # 0 bytes; blank lines only
            self.log.write_text(blank, encoding="utf-8")
            led = Ledger(self.log)
            d = self.gate.evaluate("run_cmd", {"cmd": "ls"})
            led.record(agent="b", tool="run_cmd", params={"cmd": "ls"}, decision=d, outcome="x")
            ok, msg = Ledger.load(self.log).verify()
            self.assertTrue(ok, f"{blank!r}: {msg}")

    def test_readme_names_external_head_anchor(self):
        text = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")
        self.assertIn(
            "The ledger is tamper-evident for edits, deletions and reordering; "
            "truncation and re-chaining are caught only against a head published "
            "outside the ledger (`Ledger.head()` / receipt `ledger_head`)",
            text,
        )


if __name__ == "__main__":
    unittest.main()
