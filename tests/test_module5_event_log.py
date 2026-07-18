from detector.event_log import EventLog


def test_summary_counts():
    log = EventLog()
    log.record("attack_a", 1, blocked=True)
    log.record("attack_b", 1, blocked=False)
    log.record("attack_c", 1, blocked=True)

    summary = log.summary()
    assert summary["total"] == 3
    assert summary["blocked"] == 2
    assert summary["succeeded"] == 1
