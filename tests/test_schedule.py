from warrant.schedule import all_orders, explore, run_schedule, sample


def counter_ops(shared, n_ops):
    """Two-step increment: read, then write. The classic lost update."""

    def make():
        def op():
            value = shared["v"]
            yield
            shared["v"] = value + 1
            return value

        return op()

    return [make for _ in range(n_ops)]


def test_all_orders_counts_correctly():
    # 2 operations of 2 steps each: 4!/(2!2!) = 6 distinct interleavings.
    assert len(all_orders(2, 2)) == 6
    assert len(all_orders(3, 2)) == 90


def test_run_schedule_finishes_every_operation():
    shared = {"v": 0}
    results = run_schedule(counter_ops(shared, 3), [0, 1, 2, 0, 1, 2])
    assert len(results) == 3
    assert all(r is not None for r in results)


def test_run_schedule_drains_operations_left_out_of_the_order():
    shared = {"v": 0}
    results = run_schedule(counter_ops(shared, 2), [0])
    assert all(r is not None for r in results)


def test_explore_finds_the_lost_update():
    def invariant(_results):
        return (shared["v"] == 2), f"counter reached {shared['v']}, expected 2"

    shared = {"v": 0}

    def factories():
        return counter_ops(shared, 2)

    violations = 0
    for order in all_orders(2, 2):
        shared["v"] = 0
        run_schedule(factories(), order)
        if shared["v"] != 2:
            violations += 1
    assert violations > 0


def test_explore_reports_exhaustiveness():
    shared = {"v": 0}
    report = explore(counter_ops(shared, 2), 2, lambda r: (True, ""))
    assert report["exhaustive"] is True
    assert report["schedules_checked"] == 6


def test_explore_falls_back_to_a_bounded_run():
    shared = {"v": 0}
    report = explore(counter_ops(shared, 3), 2, lambda r: (True, ""), max_schedules=5)
    assert report["exhaustive"] is False
    assert report["schedules_checked"] == 5


def test_sample_is_reproducible_for_a_given_seed():
    shared = {"v": 0}
    a = sample(counter_ops(shared, 3), 2, lambda r: (True, ""), n=50, seed=7)
    shared["v"] = 0
    b = sample(counter_ops(shared, 3), 2, lambda r: (True, ""), n=50, seed=7)
    assert a["schedules_checked"] == b["schedules_checked"]


def test_invariant_failures_are_reported_with_a_schedule():
    shared = {"v": 0}

    def bad(_results):
        return False, "always fails"

    report = explore(counter_ops(shared, 2), 2, bad)
    assert report["violations"] == report["schedules_checked"]
    assert report["first_violation"]["why"] == "always fails"
    assert isinstance(report["first_violation"]["order"], list)
