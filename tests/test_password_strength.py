from src.password_strength import assess_password


def test_weak_password_scores_low():
    result = assess_password("password")
    assert result.score <= 1


def test_long_mixed_passphrase_scores_high():
    result = assess_password("Correct horse battery staple 42!")
    assert result.score >= 3


def test_feedback_is_always_given():
    assert assess_password("abc").feedback
