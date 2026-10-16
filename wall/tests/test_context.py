from ptl.wall import TargetClass as T
from ptl.wall import WallContext, normalize_address

from .constants import ACCOUNT, COLLEAGUE, CONTACT, STRANGER


def test_basic_classes(ctx):
    assert ctx.classify(ACCOUNT) == T.SELF
    assert ctx.classify(COLLEAGUE) == T.INTERNAL
    assert ctx.classify(CONTACT) == T.CONTACT
    assert ctx.classify(STRANGER) == T.EXTERNAL


def test_case_whitespace_and_display_names(ctx):
    assert ctx.classify("  John.Doe@GMAIL.com ") == T.CONTACT
    assert ctx.classify("John Doe <john.doe@gmail.com>") == T.CONTACT


def test_lookalike_and_subdomain_are_not_internal(ctx):
    assert ctx.classify("boss@bluesparrowtech.com.evil.com") == T.EXTERNAL
    assert ctx.classify("boss@mail.bluesparrowtech.com") == T.EXTERNAL   # exact domain only
    assert ctx.classify("boss@bluesparrowtech.co") == T.EXTERNAL


def test_malformed_and_suspicious_are_unknown(ctx):
    for bad in [
        "",
        "not-an-email",
        "a@b@c.com",
        "a@b.com, c@d.com",                    # two addresses in one string
        "x <a@b.com> <c@d.com>",               # two angle addresses
        "boss@bluesparrowtéch.com",            # non-ASCII lookalike
        None,
        123,
        ["a@b.com"],
    ]:
        assert ctx.classify(bad) == T.UNKNOWN, bad


def test_internal_beats_contact(ctx):
    both = WallContext.for_account(ACCOUNT, contacts=[COLLEAGUE])
    assert both.classify(COLLEAGUE) == T.INTERNAL


def test_trust_own_domain_can_be_turned_off():
    c = WallContext.for_account(ACCOUNT, trust_own_domain=False)
    assert c.classify(COLLEAGUE) == T.EXTERNAL


def test_from_agentdojo_env_shape():
    class Contact:
        def __init__(self, email):
            self.email = email

    class Inbox:
        account_email = ACCOUNT
        contact_list = [Contact(CONTACT), Contact("BAD ADDRESS")]

    class Env:
        inbox = Inbox()

    c = WallContext.from_agentdojo_env(Env())
    assert c.account_email == ACCOUNT
    assert c.trusted_contacts == frozenset({CONTACT})   # bad entries are dropped
    assert "bluesparrowtech.com" in c.trusted_domains


def test_normalize_address():
    assert normalize_address("Bob <BOB@X.COM>") == "bob@x.com"
    assert normalize_address("bob@x") is None
