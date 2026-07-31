from __future__ import annotations

import os
import ssl
import threading
from unittest import mock

import pytest

try:
    import OpenSSL
    import OpenSSL.SSL
    from cryptography import x509
    from OpenSSL.crypto import FILETYPE_PEM, load_certificate

    from urllib3.contrib.pyopenssl import (
        PyOpenSSLContext,
        _dnsname_to_stdlib,
        get_subj_alt_name,
    )
except ImportError:
    pass


def setup_module() -> None:
    try:
        from urllib3.contrib.pyopenssl import inject_into_urllib3

        inject_into_urllib3()
    except ImportError as e:
        pytest.skip(f"Could not import PyOpenSSL: {e!r}")


def teardown_module() -> None:
    try:
        from urllib3.contrib.pyopenssl import extract_from_urllib3

        extract_from_urllib3()
    except ImportError:
        pass


from ..test_ssl import TestSSL  # noqa: E402, F401
from ..test_util import TestUtilSSL  # noqa: E402, F401
from ..with_dummyserver.test_https import (  # noqa: E402, F401
    TestHTTPS_IPV4SAN,
    TestHTTPS_IPV6SAN,
    TestHTTPS_TLSv1,
    TestHTTPS_TLSv1_1,
    TestHTTPS_TLSv1_2,
    TestHTTPS_TLSv1_3,
)
from ..with_dummyserver.test_socketlevel import (  # noqa: E402, F401
    TestClientCerts,
    TestSNI,
    TestSocketClosing,
)
from ..with_dummyserver.test_socketlevel import (  # noqa: E402, F401
    TestSSL as TestSocketSSL,
)


class TestPyOpenSSLHelpers:
    """
    Tests for PyOpenSSL helper functions.
    """

    def test_dnsname_to_stdlib_simple(self) -> None:
        """
        We can convert a dnsname to a native string when the domain is simple.
        """
        name = "उदाहरण.परीक"
        expected_result = "xn--p1b6ci4b4b3a.xn--11b5bs8d"

        assert _dnsname_to_stdlib(name) == expected_result

    def test_dnsname_to_stdlib_leading_period(self) -> None:
        """
        If there is a . in front of the domain name we correctly encode it.
        """
        name = ".उदाहरण.परीक"
        expected_result = ".xn--p1b6ci4b4b3a.xn--11b5bs8d"

        assert _dnsname_to_stdlib(name) == expected_result

    def test_dnsname_to_stdlib_leading_splat(self) -> None:
        """
        If there's a wildcard character in the front of the string we handle it
        appropriately.
        """
        name = "*.उदाहरण.परीक"
        expected_result = "*.xn--p1b6ci4b4b3a.xn--11b5bs8d"

        assert _dnsname_to_stdlib(name) == expected_result

    @mock.patch("urllib3.contrib.pyopenssl.log.warning")
    def test_get_subj_alt_name(self, mock_warning: mock.MagicMock) -> None:
        """
        If a certificate has two subject alternative names, cryptography raises
        an x509.DuplicateExtension exception.
        """
        path = os.path.join(os.path.dirname(__file__), "duplicate_san.pem")
        with open(path, "rb") as fp:
            cert = load_certificate(FILETYPE_PEM, fp.read())

        assert get_subj_alt_name(cert) == []

        assert mock_warning.call_count == 1
        assert isinstance(mock_warning.call_args[0][1], x509.DuplicateExtension)


class TestPyOpenSSLContext:
    def context(self) -> PyOpenSSLContext:
        return PyOpenSSLContext(ssl.PROTOCOL_TLS_CLIENT)

    def test_urllib3_load_verify_locations_is_idempotent(self) -> None:
        context = self.context()
        with mock.patch.object(context, "_load_verify_locations") as load:
            context._urllib3_load_verify_locations("ca.pem", "certs", b"data")
            context._urllib3_load_verify_locations("ca.pem", "certs", b"data")

        load.assert_called_once_with(b"ca.pem", b"certs", b"data")

    def test_urllib3_set_verify_mode_is_idempotent(self) -> None:
        context = self.context()
        native_verify_mode = context._ctx.get_verify_mode()

        def set_verify(value: int, callback: object) -> None:
            nonlocal native_verify_mode
            native_verify_mode = value

        with (
            mock.patch.object(
                context._ctx,
                "get_verify_mode",
                side_effect=lambda: native_verify_mode,
            ),
            mock.patch.object(
                context._ctx, "set_verify", side_effect=set_verify
            ) as set_verify_mock,
        ):
            context._urllib3_set_verify_mode(ssl.CERT_REQUIRED)
            context._urllib3_set_verify_mode(ssl.CERT_REQUIRED)

        assert set_verify_mock.call_count == 1

    def test_direct_set_verify_mode_is_not_idempotent(self) -> None:
        context = self.context()
        with mock.patch.object(context._ctx, "set_verify") as set_verify:
            context.verify_mode = ssl.CERT_REQUIRED
            context.verify_mode = ssl.CERT_REQUIRED

        assert set_verify.call_count == 2

    def test_direct_load_verify_locations_invalidates_memo(self) -> None:
        context = self.context()
        with mock.patch.object(context, "_load_verify_locations") as load:
            context._urllib3_load_verify_locations("ca.pem", None, None)
            context._urllib3_load_verify_locations("ca.pem", None, None)
            context.load_verify_locations("other-ca.pem", None, None)
            context._urllib3_load_verify_locations("ca.pem", None, None)

        assert load.call_args_list == [
            mock.call(b"ca.pem", None, None),
            mock.call(b"other-ca.pem", None, None),
            mock.call(b"ca.pem", None, None),
        ]

    def test_direct_load_verify_locations_is_not_idempotent(self) -> None:
        context = self.context()
        with mock.patch.object(context, "_load_verify_locations") as load:
            context.load_verify_locations("ca.pem", None, None)
            context.load_verify_locations("ca.pem", None, None)

        assert load.call_count == 2

    def test_failed_direct_load_verify_locations_keeps_memo(self) -> None:
        context = self.context()
        with mock.patch.object(
            context,
            "_load_verify_locations",
            side_effect=[None, ssl.SSLError("context already used")],
        ) as load:
            context._urllib3_load_verify_locations("ca.pem")
            with pytest.raises(ssl.SSLError, match="context already used"):
                context.load_verify_locations("other-ca.pem")
            context._urllib3_load_verify_locations("ca.pem")

        assert load.call_count == 2

    def test_urllib3_load_cert_chain_is_idempotent(self) -> None:
        context = self.context()
        with mock.patch.object(context, "_load_cert_chain") as load:
            context._urllib3_load_cert_chain("cert.pem", "key.pem", "secret")
            context._urllib3_load_cert_chain("cert.pem", "key.pem", "secret")

        load.assert_called_once_with("cert.pem", "key.pem", "secret")
        assert context._urllib3_loaded_cert_chain == ("cert.pem", "key.pem")

    def test_direct_load_cert_chain_invalidates_memo(self) -> None:
        context = self.context()
        with mock.patch.object(context, "_load_cert_chain") as load:
            context._urllib3_load_cert_chain("cert.pem", None, b"secret")
            context._urllib3_load_cert_chain("cert.pem", None, b"secret")
            context.load_cert_chain("other-cert.pem", "other-key.pem", b"password")
            context._urllib3_load_cert_chain("cert.pem", None, b"secret")

        assert load.call_args_list == [
            mock.call("cert.pem", "cert.pem", b"secret"),
            mock.call("other-cert.pem", "other-key.pem", b"password"),
            mock.call("cert.pem", "cert.pem", b"secret"),
        ]
        assert context._urllib3_loaded_cert_chain == ("cert.pem", "cert.pem")

    def test_direct_load_cert_chain_is_not_idempotent(self) -> None:
        context = self.context()
        with mock.patch.object(context, "_load_cert_chain") as load:
            context.load_cert_chain("cert.pem", "key.pem")
            context.load_cert_chain("cert.pem", "key.pem")

        assert load.call_count == 2

    def test_failed_direct_load_cert_chain_keeps_memo(self) -> None:
        context = self.context()
        with mock.patch.object(
            context,
            "_load_cert_chain",
            side_effect=[None, ssl.SSLError("context already used")],
        ) as load:
            context._urllib3_load_cert_chain("cert.pem", "key.pem")
            with pytest.raises(ssl.SSLError, match="context already used"):
                context.load_cert_chain("other-cert.pem", "other-key.pem")
            context._urllib3_load_cert_chain("cert.pem", "key.pem")

        assert load.call_count == 2

    def test_urllib3_set_alpn_protocols_is_idempotent(self) -> None:
        context = self.context()
        with mock.patch.object(context._ctx, "set_alpn_protos") as set_alpn:
            context._urllib3_set_alpn_protocols(["http/1.1"])
            context._urllib3_set_alpn_protocols(["http/1.1"])

        set_alpn.assert_called_once_with([b"http/1.1"])

    def test_direct_set_alpn_protocols_invalidates_memo(self) -> None:
        context = self.context()
        with mock.patch.object(context._ctx, "set_alpn_protos") as set_alpn:
            context._urllib3_set_alpn_protocols(["http/1.1"])
            context._urllib3_set_alpn_protocols(["http/1.1"])
            context.set_alpn_protocols(["h2"])
            context._urllib3_set_alpn_protocols(["http/1.1"])

        assert set_alpn.call_args_list == [
            mock.call([b"http/1.1"]),
            mock.call([b"h2"]),
            mock.call([b"http/1.1"]),
        ]

    def test_direct_set_alpn_protocols_is_not_idempotent(self) -> None:
        context = self.context()
        with mock.patch.object(context._ctx, "set_alpn_protos") as set_alpn:
            context.set_alpn_protocols(["http/1.1"])
            context.set_alpn_protocols(["http/1.1"])

        assert set_alpn.call_count == 2

    def test_failed_direct_set_alpn_protocols_keeps_memo(self) -> None:
        context = self.context()
        with mock.patch.object(
            context._ctx,
            "set_alpn_protos",
            side_effect=[None, ValueError("context already used")],
        ) as set_alpn:
            context._urllib3_set_alpn_protocols(["http/1.1"])
            with pytest.raises(ValueError, match="context already used"):
                context.set_alpn_protocols(["h2"])
            context._urllib3_set_alpn_protocols(["http/1.1"])

        assert set_alpn.call_count == 2

    @pytest.mark.skipif(
        tuple(int(part) for part in OpenSSL.__version__.split(".")[:2]) < (26, 2),
        reason="requires pyOpenSSL 26.2.0+ context mutation restrictions",
    )
    def test_direct_mutation_after_first_use_is_not_memoized(self) -> None:
        context = self.context()
        context._urllib3_set_alpn_protocols(["http/1.1"])
        OpenSSL.SSL.Connection(context._ctx, None)

        with pytest.raises(ValueError, match="already been used"):
            context.set_alpn_protocols(["http/1.1"])

    def test_setup_and_connection_creation_share_lock(self) -> None:
        context = self.context()
        setup_started = threading.Event()
        release_setup = threading.Event()
        wrap_started = threading.Event()
        connection_created = threading.Event()
        errors: list[BaseException] = []

        def blocked_load(*args: object) -> None:
            setup_started.set()
            if not release_setup.wait(1):
                raise AssertionError("Timed out waiting to release context setup")

        native_connection = mock.Mock()

        def create_connection(*args: object) -> mock.Mock:
            connection_created.set()
            return native_connection

        def run_setup() -> None:
            try:
                context._urllib3_load_verify_locations("ca.pem")
            except BaseException as e:
                errors.append(e)

        def run_wrap() -> None:
            wrap_started.set()
            try:
                context.wrap_socket(mock.Mock())
            except BaseException as e:
                errors.append(e)

        with (
            mock.patch.object(context, "_load_verify_locations", blocked_load),
            mock.patch(
                "urllib3.contrib.pyopenssl.OpenSSL.SSL.Connection",
                side_effect=create_connection,
            ),
        ):
            setup_thread = threading.Thread(target=run_setup)
            wrap_thread = threading.Thread(target=run_wrap)
            setup_thread.start()
            assert setup_started.wait(1)
            wrap_thread.start()
            assert wrap_started.wait(1)
            assert not connection_created.wait(0.1)
            release_setup.set()
            setup_thread.join(1)
            wrap_thread.join(1)

        assert not setup_thread.is_alive()
        assert not wrap_thread.is_alive()
        assert connection_created.is_set()
        assert errors == []
