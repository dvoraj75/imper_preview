import pytest

from evidenta.core.wallet.crypto_manager import CryptoManager


CRYPTO_MANAGER = CryptoManager()


def test_crypto_manager_create_password__len():
    aes_key = CRYPTO_MANAGER._create_password("some-password", "some-salt")
    assert len(aes_key) == CRYPTO_MANAGER.KEY_LENGTH


def test_crypto_manager_create_password__same_key():
    password, salt = "some-password", "some-salt"
    aes_key1 = CRYPTO_MANAGER._create_password(password, salt)
    aes_key2 = CRYPTO_MANAGER._create_password(password, salt)
    assert len(aes_key1) == CRYPTO_MANAGER.KEY_LENGTH
    assert len(aes_key2) == CRYPTO_MANAGER.KEY_LENGTH
    assert aes_key1 == aes_key2


def test_crypto_manager_create_password__different_keys():
    password1, salt1 = "password", "salt"
    password2, salt2 = "some-password", "some-salt"
    aes_key1 = CRYPTO_MANAGER._create_password(password1, salt1)
    aes_key2 = CRYPTO_MANAGER._create_password(password2, salt2)
    assert len(aes_key1) == CRYPTO_MANAGER.KEY_LENGTH
    assert len(aes_key2) == CRYPTO_MANAGER.KEY_LENGTH
    assert aes_key1 != aes_key2


def test_crypto_manager_encrypt_data():
    password, salt = "password", "salt"
    decrypted_data = "some secret"

    encrypted, nonce = CRYPTO_MANAGER.encrypt_data(password, salt, decrypted_data)

    assert isinstance(encrypted, str)
    assert isinstance(nonce, str)
    assert encrypted != decrypted_data


def test_crypto_manager_decrypt_data__success():
    password, salt = "password", "salt"
    decrypted_data = "some secret"

    encrypted, nonce = CRYPTO_MANAGER.encrypt_data(decrypted_data, password, salt)

    assert isinstance(encrypted, str)
    assert isinstance(nonce, str)
    assert encrypted != decrypted_data

    decrypted = CRYPTO_MANAGER.decrypt_data(encrypted, password, salt, nonce)

    assert decrypted_data == decrypted


@pytest.mark.parametrize(
    "password1, salt1, password2, salt2",
    [
        ("password", "salt", "wrong-password", "salt"),
        ("password", "salt", "password", "wrong-salt"),
    ],
)
def test_crypto_manager_decrypt_data__fail(password1, salt1, password2, salt2):
    decrypted_data = "some secret"

    encrypted, nonce = CRYPTO_MANAGER.encrypt_data(decrypted_data, password1, salt1)

    assert isinstance(encrypted, str)
    assert isinstance(nonce, str)
    assert encrypted != decrypted_data

    with pytest.raises(ValueError):
        CRYPTO_MANAGER.decrypt_data(encrypted, password2, salt2, nonce)


def test_crypto_manager_decrypt_data__bad_nonce():
    password, salt = "password", "salt"
    decrypted_data = "some secret"

    encrypted, nonce = CRYPTO_MANAGER.encrypt_data(decrypted_data, password, salt)

    assert isinstance(encrypted, str)
    assert isinstance(nonce, str)
    assert encrypted != decrypted_data

    with pytest.raises(ValueError):
        CRYPTO_MANAGER.decrypt_data(encrypted, password, salt, "bad-nonce")
