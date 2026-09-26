class DomainError(Exception):
    status = 400
    error = "domain_error"

    def __init__(self, message: str):
        self.message = message
        super().__init__(message)


class VersionNotFound(DomainError):
    status = 422
    error = "version_not_found"

    def __init__(self, brand, model, version):
        super().__init__(
            f"Versão '{version}' não encontrada na base curada para {brand} {model}."
        )


class InvalidAttribute(DomainError):
    status = 400
    error = "invalid_attribute"

    def __init__(self, invalid: list[str]):
        super().__init__(
            "Atributo(s) fora do dicionário oficial: " + ", ".join(invalid)
        )


class AuthenticationFailed(DomainError):
    status = 401
    error = "invalid_credentials"

    def __init__(self):
        super().__init__("Credenciais inválidas.")


class InvalidRefreshToken(DomainError):
    status = 401
    error = "invalid_refresh_token"

    def __init__(self):
        super().__init__("Refresh token inválido, expirado ou revogado.")


class UserNotFound(DomainError):
    status = 404
    error = "user_not_found"

    def __init__(self, username: str):
        super().__init__(f"Usuário '{username}' não encontrado.")


class UserAlreadyExists(DomainError):
    status = 409
    error = "user_already_exists"

    def __init__(self, username: str):
        super().__init__(f"Usuário '{username}' já existe.")


class LastAdministrator(DomainError):
    status = 409
    error = "last_administrator"

    def __init__(self):
        super().__init__("Operação removeria o último administrador ativo.")
