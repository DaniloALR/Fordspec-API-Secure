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
