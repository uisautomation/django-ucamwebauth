class MalformedResponseError(Exception):
    """Raised if a response from the raven server is malformed."""
    pass


class InvalidResponseError(Exception):
    """Raised if the response from the server is parseable but still not valid"""
    pass


class PublicKeyNotFoundError(Exception):
    """Raised if the server signs the response with a key which we don't have the public part of"""
    pass


class UserNotAuthorised(Exception):
    """Raised if the user is not current and the administrator does not want to authorised these type of users"""
    pass


class OtherStatusCode(Exception):
    """Raised if the status code is not 200"""
    pass
