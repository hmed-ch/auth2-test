from authlib.oauth2.rfc6749 import ClientMixin,TokenMixin
import datetime
import time
import six
import typing


def _deserialize(data, klass):
    """Deserializes dict, list, str into an object.

    :param data: dict, list or str.
    :param klass: class literal, or string of class name.

    :return: object.
    """
    if data is None:
        return None

    if klass in six.integer_types or klass in (float, str, bool):
        return _deserialize_primitive(data, klass)
    elif klass == object:
        return _deserialize_object(data)
    elif klass == datetime.date:
        return deserialize_date(data)
    elif klass == datetime.datetime:
        return deserialize_datetime(data)
    elif type(klass) == typing.GenericMeta:
        if klass.__extra__ == list:
            return _deserialize_list(data, klass.__args__[0])
        if klass.__extra__ == dict:
            return _deserialize_dict(data, klass.__args__[1])
    else:
        return deserialize_model(data, klass)


def _deserialize_primitive(data, klass):
    """Deserializes to primitive type.

    :param data: data to deserialize.
    :param klass: class literal.

    :return: int, long, float, str, bool.
    :rtype: int | long | float | str | bool
    """
    try:
        value = klass(data)
    except UnicodeEncodeError:
        value = six.u(data)
    except TypeError:
        value = data
    return value


def _deserialize_object(value):
    """Return a original value.

    :return: object.
    """
    return value


def deserialize_date(string):
    """Deserializes string to date.

    :param string: str.
    :type string: str
    :return: date.
    :rtype: date
    """
    try:
        from dateutil.parser import parse
        return parse(string).date()
    except ImportError:
        return string


def deserialize_datetime(string):
    """Deserializes string to datetime.

    The string should be in iso8601 datetime format.

    :param string: str.
    :type string: str
    :return: datetime.
    :rtype: datetime
    """
    try:
        from dateutil.parser import parse
        return parse(string)
    except ImportError:
        return string


def deserialize_model(data, klass):
    """Deserializes list or dict to model.

    :param data: dict, list.
    :type data: dict | list
    :param klass: class literal.
    :return: model object.
    """
    instance = klass()

    if not instance.data_types:
        return data

    for attr, attr_type in six.iteritems(instance.data_types):
        if data is not None \
                and attr in data \
                and isinstance(data, (list, dict)):
            value = data[attr]
            setattr(instance, attr, _deserialize(value, attr_type))

    return instance


def _deserialize_list(data, boxed_type):
    """Deserializes a list and its elements.

    :param data: list to deserialize.
    :type data: list
    :param boxed_type: class literal.

    :return: deserialized list.
    :rtype: list
    """
    return [_deserialize(sub_data, boxed_type)
            for sub_data in data]


def _deserialize_dict(data, boxed_type):
    """Deserializes a dict and its elements.

    :param data: dict to deserialize.
    :type data: dict
    :param boxed_type: class literal.

    :return: deserialized dict.
    :rtype: dict
    """
    return {k: _deserialize(v, boxed_type)
            for k, v in six.iteritems(data)}

class User():
    """ User which will be querying resources from the API.
    """
    def __init__(self, user_id=None, username=None, password=None):
        self.data_types={
            'user_id': str,
            'username': str,
            'password': str,
        
        }
        self.user_id=user_id
        self._username = username
        self._password = password

    def from_dict(cls, dikt) :
        
        return deserialize_model(dikt, cls)

    @property
    def user_id(self):
        return self._user_id

    @user_id.setter
    def user_id(self, value):
        self._user_id = value


    @property
    def username(self):
        return self._username

    @username.setter
    def username(self, value):
        self._username = value

    @property
    def password(self):
        return self._password

    @password.setter
    def password(self, value):
        self._password = value
    def get_user_id(self):
        return self.user_id


class Client(ClientMixin):
    """ Client application through which user is authenticating.
    RFC 6749 Section 2 (http://tools.ietf.org/html/rfc6749#section-2)
    describes clients:
     +----------+
     | Resource |
     |  Owner   |
     |          |
     +----------+
          v
          |    Resource Owner
         (A) Password Credentials
          |
          v
     +---------+                                  +---------------+
     |         |>--(B)---- Resource Owner ------->|               |
     |         |         Password Credentials     | Authorization |
     | Client  |                                  |     Server    |
     |         |<--(C)---- Access Token ---------<|               |
     |         |    (w/ Optional Refresh Token)   |               |
     +---------+                                  +---------------+
    Redirection URIs are mandatory for clients. We skip this requirement
    as this example only allows the resource owner password credentials
    grant (described in Section 4.3). In this flow, the Authorization
    Server will not redirect the user as described in subsection 3.1.2
    (Redirection Endpoint).
    """
    def __init__(self, client_id=None, client_secret=None):
        self.data_types={
            'client_secret': str,
            'client_id': str,
        
        }
        self._client_id = client_id
        self._client_secret = client_secret
    def from_dict(cls, dikt) :
        
        return deserialize_model(dikt, cls)

    @property
    def client_id(self):
        return self._client_id

    @client_id.setter
    def client_id(self, value):
        self._client_id = value

    @property
    def client_secret(self):
        return self._client_secret

    @client_secret.setter
    def client_secret(self, value):
        self._client_secret = value

    def get_client_id(self):
        return self.client_id
    def get_allowed_scope(self, scope):
        if not scope:
            return ''
        #allowed = set(scope_to_list(self.scope))

        #return list_to_scope([s for s in scope.split() if s in allowed])
        return ''
    def has_client_secret(self):
        return bool(self.client_secret)

    def check_client_secret(self, client_secret):
        return self.client_secret == client_secret
    def check_token_endpoint_auth_method(self, method):
        return method=='client_secret_basic'
    def check_response_type(self, response_type):
        return True
    def check_grant_type(self, grant_type):
        return grant_type=='password'

class Token(TokenMixin):
    """ Access or refresh token
        Because of our current grant flow, we are able to associate tokens
        with the users who are requesting them. This can be used to track usage
        and potential abuse. Only bearer tokens currently supported.
    """

    def __init__(self,  client_id=None, user_id=None,
                 token_type=None, access_token=None, refresh_token=None,
                 expires_in=None, scope=[''],issued_at=time.time(),revoked=False):

        self.data_types={
            'user_id': str,
            'client_id': str,
            'token_type': str,
            'access_token': str,
            'refresh_token': str,
            'expires_in': int,
            'issued_at': int,
            'scope': list,
            'revoked':bool

        
        }
        self._client_id = client_id
        self._user_id = user_id
        self._token_type = token_type
        self._access_token = access_token
        self._refresh_token = refresh_token
        self._expires_in = expires_in
        self._issued_at = issued_at
        self._scope = scope
        self._revoked=revoked
    def from_dict(cls, dikt) :
        
        return deserialize_model(dikt, cls)
    @property
    def client_id(self):
        return self._client_id

    @client_id.setter
    def client_id(self, value):
        self._client_id = value

    @property
    def user_id(self):
        return self._user_id

    @user_id.setter
    def user_id(self, value):
        self._user_id = value


    @property
    def token_type(self):
        return self._token_type

    @token_type.setter
    def token_type(self, value):
        self._token_type = value

    @property
    def access_token(self):
        return self._access_token

    @access_token.setter
    def access_token(self, value):
        self._access_token = value

    @property
    def refresh_token(self):
        return self._refresh_token

    @refresh_token.setter
    def refresh_token(self, value):
        self._refresh_token = value

    @property
    def expires_in(self):
        return self._expires_in

    @expires_in.setter
    def expires_in(self, value):
        self._expires_in = value
    @property
    def issued_at(self):
        return self._issued_at
    @issued_at.setter
    def issued_at(self, value):
        self._issued_at = value

    @property
    def scope(self):
        return self._scope

    @scope.setter
    def scope(self, value):
        self._scope = value

    def get_client_id(self):
        return self.client_id

    def get_scope(self):
        return self.scope

    def get_expires_in(self):
        return self.expires_in

    def get_expires_at(self):
        return self.issued_at + self.expires_in