
import ta_aws_configurator_declare

from splunktaucclib.rest_handler.endpoint import (
    field,
    validator,
    RestModel,
    DataInputModel,
)
from splunktaucclib.rest_handler import admin_external, util
from splunktaucclib.splunk_aoblib.rest_migration import ConfigMigrationHandler

util.remove_http_proxy_env_vars()


fields = [
    field.RestField(
        'interval',
        required=True,
        encrypted=False,
        default=None,
        validator=validator.Pattern(
            regex=r"""^\-[1-9]\d*$|^\d*$""", 
        )
    ), 
    field.RestField(
        'index',
        required=True,
        encrypted=False,
        default='default',
        validator=validator.String(
            min_len=1, 
            max_len=80, 
        )
    ), 
    field.RestField(
        'aws_config_role_arn',
        required=True,
        encrypted=False,
        default=None,
        validator=validator.String(
            min_len=0,
            max_len=8192,
        )
    ),
    field.RestField(
        'aws_config_sqs_url',
        required=True,
        encrypted=False,
        default=None,
        validator=validator.String(
            min_len=0,
            max_len=8192,
        )
    ),
    field.RestField(
        'aws_config_sqs_region',
        required=True,
        encrypted=False,
        default=None,
        validator=validator.String(
            min_len=0,
            max_len=8192,
        )
    ),

    field.RestField(
        'disabled',
        required=False,
        validator=None
    )

]
model = RestModel(fields, name=None)



endpoint = DataInputModel(
    'aws_configurator_config',
    model,
    app="TA-aws-configurator"
)


if __name__ == '__main__':
    admin_external.handle(
        endpoint,
        handler=ConfigMigrationHandler,
    )
