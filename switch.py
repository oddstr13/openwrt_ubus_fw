"""Support for OpenWRT (ubus) routers."""
from __future__ import annotations

import logging

from openwrt.ubus import Ubus
from openwrt.ubus.const import (
    API_RPC_CALL,
    API_SUBSYS_UCI,
    API_METHOD_GET,
    API_PARAM_CONFIG,
    API_PARAM_TYPE,
)
import voluptuous as vol

from homeassistant.components.switch import (
    SwitchEntity,
    DOMAIN,
    PLATFORM_SCHEMA as PARENT_PLATFORM_SCHEMA,
)

from homeassistant.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_USERNAME,
    CONF_PROTOCOL,
    CONF_VERIFY_SSL,
)
from homeassistant.core import HomeAssistant
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.typing import ConfigType, DiscoveryInfoType
from homeassistant.helpers.entity_platform import AddEntitiesCallback

_LOGGER = logging.getLogger(__name__)

ALLOWED_PROTOCOLS = ["http", "https"]
DEFAULT_PROTOCOL = "http"

# CONF_FW_RULES = "firewall_rules"
API_SUBSYS_SYSTEM = "system"

API_UCI_CONFIG_FIREWALL = "firewall"
API_UCI_TYPE_RULE = "rule"
API_UCI_VALUES = "values"

API_PARAM_SECTION = "section"
API_PARAM_OPTION = "option"
API_PARAM_VALUES = "values"

API_METHOD_SET = "set"
API_METHOD_COMMIT = "commit"
API_METHOD_RELOAD_CONFIG = "reload_config"
API_METHOD_BOARD = "board"

API_UCI_CONFIG_FIREWALL_ENABLED = "enabled"

PLATFORM_SCHEMA = PARENT_PLATFORM_SCHEMA.extend(
    {
        vol.Required(CONF_HOST): cv.string,
        vol.Required(CONF_PASSWORD): cv.string,
        vol.Required(CONF_USERNAME): cv.string,
        vol.Optional(CONF_PROTOCOL, default=DEFAULT_PROTOCOL): vol.In(
            ALLOWED_PROTOCOLS
        ),
        vol.Optional(CONF_VERIFY_SSL, default=True): cv.boolean,
        # vol.Optional(CONF_DHCP_SOFTWARE, default=DEFAULT_DHCP_SOFTWARE): vol.In(DHCP_SOFTWARES),
        # vol.Required(CONF_FW_RULES): cv.ensure_list(cv.string),
    }
)

# https://openwrt.org/docs/guide-developer/ubus/uci
# ubus call uci commit '{"config":"firewall"}'
# ubus call uci get '{"config":"firewall","type":"rule"}'


def setup_platform(
    hass: HomeAssistant,
    config: ConfigType,
    add_entities: AddEntitiesCallback,
    discovery_info: DiscoveryInfoType | None = None,
) -> None:
    """Set up the Awesome Light platform."""
    # Assign configuration variables.
    # The configuration check takes care they are present.
    host = config[CONF_HOST]
    username = config[CONF_USERNAME]
    password = config[CONF_PASSWORD]
    protocol = config[CONF_PROTOCOL]
    verify_ssl = config[CONF_VERIFY_SSL]

    url = f"{protocol}://{host}/ubus"
    _LOGGER.debug("URL: %s", url)

    ubus = Ubus(url, username, password, verify=verify_ssl)
    ubus.debug_api = True

    success_init = None
    try:
        success_init = ubus.connect() is not None
    except Exception as ex:
        _LOGGER.exception("Exception in ubus.connect()")

    # Verify that passed in configuration works
    if not success_init:
        _LOGGER.error("Could not connect to OpenWRT ubus hub")
        return

    # ubus call system board '{}'
    system_info = ubus.api_call(API_RPC_CALL, API_SUBSYS_SYSTEM, API_METHOD_BOARD)

    # fwrules = ubus.api_call(API_RPC_CALL, API_SUBSYS_UCI, API_METHOD_GET, {"config":"firewall","type":"rule"})
    fwrules = ubus.get_uci_config(API_UCI_CONFIG_FIREWALL, API_UCI_TYPE_RULE)
    _LOGGER.debug(fwrules)
    if not fwrules:
        return

    # Add devices
    add_entities(
        FirewallRuleSwitch(ubus, system_info.get("hostname"), rule)
        for _name, rule in fwrules.get(API_UCI_VALUES, {}).items()
        if not rule.get(".anonymous")
    )


def _refresh_on_access_denied(func):
    """If remove rebooted, it lost our session so rebuild one and try again."""

    def decorator(self, *args, **kwargs):
        """Wrap the function to refresh session_id on PermissionError."""
        try:
            return func(self, *args, **kwargs)
        except PermissionError:
            _LOGGER.warning(
                "Invalid session detected."
                " Trying to refresh session_id and re-run RPC"
            )
            self.ubus.connect()

            return func(self, *args, **kwargs)

    return decorator


class FirewallRuleSwitch(SwitchEntity):
    def __init__(self, ubus: Ubus, hostname: str, rule: dict):
        """Initialize the scanner."""
        self.hostname = hostname
        self.ubus = ubus
        self._rule = rule
        _LOGGER.info("Added rule %s (%s)", self.rule_id, self.name)

    has_entity_name = True

    @property
    def name(self):
        return self._rule.get("name")

    @property
    def rule_id(self):
        return self._rule.get(".name")

    @property
    def unique_id(self) -> str:
        return f"{self.hostname}_{self.rule_id}"

    @property
    def is_on(self) -> bool:
        return bool(int(self._rule.get(API_UCI_CONFIG_FIREWALL_ENABLED, 0)))

    # ubus call uci set '{"config":"firewall","type":"rule", "section": "firewall_rule_name", "values": {"enabled":"1"}}'
    @_refresh_on_access_denied
    def _enable(self, value: bool):
        self._rule[API_UCI_CONFIG_FIREWALL_ENABLED] = value
        self.ubus.api_call(
            API_RPC_CALL,
            API_SUBSYS_UCI,
            API_METHOD_SET,
            {
                API_PARAM_CONFIG: API_UCI_CONFIG_FIREWALL,
                API_PARAM_TYPE: API_UCI_TYPE_RULE,
                API_PARAM_SECTION: self.rule_id,
                API_PARAM_VALUES: {
                    API_UCI_CONFIG_FIREWALL_ENABLED: "1" if value else "0",
                },
            },
        )
        # ubus call uci commit '{"config":"firewall"}'
        self.ubus.api_call(
            API_RPC_CALL,
            API_SUBSYS_UCI,
            API_METHOD_COMMIT,
            {
                API_PARAM_CONFIG: API_UCI_CONFIG_FIREWALL,
            },
        )
        # ubus call uci reload_config
        self.ubus.api_call(
            API_RPC_CALL,
            API_SUBSYS_UCI,
            API_METHOD_RELOAD_CONFIG,
        )

        self.update()

    def turn_on(self, **kwargs):
        self._enable(True)

    def turn_off(self, **kwargs):
        self._enable(False)

    @_refresh_on_access_denied
    def update(self) -> None:
        rule = self.ubus.api_call(
            API_RPC_CALL,
            API_SUBSYS_UCI,
            API_METHOD_GET,
            {
                API_PARAM_CONFIG: API_UCI_CONFIG_FIREWALL,
                API_PARAM_TYPE: API_UCI_TYPE_RULE,
                API_PARAM_SECTION: self.rule_id,
            },
        )
        if rule and rule.get(API_UCI_VALUES):
            self._rule = rule.get(API_UCI_VALUES)
