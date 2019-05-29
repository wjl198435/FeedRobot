"""  """

"""Example Load Platform integration."""
DOMAIN = 'haiwa_piio'
HAIWA_DEVICES = 'haiwa_devices'
from homeassistant.helpers import discovery

# HAIWA_PLATFORMS = ['feedrobot', 'fan', 'vacuum', 'climate', 'air_quality']
HAIWA_PLATFORMS = ['feedrobot']

def setup(hass, config):
    if HAIWA_DEVICES not in hass.data:
        hass.data[HAIWA_DEVICES] = []
    """Your controller/hub specific code."""
    # Data that you want to share with your platforms
    # hass.data[DOMAIN] = {
    #   'temperature': 23
    # }

    # hass.helpers.discovery.load_platform('feedrobot', DOMAIN, {}, config)
    if hass.data[HAIWA_DEVICES]:
        for platform in HAIWA_PLATFORMS:
            discovery.load_platform(hass, platform, DOMAIN, {}, config)
        
    return True