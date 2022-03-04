known_adnetworks = {
    "4fzdc2evr5": "Aarki",
    "23zd986j2c": "adgoji",
    "ydx93a7ass": "Adikteev",
    "v72qych5uu": "Appier",
    "6xzpu9s2p8": "Applift",
    "mlmmfzh3r3": "Appreciate",
    "c6k4g5qg8m": "Beeswax",
    "hs6bdukanm": "Criteo",
    "m8dbw4sv7c": "Dataseat",
    "w9q455wk68": "Hybrid",
    "yclnxrl5pm": "Jampp",
    "4468km3ulz": "Kayzen",
    "t38b2kh725": "Lifestreet",
    "7ug5zh24hu": "Liftoff",
    "9t245vhmpl": "Moloco",
    "cad8qz2s3j": "MYAPPFREE",
    "44jx6755aq": "Persona.ly",
    "tl55sbb4fm": "PubNative",
    "2u9pt9hc89": "Remerge",
    "5a6flpkh64": "RevX",
    "8s468mfl3y": "RTBHouse",
    "klf5c3l5u5": "Sift",
    "av6w8kgt66": "ScaleMonk",
    "ppxm28t8ap": "Smadex",
    "44n7hlldy6": "SpykeMedia",
    "6964rsfnh4": "ThingOrTwo",
    "3rd42ekr43": "YouAppi"
}

def check_adnetworkidentifiers(p_list):
    """Collect all available AdNetworkItems and translate them into human readable name, if possible"""

    adnetworkidentifiers = []

    skadnetworkitems = p_list.get('SKAdNetworkItems', [])
    if not skadnetworkitems:
        return []

    if isinstance(skadnetworkitems, dict):
        skadnetworkitems = [skadnetworkitems]

    for dic_item in skadnetworkitems:
        adnetworkidentifier = dic_item.get('SKAdNetworkIdentifier')
        if adnetworkidentifier is None:
            continue

        adnetworkidentifier = adnetworkidentifier.split('.')[0] # default extension is '.skadnetwork'

        known_adnetworkidentifier = known_adnetworks.get(adnetworkidentifier)
        if known_adnetworkidentifier is not None:
            dic_item['known_adnetworkidentifier'] = known_adnetworkidentifier

        adnetworkidentifiers.append(dic_item)

    return adnetworkidentifiers
