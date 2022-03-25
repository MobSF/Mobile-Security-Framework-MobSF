known_adnetworks = {
    '4fzdc2evr5': 'Aarki',
    '23zd986j2c': 'adgoji',
    'ydx93a7ass': 'Adikteev',
    'v72qych5uu': 'Appier',
    '6xzpu9s2p8': 'Applift',
    'mlmmfzh3r3': 'Appreciate',
    'c6k4g5qg8m': 'Beeswax',
    'hs6bdukanm': 'Criteo',
    'm8dbw4sv7c': 'Dataseat',
    'w9q455wk68': 'Hybrid',
    'yclnxrl5pm': 'Jampp',
    '4468km3ulz': 'Kayzen',
    't38b2kh725': 'Lifestreet',
    '7ug5zh24hu': 'Liftoff',
    '9t245vhmpl': 'Moloco',
    'cad8qz2s3j': 'MYAPPFREE',
    '44jx6755aq': 'Persona.ly',
    'tl55sbb4fm': 'PubNative',
    '2u9pt9hc89': 'Remerge',
    '5a6flpkh64': 'RevX',
    '8s468mfl3y': 'RTBHouse',
    'klf5c3l5u5': 'Sift',
    'av6w8kgt66': 'ScaleMonk',
    'ppxm28t8ap': 'Smadex',
    '44n7hlldy6': 'SpykeMedia',
    '6964rsfnh4': 'ThingOrTwo',
    '3rd42ekr43': 'YouAppi',
    '4pfyvq9l8r': 'AdColony',
    '488r3q3dtq': 'Adtiming',
    'ludvb6z3bs': 'AppLovin',
    'lr83yxwka7': 'Apptimus',
    'wg4vff78zm': 'Bidmachine',
    '3sh42y64q3': 'Centro',
    'f38h382jlk': 'Chartboost',
    '9rd848q2bz': 'Criteo',
    'prcb7njmu6': 'CrossInstall',
    '52fl2v3hgk': 'Curate',
    'm5mvw97r93': 'DisciplineDigital',
    'v9wttpbfk9': 'Facebook Audience Network 1',
    'n38lu8286q': 'Facebook Audience Network 2',
    'fz2k2k5tej': 'FeedMob',
    'g2y4y55b64': 'GlobalWide',
    'cstr6suwn9': 'AdMob',
    'wzmmz9fp6w': 'InMobi',
    'su67r6k2v3': 'ironSource',
    'v79kvwwj4g': 'Kidoz',
    '5lm9lj6jb7': 'Loopme',
    'zmvfpc5aq8': 'Maiden',
    'kbd757ywx3': 'Mintegral',
    '275upjj5gd': 'Mobupps',
    '238da6jt44': 'Pangle China',
    '22mmun2rn5': 'Pangle Non China',
    '24zw6aqk47': 'Qverse',
    'glqzh8vgby': 'Sabio Mobile',
    '424m5254lk': 'Snap Inc.',
    'f73kdq92p3': 'Spotad',
    'ecpz2srf59': 'TapJoy',
    'pwa73g5rt2': 'Tremor',
    '4dzt52r2t5': 'Unity',
    'bvpn9ufa9b': 'Unity',
    'gta9lk7p23': 'Vungle',
}


def check_adnetworkidentifiers(p_list):
    """Collect all available AdNetworkItems."""
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

        adnetworkidentifier = adnetworkidentifier.split('.')[0]

        known_adnetworkidentifier = known_adnetworks.get(adnetworkidentifier)
        if known_adnetworkidentifier is not None:
            dic_item['known_adnetworkidentifier'] = known_adnetworkidentifier

        adnetworkidentifiers.append(dic_item)

    return adnetworkidentifiers
