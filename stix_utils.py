import json
import re
import uuid
from datetime import datetime

import geoip2.database
import stix2
from geoip2.errors import AddressNotFoundError


def to_observed_data(r):
    """ Fungsi untuk mengubah menjadi objek stix observable """

    uid = str(uuid.uuid4())
    created = datetime.now()
    modified = created
    temp_first = float(r["first_observed"])
    temp_last = float(r["last_observed"])
    first_observed = datetime.fromtimestamp(temp_first)
    last_observed = datetime.fromtimestamp(temp_last)
    number_observed = int(r["number_observed"])

    observed = stix2.ObservedData(
        id="observed-data--" + uid,
        created=created,
        modified=modified,
        first_observed=first_observed,
        last_observed=last_observed,
        number_observed=number_observed,
        objects=
        {
            "0": {
                "type": "ipv4-addr",
                "value": r["src_ip"]
            },
            "1": {
                "type": "ipv4-addr",
                "value": r["dest_ip"]
            },
            "2": {
                "type": "network-traffic",
                "src_ref": "0",
                "dst_ref": "1",
                # "src_port": r["src_port"],
                "dst_port": r["dest_port"],
                "protocols": [
                    "ipv4",
                    r["protocol"]
                ],
            }
        }
    )

    return observed


def to_indicator(r):
    """ Fungsi untuk mengubah menjadi objek stix indicator """

    uid = str(uuid.uuid4())
    created = datetime.now()
    modified = created
    valid_from = created
    src_type = "ipv4-addr"
    dst_type = "ipv4-addr"
    src_ip = r['src_ip']
    dst_ip = r['dest_ip']

    indicator = stix2.Indicator(
        id="indicator--" + uid,
        created=created,
        modified=modified,
        name="Malicious Network Flow",
        description="Malicious IP: " + src_ip + " detected.",
        labels=["malicious-activity"],
        pattern="[network-traffic:src_ref.type = '"
                + src_type + "' AND network-traffic:src_ref.value = '"
                + src_ip + "'] AND [network-traffic:dst_ref.type = '"
                + dst_type + "' AND network-traffic:dst_ref.value = '"
                + dst_ip + "'] REPEATS " + str(r['number_observed']) + " TIMES",
        valid_from=valid_from
    )

    return indicator


def to_identity(r, target=False):
    """ Fungsi untuk mengubah menjadi objek stix identity dengan cara lookup ip ke geoip maxmind """

    uid = str(uuid.uuid4())
    created = datetime.now()
    modified = created

    if target:
        ip = r['dest_ip']
    else:
        ip = r['src_ip']
    geoip = lookup_ip(ip)

    if geoip['city'] == 'PRIVATE':
        name = 'Internal system'
        desc = 'identity from internal | ' + ip
    else:
        name = geoip['country'] + ' generic'
        desc = 'Individual identity from ' + geoip['city'] + ', ' + geoip['country'] + ' | ' + ip

    identity = stix2.Identity(
        id="identity--" + uid,
        created=created,
        modified=modified,
        name=name,
        description=desc,
        identity_class="individual"
    )

    return identity


def to_threat_actor(r):
    """ Fungsi untuk mengubah menjadi objek stix threat-actor dengan cara lookup ip ke geoip maxmind """

    uid = str(uuid.uuid4())
    created = datetime.now()
    modified = created

    ip = r['src_ip']
    geoip = lookup_ip(ip)
    if geoip['city'] == 'PRIVATE':
        name = 'Internal threat actor'
        desc = 'Threat actor from internal system | ' + ip
    else:
        name = geoip['country'] + ' threat actor'
        desc = 'Threat actor from ' + geoip['city'] + ', ' + geoip['country'] + ' | ' + ip

    threat_actor = stix2.ThreatActor(
        id="threat-actor--" + uid,
        created=created,
        modified=modified,
        name=name,
        description=desc,
        labels=["crime-syndicate"]
    )

    return threat_actor


def to_attack_pattern(r):
    """ Fungsi untuk mengubah menjadi objek stix attack-pattern """

    uid = str(uuid.uuid4())
    created = datetime.now()
    modified = created

    name = r['alert_msg']
    desc = 'attack from ' + r['src_ip'] + ' to ' + r['dest_ip']

    attack_pattern = stix2.AttackPattern(
        id="attack-pattern--" + uid,
        created=created,
        modified=modified,
        name=name,
        description=desc
    )

    return attack_pattern


def to_relationship(obj1, relation, obj2):
    relationship = stix2.Relationship(obj1, relation, obj2)
    return relationship


def to_bundle(obj):
    bundle = stix2.Bundle(objects=obj)
    return bundle


def lookup_ip(ip):
    """ Fungsi untuk lookup ip ke datavase geoip maxmind """
    geo_dict = {}
    reader = geoip2.database.Reader('data/GeoLite2-City.mmdb')
    try:
        result = reader.city(ip)
        country = result.country.name
        city = result.city.name

        if city is None:
            city = "UNDEFINED"
        if country is None:
            country = "UNDEFINED"

        geo_dict['country'] = country
        geo_dict['city'] = city

    except AddressNotFoundError:
        if is_private(ip):
            geo_dict['country'] = 'PRIVATE'
            geo_dict['city'] = 'PRIVATE'
        else:
            geo_dict['country'] = 'UNDEFINED'
            geo_dict['city'] = 'UNDEFINED'

    return geo_dict


def is_private(ip):
    """ Fungsi untuk melakukan pengecekan apakah ip tersebut private """

    regex = r"(^127\.)|(^192\.168\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)"

    if re.search(regex, ip):
        return True
    else:
        return False
