from __future__ import print_function

import json
import multiprocessing
import re
import sys
import time

from pymongo import MongoClient

from progressbar import ProgressBar
from stix_utils import (to_attack_pattern, to_bundle, to_identity,
                        to_indicator, to_observed_data, to_relationship,
                        to_threat_actor)


def stixie(event):
    observed_data = to_observed_data(event)
    indicator = to_indicator(event)
    identity = to_identity(event)
    identity_target = to_identity(event, target=True)
    threat_actor = to_threat_actor(event)
    attack_pattern = to_attack_pattern(event)
    relationship1 = to_relationship(indicator, 'indicates', attack_pattern)
    relationship2 = to_relationship(threat_actor, 'attributed-to', identity)
    relationship3 = to_relationship(threat_actor, 'uses', attack_pattern)
    relationship4 = to_relationship(attack_pattern, 'targets', identity_target)
    relationship5 = to_relationship(observed_data, 'observe', indicator)
    bundle = to_bundle([
        observed_data, indicator, identity, identity_target, threat_actor, attack_pattern, relationship1, 
        relationship2, relationship3, relationship4, relationship5
        ])

    # update progress bar
    progress.current += 1
    progress()

    return bundle


def sdo_to_dict(sdo):
    return json.loads(sdo.serialize())


if __name__ == "__main__":

    client = MongoClient('mongodb://localhost:27017')

    db = client['stix']
    event_coll = db['event']
    observed_data_coll = db['observed_data']
    indicator_coll = db['indicator']
    identity_coll = db['identity']
    threat_actor_coll = db['threat_actor']
    attack_pattern_coll = db['attack_pattern']
    bundle_coll = db['bundle']

    events = list(event_coll.find())
    event_count = event_coll.count()

    progress = ProgressBar(event_count, fmt=ProgressBar.FULL)

    start_time = time.time()

    # res = map(stixie, events)
    bundles = []
    observed_datas = []
    indicators = []
    identities = []
    threat_actors = []
    attack_patterns = []

    for event in events:
        observed_data = to_observed_data(event)
        indicator = to_indicator(event)
        identity = to_identity(event)
        identity_target = to_identity(event, target=True)
        threat_actor = to_threat_actor(event)
        attack_pattern = to_attack_pattern(event)
        relationship1 = to_relationship(indicator, 'indicates', attack_pattern)
        relationship2 = to_relationship(threat_actor, 'attributed-to', identity)
        relationship3 = to_relationship(threat_actor, 'uses', attack_pattern)
        relationship4 = to_relationship(attack_pattern, 'targets', identity_target)
        relationship5 = to_relationship(observed_data, 'observe', indicator)
        bundle = to_bundle([
            observed_data, indicator, identity, identity_target, threat_actor, attack_pattern, relationship1, 
            relationship2, relationship3, relationship4, relationship5
            ])
        
        observed_datas.append(sdo_to_dict(observed_data))
        indicators.append(sdo_to_dict(indicator))
        identities.append(sdo_to_dict(identity))
        threat_actors.append(sdo_to_dict(threat_actor))
        attack_patterns.append(sdo_to_dict(attack_pattern))
        bundles.append(sdo_to_dict(bundle))

        # update progress bar
        progress.current += 1
        progress()

    print("\n--- Time elapsed %s seconds ---" % (time.time() - start_time))

    print("Write data to mongo")
    start_time = time.time()

    observed_data_coll.insert_many(observed_datas)
    indicator_coll.insert_many(indicators)
    identity_coll.insert_many(identities)
    threat_actor_coll.insert_many(threat_actors)
    attack_pattern_coll.insert_many(attack_patterns)
    bundle_coll.insert(bundles)

    print("\n--- Time elapsed %s seconds ---" % (time.time() - start_time))
