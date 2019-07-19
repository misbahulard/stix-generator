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

def sdo_to_dict(sdo):
    return json.loads(sdo.serialize())


if __name__ == "__main__":

    client = MongoClient('mongodb://localhost:27017')

    db = client['stix_pcap']
    event_coll = db['event']
    observed_data_coll = db['observed_data_ddos']
    indicator_coll = db['indicator_ddos']
    identity_coll = db['identity_ddos']
    threat_actor_coll = db['threat_actor_ddos']
    attack_pattern_coll = db['attack_pattern_ddos']
    bundle_coll = db['bundle_ddos']

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

    ddos_event = []
    uniq_event = []

    for event in events:
        uniq_event.append([event['dest_ip'], event['dest_port'], event['protocol'], event['alert_msg']])

    # print(len(uniq_event))

    uniq_event_processed = list(set(map(tuple, uniq_event)))

    # print(len(uniq_event_processed))

    uniq_event_processed = map(list, uniq_event_processed) 
    label = ['dest_ip', 'dest_port', 'protocol', 'alert_msg', 'src_ip', 'first_observed', 'last_observed', 'number_observed']
    uniq_objects = []
    for uniq in uniq_event_processed:
        uniq.append([])
        uniq.append('999999999999999999')
        uniq.append('')
        uniq.append(0)
        uniq_objects.append(dict(zip(label, uniq)))

    # print(uniq_objects[0])

    for event in events:
        for obj in uniq_objects:
            # print(event['dest_ip'])
            # print(obj['dest_ip'])
            # print('\n')
            if obj['dest_ip'] == event['dest_ip'] and obj['dest_port'] == event['dest_port'] and obj['protocol'] == event['protocol'] and obj['alert_msg'] == event['alert_msg']:
                # update source ip
                if event['src_ip'] not in obj['src_ip']:
                    obj['src_ip'].append(event['src_ip'])
                if event['first_observed'] < obj['first_observed']:
                    obj['first_observed'] = event['first_observed']
                if event['last_observed'] > obj['last_observed']:
                    obj['last_observed'] = event['last_observed']
                obj['number_observed'] = obj['number_observed'] + event['number_observed']


    # for uniq in uniq_objects:
    #     print(uniq)

    # print("\nUniq Object terakhir")
    # print(uniq_objects[-1])

    # event = uniq_objects[-1]
    # observed_data = to_observed_data(event)
    # indicator = to_indicator(event)
    # identity = to_identity(event)
    # identity_target = to_identity(event, target=True)
    # threat_actor = to_threat_actor(event)
    # attack_pattern = to_attack_pattern(event)
    

    # print("\nDATA")
    # print('observed', len(observed_data))
    # print('indicator', len(indicator))
    # print('indetiry', len(identity))
    # print('identity target', len(identity_target))
    # print('threat actor', len(threat_actor))
    # print('attack pattern', len(attack_pattern))

    bundles = []
    observed_datas = []
    indicators = []
    identities = []
    threat_actors = []
    attack_patterns = []

    # coba looping
    for event in uniq_objects:
        observed_data = to_observed_data(event)
        indicator = to_indicator(event)
        identity = to_identity(event)
        identity_target = to_identity(event, target=True)
        threat_actor = to_threat_actor(event)
        attack_pattern = to_attack_pattern(event)
        relationship_indicates = to_relationship(indicator, 'indicates', attack_pattern)
        relationship_target = to_relationship(attack_pattern, 'targets', identity_target)
        relationship_observe = to_relationship(observed_data, 'observe', indicator)
        relationship_attributed = to_relationship(threat_actor, 'attributed-to', identity) # list
        relationship_uses = to_relationship(threat_actor, 'uses', attack_pattern) # list

        satuan = [observed_data, indicator, identity_target, attack_pattern, relationship_indicates, relationship_target, relationship_observe] + identity + threat_actor + relationship_attributed + relationship_uses

        bundle = to_bundle(satuan)

        # observed_datas.append(sdo_to_dict(observed_data))
        # indicators.append(sdo_to_dict(indicator))
        # for item in identity:
            # identities.append(sdo_to_dict(item))
        # for item in threat_actor:
            # threat_actors.append(sdo_to_dict(item))
        # attack_patterns.append(sdo_to_dict(attack_pattern))
        bundles.append(sdo_to_dict(bundle))

        # update progress bar
        progress.current += 1
        progress()
    
    print("\n--- Time elapsed %s seconds ---" % (time.time() - start_time))

    print("Write data to mongo")
    start_time = time.time()

    # observed_data_coll.insert_many(observed_datas)
    # indicator_coll.insert_many(indicators)
    # identity_coll.insert_many(identities)
    # threat_actor_coll.insert_many(threat_actors)
    # attack_pattern_coll.insert_many(attack_patterns)
    bundle_coll.insert(bundles)

    print("\n--- Time elapsed %s seconds ---" % (time.time() - start_time))
