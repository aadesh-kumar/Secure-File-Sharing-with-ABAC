from pymongo import MongoClient
from py_abac import PDP, Policy, Request
from py_abac.storage.mongo import MongoStorage

# Policy definition in JSON
policy1 = {
    "uid": "1",
    "description": "Users are allowed to create any resource.",
    "effect": "allow",
    "rules": {
        "subject": {"$.name": {"condition": "RegexMatch", "value": ".*"}},
        "resource": {"$.name": {"condition": "RegexMatch", "value": ".*"}},
        "action": {"$.method": {"condition": "Equals", "value": "create"}},
        "context": {}
    },
    "targets": {},
    "priority": 0
}

policy2 = {
    "uid": "2",
    "description": "Users are allowed to delete their created resources.",
    "effect": "allow",
    "rules": {
        "subject": {"$.name": {"condition": "RegexMatch", "value": ".*"}},
        "resource": {"$.name": {"condition": "RegexMatch", "value": ".*"}},
        "action": {"$.method": {"condition": "Equals", "value": "delete"}},
        "context": {"$.created_by": {"condition": "EqualsAttribute", "ace": "subject", "path": "$.name"}}
    },
    "targets": {},
    "priority": 0
}

policy3 = {
    "uid": "3",
    "description": "Users are allowed to get resources created by them or shared with them.",
    "effect": "allow",
    "rules": {
        "subject": {"$.name": {"condition": "RegexMatch", "value": ".*"}},
        "resource": {"$.name": {"condition": "RegexMatch", "value": ".*"}},
        "action": {"$.method": {"condition": "Equals", "value": "get"}},
        "context": [{"$.created_by": {"condition": "EqualsAttribute", "ace": "subject", "path": "$.name"}},
                    {"$.receiver": {"condition": "EqualsAttribute", "ace": "subject", "path": "$.name"}}]
    },
    "targets": {},
    "priority": 0
}
policies = [policy1, policy2, policy3]

# Parse JSON and create policy object
for i in range(0,len(policies)):
    policies[i] = Policy.from_json(policies[i])

# Setup policy storage
client = MongoClient()
storage = MongoStorage(client)
cnt = 0
# Add policy to storage
for p in policies:
    storage.add(p)
    cnt += 1

print(str(cnt) + ' policies have been added successfully 😀')