from pymongo import MongoClient
from bson.objectid import ObjectId  # ObjectId(oid)
import urllib.parse  # in order to escape
from pymongo.errors import ConnectionFailure

"""
some errors - Exceptions
-pymongo.errors.OperationFailure
:Authentication failed., full error: {'ok': 0.0, 'errmsg': 'Authentication failed.', 'code': 18, 'codeName': 'AuthenticationFailed'}
:Connection refused, Timeout: 30s, Topology Description: <TopologyDescription id: 61f10bd615d536c72aae7ad4, topology_type: Unknown, servers:
[<ServerDescription ('localhost', 27017) server_type: Unknown, rtt: None, error=AutoReconnect('localhost:27017: [Errno 111] Connection refused')>]
-$sudo start pymongod start
: Name or service not known, Timeout: 30s, Topology Description: <TopologyDescription id: 61f12e2bd92cc85a23b6ff92, topology_type: Unknown, servers:
[<ServerDescription ('localhos', 27017) server_type: Unknown, rtt: None, error=AutoReconnect('localhos:27017: [Errno -2] Name or service not known')>]>
-check the URL
"""


class Mongo(object):

    def __init__(self, url, db_name, collection_name):
        self.url = url
        self.client = MongoClient(url)
        self.db = self.client[db_name]
        self.collection = self.db.get_collection(collection_name)

    def addOne(self, post):
        try:
            return self.collection.insert_one(post)
        except Exception as e:
            exit("Fail to insert the data into the database.(addOne()) " + str(e))

    def addMany(self, post):
        try:
            return self.collection.insert_many(post)
        except Exception as e:
            exit("Fail to insert the data into the database.(addMany()) " + str(e))

    def getOne(self, filter):
        try:
            return self.collection.find_one(filter)
        except Exception as e:
            exit("Fail to get the deviece from the database.(getOne()) " + str(e))

    def getCount(self, filter=None):
        if filter is None:
            try:
                return self.collection.estimated_document_count()
            except Exception as e:
                exit(
                    "Fail to count the number of the devices in the database.(getCount()) " + str(e))

        try:
            return self.collection.count_documents(filter)
        except Exception as e:
            exit(
                "Fail to count the number of the devices in the database.(getCount()) " + str(e))

    def updateMany(self, filter, post, x=False):
        try:
            return self.collection.update_many(filter, post, upsert=x)
        except Exception as e:
            exit("Fail to update the data in the database.(update()) " + str(e))

    def deleteOne(self, filter):
        try:
            return self.collection.delete_one(filter)
        except Exception as e:
            exit("Fail to delete the data in the database.(deleteOne()) " + str(e))

    def deleteMany(self, filter):
        try:
            return self.collection.delete_many(filter)
        except Exception as e:
            exit("Fail to delete the data in the database.(deleteMany()) " + str(e))