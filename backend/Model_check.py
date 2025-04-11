import pickle

import pickle
loaded_model = pickle.load(open('model_artifacts/model_20250220_093453.pkl', 'rb'))
print(type(loaded_model).__module__)  # Shows which module the model comes from
