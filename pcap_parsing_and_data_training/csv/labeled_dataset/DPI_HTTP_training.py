
# coding: utf-8

# In[1]:

from IPython.display import display
import sklearn
import pandas as pd
import numpy as np
import re
import time
import matplotlib
get_ipython().magic('matplotlib inline')
print(sklearn.__version__)
print(pd.__version__)

## import csv data, return list of dict
httpDF = pd.read_csv('http.csv',index_col=0)
httpDF.shape


# In[2]:

col=['len','Host','Accept','Connection','httpMethod','httpProto','uAgentBrowser','uAgentOS','label']
httpDF[['Host']] = httpDF[['Host']].fillna(0)
httpDF[['Accept']] = httpDF[['Accept']].fillna(0)
httpDF['Host'][httpDF['Host']!=0] = 1
httpDF['Accept'][httpDF['Accept']!=0] = 1


# In[3]:

cols_to_transform = ['Connection','httpMethod','httpProto','uAgentBrowser','uAgentOS']
new_features = pd.get_dummies( httpDF[col], columns = cols_to_transform )


# In[4]:

X = new_features.drop(['label','len'],axis=1)
#X = new_features.drop(['label'],axis=1)
y = new_features.label
print(X.shape)
print(y.shape)


# In[5]:

X.columns


# In[6]:

len(new_features.label.unique())


# In[7]:

from sklearn.cross_validation import train_test_split
X_train, X_test, y_train, y_test = train_test_split(X, y, random_state=1)
print(X_train.shape)
print(X_test.shape)
print(y_train.shape)
print(y_test.shape)


# In[8]:

## SVM
#from sklearn import svm
#clf = svm.SVC(decision_function_shape='ovr')
#clf = svm.SVC()

## Knearest
from sklearn.neighbors import KNeighborsClassifier
clf = KNeighborsClassifier(n_neighbors=len(new_features.label.unique()), weights='distance')

## Decision tree
#from sklearn.tree import DecisionTreeClassifier, export_graphviz
#clf = DecisionTreeClassifier()

## rand. forest
#from sklearn.ensemble import RandomForestClassifier
#clf = RandomForestClassifier(n_estimators=10)

## Gaussian Naive bayes
#from sklearn.naive_bayes import GaussianNB
#clf = GaussianNB()

## SDG
#from sklearn.linear_model import SGDClassifier
#clf = SGDClassifier(loss="log", penalty="l2")
get_ipython().magic('time clf.fit(X_train, y_train)')


# In[9]:

result = clf.predict(X_test)

#from sklearn.metrics import accuracy_score
#accuracy_score(y_test, result) #(true, pred)

# calculate accuracy of class predictions
from sklearn import metrics
metrics.accuracy_score(y_test, result)


# ## for decision tree

# In[10]:

#export_graphviz(clf, feature_names=X_train.columns)


# ## new a cell run below to get a image for the dtree
#     !dot -Tpng tree.dot -o tree.png

# In[11]:

from sklearn.externals import joblib
## save model
joblib.dump(clf, 'http_clf_kn.pkl') 

#load the model
#clf = joblib.load('filename.pkl') 


# In[12]:

t = np.array(y_test, dtype=pd.Series)
for x in range(0,len(result)):
    if result[x] != t[x]:
        print(result[x],t[x])


# In[14]:

X_test[y_test > result]

