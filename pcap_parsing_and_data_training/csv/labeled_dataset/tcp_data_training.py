
# coding: utf-8

# # Import parsed CSV files and order the columns

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
#csv = ["arp.csv","ipv4.csv","icmp.csv","tcp.csv","udp.csv","dns.csv","ftp.csv","http.csv"]
csv = ["ipv4.csv","tcp.csv"]
def imp_csv(csv):
    ls_of_df = []
    for c in csv:
        df = pd.read_csv(c,index_col=0)
        ls_of_df.append(df)    
    return ls_of_df

# assign DF by order of variable "csv"
ipv4DF,tcpDF=imp_csv(csv)

# re-order the columns for each dataframe
#col = ['httpMethod','httpPath','httpProto','Host','Accept','Accept-Encoding','Accept-Language','Connection','uAgentBrowser','uAgentOS']
#http_reqDF = httpDF[col]
#http_reqDF = http_reqDF[http_reqDF.tcpDport==80]
#col = ['tcpSport','tcpDport','respCode','respMsg','Server','Content-Length','Content-Type','Connection']
#http_respDF = httpDF[col]
#http_respDF = http_respDF[http_respDF.tcpSport==80]


# # check the columns type, ensure they are in numeric

# In[2]:

print(tcpDF.info())
#print(ipv4DF.info())


# # SKIP useless, just test for combine http request and response

# In[3]:

#test = pd.concat([http_reqDF[['httpMethod','httpPath','httpProto','Host','Accept','Accept-Encoding','Accept-Language','Connection','uAgentBrowser','uAgentOS']],http_respDF[['respCode','respMsg','Server','Content-Length','Content-Type','Connection']]], axis=0)
#test = pd.concat([tcpDF, test], axis=1, join_axes=[test.index])
#test.sort_index()


# # A simple function for convert TCP flag from int to string

# In[4]:

def tcpFlg(list_of_flg):
    import operator
    strFlg = []   
    flgs = {'URG':32,'ACK':16,'PSH':8,'RST':4,'SYN':2,'FIN':1} # Unskilled Attackers Pester Real Security Folks
    for f in list_of_flg:
        flg = []
        for key,val in sorted(flgs.items(), key=operator.itemgetter(1)): # sort dict by value, (itemgetter(1) 0->by key 1->by value)
            if (f & val) != 0:
                flg.append(key)
        strFlg.append('/'.join(flg))
    
    result = pd.DataFrame({'Flag': strFlg})
    result.index = list_of_flg.index        
    return result

# testing example
#tcpDF = pd.concat([tcpDF,tcpFlg(tcpDF['tcpFlgint'])], axis=1)
#tcpDF


# # assign unknown port to other

# In[5]:

other = tcpDF[tcpDF.label=='?']
tcpDF = tcpDF[tcpDF.label!='?']
#tcpDF = tcpDF[tcpDF.tcpSport>32768]


# In[6]:

other.shape


# # For predict webmin & jupyter later -> http

# In[7]:

webmin = other[other['tcpDport']==10000]
jupyter = other[other['tcpDport']==8888]


# # For DF not nil, train the model
# ---

# ## Define X training data, y label

# In[8]:

#X = tcpDF.drop(['label','time','tcpSport','tcpDport'],axis=1)
X = tcpDF.drop(['label','time'],axis=1) # should i drop sport & dport?
y = tcpDF.label
print(X.shape)
print(y.shape)


# ## Split the dataset into training and testing data

# In[9]:

from sklearn.cross_validation import train_test_split
X_train, X_test, y_train, y_test = train_test_split(X, y, random_state=1)
print(X_train.shape)
print(X_test.shape)
print(y_train.shape)
print(y_test.shape)


# ## Feature scaling

# In[22]:

X.head(5)


# In[11]:

# feature scaling
from sklearn import preprocessing

mean_of_array = X.mean(axis=0)
std_of_array = X.std(axis=0)

X_train = preprocessing.scale(X_train)
X_test = preprocessing.scale(X_test)


# ## Train the classifier

# In[12]:

print(len(tcpDF.label.unique()))


# In[13]:

## SVM
#from sklearn import svm
#clf = svm.SVC(decision_function_shape='ovr')
#clf = svm.SVC()

## Knearest
from sklearn.neighbors import KNeighborsClassifier
clf = KNeighborsClassifier(n_neighbors=len(tcpDF.label.unique()), weights='distance')

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

## Kmeans
#from sklearn.cluster import MiniBatchKMeans
#clf = MiniBatchKMeans(n_clusters=len(tcpDF.label.unique()), random_state=0)
#%time clf.fit(X_train) 
get_ipython().magic('time clf.fit(X_train, y_train)')


# # Save the trained model 

# In[14]:

from sklearn.externals import joblib
## save model
joblib.dump(clf, 'tcp_clf_kn.pkl') 

##load the model
##clf = joblib.load('filename.pkl') 


# ## Predict

# In[15]:

result = clf.predict(X_test)

#from sklearn.metrics import accuracy_score
#accuracy_score(y_test, result) #(true, pred)

# calculate accuracy of class predictions
from sklearn import metrics
metrics.accuracy_score(y_test, result)


# # predict jupyter

# In[16]:

#result = clf.predict(jupyter.drop(['label','time'],axis=1))

#from sklearn.metrics import accuracy_score
#accuracy_score(y_test, result) #(true, pred)

#for i in result:
#    print(i)


# # print the confusion matrix

# In[17]:

#metrics.confusion_matrix(y_test, result)


# In[18]:

#X_test[y_test < result][0]


# In[19]:

print(type(result))
print(type(y_test))
t = np.array(y_test, dtype=pd.Series)
for x in range(0,len(result)):
    if result[x] != t[x]:
        print(result[x],t[x])
#(X_test[y_test < result][0] * std_of_array) + mean_of_array


# ## init classifier, fit, transform etc...
