#!/bin/env python

from IPython.display import display
import sklearn
import pandas as pd
import numpy as np
import re
import time
import matplotlib
get_ipython().magic('matplotlib inline')
print('sckit ver: ',sklearn.__version__)
print('pandas ver: ',pd.__version__)

## import csv data, return list of dict
csv = ["arp.csv","ipv4.csv","icmp.csv","tcp.csv","udp.csv","dns.csv","ftp.csv","http.csv"]
def imp_csv(csv):
    ls_of_df = []
    for c in csv:
        df = pd.read_csv(c,index_col=0)
        ls_of_df.append(df)
    return ls_of_df

# assign DF by order of variable "csv"
arpDF,ipv4DF,icmpDF,tcpDF,udpDF,dnsDF,ftpDF,httpDF=imp_csv(csv)
ls_of_df = arpDF,ipv4DF,icmpDF,tcpDF,udpDF,dnsDF,ftpDF,httpDF

print(tcpDF.shape)


# # Add label, remember change name but not No.

# In[3]:

# add labels
def add_label(name,ls_of_df):
    arpDF,ipv4DF,icmpDF,tcpDF,udpDF,dnsDF,ftpDF,httpDF=ls_of_df
    if tcpDF.empty == False:
        #col = ['time','len','ipv4Ihl','ipv4Tos','ipv4Flg','ipv4Frg','ipv4Len','ipv4TTL','tcpSport','tcpDport','tcpFlgint','tcpOfs','tcpWnd','label']
        tcpDF['label'] = '?'
        tcpDF['label'][tcpDF['tcpDport']==80] = 'http_'+name+'_request'
        tcpDF['label'][tcpDF['tcpSport']==80] = 'http_'+name+'_response'

        tcpDF['label'][tcpDF['tcpDport']==443] = 'https_'+name+'_request'
        tcpDF['label'][tcpDF['tcpSport']==443] = 'https_'+name+'_response'

        tcpDF['label'][tcpDF['tcpDport']==21] = 'ftp_'+name+'_request'
        tcpDF['label'][tcpDF['tcpSport']==21] = 'ftp_'+name+'_response'

        tcpDF['label'][tcpDF['tcpDport']==25] = 'smtp_'+name+'_request'
        tcpDF['label'][tcpDF['tcpSport']==25] = 'smtp_'+name+'_response'
        tcpDF['label'][tcpDF['tcpDport']==465] = 'smtps_'+name+'_request'
        tcpDF['label'][tcpDF['tcpSport']==465] = 'smtps_'+name+'_response'
        tcpDF['label'][tcpDF['tcpDport']==587] = 'msa_'+name+'_request'
        tcpDF['label'][tcpDF['tcpSport']==587] = 'msa_'+name+'_response'

        tcpDF['label'][tcpDF['tcpDport']==110] = 'pop_'+name+'_request'
        tcpDF['label'][tcpDF['tcpSport']==110] = 'pop_'+name+'_response'
        tcpDF['label'][tcpDF['tcpDport']==995] = 'pops_'+name+'_request'
        tcpDF['label'][tcpDF['tcpSport']==995] = 'pops_'+name+'_response'

        tcpDF['label'][tcpDF['tcpDport']==143] = 'imap_'+name+'_request'
        tcpDF['label'][tcpDF['tcpSport']==143] = 'imap_'+name+'_response'
        tcpDF['label'][tcpDF['tcpDport']==993] = 'imaps_'+name+'_request'
        tcpDF['label'][tcpDF['tcpSport']==993] = 'imaps_'+name+'_response'

        tcpDF['label'][tcpDF['tcpDport']==53] = 'dns_'+name+'_request'
        tcpDF['label'][tcpDF['tcpSport']==53] = 'dns_'+name+'_response'

        tcpDF['label'][tcpDF['tcpDport']==22] = 'ssh_'+name+'_request'
        tcpDF['label'][tcpDF['tcpSport']==22] = 'ssh_'+name+'_response'

        tcpDF['label'][tcpDF['tcpDport']==3389] = 'rdp_'+name+'_request'
        tcpDF['label'][tcpDF['tcpSport']==3389] = 'rdp_'+name+'_response'
    #tcpDF[col]

    if icmpDF.empty == False:
        #col=['time','len','ipv4Ihl','ipv4Tos','ipv4Flg','ipv4Frg','ipv4Len','ipv4TTL','icmpCode','icmpID','icmpSeq','icmpType','label']
        icmpDF['label'] = '?'
        icmpDF['label'][icmpDF['type']==8] = 'icmp_'+name+'_request'
        icmpDF['label'][icmpDF['type']==0] = 'icmp_'+name+'_reply'
    #icmpDF

    if arpDF.empty == False:
        arpDF['label'] = '?'
        arpDF['label'][arpDF['op']==1] = 'arp_'+name+'_request'
        arpDF['label'][arpDF['op']==2] = 'arp_'+name+'_reply'
    #arpDF

    if httpDF.empty == False:
        httpDF['label'] = '?'
        httpDF = httpDF[httpDF['httpMethod'].notnull()]
        httpDF['label'] = name

    #if ftpDF.empty == False:
    #    display(ftpDF)

    return (arpDF,ipv4DF,icmpDF,tcpDF,udpDF,dnsDF,ftpDF,httpDF)

arpDF,ipv4DF,icmpDF,tcpDF,udpDF,dnsDF,ftpDF,httpDF = add_label("bad",ls_of_df)


# # useless, just for separate httpd request and response

# In[4]:

#httpDF_request = httpDF[pd.notnull(httpDF['httpMethod'])]
#httpDF_respones = httpDF[pd.notnull(httpDF['respCode'])]
#print(httpDF.shape)
#print(httpDF_request.shape)
#print(httpDF_respones.shape)


# # concatenat columns

# In[5]:

# concatenat columns
tcpDF = pd.concat([ipv4DF,tcpDF], axis=1, join_axes=[tcpDF.index])
icmpDF = pd.concat([ipv4DF,icmpDF], axis=1, join_axes=[icmpDF.index])


# In[6]:

if tcpDF.empty==False:
    col = ['len','ipv4Ihl','ipv4Tos','ipv4Flg','ipv4Frg','ipv4Len','ipv4TTL','ipv4Pro','tcpSport','tcpDport','tcpFlgint','tcpOfs','tcpWnd','label']
    tcpDF = tcpDF[col]
    #col = ['time','len','ipv4Ihl', 'ipv4Tos', 'ipv4Flg', 'ipv4Frg','ipv4Len', 'ipv4TTL', 'ipv4Pro', 'seq', 'type', 'label']
    #icmpDF = icmpDF[col]

    tcpDF = tcpDF.loc[:,~tcpDF.columns.duplicated()]
    #icmpDF = icmpDF.loc[:,~icmpDF.columns.duplicated()]
    print(tcpDF.columns)
    #print(icmpDF.columns)

if icmpDF.empty==False:
    icmpDF = icmpDF.loc[:,~icmpDF.columns.duplicated()]


# # export as CSV, remember change name

# In[7]:

# export dataframe to csv file
def df_to_csv(name,ls_of_DF):
    import os
    i = 0 # 0:ipv4 1:icmp 2:tcp 3:http 4:ftp
    ls = ["arp","ipv4","icmp","tcp","udp","dns","http","ftp"]
    #ls = ["arp_"+name,"ipv4_"+name,"icmp_"+name,"tcp_"+name,"udp_"+name,"dns_"+name,"http_"+name,"ftp_"+name]
    path_d = 'labeled_dataset/'
    for df in ls_of_DF:
        if df.empty == False:
            fname = ls[i] + '.csv'
            existing = pd.read_csv(os.path.join(path_d, fname),index_col=0)
            if len(existing.columns) > 0:
                print(ls[i],existing.shape)
                df = pd.concat([existing,df],axis=0,join_axes=[existing.columns])
                df = df[~df.duplicated(keep='first')] # drop duplicate
                print(ls[i],df.shape)
                df.to_csv(os.path.join(path_d, fname))
        i = i + 1

ls_of_DF = [arpDF,ipv4DF,icmpDF,tcpDF,udpDF,dnsDF,httpDF,ftpDF]
df_to_csv("tmp being useless",ls_of_DF)


# In[8]:

existing = pd.read_csv('labeled_dataset/tcp.csv',index_col=0)
display(existing.tail(4))
print(existing.shape)
#display(tcpDF[col].tail(5))
#existing = pd.read_csv('labeled_dataset/tcp.csv',index_col=0)
#display(existing.tail(5))


# In[9]:

#existing = pd.read_csv('labeled_dataset/http_norm1.csv',index_col=0)
#if existing.empty == False:
#    existing['label'] = '?'
#    existing = httpDF[httpDF['httpMethod'].notnull()]
#    existing['label'] = 'norm'
#httpDF = pd.read_csv('labeled_dataset/http.csv',index_col=0)

#print(existing.shape)
#print(httpDF.shape)
#httpDF = pd.concat([httpDF,existing],axis=0,join_axes=[httpDF.columns])
#print(httpDF.shape)
#httpDF = httpDF[~httpDF.index.duplicated(keep='first')]
#print(httpDF.shape)
#display(httpDF)
#httpDF.to_csv('labeled_dataset/http.csv')
