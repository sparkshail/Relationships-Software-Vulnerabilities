#!/usr/bin/env python
# coding: utf-8

# In[2]:


from bs4 import BeautifulSoup
from lxml import etree
import xml.etree.ElementTree as ET
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
import sklearn
import gensim
import gensim.similarities 
from gensim.models.word2vec import Word2Vec
from scipy import spatial
import treelib
from treelib import Node, Tree
# Network x
import networkx as nx
import matplotlib.pyplot as plt
# Path Py
#import igraph
import numpy as np
import pathpy as pp
from numpy.linalg import norm
from IPython.display import *
from IPython.display import HTML
import networkx as nx
from networkx.algorithms import community
import networkx.algorithms.community as nxcom
from networkx.algorithms import community
from networkx.algorithms.community.centrality import girvan_newman
#communities_generator = community.centrality.girvan_newman(G_firstfive_2021)
import matplotlib.pyplot as plt
import networkx as nx
from networkx.algorithms.community.centrality import girvan_newman
get_ipython().run_line_magic('matplotlib', 'inline')


# In[2]:


# each has vulerabilities, each with titles, notes, cve, and references
# there can be multiple notes and references 
tree_2020 = ET.parse('allitems-cvrf-year-2020.xml')
root_2020 = tree_2020.getroot()
tree_2019 = ET.parse('allitems-cvrf-year-2019.xml')
root_2019 = tree_2019.getroot()


# In[1]:


notes_every_set = list();
all_notes_2020 = list();
all_notes_2019 = list();
cve_2020 = list()
cve_2019 = list()

# Exctracting publication dates for time staps 
# if not date/text is published remove the vulnerability 
pub_2020 = list()
pub_2019 = list()

for i in range(5,25905):
    try:
        all_notes_2020.append(root_2020[i][1][0].text)
        notes_every_set.append(root_2020[i][1][0].text)
        pub_2020.append(root_2020[i][1][1].text)
        cve_2020.append(root_2020[i][2].text)
    except:
        continue
    
for i in range(5,25000):
    try:
        pub_2019.append(root_2019[i][1][1].text)
        all_notes_2019.append((root_2019[i][1][0].text))
        notes_every_set.append(root_2019[i][1][0].text)
        cve_2019.append(root_2019[i][2].text)
    except:
        continue


# In[5]:


untokenized_notes = list();
for sentence in all_notes_2020: 
    untokenized_notes.append(sentence)
for sentence in all_notes_2019: 
    untokenized_notes.append(sentence)

sentences_2020 = all_notes_2020
sentences_2019 = all_notes_2019


for i in range(0, len(all_notes_2020)):
    all_notes_2020[i] = word_tokenize(all_notes_2020[i])

for i in range(0, len(all_notes_2019)):
    all_notes_2019[i] = word_tokenize(all_notes_2019[i])
    
sentences_2020 = all_notes_2020
sentences_2019 = all_notes_2019


# In[6]:


# Remove stopwords 

stop_words = list(stopwords.words("english"))
extra = ['(',')','.',',',';',':',"'","''"]
for i in extra:
    stop_words.append(i)

for sentence in sentences_2020:
    for word in sentence:
        if word.casefold() in stop_words:
            sentence.remove(word)

for sentence in sentences_2019:
    for word in sentence:
        if word.casefold() in stop_words:
            sentence.remove(word)


# In[7]:


def read_corpus(fname, tokens_only=False):
    count=0
    for doc in notes_every_set:
        count+=1
        tokens = gensim.utils.simple_preprocess(doc)
        if tokens_only:
            yield tokens
        else:
            yield gensim.models.doc2vec.TaggedDocument(tokens, [count])


train_corpus = list(read_corpus(notes_every_set))
test_corpus = list(read_corpus(notes_every_set, tokens_only=True))
model = gensim.models.doc2vec.Doc2Vec(vector_size=100, min_count=2, epochs=20)
model.build_vocab(train_corpus)
model.train(train_corpus, total_examples=model.corpus_count, epochs=model.epochs)


# In[8]:


vectors_2020 = list();

for sentence in sentences_2020:
    vectors_2020.append(model.infer_vector(sentence))
    
vectors_2019 = list();

for sentence in sentences_2019:
    vectors_2019.append(model.infer_vector(sentence))


# In[9]:


# Create dictionaries for every year 

entries_2020 = {0: {'CVE': "", 'Date': "",'Description': [],'Month':""}}

for i in range(0,len(pub_2020)):
    entries_2020[i] = {}
    entries_2020[i]['CVE'] = cve_2020[i]
    entries_2020[i]['Date'] = pub_2020[i]
    entries_2020[i]['Description'] = sentences_2020[i]
    entries_2020[i]['Month'] = "n/a"
    
entries_2019 = {0: {'CVE': "", 'Date': "", 'Description': [],'Month':""}}
    
for i in range(0,len(pub_2019)):
    entries_2019[i] = {}
    entries_2019[i]['CVE'] = cve_2019[i]
    entries_2019[i]['Date'] = pub_2019[i]
    entries_2019[i]['Description'] = sentences_2019[i]
    entries_2019[i]['Month'] = "n/a"


# In[10]:


months_2020 = [0,0,0,0,0,0,0,0,0,0,0,0]
for i in range(len(entries_2020)):
    if str(entries_2020[i]['Date'])[5] == '0' and entries_2020[i]['Date'][6] == '1':
        entries_2020[i]["Month"] = "January"
        months_2020[0] +=1
    if str(entries_2020[i]['Date'])[5] == '0' and entries_2020[i]['Date'][6] == '2':
        entries_2020[i]["Month"] = "February"
        months_2020[1] +=1
    if str(entries_2020[i]['Date'])[5] == '0' and entries_2020[i]['Date'][6] == '3':
        entries_2020[i]["Month"] = "March"
        months_2020[2] +=1
    if str(entries_2020[i]['Date'])[5] == '0' and entries_2020[i]['Date'][6] == '4':
        entries_2020[i]["Month"] = "April"
        months_2020[3] +=1
    if str(entries_2020[i]['Date'])[5] == '0' and entries_2020[i]['Date'][6] == '5':
        entries_2020[i]["Month"] = "May"
        months_2020[4] +=1
    if str(entries_2020[i]['Date'])[5] == '0' and entries_2020[i]['Date'][6] == '6':
        entries_2020[i]["Month"] = "June"
        months_2020[5] +=1
    if str(entries_2020[i]['Date'])[5] == '0' and entries_2020[i]['Date'][6] == '7':
        entries_2020[i]["Month"] = "July"
        months_2020[6] +=1
    if str(entries_2020[i]['Date'])[5] == '0' and entries_2020[i]['Date'][6] == '8':
        entries_2020[i]["Month"] = "August"
        months_2020[7] +=1
    if str(entries_2020[i]['Date'])[5] == '0' and entries_2020[i]['Date'][6] == '9':
        entries_2020[i]["Month"] = "September"
        months_2020[8] +=1
    if str(entries_2020[i]['Date'])[5] == '1' and entries_2020[i]['Date'][6] == '0':
        entries_2020[i]["Month"] = "October"
        months_2020[9] +=1
    if str(entries_2020[i]['Date'])[5] == '1' and entries_2020[i]['Date'][6] == '1':
        entries_2020[i]["Month"] = "November"
        months_2020[10] +=1
    if str(entries_2020[i]['Date'])[5] == '1' and entries_2020[i]['Date'][6] == '2':
        entries_2020[i]["Month"] = "December"
        months_2020[11] +=1


# In[11]:


months_2019 = [0,0,0,0,0,0,0,0,0,0,0,0]
for i in range(len(entries_2019)):
    if str(entries_2019[i]['Date'])[5] == '0' and entries_2019[i]['Date'][6] == '1':
        entries_2019[i]["Month"] = "January"
        months_2019[0] +=1
    if str(entries_2019[i]['Date'])[5] == '0' and entries_2019[i]['Date'][6] == '2':
        entries_2019[i]["Month"] = "February"
        months_2019[1] +=1
    if str(entries_2019[i]['Date'])[5] == '0' and entries_2019[i]['Date'][6] == '3':
        entries_2019[i]["Month"] = "March"
        months_2019[2] +=1
    if str(entries_2019[i]['Date'])[5] == '0' and entries_2019[i]['Date'][6] == '4':
        entries_2019[i]["Month"] = "April"
        months_2019[3] +=1
    if str(entries_2019[i]['Date'])[5] == '0' and entries_2019[i]['Date'][6] == '5':
        entries_2019[i]["Month"] = "May"
        months_2019[4] +=1
    if str(entries_2019[i]['Date'])[5] == '0' and entries_2019[i]['Date'][6] == '6':
        entries_2019[i]["Month"] = "June"
        months_2019[5] +=1
    if str(entries_2019[i]['Date'])[5] == '0' and entries_2019[i]['Date'][6] == '7':
        entries_2019[i]["Month"] = "July"
        months_2019[6] +=1
    if str(entries_2019[i]['Date'])[5] == '0' and entries_2019[i]['Date'][6] == '8':
        entries_2019[i]["Month"] = "August"
        months_2019[7] +=1
    if str(entries_2019[i]['Date'])[5] == '0' and entries_2019[i]['Date'][6] == '9':
        entries_2019[i]["Month"] = "September"
        months_2019[8] +=1
    if str(entries_2019[i]['Date'])[5] == '1' and entries_2019[i]['Date'][6] == '0':
        entries_2019[i]["Month"] = "October"
        months_2019[9] +=1
    if str(entries_2019[i]['Date'])[5] == '1' and entries_2019[i]['Date'][6] == '1':
        entries_2019[i]["Month"] = "November"
        months_2019[10] +=1
    if str(entries_2019[i]['Date'])[5] == '1' and entries_2019[i]['Date'][6] == '2':
        entries_2019[i]["Month"] = "December"
        months_2019[11] +=1


# # 2020

# In[13]:


#create the cos matrix for all of 2020
length = len(entries_2020)
entire_2020 = np.zeros((length, length))
row_means =list() 
for i in range(0,length):
    for j in range(i,length):
        mean = 0
        cos = abs(1/(spatial.distance.cosine(vectors_2020[i], vectors_2020[j])-1))
        entire_2020[i][j] = cos
        entire_2020[j][i] = cos 
        mean +=cos
        
        if(cos ==1):
            entire_2020[i][j] = 999
            entire_2020[j][i] = 999
    mean = mean/length
    row_means.append(mean)


# In[14]:


for i in range(0,length):
    for j in range(i,length):
        if  entire_2020[i][j] < row_means[i]:
            entire_2020[i][j] = 0
            entire_2020[j][i] = 0 


# In[15]:


from scipy import sparse
from scipy.sparse import csr_matrix
from scipy.sparse.csgraph import minimum_spanning_tree


# Minimum spanning tree
X = sparse.csr_matrix(entire_2020)
print(X.shape)
Tcsr = minimum_spanning_tree(X)
Tcsr.toarray().astype(float)

G_entire_2020 = nx.from_numpy_array(Tcsr.toarray(), parallel_edges=False, create_using=None)


# In[64]:


comp = nxcom.girvan_newman(G_entire_2020)
tuple(sorted(c) for c in next(comp))
([0, 1, 2, 3, 4], [5, 6, 7, 8, 9])

node_groups = []
for com in next(comp):
    #print(com)
    node_groups.append(list(com))


# In[16]:


# networkX to igraph
import igraph as ig
# largest connected component
components = nx.connected_components(G_entire_2020)
largest_component = max(components, key=len)
H = G_entire_2020.subgraph(largest_component)

# convert to igraph
h = ig.Graph.from_networkx(H)


# In[17]:


weights=h.es["weight"]
spanning_tree = h.spanning_tree(weights=weights, return_tree=True)
visual_style = dict()
visual_style["bbox"] = (500, 500)


# In[18]:


# note: try replacing h with spanning_tree 

gn = spanning_tree.community_edge_betweenness()
clust=gn.as_clustering()
print(clust)


# In[18]:


ig.plot(clust,vertex_size = 5,mark_groups = True,**visual_style)


# In[72]:


# using louvain instead of givran-newman
import community as community_louvain
import matplotlib.cm as cm
import matplotlib.pyplot as plt
import networkx as nx
import networkx.algorithms.community as nxcomm

partition_2020 = community_louvain.best_partition(G_entire_2020)

# or for igraph
louvain_2020 = spanning_tree.community_multilevel(weights=h.es['weight'], return_levels=False)


# In[73]:


print(louvain_2020)


# In[74]:


ig.plot(louvain_2020,vertex_size = 5,mark_groups = True,**visual_style)


# In[ ]:


edges = list(G_entire_2020.edges(data=True))


# In[ ]:


edges = list(G_entire_2020.edges(data=True))
node_edge_count = {0 : 0}


for edge in edges:
    if  node_edge_count[edge[]] == 0:
        node_edge_count[edge[]] = 1
    else:
        node_edge_count[edge[]] += 1


# # 2020 Clusters

# In[ ]:


clutser_counts = list()
cluster_1= defaultdict()
cluster_3= defaultdict()
cluster_6= defaultdict()
cluster_9= defaultdict()
cluster_12= defaultdict()

for i in range(0,len(clust)):
    for node in clust[i]:
        month = entries_2020[node]["Month"]
        if month == "January":
            try:
                cluster_1[node] +=1
                cluster_3[node] +=1
                cluster_6[node] +=1
                cluster_9[node] +=1
                cluster_12[node] +=1
            except:
                cluster_1[node] =1
                cluster_3[node] =1
                cluster_6[node] =1
                cluster_9[node] =1
                cluster_12[node] =1
        elif month == "February" or month == "March":
            try:
                cluster_3[node] +=1
                cluster_6[node] +=1
                cluster_9[node] +=1
                cluster_12[node] +=1
            except:
                cluster_3[node] =1
                cluster_6[node] =1
                cluster_9[node] =1
                cluster_12[node] =1
        elif month == "April" or month == "May" or month == "June":
            try:
                cluster_6[node] +=1
                cluster_9[node] +=1
                cluster_12[node] +=1
            except:
                cluster_6[node] =1
                cluster_9[node] =1
                cluster_12[node] =1
        elif month == "July" or month == "August" or month == "September":
            try:
                cluster_9[node] +=1
                cluster_12[node] +=1
            except:
                cluster_9[node] =1
                cluster_12[node] =1
        else:
            try:
                cluster_12[node] +=1
            except:
                cluster_12[node] =1


# In[ ]:


cluster_1c= defaultdict()
cluster_3c= defaultdict()
cluster_6c= defaultdict()
cluster_9c= defaultdict()
cluster_12c= defaultdict()

cluster_1c= {}
cluster_3c= {}
cluster_6c= {}
cluster_9c= {}
cluster_12c= {}

for i in range(0,len(clust)):
    cluster_1c[i] =0
    cluster_3c[i] =0
    cluster_6c[i] =0
    cluster_9c[i] =0
    cluster_12c[i] =0

for i in range(0,len(clust)):
    for node in clust[i]:
        month = entries_2020[node]["Month"]
        if month == "January":
            try:
                cluster_1c[i] +=1
                cluster_3c[i] +=1
                cluster_6c[i] +=1
                cluster_9c[i] +=1
                cluster_1c[i] +=1
            except:
                cluster_1c[i] =1
                cluster_3c[i] =1
                cluster_6c[i] =1
                cluster_9c[i] =1
                cluster_12c[i] =1
        elif month == "February" or month == "March":
            try:
                cluster_3c[i] +=1
                cluster_6c[i] +=1
                cluster_9c[i] +=1
                cluster_12c[i] +=1
            except:
                cluster_3c[i] =1
                cluster_6c[i] =1
                cluster_9c[i] =1
                cluster_12c[i] =1
        elif month == "April" or month == "May" or month == "June":
            try:
                cluster_6c[i] +=1
                cluster_9c[i] +=1
                cluster_12c[i] +=1
            except:
                cluster_6c[i] =1
                cluster_9c[i] =1
                cluster_12c[i] =1
        elif month == "July" or month == "August" or month == "September":
            try:
                cluster_9c[i] +=1
                cluster_12c[i] +=1
            except:
                cluster_9c[i] =1
                cluster_12c[i] =1
        else:
            try:
                cluster_12c[i] +=1
            except:
                cluster_12c[i] =1
   


# In[ ]:


counts_12c = list()
counts_9c = list()
counts_6c = list()
counts_3c = list()
counts_1c = list()

for key,value in cluster_12c.items():
    counts_12c.append(value)
for key,value in cluster_9c.items():
    counts_9c.append(value)
for key,value in cluster_6c.items():
    counts_6c.append(value)
for key,value in cluster_3c.items():
    counts_3c.append(value)
for key,value in cluster_1c.items():
    counts_1c.append(value)


# In[ ]:


plt.rcParams["figure.figsize"] = [10.00, 3.50]
plt.rcParams["figure.autolayout"] = True


x = list()
for i in range(0,len(clust)):
    x.append(i)

default_x_ticks = range(len(x))
plt.plot(default_x_ticks, counts_12c,label = "12 months")

plt.plot(default_x_ticks, counts_9c,label = "9 months")

plt.plot(default_x_ticks, counts_6c,label = "6 months")

plt.plot(default_x_ticks, counts_3c,label = "3 Months")

plt.plot(default_x_ticks, counts_1c,label = "1 Month")

plt.ylabel('Cluster Size')
plt.xlabel('Cluster Number')
plt.title('Cluster Size Changes in 2020')
plt.legend()
plt.show()
    


# # 2019

# In[19]:


#create the cos matrix for all of 2019
length = len(entries_2019)
entire_2019 = np.zeros((length, length))
row_means =list() 
for i in range(0,length):
    for j in range(i,length):
        mean = 0
        cos = abs(1/(spatial.distance.cosine(vectors_2019[i], vectors_2019[j])-1))
        entire_2019[i][j] = cos
        entire_2019[j][i] = cos 
        mean +=cos
        
        if(cos ==1):
            entire_2019[i][j] = 999
            entire_2019[j][i] = 999
    mean = mean/length
    row_means.append(mean)


# In[22]:


for i in range(0,length):
    for j in range(i,length):
        if  entire_2019[i][j] < row_means[i]:
            entire_2019[i][j] = 0
            entire_2019[j][i] = 0 
            
            


# In[ ]:


X = sparse.csr_matrix(entire_2019)
print(X.shape)
Tcsr = minimum_spanning_tree(X)
Tcsr.toarray().astype(float)

G_entire_2019 = nx.from_numpy_array(Tcsr.toarray(), parallel_edges=False, create_using=None)


# In[79]:


comp = nxcom.girvan_newman(G_entire_2019)
tuple(sorted(c) for c in next(comp))
([0, 1, 2, 3, 4], [5, 6, 7, 8, 9])

node_groups = []
for com in next(comp):
    #print(com)
    node_groups.append(list(com))


# In[21]:


# networkX to igraph
import igraph as ig
# largest connected component
components = nx.connected_components(G_entire_2019)
largest_component = max(components, key=len)
H = G_entire_2019.subgraph(largest_component)

# convert to igraph
h = ig.Graph.from_networkx(H)


# In[81]:


weights=h.es["weight"]
spanning_tree = h.spanning_tree(weights=weights, return_tree=True)
visual_style = dict()
visual_style["bbox"] = (500, 500)


# In[82]:


gn = spanning_tree.community_edge_betweenness()
clust=gn.as_clustering()
print(clust)


# In[83]:


ig.plot(clust,vertex_size = 5,mark_groups = True,**visual_style)


# In[84]:


# using louvain instead of givran-newman
import community as community_louvain
import matplotlib.cm as cm
import matplotlib.pyplot as plt
import networkx as nx
import networkx.algorithms.community as nxcomm

partition_2019 = community_louvain.best_partition(G_entire_2019)

# or for igraph
louvain_2019 = spanning_tree.community_multilevel(weights=h.es['weight'], return_levels=False)


# In[86]:


print(louvain_2019)


# In[1]:


ig.plot(louvain_2019,vertex_size = 5,mark_groups = True,**visual_style)


# # 2019 Clusters

# In[ ]:


clutser_counts = list()
cluster_1= defaultdict()
cluster_3= defaultdict()
cluster_6= defaultdict()
cluster_9= defaultdict()
cluster_12= defaultdict()

for i in range(0,len(clust)):
    for node in clust[i]:
        month = entries_2019[node]["Month"]
        if month == "January":
            try:
                cluster_1[node] +=1
                cluster_3[node] +=1
                cluster_6[node] +=1
                cluster_9[node] +=1
                cluster_12[node] +=1
            except:
                cluster_1[node] =1
                cluster_3[node] =1
                cluster_6[node] =1
                cluster_9[node] =1
                cluster_12[node] =1
        elif month == "February" or month == "March":
            try:
                cluster_3[node] +=1
                cluster_6[node] +=1
                cluster_9[node] +=1
                cluster_12[node] +=1
            except:
                cluster_3[node] =1
                cluster_6[node] =1
                cluster_9[node] =1
                cluster_12[node] =1
        elif month == "April" or month == "May" or month == "June":
            try:
                cluster_6[node] +=1
                cluster_9[node] +=1
                cluster_12[node] +=1
            except:
                cluster_6[node] =1
                cluster_9[node] =1
                cluster_12[node] =1
        elif month == "July" or month == "August" or month == "September":
            try:
                cluster_9[node] +=1
                cluster_12[node] +=1
            except:
                cluster_9[node] =1
                cluster_12[node] =1
        else:
            try:
                cluster_12[node] +=1
            except:
                cluster_12[node] =1


# In[ ]:


cluster_1c= defaultdict()
cluster_3c= defaultdict()
cluster_6c= defaultdict()
cluster_9c= defaultdict()
cluster_12c= defaultdict()

cluster_1c= {}
cluster_3c= {}
cluster_6c= {}
cluster_9c= {}
cluster_12c= {}

for i in range(0,len(clust)):
    cluster_1c[i] =0
    cluster_3c[i] =0
    cluster_6c[i] =0
    cluster_9c[i] =0
    cluster_12c[i] =0

for i in range(0,len(clust)):
    for node in clust[i]:
        month = entries_2019[node]["Month"]
        if month == "January":
            try:
                cluster_1c[i] +=1
                cluster_3c[i] +=1
                cluster_6c[i] +=1
                cluster_9c[i] +=1
                cluster_1c[i] +=1
            except:
                cluster_1c[i] =1
                cluster_3c[i] =1
                cluster_6c[i] =1
                cluster_9c[i] =1
                cluster_12c[i] =1
        elif month == "February" or month == "March":
            try:
                cluster_3c[i] +=1
                cluster_6c[i] +=1
                cluster_9c[i] +=1
                cluster_12c[i] +=1
            except:
                cluster_3c[i] =1
                cluster_6c[i] =1
                cluster_9c[i] =1
                cluster_12c[i] =1
        elif month == "April" or month == "May" or month == "June":
            try:
                cluster_6c[i] +=1
                cluster_9c[i] +=1
                cluster_12c[i] +=1
            except:
                cluster_6c[i] =1
                cluster_9c[i] =1
                cluster_12c[i] =1
        elif month == "July" or month == "August" or month == "September":
            try:
                cluster_9c[i] +=1
                cluster_12c[i] +=1
            except:
                cluster_9c[i] =1
                cluster_12c[i] =1
        else:
            try:
                cluster_12c[i] +=1
            except:
                cluster_12c[i] =1
   


# In[ ]:


counts_12c = list()
counts_9c = list()
counts_6c = list()
counts_3c = list()
counts_1c = list()

for key,value in cluster_12c.items():
    counts_12c.append(value)
for key,value in cluster_9c.items():
    counts_9c.append(value)
for key,value in cluster_6c.items():
    counts_6c.append(value)
for key,value in cluster_3c.items():
    counts_3c.append(value)
for key,value in cluster_1c.items():
    counts_1c.append(value)


# In[ ]:


plt.rcParams["figure.figsize"] = [10.00, 3.50]
plt.rcParams["figure.autolayout"] = True


x = list()
for i in range(0,len(clust)):
    x.append(i)

default_x_ticks = range(len(x))
plt.plot(default_x_ticks, counts_12c,label = "12 months")

plt.plot(default_x_ticks, counts_9c,label = "9 months")

plt.plot(default_x_ticks, counts_6c,label = "6 months")

plt.plot(default_x_ticks, counts_3c,label = "3 Months")

plt.plot(default_x_ticks, counts_1c,label = "1 Month")

plt.ylabel('Cluster Size')
plt.xlabel('Cluster Number')
plt.title('Cluster Size Changes in 2019')
plt.legend()
plt.show()
    

